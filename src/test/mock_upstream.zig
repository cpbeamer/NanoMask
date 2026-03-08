const std = @import("std");
const builtin = @import("builtin");
const http = std.http;

/// A minimal HTTP server for E2E testing that records the received request
/// head/body and returns a configurable response.
pub const MockUpstream = struct {
    allocator: std.mem.Allocator,
    net_server: std.net.Server,
    port: u16,
    response_body: []const u8,
    response_stream_chunks: []const []const u8,
    response_inter_chunk_delay_ms: u64,
    response_content_type: []const u8,
    response_extra_headers: []const http.Header,
    recorded_body: ?[]u8,
    recorded_head: ?[]u8,
    thread: ?std.Thread,
    should_stop: std.atomic.Value(bool),

    pub fn init(
        allocator: std.mem.Allocator,
        response_body: []const u8,
        response_content_type: []const u8,
        response_extra_headers: []const http.Header,
    ) !MockUpstream {
        var server = try std.net.Address.listen(
            try std.net.Address.parseIp("127.0.0.1", 0),
            .{ .reuse_address = true },
        );
        const port = server.listen_address.getPort();
        return .{
            .allocator = allocator,
            .net_server = server,
            .port = port,
            .response_body = response_body,
            .response_stream_chunks = &.{},
            .response_inter_chunk_delay_ms = 0,
            .response_content_type = response_content_type,
            .response_extra_headers = response_extra_headers,
            .recorded_body = null,
            .recorded_head = null,
            .thread = null,
            .should_stop = std.atomic.Value(bool).init(false),
        };
    }

    pub fn start(self: *MockUpstream) !void {
        self.thread = try std.Thread.spawn(.{}, acceptLoop, .{self});
    }

    pub fn stop(self: *MockUpstream) void {
        self.should_stop.store(true, .release);
        if (std.net.tcpConnectToAddress(self.net_server.listen_address)) |conn| {
            conn.close();
        } else |_| {}
    }

    fn acceptLoop(self: *MockUpstream) void {
        while (!self.should_stop.load(.acquire)) {
            const connection = self.net_server.accept() catch {
                if (self.should_stop.load(.acquire)) return;
                continue;
            };
            // Check again after accept — stop() sends a sentinel connection to
            // unblock the accept() call. Close it immediately and exit.
            if (self.should_stop.load(.acquire)) {
                connection.stream.close();
                return;
            }
            self.handleOne(connection) catch {};
            return;
        }
    }

    fn handleOne(self: *MockUpstream, connection: std.net.Server.Connection) !void {
        defer connection.stream.close();

        var read_buf: [16 * 1024]u8 = undefined;
        var write_buf: [16 * 1024]u8 = undefined;

        var stream_reader = connection.stream.reader(&read_buf);
        var stream_writer = connection.stream.writer(&write_buf);
        // keep alive: prevent compiler from eliding stack-locals before .interface() borrows them
        _ = &stream_reader;
        _ = &stream_writer;

        const reader_iface_ptr = stream_reader.interface();
        var reader_iface: std.Io.Reader = reader_iface_ptr.*;
        var writer_iface: std.Io.Writer = stream_writer.interface;
        var server = http.Server.init(&reader_iface, &writer_iface);
        var request = try server.receiveHead();

        if (self.recorded_head) |old_head| self.allocator.free(old_head);
        self.recorded_head = try self.allocator.dupe(u8, request.head_buffer);

        if (request.head.method.requestHasBody()) {
            request.head.expect = null;
            var body_read_buf: [8192]u8 = undefined;
            const body_reader = request.readerExpectNone(&body_read_buf);
            var body = std.ArrayListUnmanaged(u8).empty;
            defer body.deinit(self.allocator);

            var chunk_buf: [8192]u8 = undefined;
            while (true) {
                const n = body_reader.readSliceShort(&chunk_buf) catch break;
                if (n == 0) break;
                try body.appendSlice(self.allocator, chunk_buf[0..n]);
            }

            if (self.recorded_body) |old_body| self.allocator.free(old_body);
            self.recorded_body = try body.toOwnedSlice(self.allocator);
        }

        var headers = std.ArrayListUnmanaged(http.Header).empty;
        defer headers.deinit(self.allocator);
        try headers.append(self.allocator, .{ .name = "Content-Type", .value = self.response_content_type });
        try headers.appendSlice(self.allocator, self.response_extra_headers);

        if (self.response_stream_chunks.len == 0) {
            try request.respond(self.response_body, .{
                .status = .ok,
                .extra_headers = headers.items,
            });
            return;
        }

        var resp_buf: [1024]u8 = undefined;
        var response_writer = try request.respondStreaming(&resp_buf, .{
            .respond_options = .{
                .status = .ok,
                .extra_headers = headers.items,
            },
        });

        for (self.response_stream_chunks, 0..) |chunk, i| {
            if (chunk.len > 0) {
                try response_writer.writer.writeAll(chunk);
                try response_writer.flush();
            }

            if (self.response_inter_chunk_delay_ms > 0 and i + 1 < self.response_stream_chunks.len) {
                std.Thread.sleep(self.response_inter_chunk_delay_ms * std.time.ns_per_ms);
            }
        }

        try response_writer.end();
    }

    pub fn getRecordedBody(self: *const MockUpstream) ?[]const u8 {
        return self.recorded_body;
    }

    pub fn getRecordedHead(self: *const MockUpstream) ?[]const u8 {
        return self.recorded_head;
    }

    pub fn deinit(self: *MockUpstream) void {
        self.stop();
        if (self.thread) |t| t.join();
        self.net_server.deinit();
        if (self.recorded_body) |b| self.allocator.free(b);
        if (self.recorded_head) |h| self.allocator.free(h);
    }
};

// ===========================================================================
// Unit Tests - verify mock server records bodies and returns responses
// ===========================================================================

test "MockUpstream - echo round-trip" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    const response_text = "Hello from upstream";
    var mock = try MockUpstream.init(allocator, response_text, "text/plain", &.{});
    defer mock.deinit();
    try mock.start();

    // Give the accept thread a moment to start listening (10ms)
    std.Thread.sleep(10_000_000);

    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/test", .{mock.port});
    const uri = try std.Uri.parse(url);

    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    const send_body = "test request body";
    var req = try client.request(.POST, uri, .{});
    defer req.deinit();
    req.transfer_encoding = .{ .content_length = send_body.len };

    var body_buf: [1]u8 = undefined;
    var body_writer = try req.sendBodyUnflushed(&body_buf);
    try body_writer.writer.writeAll(send_body);
    try body_writer.end();
    try req.connection.?.flush();

    var redirect_buf: [4096]u8 = undefined;
    var res = try req.receiveHead(&redirect_buf);
    try std.testing.expectEqual(std.http.Status.ok, res.head.status);

    // Read response body using Content-Length for deterministic reads
    var transfer_buf: [4096]u8 = undefined;
    const reader = res.reader(&transfer_buf);
    var resp_body = std.ArrayListUnmanaged(u8).empty;
    defer resp_body.deinit(allocator);
    var chunk: [1024]u8 = undefined;
    while (true) {
        const n = reader.readSliceShort(&chunk) catch break;
        if (n == 0) break;
        try resp_body.appendSlice(allocator, chunk[0..n]);
    }

    try std.testing.expectEqualStrings(response_text, resp_body.items);

    // Stop the mock before verifying recorded data to ensure clean shutdown
    mock.stop();
    if (mock.thread) |t| {
        t.join();
        mock.thread = null;
    }

    const recorded = mock.getRecordedBody() orelse return error.NoBodyRecorded;
    try std.testing.expectEqualStrings(send_body, recorded);
    try std.testing.expect(mock.getRecordedHead() != null);
}
