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
    response_delay_ms: u64,
    response_content_type: []const u8,
    response_extra_headers: []const http.Header,
    record_requests: bool,
    max_requests: usize,
    recorded_body: ?[]u8,
    recorded_head: ?[]u8,
    thread: ?std.Thread,
    should_stop: std.atomic.Value(bool),
    request_started: std.atomic.Value(bool),
    handled_requests: std.atomic.Value(usize),
    record_mutex: std.Thread.Mutex = .{},
    connection_threads: std.ArrayListUnmanaged(std.Thread),
    connection_threads_mutex: std.Thread.Mutex = .{},

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
            .response_delay_ms = 0,
            .response_content_type = response_content_type,
            .response_extra_headers = response_extra_headers,
            .record_requests = true,
            .max_requests = 1,
            .recorded_body = null,
            .recorded_head = null,
            .thread = null,
            .should_stop = std.atomic.Value(bool).init(false),
            .request_started = std.atomic.Value(bool).init(false),
            .handled_requests = std.atomic.Value(usize).init(0),
            .connection_threads = .empty,
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

    fn flushResponseChunk(writer: *http.BodyWriter) !void {
        try writer.writer.flush();
        try writer.flush();
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
            const thread = std.Thread.spawn(.{}, handleConnectionThread, .{ self, connection }) catch {
                self.handleOne(connection) catch {};
                self.markRequestHandled();
                continue;
            };

            self.connection_threads_mutex.lock();
            self.connection_threads.append(self.allocator, thread) catch {
                self.connection_threads_mutex.unlock();
                thread.detach();
                continue;
            };
            self.connection_threads_mutex.unlock();
        }
    }

    fn handleConnectionThread(self: *MockUpstream, connection: std.net.Server.Connection) void {
        self.handleOne(connection) catch {};
        self.markRequestHandled();
    }

    fn markRequestHandled(self: *MockUpstream) void {
        const handled = self.handled_requests.fetchAdd(1, .acq_rel) + 1;
        if (handled >= self.max_requests) {
            self.stop();
        }
    }

    fn handleOne(self: *MockUpstream, connection: std.net.Server.Connection) !void {
        defer connection.stream.close();

        var read_buf: [16 * 1024]u8 = undefined;
        var write_buf: [16 * 1024]u8 = undefined;

        var stream_reader = connection.stream.reader(&read_buf);
        var stream_writer = connection.stream.writer(&write_buf);
        var server = http.Server.init(stream_reader.interface(), &stream_writer.interface);
        var request = try server.receiveHead();
        self.request_started.store(true, .release);

        if (self.record_requests) {
            const recorded_head = try self.allocator.dupe(u8, request.head_buffer);
            self.record_mutex.lock();
            defer self.record_mutex.unlock();
            if (self.recorded_head) |old_head| self.allocator.free(old_head);
            self.recorded_head = recorded_head;
        }

        if (request.head.method.requestHasBody()) {
            request.head.expect = null;
            var body_read_buf: [8192]u8 = undefined;
            var body_reader = request.readerExpectNone(&body_read_buf);

            if (self.record_requests) {
                var body_out: std.Io.Writer.Allocating = .init(self.allocator);
                defer body_out.deinit();

                _ = try body_reader.streamRemaining(&body_out.writer);

                const recorded_body = try body_out.toOwnedSlice();
                self.record_mutex.lock();
                defer self.record_mutex.unlock();
                if (self.recorded_body) |old_body| self.allocator.free(old_body);
                self.recorded_body = recorded_body;
            } else {
                var discard_buf: [4096]u8 = undefined;
                while (true) {
                    const bytes_read = try body_reader.readSliceShort(&discard_buf);
                    if (bytes_read == 0 or bytes_read < discard_buf.len) break;
                }
            }
        }

        var headers = std.ArrayListUnmanaged(http.Header).empty;
        defer headers.deinit(self.allocator);
        try headers.append(self.allocator, .{ .name = "Content-Type", .value = self.response_content_type });
        try headers.appendSlice(self.allocator, self.response_extra_headers);

        if (self.response_delay_ms > 0) {
            std.Thread.sleep(self.response_delay_ms * std.time.ns_per_ms);
        }

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
                try flushResponseChunk(&response_writer);
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

    pub fn hasStartedRequest(self: *const MockUpstream) bool {
        return self.request_started.load(.acquire);
    }

    pub fn deinit(self: *MockUpstream) void {
        self.stop();
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
        self.joinConnectionThreads();
        self.net_server.deinit();
        if (self.recorded_body) |b| self.allocator.free(b);
        if (self.recorded_head) |h| self.allocator.free(h);
    }

    fn joinConnectionThreads(self: *MockUpstream) void {
        self.connection_threads_mutex.lock();
        defer self.connection_threads_mutex.unlock();

        for (self.connection_threads.items) |thread| {
            thread.join();
        }
        self.connection_threads.deinit(self.allocator);
        self.connection_threads = .empty;
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
    var resp_out: std.Io.Writer.Allocating = .init(allocator);
    defer resp_out.deinit();
    _ = try reader.streamRemaining(&resp_out.writer);
    const resp_body = try resp_out.toOwnedSlice();
    defer allocator.free(resp_body);

    try std.testing.expectEqualStrings(response_text, resp_body);

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
