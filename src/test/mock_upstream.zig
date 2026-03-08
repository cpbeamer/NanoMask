const std = @import("std");
const builtin = @import("builtin");
const http = std.http;

/// A minimal HTTP server for E2E testing that records the received request
/// body and returns a configurable response. Runs in a background thread
/// so the test can act as both the client and the assertion driver.
pub const MockUpstream = struct {
    /// Allocator used for dynamic buffers.
    allocator: std.mem.Allocator,
    /// The underlying TCP listener.
    net_server: std.net.Server,
    /// Port the server is listening on (OS-assigned via port 0).
    port: u16,
    /// Body to return in responses.
    response_body: []const u8,
    /// Content-Type header for the response.
    response_content_type: []const u8,
    /// Recorded request body from the most recent request (heap-allocated).
    recorded_body: ?[]u8,
    /// Background accept-loop thread handle.
    thread: ?std.Thread,
    /// Signal to stop the accept loop.
    should_stop: std.atomic.Value(bool),

    /// Initialise and bind to a random available port on localhost.
    pub fn init(
        allocator: std.mem.Allocator,
        response_body: []const u8,
        response_content_type: []const u8,
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
            .response_content_type = response_content_type,
            .recorded_body = null,
            .thread = null,
            .should_stop = std.atomic.Value(bool).init(false),
        };
    }

    /// Start the accept loop in a background thread.
    pub fn start(self: *MockUpstream) !void {
        self.thread = try std.Thread.spawn(.{}, acceptLoop, .{self});
    }

    fn acceptLoop(self: *MockUpstream) void {
        while (!self.should_stop.load(.acquire)) {
            const connection = self.net_server.accept() catch {
                if (self.should_stop.load(.acquire)) return;
                continue;
            };
            self.handleOne(connection) catch {};
            // Only handle a single request per E2E test.
            return;
        }
    }

    fn handleOne(self: *MockUpstream, connection: std.net.Server.Connection) !void {
        defer connection.stream.close();

        var read_buf: [16 * 1024]u8 = undefined;
        var write_buf: [16 * 1024]u8 = undefined;

        var stream_reader = connection.stream.reader(&read_buf);
        var stream_writer = connection.stream.writer(&write_buf);
        // Mutation happens through the interface pointers, not the binding.
        _ = &stream_reader;
        _ = &stream_writer;

        const reader_iface_ptr = stream_reader.interface();
        var reader_iface: std.Io.Reader = reader_iface_ptr.*;
        var writer_iface: std.Io.Writer = stream_writer.interface;
        var server = http.Server.init(&reader_iface, &writer_iface);
        var request = try server.receiveHead();

        const method = request.head.method;
        // Record request body
        if (method.requestHasBody()) {
            // Clear expect header — we handle the body directly
            request.head.expect = null;
            var body_read_buf: [8192]u8 = undefined;
            const body_reader = request.readerExpectNone(&body_read_buf);
            var body = std.ArrayListUnmanaged(u8).empty;
            var chunk_buf: [8192]u8 = undefined;
            while (true) {
                const n = body_reader.readSliceShort(&chunk_buf) catch break;
                if (n == 0) break;
                try body.appendSlice(self.allocator, chunk_buf[0..n]);
            }
            // Free any previously recorded body
            if (self.recorded_body) |old| self.allocator.free(old);
            self.recorded_body = try body.toOwnedSlice(self.allocator);
        }

        // Send response using simple respond() API
        try request.respond(self.response_body, .{
            .status = .ok,
            .extra_headers = &.{
                .{ .name = "Content-Type", .value = self.response_content_type },
            },
        });
    }

    /// Return the body that the mock upstream received.
    pub fn getRecordedBody(self: *const MockUpstream) ?[]const u8 {
        return self.recorded_body;
    }

    /// Stop the server and clean up.
    pub fn deinit(self: *MockUpstream) void {
        self.should_stop.store(true, .release);
        // Unblock the accept() call by connecting and immediately closing.
        if (std.net.tcpConnectToAddress(self.net_server.listen_address)) |conn| {
            conn.close();
        } else |_| {}
        if (self.thread) |t| t.join();
        self.net_server.deinit();
        if (self.recorded_body) |b| self.allocator.free(b);
    }
};

// ===========================================================================
// Unit Tests — verify mock server records bodies and returns responses
// ===========================================================================

test "MockUpstream - echo round-trip" {
    // Zig 0.15 std.net has known issues with concurrent socket I/O on Windows
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    const response_text = "Hello from upstream";
    var mock = try MockUpstream.init(allocator, response_text, "text/plain");
    defer mock.deinit();
    try mock.start();

    // Build URL for the mock
    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/test", .{mock.port});
    const uri = try std.Uri.parse(url);

    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    // Send a POST with a body using content-length encoding
    const send_body = "test request body";
    var req = try client.request(.POST, uri, .{});
    defer req.deinit();
    req.transfer_encoding = .{ .content_length = send_body.len };

    var body_buf: [1]u8 = undefined;
    var body_writer = try req.sendBodyUnflushed(&body_buf);
    try body_writer.writer.writeAll(send_body);
    try body_writer.end();
    try req.connection.?.flush();

    // Read the response
    var redirect_buf: [4096]u8 = undefined;
    var res = try req.receiveHead(&redirect_buf);
    try std.testing.expectEqual(std.http.Status.ok, res.head.status);

    var transfer_buf: [4096]u8 = undefined;
    const reader = res.reader(&transfer_buf);
    var resp_body = std.ArrayListUnmanaged(u8).empty;
    defer resp_body.deinit(allocator);
    var chunk: [1024]u8 = undefined;
    while (true) {
        const n = reader.readSliceShort(&chunk) catch break;
        if (n == 0) break;
        try resp_body.appendSlice(allocator, chunk[0..n]);
        if (n < chunk.len) break;
    }

    try std.testing.expectEqualStrings(response_text, resp_body.items);

    // Wait for mock thread to finish processing
    if (mock.thread) |t| {
        t.join();
        mock.thread = null;
    }

    // Verify the mock recorded the request body
    const recorded = mock.getRecordedBody() orelse return error.NoBodyRecorded;
    try std.testing.expectEqualStrings(send_body, recorded);
}
