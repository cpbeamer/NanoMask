const std = @import("std");
const builtin = @import("builtin");
const http = std.http;
const MockUpstream = @import("mock_upstream.zig").MockUpstream;
const proxy = @import("../net/proxy.zig");
const entity_mask = @import("../redaction/entity_mask.zig");
const fuzzy_match = @import("../redaction/fuzzy_match.zig");
const admin = @import("../admin/admin.zig");
const logger_mod = @import("../infra/logger.zig");
const schema_mod = @import("../schema/schema.zig");
const hasher_mod = @import("../schema/hasher.zig");

/// Result of an E2E round-trip through the proxy.
pub const RoundTripResult = struct {
    /// Body received by the mock upstream (post-redaction).
    upstream_body: []u8,
    /// Body received by the test client (post-unmasking).
    client_body: []u8,
    /// HTTP status returned to the client.
    status: http.Status,
    /// Allocator for freeing results.
    allocator: std.mem.Allocator,

    pub fn deinit(self: *RoundTripResult) void {
        self.allocator.free(self.upstream_body);
        self.allocator.free(self.client_body);
    }
};

/// Configuration for a single E2E test run.
pub const HarnessConfig = struct {
    /// Entity names for Aho-Corasick masking. Empty = SSN-only mode.
    entity_names: []const []const u8 = &.{},
    /// Fuzzy matching threshold (0.0–1.0). 0 = disabled.
    fuzzy_threshold: f32 = 0.0,
    /// Response body the mock upstream should return.
    upstream_response: []const u8 = "OK",
    /// Content-Type for the upstream response.
    upstream_content_type: []const u8 = "text/plain",
    /// Pattern library flags.
    enable_email: bool = false,
    enable_phone: bool = false,
    enable_credit_card: bool = false,
    enable_ip: bool = false,
    enable_healthcare: bool = false,
    /// Schema for schema-aware redaction (null = chunked pipeline).
    schema: ?*const schema_mod.Schema = null,
    /// Hasher for HASH-mode pseudonymisation (null = disabled).
    hasher: ?*hasher_mod.Hasher = null,
};

/// Send a POST request to `uri` with `payload` using content-length encoding
/// and return the response status and body.
fn httpPost(
    allocator: std.mem.Allocator,
    uri: std.Uri,
    payload: []const u8,
) !struct { status: http.Status, body: []u8 } {
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    var req = try client.request(.POST, uri, .{
        .headers = .{ .content_type = .{ .override = "application/json" } },
    });
    defer req.deinit();

    // Use content-length (not chunked) — matches fetch() implementation pattern
    req.transfer_encoding = .{ .content_length = payload.len };
    var body_buf: [1]u8 = undefined;
    var body_writer = try req.sendBodyUnflushed(&body_buf);
    try body_writer.writer.writeAll(payload);
    try body_writer.end();
    try req.connection.?.flush();

    // Read response
    var redirect_buf: [4096]u8 = undefined;
    var res = try req.receiveHead(&redirect_buf);
    const status = res.head.status;

    // Read response body
    var transfer_buf: [4096]u8 = undefined;
    const reader = res.reader(&transfer_buf);
    var resp_body = std.ArrayListUnmanaged(u8).empty;
    defer resp_body.deinit(allocator);
    var chunk: [4096]u8 = undefined;
    while (true) {
        const n = reader.readSliceShort(&chunk) catch break;
        if (n == 0) break;
        try resp_body.appendSlice(allocator, chunk[0..n]);
        if (n < chunk.len) break;
    }

    return .{
        .status = status,
        .body = try allocator.dupe(u8, resp_body.items),
    };
}

/// Perform a full E2E round-trip: client → NanoMask proxy → mock upstream → proxy → client.
pub fn roundTrip(
    allocator: std.mem.Allocator,
    request_body: []const u8,
    config: HarnessConfig,
) !RoundTripResult {
    // --- 1. Start mock upstream ---
    var mock = try MockUpstream.init(
        allocator,
        config.upstream_response,
        config.upstream_content_type,
    );
    defer mock.deinit();
    try mock.start();

    // --- 2. Start a minimal proxy listener ---
    var proxy_server = try std.net.Address.listen(
        try std.net.Address.parseIp("127.0.0.1", 0),
        .{ .reuse_address = true },
    );
    defer proxy_server.deinit();
    const proxy_port = proxy_server.listen_address.getPort();

    // Build entity map if names provided
    var entity_map: ?entity_mask.EntityMap = null;
    defer if (entity_map) |*em| em.deinit();

    if (config.entity_names.len > 0) {
        entity_map = try entity_mask.EntityMap.init(allocator, config.entity_names);
    }

    // Build fuzzy matcher if threshold > 0
    var fuzzy_matcher: ?fuzzy_match.FuzzyMatcher = null;
    defer if (fuzzy_matcher) |*fm| fm.deinit();

    if (config.fuzzy_threshold > 0.0 and config.entity_names.len > 0) {
        fuzzy_matcher = try fuzzy_match.FuzzyMatcher.init(allocator, config.entity_names, &.{}, config.fuzzy_threshold);
    }

    // Create a logger that discards output (tests should not pollute stderr)
    var log = try logger_mod.Logger.init(.error_, false, null);
    defer log.deinit();

    // Shared HTTP client for the proxy's upstream connection
    var upstream_client = std.http.Client{ .allocator = allocator };
    defer upstream_client.deinit();

    // Atomic counters (required by ProxyContext, not used for assertions)
    var active_connections = std.atomic.Value(u32).init(1);
    var connections_total = std.atomic.Value(u64).init(0);
    const start_time = std.time.timestamp();

    // Thread context for the proxy handler
    const proxy_ctx = proxy.ProxyContext{
        .allocator = allocator,
        .client = &upstream_client,
        .target_host = "127.0.0.1",
        .target_port = mock.port,
        .target_tls = false,
        .session_entity_map = if (entity_map) |*em| em else null,
        .session_fuzzy_matcher = if (fuzzy_matcher) |*fm| fm else null,
        .entity_set = null,
        .admin_config = .{ .enabled = false, .token = null, .entity_file_sync = false, .entity_file = null, .fuzzy_threshold = 0.0 },
        .max_body_size = 1024 * 1024,
        .log = &log,
        .session_id = "e2e-test",
        .active_connections = &active_connections,
        .connections_total = &connections_total,
        .start_time = start_time,
        .enable_email = config.enable_email,
        .enable_phone = config.enable_phone,
        .enable_credit_card = config.enable_credit_card,
        .enable_ip = config.enable_ip,
        .enable_healthcare = config.enable_healthcare,
        .schema = config.schema,
        .hasher = config.hasher,
    };

    // Spawn a thread that accepts one connection and runs the proxy pipeline
    const ProxyThread = struct {
        fn run(server: *std.net.Server, ctx: proxy.ProxyContext) void {
            const connection = server.accept() catch return;
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
            var http_server = http.Server.init(&reader_iface, &writer_iface);
            var request = http_server.receiveHead() catch return;

            proxy.handleRequest(&request, ctx) catch {};
        }
    };

    const proxy_thread = try std.Thread.spawn(.{}, ProxyThread.run, .{ &proxy_server, proxy_ctx });

    // --- 3. Send request through the proxy ---
    var url_buf: [256]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/api/data", .{proxy_port});
    const uri = try std.Uri.parse(url);

    const result = try httpPost(allocator, uri, request_body);

    // Join proxy thread
    proxy_thread.join();

    // Wait for mock to finish recording
    if (mock.thread) |t| {
        t.join();
        mock.thread = null;
    }

    // --- 4. Collect results ---
    const recorded = mock.getRecordedBody() orelse "";
    const upstream_body = try allocator.dupe(u8, recorded);

    return .{
        .upstream_body = upstream_body,
        .client_body = result.body,
        .status = result.status,
        .allocator = allocator,
    };
}

// ===========================================================================
// Smoke Test — verify the harness itself works
// ===========================================================================

test "harness - passthrough round-trip" {
    // Zig 0.15 std.net has known issues with concurrent socket I/O on Windows
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    const body = "Hello, this is a clean payload with no PII.";
    var result = try roundTrip(allocator, body, .{
        .upstream_response = "upstream says hi",
    });
    defer result.deinit();

    // No PII → body should pass through unchanged
    try std.testing.expectEqualStrings(body, result.upstream_body);
    try std.testing.expectEqualStrings("upstream says hi", result.client_body);
    try std.testing.expectEqual(http.Status.ok, result.status);
}
