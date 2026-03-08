const std = @import("std");
const builtin = @import("builtin");
const http = std.http;
const MockUpstream = @import("mock_upstream.zig").MockUpstream;
const proxy = @import("../net/proxy.zig");
const body_policy = @import("../net/body_policy.zig");
const entity_mask = @import("../redaction/entity_mask.zig");
const fuzzy_match = @import("../redaction/fuzzy_match.zig");
const admin = @import("../admin/admin.zig");
const logger_mod = @import("../infra/logger.zig");
const schema_mod = @import("../schema/schema.zig");
const hasher_mod = @import("../schema/hasher.zig");

/// Result of an E2E round-trip through the proxy.
pub const RoundTripResult = struct {
    /// Body received by the mock upstream (post-redaction or bypass).
    upstream_body: []u8,
    /// Raw request head received by the mock upstream.
    upstream_head: []u8,
    /// Body received by the test client.
    client_body: []u8,
    /// Raw response head received by the test client.
    client_head: []u8,
    /// HTTP status returned to the client.
    status: http.Status,
    /// Allocator for freeing results.
    allocator: std.mem.Allocator,

    pub fn deinit(self: *RoundTripResult) void {
        self.allocator.free(self.upstream_body);
        self.allocator.free(self.upstream_head);
        self.allocator.free(self.client_body);
        self.allocator.free(self.client_head);
    }
};

/// Configuration for a single E2E test run.
pub const HarnessConfig = struct {
    /// Entity names for Aho-Corasick masking. Empty = SSN-only mode.
    entity_names: []const []const u8 = &.{},
    /// Fuzzy matching threshold (0.0-1.0). 0 = disabled.
    fuzzy_threshold: f32 = 0.0,
    /// Content-Type to send to NanoMask. Null omits the header entirely.
    request_content_type: ?[]const u8 = "application/json",
    /// Optional Content-Encoding to send to NanoMask.
    request_content_encoding: ?[]const u8 = null,
    /// Response body the mock upstream should return.
    upstream_response: []const u8 = "OK",
    /// Content-Type for the upstream response.
    upstream_content_type: []const u8 = "text/plain",
    /// Additional upstream response headers.
    upstream_extra_headers: []const http.Header = &.{},
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
    /// Unsupported request body handling.
    unsupported_request_body_behavior: body_policy.UnsupportedBodyBehavior = .reject,
    /// Unsupported response body handling.
    unsupported_response_body_behavior: body_policy.UnsupportedBodyBehavior = .bypass,
    /// Additional request headers to send (NMV2-002 header fidelity testing).
    request_extra_headers: []const http.Header = &.{},
};

/// Send a POST request to `uri` with `payload` using content-length encoding
/// and return the response status and body.
fn httpPost(
    allocator: std.mem.Allocator,
    uri: std.Uri,
    payload: []const u8,
    content_type: ?[]const u8,
    extra_headers: []const http.Header,
) !struct { status: http.Status, body: []u8, head: []u8 } {
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    const content_type_header: http.Client.Request.Headers.Value = if (content_type) |ct|
        .{ .override = ct }
    else
        .omit;

    var req = try client.request(.POST, uri, .{
        .headers = .{ .content_type = content_type_header },
        .extra_headers = extra_headers,
    });
    defer req.deinit();

    req.transfer_encoding = .{ .content_length = payload.len };
    var body_buf: [1]u8 = undefined;
    var body_writer = try req.sendBodyUnflushed(&body_buf);
    try body_writer.writer.writeAll(payload);
    try body_writer.end();
    try req.connection.?.flush();

    var redirect_buf: [4096]u8 = undefined;
    var res = try req.receiveHead(&redirect_buf);
    const status = res.head.status;
    // Capture response head bytes before reader() invalidates them
    const head_bytes = try allocator.dupe(u8, res.head.bytes);

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
        .head = head_bytes,
    };
}

/// Perform a full E2E round-trip: client -> NanoMask proxy -> mock upstream -> proxy -> client.
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
        config.upstream_extra_headers,
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

    var entity_map: ?entity_mask.EntityMap = null;
    defer if (entity_map) |*em| em.deinit();

    if (config.entity_names.len > 0) {
        entity_map = try entity_mask.EntityMap.init(allocator, config.entity_names);
    }

    var fuzzy_matcher: ?fuzzy_match.FuzzyMatcher = null;
    defer if (fuzzy_matcher) |*fm| fm.deinit();

    if (config.fuzzy_threshold > 0.0 and config.entity_names.len > 0) {
        fuzzy_matcher = try fuzzy_match.FuzzyMatcher.init(allocator, config.entity_names, &.{}, config.fuzzy_threshold);
    }

    var log = try logger_mod.Logger.init(.error_, false, null);
    defer log.deinit();

    var upstream_client = std.http.Client{ .allocator = allocator };
    defer upstream_client.deinit();

    var active_connections = std.atomic.Value(u32).init(1);
    var connections_total = std.atomic.Value(u64).init(0);
    const start_time = std.time.timestamp();

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
        .unsupported_request_body_behavior = config.unsupported_request_body_behavior,
        .unsupported_response_body_behavior = config.unsupported_response_body_behavior,
        .enable_email = config.enable_email,
        .enable_phone = config.enable_phone,
        .enable_credit_card = config.enable_credit_card,
        .enable_ip = config.enable_ip,
        .enable_healthcare = config.enable_healthcare,
        .schema = config.schema,
        .hasher = config.hasher,
    };

    const ProxyThread = struct {
        fn run(server: *std.net.Server, ctx: proxy.ProxyContext) void {
            const connection = server.accept() catch return;
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
            var http_server = http.Server.init(&reader_iface, &writer_iface);
            var request = http_server.receiveHead() catch return;

            proxy.handleRequest(&request, ctx) catch {};
        }
    };

    const proxy_thread = try std.Thread.spawn(.{}, ProxyThread.run, .{ &proxy_server, proxy_ctx });

    // Build merged request headers: user-provided extra headers + Content-Encoding
    var request_headers = std.ArrayListUnmanaged(http.Header).empty;
    defer request_headers.deinit(allocator);

    // Copy user-provided extra headers first
    for (config.request_extra_headers) |h| {
        try request_headers.append(allocator, h);
    }

    // Add Content-Encoding if specified
    if (config.request_content_encoding) |content_encoding| {
        try request_headers.append(allocator, .{ .name = "Content-Encoding", .value = content_encoding });
    }

    var url_buf: [256]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/api/data", .{proxy_port});
    const uri = try std.Uri.parse(url);

    const result = try httpPost(
        allocator,
        uri,
        request_body,
        config.request_content_type,
        request_headers.items,
    );

    proxy_thread.join();

    mock.stop();
    if (mock.thread) |t| {
        t.join();
        mock.thread = null;
    }

    const recorded_body = mock.getRecordedBody() orelse "";
    const recorded_head = mock.getRecordedHead() orelse "";
    const upstream_body = try allocator.dupe(u8, recorded_body);
    const upstream_head = try allocator.dupe(u8, recorded_head);

    return .{
        .upstream_body = upstream_body,
        .upstream_head = upstream_head,
        .client_body = result.body,
        .client_head = result.head,
        .status = result.status,
        .allocator = allocator,
    };
}

// ===========================================================================
// Smoke Test - verify the harness itself works
// ===========================================================================

test "harness - passthrough round-trip" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    const body = "Hello, this is a clean payload with no PII.";
    var result = try roundTrip(allocator, body, .{
        .upstream_response = "upstream says hi",
    });
    defer result.deinit();

    try std.testing.expectEqualStrings(body, result.upstream_body);
    try std.testing.expectEqualStrings("upstream says hi", result.client_body);
    try std.testing.expectEqual(http.Status.ok, result.status);
}
