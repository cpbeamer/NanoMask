const std = @import("std");
const builtin = @import("builtin");
const http = std.http;
const MockUpstream = @import("mock_upstream.zig").MockUpstream;
const proxy = @import("../net/proxy.zig");
const proxy_server_mod = @import("../net/proxy_server.zig");
const body_policy = @import("../net/body_policy.zig");
const entity_mask = @import("../redaction/entity_mask.zig");
const fuzzy_match = @import("../redaction/fuzzy_match.zig");
const admin = @import("../admin/admin.zig");
const logger_mod = @import("../infra/logger.zig");
const observability_mod = @import("../infra/observability.zig");
const shutdown_mod = @import("../infra/shutdown.zig");
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
    /// Structured proxy logs captured during the request.
    proxy_logs: []u8,
    /// Number of response body reads observed by the client.
    client_chunk_count: usize,
    /// Time from starting to receive the response to the first body bytes.
    first_chunk_latency_ns: ?u64,
    /// Time from starting to receive the response to the end of the body.
    total_response_latency_ns: u64,
    /// Allocator for freeing results.
    allocator: std.mem.Allocator,

    pub fn deinit(self: *RoundTripResult) void {
        self.allocator.free(self.upstream_body);
        self.allocator.free(self.upstream_head);
        self.allocator.free(self.client_body);
        self.allocator.free(self.client_head);
        self.allocator.free(self.proxy_logs);
    }
};

/// Configuration for a single E2E test run.
pub const HarnessConfig = struct {
    /// Entity names for Aho-Corasick masking. Empty = SSN-only mode.
    entity_names: []const []const u8 = &.{},
    /// Fuzzy matching threshold (0.0-1.0). 0 = disabled.
    fuzzy_threshold: f32 = 0.0,
    /// HTTP method to send to NanoMask.
    request_method: http.Method = .POST,
    /// Request target sent to NanoMask, including any query string.
    request_target: []const u8 = "/api/data",
    /// Content-Type to send to NanoMask. Null omits the header entirely.
    request_content_type: ?[]const u8 = "application/json",
    /// Optional Content-Encoding to send to NanoMask.
    request_content_encoding: ?[]const u8 = null,
    /// Response body the mock upstream should return.
    upstream_response: []const u8 = "OK",
    /// Optional chunked response body fragments from the mock upstream.
    upstream_stream_chunks: []const []const u8 = &.{},
    /// Delay between streamed upstream chunks in milliseconds.
    upstream_inter_chunk_delay_ms: u64 = 0,
    /// Delay before the mock upstream sends response headers/body.
    upstream_response_delay_ms: u64 = 0,
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
    /// Enable audit event emission in captured proxy logs.
    audit_log: bool = false,
    /// Unsupported request body handling.
    unsupported_request_body_behavior: body_policy.UnsupportedBodyBehavior = .reject,
    /// Unsupported response body handling.
    unsupported_response_body_behavior: body_policy.UnsupportedBodyBehavior = .bypass,
    /// Upstream TCP connect timeout in milliseconds.
    upstream_connect_timeout_ms: u64 = 5_000,
    /// Upstream response read timeout in milliseconds.
    upstream_read_timeout_ms: u64 = 30_000,
    /// Overall upstream request timeout in milliseconds.
    upstream_request_timeout_ms: u64 = 60_000,
    /// Additional request headers to send (NMV2-002 header fidelity testing).
    request_extra_headers: []const http.Header = &.{},
};

fn elapsedSince(start_ns: @TypeOf(std.time.nanoTimestamp())) u64 {
    const delta = std.time.nanoTimestamp() - start_ns;
    return if (delta < 0) 0 else @intCast(delta);
}

const TimingBodyCollector = struct {
    sink: std.Io.Writer.Allocating,
    writer: std.Io.Writer,
    receive_start_ns: @TypeOf(std.time.nanoTimestamp()),
    chunk_count: usize = 0,
    first_chunk_latency_ns: ?u64 = null,

    const vtable: std.Io.Writer.VTable = .{
        .drain = drain,
        .flush = flush,
    };

    fn init(allocator: std.mem.Allocator, receive_start_ns: @TypeOf(std.time.nanoTimestamp())) TimingBodyCollector {
        return .{
            .sink = .init(allocator),
            .writer = .{
                .vtable = &vtable,
                .buffer = &.{},
            },
            .receive_start_ns = receive_start_ns,
        };
    }

    fn deinit(self: *TimingBodyCollector) void {
        self.sink.deinit();
    }

    fn toOwnedSlice(self: *TimingBodyCollector) ![]u8 {
        return self.sink.toOwnedSlice();
    }

    fn drain(
        writer: *std.Io.Writer,
        data: []const []const u8,
        splat: usize,
    ) std.Io.Writer.Error!usize {
        const self: *TimingBodyCollector = @alignCast(@fieldParentPtr("writer", writer));
        self.chunk_count += 1;
        if (self.first_chunk_latency_ns == null) {
            self.first_chunk_latency_ns = elapsedSince(self.receive_start_ns);
        }
        return self.sink.writer.writeSplat(data, splat) catch return error.WriteFailed;
    }

    fn flush(writer: *std.Io.Writer) std.Io.Writer.Error!void {
        _ = writer;
    }
};

/// Send an HTTP request to `uri` and return the response status and body.
fn httpRequest(
    allocator: std.mem.Allocator,
    method: http.Method,
    uri: std.Uri,
    payload: []const u8,
    content_type: ?[]const u8,
    extra_headers: []const http.Header,
) !struct {
    status: http.Status,
    body: []u8,
    head: []u8,
    chunk_count: usize,
    first_chunk_latency_ns: ?u64,
    total_response_latency_ns: u64,
} {
    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    const content_type_header: http.Client.Request.Headers.Value = if (content_type) |ct|
        .{ .override = ct }
    else
        .omit;

    var req = try client.request(method, uri, .{
        .headers = .{ .content_type = content_type_header },
        .extra_headers = extra_headers,
    });
    defer req.deinit();

    if (method.requestHasBody()) {
        req.transfer_encoding = .{ .content_length = payload.len };
        var body_buf: [1]u8 = undefined;
        var body_writer = try req.sendBodyUnflushed(&body_buf);
        try body_writer.writer.writeAll(payload);
        try body_writer.end();
    } else {
        try req.sendBodilessUnflushed();
    }
    try req.connection.?.flush();

    var redirect_buf: [4096]u8 = undefined;
    const receive_start = std.time.nanoTimestamp();
    var res = try req.receiveHead(&redirect_buf);
    const status = res.head.status;
    // Capture response head bytes before reader() invalidates them
    const head_bytes = try allocator.dupe(u8, res.head.bytes);

    var transfer_buf: [4096]u8 = undefined;
    const reader = res.reader(&transfer_buf);
    var collector = TimingBodyCollector.init(allocator, receive_start);
    defer collector.deinit();
    _ = try reader.streamRemaining(&collector.writer);
    const response_body = try collector.toOwnedSlice();

    return .{
        .status = status,
        .body = response_body,
        .head = head_bytes,
        .chunk_count = collector.chunk_count,
        .first_chunk_latency_ns = collector.first_chunk_latency_ns,
        .total_response_latency_ns = elapsedSince(receive_start),
    };
}

/// Perform a full E2E round-trip: client -> NanoMask proxy -> mock upstream -> proxy -> client.
pub fn roundTrip(
    allocator: std.mem.Allocator,
    request_body: []const u8,
    config: HarnessConfig,
) !RoundTripResult {
    if (config.request_target.len == 0 or config.request_target[0] != '/') {
        return error.InvalidRequestTarget;
    }

    // --- 1. Start mock upstream ---
    var mock = try MockUpstream.init(
        allocator,
        config.upstream_response,
        config.upstream_content_type,
        config.upstream_extra_headers,
    );
    mock.response_stream_chunks = config.upstream_stream_chunks;
    mock.response_inter_chunk_delay_ms = config.upstream_inter_chunk_delay_ms;
    mock.response_delay_ms = config.upstream_response_delay_ms;
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

    var log_capture_buf: [64 * 1024]u8 = undefined;
    var log_capture = std.io.fixedBufferStream(&log_capture_buf);
    var log = try logger_mod.Logger.init(.info, config.audit_log, null);
    log.test_writer = log_capture.writer().any();
    defer log.deinit();

    var upstream_client = std.http.Client{ .allocator = allocator };
    defer upstream_client.deinit();

    var active_connections = std.atomic.Value(u32).init(1);
    var connections_total = std.atomic.Value(u64).init(0);
    const start_time = std.time.timestamp();
    var observability = observability_mod.Observability.init(&log, &active_connections);
    var shutdown_state = shutdown_mod.ShutdownState{};
    observability.markStartupReady();

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
        .observability = &observability,
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
        .shutdown_state = &shutdown_state,
        .upstream_timeouts = .{
            .connect_timeout_ms = config.upstream_connect_timeout_ms,
            .read_timeout_ms = config.upstream_read_timeout_ms,
            .request_timeout_ms = config.upstream_request_timeout_ms,
        },
    };

    const ProxyThread = struct {
        fn run(server: *std.net.Server, ctx: proxy.ProxyContext) void {
            const connection = server.accept() catch return;
            defer connection.stream.close();

            var read_buf: [16 * 1024]u8 = undefined;
            var write_buf: [16 * 1024]u8 = undefined;

            var stream_reader = connection.stream.reader(&read_buf);
            var stream_writer = connection.stream.writer(&write_buf);
            var http_server = http.Server.init(stream_reader.interface(), &stream_writer.interface);
            var request = http_server.receiveHead() catch return;

            proxy.handleRequest(&request, ctx) catch {};
        }
    };

    const proxy_thread = try std.Thread.spawn(.{}, ProxyThread.run, .{ &proxy_server, proxy_ctx });
    var proxy_thread_joined = false;
    defer if (!proxy_thread_joined) {
        if (std.net.tcpConnectToAddress(proxy_server.listen_address)) |conn| {
            conn.close();
        } else |_| {}
        proxy_thread.join();
    };

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

    var url_buf: [512]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}{s}", .{ proxy_port, config.request_target });
    const uri = try std.Uri.parse(url);

    const result = try httpRequest(
        allocator,
        config.request_method,
        uri,
        request_body,
        config.request_content_type,
        request_headers.items,
    );

    proxy_thread.join();
    proxy_thread_joined = true;

    mock.stop();
    if (mock.thread) |t| {
        t.join();
        mock.thread = null;
    }

    const recorded_body = mock.getRecordedBody() orelse "";
    const recorded_head = mock.getRecordedHead() orelse "";
    const upstream_body = try allocator.dupe(u8, recorded_body);
    const upstream_head = try allocator.dupe(u8, recorded_head);
    const proxy_logs = try allocator.dupe(u8, log_capture.getWritten());

    return .{
        .upstream_body = upstream_body,
        .upstream_head = upstream_head,
        .client_body = result.body,
        .client_head = result.head,
        .status = result.status,
        .proxy_logs = proxy_logs,
        .client_chunk_count = result.chunk_count,
        .first_chunk_latency_ns = result.first_chunk_latency_ns,
        .total_response_latency_ns = result.total_response_latency_ns,
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

test "harness - invalid request target is rejected before network setup" {
    const allocator = std.testing.allocator;

    try std.testing.expectError(error.InvalidRequestTarget, roundTrip(allocator, "{}", .{
        .request_target = "api/data",
    }));
}

test "harness - graceful shutdown drains active request" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;

    const allocator = std.testing.allocator;

    var mock = try MockUpstream.init(allocator, "upstream says hi", "text/plain", &.{});
    mock.response_delay_ms = 150;
    defer mock.deinit();
    try mock.start();

    const proxy_listener = try std.net.Address.listen(
        try std.net.Address.parseIp("127.0.0.1", 0),
        .{ .reuse_address = true },
    );

    var log_capture_buf: [64 * 1024]u8 = undefined;
    var log_capture = std.io.fixedBufferStream(&log_capture_buf);
    var log = try logger_mod.Logger.init(.info, false, null);
    log.test_writer = log_capture.writer().any();
    defer log.deinit();

    var upstream_client_instance = std.http.Client{ .allocator = allocator };
    defer upstream_client_instance.deinit();

    var active_connections = std.atomic.Value(u32).init(0);
    var connections_total = std.atomic.Value(u64).init(0);
    const start_time = std.time.timestamp();
    var observability = observability_mod.Observability.init(&log, &active_connections);
    var shutdown_state = shutdown_mod.ShutdownState{};
    observability.markStartupReady();

    var proxy_server = proxy_server_mod.ProxyServer{
        .net_server = proxy_listener,
        .ctx = .{
            .allocator = allocator,
            .target_host = "127.0.0.1",
            .target_port = mock.port,
            .entity_set = null,
            .http_client = &upstream_client_instance,
            .active_connections = &active_connections,
            .admin_config = .{ .enabled = false, .token = null, .entity_file_sync = false, .entity_file = null, .fuzzy_threshold = 0.0 },
            .tls_context = null,
            .target_tls = false,
            .max_body_size = 1024 * 1024,
            .log = &log,
            .observability = &observability,
            .connections_total = &connections_total,
            .start_time = start_time,
            .unsupported_request_body_behavior = .reject,
            .unsupported_response_body_behavior = .bypass,
            .enable_email = false,
            .enable_phone = false,
            .enable_credit_card = false,
            .enable_ip = false,
            .enable_healthcare = false,
            .schema = null,
            .hasher = null,
            .shutdown_state = &shutdown_state,
            .upstream_timeouts = .{},
        },
        .max_connections = 16,
        .drain_timeout_ms = 1_000,
        .active_connections = &active_connections,
        .logger = &log,
        .observability = &observability,
        .shutdown_state = &shutdown_state,
    };
    defer proxy_server.deinit();

    const ServerThread = struct {
        fn run(server: *proxy_server_mod.ProxyServer) void {
            server.serve();
        }
    };
    const ShutdownThread = struct {
        fn run(server: *proxy_server_mod.ProxyServer, upstream: *MockUpstream) void {
            while (!upstream.hasStartedRequest()) {
                std.Thread.sleep(5 * std.time.ns_per_ms);
            }
            server.initiateShutdown("test");
        }
    };

    const server_thread = try std.Thread.spawn(.{}, ServerThread.run, .{&proxy_server});
    var server_thread_joined = false;
    defer if (!server_thread_joined) server_thread.join();

    const shutdown_thread = try std.Thread.spawn(.{}, ShutdownThread.run, .{ &proxy_server, &mock });
    var shutdown_thread_joined = false;
    defer if (!shutdown_thread_joined) shutdown_thread.join();

    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/shutdown", .{proxy_server.net_server.listen_address.getPort()});
    const uri = try std.Uri.parse(url);

    const response = try httpRequest(allocator, .POST, uri, "hello", "text/plain", &.{}); 
    defer allocator.free(response.body);
    defer allocator.free(response.head);

    try std.testing.expectEqual(http.Status.ok, response.status);
    try std.testing.expectEqualStrings("upstream says hi", response.body);

    server_thread.join();
    server_thread_joined = true;
    shutdown_thread.join();
    shutdown_thread_joined = true;

    try std.testing.expect(std.mem.indexOf(u8, log_capture.getWritten(), "\"msg\":\"shutdown_requested\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, log_capture.getWritten(), "\"outcome\":\"drained_shutdown\"") != null);

    const second_attempt = httpRequest(allocator, .POST, uri, "again", "text/plain", &.{});
    try std.testing.expectError(error.ConnectionRefused, second_attempt);
}
