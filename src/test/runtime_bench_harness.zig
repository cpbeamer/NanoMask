const std = @import("std");
const http = std.http;
const MockUpstream = @import("mock_upstream.zig").MockUpstream;
const proxy_server_mod = @import("../net/proxy_server.zig");
const runtime_model_mod = @import("../net/runtime_model.zig");
const logger_mod = @import("../infra/logger.zig");
const observability_mod = @import("../infra/observability.zig");
const shutdown_mod = @import("../infra/shutdown.zig");
const bench_util = @import("bench_util.zig");

pub const RuntimeModel = runtime_model_mod.RuntimeModel;

pub const BurstScenario = struct {
    runtime_model: RuntimeModel,
    runtime_worker_threads: usize = 0,
    concurrent_clients: usize = 64,
    iterations: usize = 3,
    payload_bytes: usize = 2048,
    upstream_delay_ms: u64 = 2,
    max_connections: u32 = 128,
};

pub const BurstMetrics = struct {
    runtime_model: RuntimeModel,
    runtime_worker_threads: usize,
    successful_requests: usize,
    failed_requests: usize,
    total_requests: usize,
    payload_bytes: usize,
    p50_ms: f64,
    p95_ms: f64,
    estimated_handler_threads: usize,
    estimated_reserved_stack_bytes: usize,
};

const ClientResult = struct {
    success: bool = false,
    latency_ns: u64 = 0,
};

const ClientTask = struct {
    url: []const u8,
    payload: []const u8,
    ready_count: *std.atomic.Value(usize),
    start_flag: *std.atomic.Value(bool),
    result: *ClientResult,
};

fn elapsedSince(start_ns: @TypeOf(std.time.nanoTimestamp())) u64 {
    return bench_util.elapsedSince(start_ns);
}

fn nsToMs(ns: u64) f64 {
    return bench_util.nsToMs(ns);
}

fn percentileIndex(len: usize, numerator: usize, denominator: usize) usize {
    return bench_util.percentileIndex(len, numerator, denominator);
}

fn sortAndSummarize(samples: []u64) struct { p50_ms: f64, p95_ms: f64 } {
    return bench_util.sortAndSummarize(samples);
}

fn buildPayload(allocator: std.mem.Allocator, approx_bytes: usize) ![]u8 {
    const snippet = "Patient Jane Smith with SSN 123-45-6789 email jane.smith@hospital.org phone (555) 123-4567. ";

    var buffer = std.ArrayListUnmanaged(u8).empty;
    errdefer buffer.deinit(allocator);

    try buffer.appendSlice(allocator, "{\"prompt\":\"");
    while (buffer.items.len + snippet.len + 3 < approx_bytes) {
        try buffer.appendSlice(allocator, snippet);
    }
    try buffer.appendSlice(allocator, "\"}");

    return try buffer.toOwnedSlice(allocator);
}

fn sendRequest(url: []const u8, payload: []const u8) !u64 {
    const allocator = std.heap.page_allocator;
    const uri = try std.Uri.parse(url);

    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    var req = try client.request(.POST, uri, .{
        .headers = .{
            .content_type = .{ .override = "application/json" },
        },
    });
    defer req.deinit();

    req.transfer_encoding = .{ .content_length = payload.len };
    var body_buf: [1]u8 = undefined;
    var body_writer = try req.sendBodyUnflushed(&body_buf);
    try body_writer.writer.writeAll(payload);
    try body_writer.end();
    try req.connection.?.flush();

    var redirect_buf: [4096]u8 = undefined;
    const receive_start = std.time.nanoTimestamp();
    var res = try req.receiveHead(&redirect_buf);
    if (res.head.status != .ok) return error.UnexpectedStatus;

    var transfer_buf: [4096]u8 = undefined;
    const reader = res.reader(&transfer_buf);
    var sink: std.Io.Writer.Allocating = .init(allocator);
    defer sink.deinit();
    _ = try reader.streamRemaining(&sink.writer);

    return elapsedSince(receive_start);
}

fn runClient(task: *const ClientTask) void {
    _ = task.ready_count.fetchAdd(1, .acq_rel);
    while (!task.start_flag.load(.acquire)) {
        std.Thread.sleep(100 * std.time.ns_per_us);
    }

    task.result.* = .{};
    task.result.latency_ns = sendRequest(task.url, task.payload) catch return;
    task.result.success = true;
}

fn configureProxyServer(
    allocator: std.mem.Allocator,
    listener: std.net.Server,
    target_port: u16,
    http_client: *std.http.Client,
    log: *logger_mod.Logger,
    observability: *observability_mod.Observability,
    active_connections: *std.atomic.Value(u32),
    connections_total: *std.atomic.Value(u64),
    shutdown_state: *shutdown_mod.ShutdownState,
    scenario: BurstScenario,
    resolved_worker_threads: usize,
) proxy_server_mod.ProxyServer {
    return .{
        .net_server = listener,
        .handler = .{
            .ctx = .{
                .allocator = allocator,
                .target_host = "127.0.0.1",
                .target_port = target_port,
                .entity_set = null,
                .http_client = http_client,
                .active_connections = active_connections,
                .admin_config = .{
                    .enabled = false,
                    .token = null,
                    .entity_file_sync = false,
                    .entity_file = null,
                    .fuzzy_threshold = 0.0,
                },
                .tls_context = null,
                .target_tls = false,
                .max_body_size = 1024 * 1024,
                .logger = log,
                .observability = observability,
                .connections_total = connections_total,
                .start_time = std.time.timestamp(),
                .unsupported_request_body_behavior = .reject,
                .unsupported_response_body_behavior = .bypass,
                .enable_email = false,
                .enable_phone = false,
                .enable_credit_card = false,
                .enable_ip = false,
                .enable_healthcare = false,
                .schema = null,
                .hasher = null,
                .shutdown_state = shutdown_state,
                .listener_mode = .combined,
                .upstream_timeouts = .{},
            },
        },
        .max_connections = @max(scenario.max_connections, @as(u32, @intCast(scenario.concurrent_clients))),
        .drain_timeout_ms = 2_000,
        .active_connections = active_connections,
        .logger = log,
        .observability = observability,
        .shutdown_state = shutdown_state,
        .runtime_model = scenario.runtime_model,
        .runtime_worker_threads = resolved_worker_threads,
    };
}

fn runBurstIteration(
    allocator: std.mem.Allocator,
    payload: []const u8,
    scenario: BurstScenario,
    resolved_worker_threads: usize,
    latencies: *std.ArrayListUnmanaged(u64),
    successes: *usize,
    failures: *usize,
) !void {
    var mock = try MockUpstream.init(allocator, "OK", "text/plain", &.{});
    mock.response_delay_ms = scenario.upstream_delay_ms;
    mock.max_requests = scenario.concurrent_clients;
    mock.record_requests = false;
    defer mock.deinit();
    try mock.start();

    const proxy_listener = try std.net.Address.listen(
        try std.net.Address.parseIp("127.0.0.1", 0),
        .{ .reuse_address = true },
    );

    var log = try logger_mod.Logger.init(.error_, false, null);
    defer log.deinit();

    var http_client = std.http.Client{ .allocator = allocator };
    defer http_client.deinit();

    var active_connections = std.atomic.Value(u32).init(0);
    var connections_total = std.atomic.Value(u64).init(0);
    var observability = observability_mod.Observability.init(&log, &active_connections);
    var shutdown_state = shutdown_mod.ShutdownState{};
    observability.markStartupReady();

    var proxy_server = configureProxyServer(
        allocator,
        proxy_listener,
        mock.port,
        &http_client,
        &log,
        &observability,
        &active_connections,
        &connections_total,
        &shutdown_state,
        scenario,
        resolved_worker_threads,
    );
    defer proxy_server.deinit();

    const ServerThread = struct {
        fn run(server: *proxy_server_mod.ProxyServer) void {
            server.serve();
        }
    };

    const server_thread = try std.Thread.spawn(.{}, ServerThread.run, .{&proxy_server});
    errdefer proxy_server.initiateShutdown("runtime_benchmark_error");
    defer server_thread.join();

    var url_buf: [128]u8 = undefined;
    const url = try std.fmt.bufPrint(
        &url_buf,
        "http://127.0.0.1:{d}/gateway-burst",
        .{proxy_server.net_server.listen_address.getPort()},
    );

    const threads = try allocator.alloc(std.Thread, scenario.concurrent_clients);
    defer allocator.free(threads);
    const results = try allocator.alloc(ClientResult, scenario.concurrent_clients);
    defer allocator.free(results);
    const tasks = try allocator.alloc(ClientTask, scenario.concurrent_clients);
    defer allocator.free(tasks);

    var ready_count = std.atomic.Value(usize).init(0);
    var start_flag = std.atomic.Value(bool).init(false);

    for (results) |*result| {
        result.* = .{};
    }

    for (tasks, 0..) |*task, index| {
        task.* = .{
            .url = url,
            .payload = payload,
            .ready_count = &ready_count,
            .start_flag = &start_flag,
            .result = &results[index],
        };
        threads[index] = try std.Thread.spawn(.{}, runClient, .{task});
    }

    while (ready_count.load(.acquire) < scenario.concurrent_clients) {
        std.Thread.sleep(100 * std.time.ns_per_us);
    }
    start_flag.store(true, .release);

    for (threads) |thread| {
        thread.join();
    }

    for (results) |result| {
        if (result.success) {
            try latencies.append(allocator, result.latency_ns);
            successes.* += 1;
        } else {
            failures.* += 1;
        }
    }

    proxy_server.initiateShutdown("runtime_benchmark_complete");
}

pub fn runProxyBurst(allocator: std.mem.Allocator, scenario: BurstScenario) !BurstMetrics {
    const payload = try buildPayload(allocator, scenario.payload_bytes);
    defer allocator.free(payload);

    const max_connections = @max(scenario.max_connections, @as(u32, @intCast(scenario.concurrent_clients)));
    const resolved_worker_threads = runtime_model_mod.resolveWorkerThreads(
        scenario.runtime_model,
        scenario.runtime_worker_threads,
        max_connections,
    );

    var latencies = std.ArrayListUnmanaged(u64).empty;
    defer latencies.deinit(allocator);

    var successes: usize = 0;
    var failures: usize = 0;
    for (0..scenario.iterations) |_| {
        try runBurstIteration(
            allocator,
            payload,
            scenario,
            resolved_worker_threads,
            &latencies,
            &successes,
            &failures,
        );
    }

    const stats = sortAndSummarize(latencies.items);
    const total_requests = scenario.concurrent_clients * scenario.iterations;
    return .{
        .runtime_model = scenario.runtime_model,
        .runtime_worker_threads = resolved_worker_threads,
        .successful_requests = successes,
        .failed_requests = failures,
        .total_requests = total_requests,
        .payload_bytes = payload.len,
        .p50_ms = stats.p50_ms,
        .p95_ms = stats.p95_ms,
        .estimated_handler_threads = runtime_model_mod.estimatedHandlerThreads(
            scenario.runtime_model,
            resolved_worker_threads,
            scenario.concurrent_clients,
        ),
        .estimated_reserved_stack_bytes = runtime_model_mod.estimatedReservedStackBytes(
            scenario.runtime_model,
            resolved_worker_threads,
            scenario.concurrent_clients,
        ),
    };
}
