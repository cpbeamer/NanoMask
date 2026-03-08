const std = @import("std");
const logger_mod = @import("logger.zig");
const Logger = logger_mod.Logger;

const AtomicU64 = std.atomic.Value(u64);

pub const Route = enum(u8) {
    proxy,
    healthz,
    readyz,
    metrics,
    admin,
};

pub const MatchStage = enum(u8) {
    entity_mask,
    ssn,
    pattern_library,
    fuzzy_match,
    schema,
};

const histogram_bounds_us = [_]u64{
    100,
    500,
    1_000,
    5_000,
    10_000,
    25_000,
    50_000,
    100_000,
    250_000,
    500_000,
    1_000_000,
    5_000_000,
};

const route_count = std.meta.fields(Route).len;
const stage_count = std.meta.fields(MatchStage).len;
const latency_bucket_count = histogram_bounds_us.len + 1;

fn initAtomicArray(comptime N: usize) [N]AtomicU64 {
    var values: [N]AtomicU64 = undefined;
    for (&values) |*slot| {
        slot.* = AtomicU64.init(0);
    }
    return values;
}

fn initAtomicMatrix(comptime Rows: usize, comptime Cols: usize) [Rows][Cols]AtomicU64 {
    @setEvalBranchQuota(20_000);
    var values: [Rows][Cols]AtomicU64 = undefined;
    for (&values) |*row| {
        row.* = initAtomicArray(Cols);
    }
    return values;
}

fn routeLabel(route: Route) []const u8 {
    return switch (route) {
        .proxy => "proxy",
        .healthz => "healthz",
        .readyz => "readyz",
        .metrics => "metrics",
        .admin => "admin",
    };
}

fn stageLabel(stage: MatchStage) []const u8 {
    return switch (stage) {
        .entity_mask => "entity_mask",
        .ssn => "ssn",
        .pattern_library => "pattern_library",
        .fuzzy_match => "fuzzy_match",
        .schema => "schema",
    };
}

fn observeHistogram(
    buckets: []AtomicU64,
    count: *AtomicU64,
    sum_us: *AtomicU64,
    value_us: u64,
) void {
    const bucket_index = blk: {
        for (histogram_bounds_us, 0..) |bound, idx| {
            if (value_us <= bound) break :blk idx;
        }
        break :blk histogram_bounds_us.len;
    };

    _ = buckets[bucket_index].fetchAdd(1, .monotonic);
    _ = count.fetchAdd(1, .monotonic);
    _ = sum_us.fetchAdd(value_us, .monotonic);
}

fn writeMicrosAsSeconds(writer: anytype, micros: u64) !void {
    const secs = @as(f64, @floatFromInt(micros)) / 1_000_000.0;
    try std.fmt.format(writer, "{d:.6}", .{secs});
}

pub const ReadinessSnapshot = struct {
    startup_ready: bool,
    entity_reload_ready: bool,
    shutdown_draining: bool,
    entity_reload_success_total: u64,
    entity_reload_failure_total: u64,

    pub fn isReady(self: ReadinessSnapshot) bool {
        return self.startup_ready and self.entity_reload_ready and !self.shutdown_draining;
    }
};

// HTTP status codes range from 100–599. We offset by 100 so index 0 = status 100.
const status_array_offset = 100;
const status_array_len = 500;

pub const Observability = struct {
    logger: *Logger,
    active_connections: *std.atomic.Value(u32),
    request_totals: [route_count]AtomicU64 = initAtomicArray(route_count),
    request_latency_buckets: [route_count][latency_bucket_count]AtomicU64 = initAtomicMatrix(route_count, latency_bucket_count),
    request_latency_count: [route_count]AtomicU64 = initAtomicArray(route_count),
    request_latency_sum_us: [route_count]AtomicU64 = initAtomicArray(route_count),
    upstream_latency_buckets: [latency_bucket_count]AtomicU64 = initAtomicArray(latency_bucket_count),
    upstream_latency_count: AtomicU64 = AtomicU64.init(0),
    upstream_latency_sum_us: AtomicU64 = AtomicU64.init(0),
    response_status_counts: [status_array_len]AtomicU64 = initAtomicArray(status_array_len),
    request_bytes_total: AtomicU64 = AtomicU64.init(0),
    response_bytes_total: AtomicU64 = AtomicU64.init(0),
    redaction_stage_counts: [stage_count]AtomicU64 = initAtomicArray(stage_count),
    entity_reload_success_total: AtomicU64 = AtomicU64.init(0),
    entity_reload_failure_total: AtomicU64 = AtomicU64.init(0),
    startup_ready: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    entity_reload_ready: std.atomic.Value(bool) = std.atomic.Value(bool).init(true),
    shutdown_draining: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    pub fn init(
        logger: *Logger,
        active_connections: *std.atomic.Value(u32),
    ) Observability {
        return .{
            .logger = logger,
            .active_connections = active_connections,
        };
    }

    pub fn markStartupReady(self: *Observability) void {
        self.startup_ready.store(true, .release);
    }

    pub fn markEntityReloadSuccess(self: *Observability) void {
        _ = self.entity_reload_success_total.fetchAdd(1, .monotonic);
        self.entity_reload_ready.store(true, .release);
    }

    pub fn markEntityReloadFailure(self: *Observability) void {
        _ = self.entity_reload_failure_total.fetchAdd(1, .monotonic);
        self.entity_reload_ready.store(false, .release);
    }

    pub fn markShutdownDraining(self: *Observability) void {
        self.shutdown_draining.store(true, .release);
    }

    pub fn readinessSnapshot(self: *const Observability) ReadinessSnapshot {
        return .{
            .startup_ready = self.startup_ready.load(.acquire),
            .entity_reload_ready = self.entity_reload_ready.load(.acquire),
            .shutdown_draining = self.shutdown_draining.load(.acquire),
            .entity_reload_success_total = self.entity_reload_success_total.load(.acquire),
            .entity_reload_failure_total = self.entity_reload_failure_total.load(.acquire),
        };
    }

    pub fn recordRequest(
        self: *Observability,
        route: Route,
        status_code: u16,
        total_latency_us: u64,
        request_bytes: u64,
        response_bytes: u64,
    ) void {
        const route_idx = @intFromEnum(route);
        _ = self.request_totals[route_idx].fetchAdd(1, .monotonic);
        observeHistogram(
            self.request_latency_buckets[route_idx][0..],
            &self.request_latency_count[route_idx],
            &self.request_latency_sum_us[route_idx],
            total_latency_us,
        );
        if (status_code >= status_array_offset and status_code < status_array_offset + status_array_len) {
            _ = self.response_status_counts[status_code - status_array_offset].fetchAdd(1, .monotonic);
        }
        _ = self.request_bytes_total.fetchAdd(request_bytes, .monotonic);
        _ = self.response_bytes_total.fetchAdd(response_bytes, .monotonic);
    }

    pub fn recordUpstreamLatency(self: *Observability, latency_us: u64) void {
        observeHistogram(
            self.upstream_latency_buckets[0..],
            &self.upstream_latency_count,
            &self.upstream_latency_sum_us,
            latency_us,
        );
    }

    /// Record a redaction stage hit. Callers are responsible for filtering
    /// events that should not be counted (e.g. schema_keep).
    pub fn recordAuditStage(self: *Observability, stage: MatchStage) void {
        _ = self.redaction_stage_counts[@intFromEnum(stage)].fetchAdd(1, .monotonic);
    }

    pub fn renderMetrics(self: *const Observability, allocator: std.mem.Allocator) ![]u8 {
        var buf: std.ArrayListUnmanaged(u8) = .empty;
        errdefer buf.deinit(allocator);
        const writer = buf.writer(allocator);

        try writer.writeAll(
            \\# HELP nanomask_http_requests_total Total HTTP requests handled by NanoMask.
            \\# TYPE nanomask_http_requests_total counter
        );
        for (0..route_count) |idx| {
            const route: Route = @enumFromInt(idx);
            try std.fmt.format(
                writer,
                "nanomask_http_requests_total{{route=\"{s}\"}} {d}\n",
                .{ routeLabel(route), self.request_totals[idx].load(.acquire) },
            );
        }
        try writer.writeByte('\n');

        try writer.writeAll(
            \\# HELP nanomask_http_request_duration_seconds End-to-end HTTP request latency in seconds.
            \\# TYPE nanomask_http_request_duration_seconds histogram
        );
        for (0..route_count) |route_idx| {
            const route: Route = @enumFromInt(route_idx);
            var cumulative: u64 = 0;
            for (histogram_bounds_us, 0..) |bound, idx| {
                cumulative += self.request_latency_buckets[route_idx][idx].load(.acquire);
                try std.fmt.format(
                    writer,
                    "nanomask_http_request_duration_seconds_bucket{{route=\"{s}\",le=\"",
                    .{routeLabel(route)},
                );
                try writeMicrosAsSeconds(writer, bound);
                try std.fmt.format(writer, "\"}} {d}\n", .{cumulative});
            }
            cumulative += self.request_latency_buckets[route_idx][histogram_bounds_us.len].load(.acquire);
            try std.fmt.format(
                writer,
                "nanomask_http_request_duration_seconds_bucket{{route=\"{s}\",le=\"+Inf\"}} {d}\n",
                .{ routeLabel(route), cumulative },
            );
            try std.fmt.format(
                writer,
                "nanomask_http_request_duration_seconds_sum{{route=\"{s}\"}} ",
                .{routeLabel(route)},
            );
            try writeMicrosAsSeconds(writer, self.request_latency_sum_us[route_idx].load(.acquire));
            try writer.writeByte('\n');
            try std.fmt.format(
                writer,
                "nanomask_http_request_duration_seconds_count{{route=\"{s}\"}} {d}\n",
                .{ routeLabel(route), self.request_latency_count[route_idx].load(.acquire) },
            );
        }
        try writer.writeByte('\n');

        try writer.writeAll(
            \\# HELP nanomask_upstream_request_duration_seconds Time to receive upstream response headers in seconds.
            \\# TYPE nanomask_upstream_request_duration_seconds histogram
        );
        var upstream_cumulative: u64 = 0;
        for (histogram_bounds_us, 0..) |bound, idx| {
            upstream_cumulative += self.upstream_latency_buckets[idx].load(.acquire);
            try writer.writeAll("nanomask_upstream_request_duration_seconds_bucket{le=\"");
            try writeMicrosAsSeconds(writer, bound);
            try std.fmt.format(writer, "\"}} {d}\n", .{upstream_cumulative});
        }
        upstream_cumulative += self.upstream_latency_buckets[histogram_bounds_us.len].load(.acquire);
        try std.fmt.format(
            writer,
            "nanomask_upstream_request_duration_seconds_bucket{{le=\"+Inf\"}} {d}\n",
            .{upstream_cumulative},
        );
        try writer.writeAll("nanomask_upstream_request_duration_seconds_sum ");
        try writeMicrosAsSeconds(writer, self.upstream_latency_sum_us.load(.acquire));
        try writer.writeByte('\n');
        try std.fmt.format(
            writer,
            "nanomask_upstream_request_duration_seconds_count {d}\n\n",
            .{self.upstream_latency_count.load(.acquire)},
        );

        try writer.writeAll(
            \\# HELP nanomask_http_responses_total Downstream HTTP responses by status code.
            \\# TYPE nanomask_http_responses_total counter
        );
        var wrote_status_metric = false;
        for (self.response_status_counts, 0..) |counter, idx| {
            const value = counter.load(.acquire);
            if (value == 0) continue;
            wrote_status_metric = true;
            try std.fmt.format(
                writer,
                "nanomask_http_responses_total{{code=\"{d}\"}} {d}\n",
                .{ idx + status_array_offset, value },
            );
        }
        if (!wrote_status_metric) {
            try writer.writeAll("nanomask_http_responses_total{code=\"200\"} 0\n");
        }
        try writer.writeByte('\n');

        try writer.writeAll(
            \\# HELP nanomask_bytes_processed_total Total request and response body bytes processed.
            \\# TYPE nanomask_bytes_processed_total counter
        );
        try std.fmt.format(
            writer,
            "nanomask_bytes_processed_total{{direction=\"request\"}} {d}\n",
            .{self.request_bytes_total.load(.acquire)},
        );
        try std.fmt.format(
            writer,
            "nanomask_bytes_processed_total{{direction=\"response\"}} {d}\n\n",
            .{self.response_bytes_total.load(.acquire)},
        );

        try writer.writeAll(
            \\# HELP nanomask_redaction_matches_total Redaction matches and schema actions by stage.
            \\# TYPE nanomask_redaction_matches_total counter
        );
        for (0..stage_count) |idx| {
            const stage: MatchStage = @enumFromInt(idx);
            try std.fmt.format(
                writer,
                "nanomask_redaction_matches_total{{stage=\"{s}\"}} {d}\n",
                .{
                    stageLabel(stage),
                    self.redaction_stage_counts[idx].load(.acquire),
                },
            );
        }
        try writer.writeByte('\n');

        try writer.writeAll(
            \\# HELP nanomask_active_connections Active downstream client connections.
            \\# TYPE nanomask_active_connections gauge
        );
        try std.fmt.format(
            writer,
            "nanomask_active_connections {d}\n\n",
            .{self.active_connections.load(.acquire)},
        );

        try writer.writeAll(
            \\# HELP nanomask_entity_reload_total Entity reload attempts by result.
            \\# TYPE nanomask_entity_reload_total counter
        );
        try std.fmt.format(
            writer,
            "nanomask_entity_reload_total{{result=\"success\"}} {d}\n",
            .{self.entity_reload_success_total.load(.acquire)},
        );
        try std.fmt.format(
            writer,
            "nanomask_entity_reload_total{{result=\"failure\"}} {d}\n\n",
            .{self.entity_reload_failure_total.load(.acquire)},
        );

        try writer.writeAll(
            \\# HELP nanomask_log_dropped_lines_total Structured log lines dropped due to write failures.
            \\# TYPE nanomask_log_dropped_lines_total counter
        );
        try std.fmt.format(
            writer,
            "nanomask_log_dropped_lines_total {d}\n\n",
            .{self.logger.dropped_lines.load(.acquire)},
        );

        try writer.writeAll(
            \\# HELP nanomask_ready NanoMask readiness state (1 = ready, 0 = not ready).
            \\# TYPE nanomask_ready gauge
        );
        try std.fmt.format(
            writer,
            "nanomask_ready {d}\n",
            .{if (self.readinessSnapshot().isReady()) @as(u8, 1) else @as(u8, 0)},
        );
        try writer.writeAll(
            \\# HELP nanomask_shutdown_draining NanoMask shutdown drain state (1 = draining, 0 = running).
            \\# TYPE nanomask_shutdown_draining gauge
        );
        try std.fmt.format(
            writer,
            "nanomask_shutdown_draining {d}\n",
            .{if (self.shutdown_draining.load(.acquire)) @as(u8, 1) else @as(u8, 0)},
        );

        return try buf.toOwnedSlice(allocator);
    }
};

test "Observability - readiness tracks startup and reload failures" {
    var output_buf: [1024]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&output_buf);
    var logger = Logger{
        .mutex = .{},
        .min_level = .info,
        .audit_enabled = false,
        .output_file = null,
        .test_writer = fbs.writer().any(),
        .owns_file = false,
    };
    var active_connections = std.atomic.Value(u32).init(0);
    var obs = Observability.init(&logger, &active_connections);

    try std.testing.expect(!obs.readinessSnapshot().isReady());

    obs.markStartupReady();
    try std.testing.expect(obs.readinessSnapshot().isReady());

    obs.markEntityReloadFailure();
    const failed = obs.readinessSnapshot();
    try std.testing.expect(!failed.isReady());
    try std.testing.expectEqual(@as(u64, 1), failed.entity_reload_failure_total);
    try std.testing.expect(!failed.shutdown_draining);

    obs.markEntityReloadSuccess();
    const recovered = obs.readinessSnapshot();
    try std.testing.expect(recovered.isReady());
    try std.testing.expectEqual(@as(u64, 1), recovered.entity_reload_success_total);

    obs.markShutdownDraining();
    const draining = obs.readinessSnapshot();
    try std.testing.expect(!draining.isReady());
    try std.testing.expect(draining.shutdown_draining);
}

test "Observability - metrics render required series" {
    var output_buf: [1024]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&output_buf);
    var logger = Logger{
        .mutex = .{},
        .min_level = .info,
        .audit_enabled = false,
        .output_file = null,
        .test_writer = fbs.writer().any(),
        .owns_file = false,
    };
    var active_connections = std.atomic.Value(u32).init(3);
    var obs = Observability.init(&logger, &active_connections);
    obs.markStartupReady();
    obs.recordRequest(.proxy, 200, 12_500, 128, 256);
    obs.recordRequest(.metrics, 200, 800, 0, 512);
    obs.recordUpstreamLatency(7_500);
    obs.recordAuditStage(.ssn);
    obs.markEntityReloadFailure();

    const rendered = try obs.renderMetrics(std.testing.allocator);
    defer std.testing.allocator.free(rendered);

    try std.testing.expect(std.mem.indexOf(u8, rendered, "nanomask_http_requests_total{route=\"proxy\"} 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "nanomask_http_request_duration_seconds_bucket{route=\"proxy\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "nanomask_upstream_request_duration_seconds_bucket") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "nanomask_http_responses_total{code=\"200\"} 2") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "nanomask_bytes_processed_total{direction=\"request\"} 128") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "nanomask_bytes_processed_total{direction=\"response\"} 768") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "nanomask_redaction_matches_total{stage=\"ssn\"} 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "nanomask_active_connections 3") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "nanomask_entity_reload_total{result=\"failure\"} 1") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "nanomask_log_dropped_lines_total 0") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "nanomask_ready 0") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "nanomask_shutdown_draining 0") != null);
}
