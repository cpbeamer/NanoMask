const std = @import("std");
const http = std.http;
const redact = @import("../redaction/redact.zig");
const entity_mask = @import("../redaction/entity_mask.zig");
const fuzzy_match = @import("../redaction/fuzzy_match.zig");
const admin = @import("../admin/admin.zig");
const versioned_entity_set = @import("../entity/versioned_entity_set.zig");
const VersionedEntitySet = versioned_entity_set.VersionedEntitySet;
const http_util = @import("http_util.zig");
const config_mod = @import("../infra/config.zig");
const Config = config_mod.Config;
const logger_mod = @import("../infra/logger.zig");
const Logger = logger_mod.Logger;
const observability_mod = @import("../infra/observability.zig");
const Observability = observability_mod.Observability;
const Route = observability_mod.Route;
const redaction_audit = @import("../infra/redaction_audit.zig");
const shutdown_mod = @import("../infra/shutdown.zig");
const body_policy = @import("body_policy.zig");
const UnsupportedBodyBehavior = body_policy.UnsupportedBodyBehavior;
const upstream_client = @import("upstream_client.zig");

// Unified single-pass pattern scanner (Phase 5 / Epic 7)
const scanner = @import("../patterns/scanner.zig");

// Schema-aware JSON redaction (Phase 5 / Epic 8)
const schema_mod = @import("../schema/schema.zig");
const json_redactor = @import("../schema/json_redactor.zig");
const hasher_mod = @import("../schema/hasher.zig");

/// Maximum length for the constructed target URL (stack-allocated).
const max_url_len = 2048;

/// Maximum number of entities accepted via the X-ZPG-Entities header.
/// Prevents Aho-Corasick construction DoS from oversized entity lists.
const max_header_entities: usize = 100;

/// Find a custom header value by name (case-insensitive).
/// Delegates to the shared http_util implementation.
const findHeader = http_util.findHeader;

/// Parse a comma-separated header value into individual trimmed name slices.
/// Returns owned slice of slices pointing into `header_value` memory.
///
/// SAFETY: The returned slices borrow from `header_value`. Callers must ensure
/// `header_value` outlives the returned slice, or dupe the strings before the
/// source buffer is freed. `EntityMap.init` dupes all names, so the current
/// call site in `handleRequest` is safe.
fn parseEntityHeader(header_value: []const u8, allocator: std.mem.Allocator) ![][]const u8 {
    var names: std.ArrayListUnmanaged([]const u8) = .empty;
    defer names.deinit(allocator);

    var it = std.mem.splitScalar(u8, header_value, ',');
    while (it.next()) |segment| {
        const trimmed = std.mem.trim(u8, segment, " \t");
        if (trimmed.len > 0) {
            try names.append(allocator, trimmed);
        }
    }

    return try names.toOwnedSlice(allocator);
}

fn sendTextResponse(
    request: *http.Server.Request,
    status: http.Status,
    body: []const u8,
) !usize {
    try request.respond(body, .{
        .status = status,
        .extra_headers = &.{
            .{ .name = "Content-Type", .value = "text/plain; charset=utf-8" },
        },
    });
    return body.len;
}

fn sendBodyPolicyResponse(
    request: *http.Server.Request,
    status: http.Status,
    prefix: []const u8,
    classification: body_policy.Classification,
) !usize {
    var buf: [512]u8 = undefined;
    const message = std.fmt.bufPrint(
        &buf,
        "{s}: content-type '{s}', content-encoding '{s}'\n",
        .{
            prefix,
            body_policy.contentTypeForLog(classification.content_type),
            body_policy.contentEncodingForLog(classification.content_encoding),
        },
    ) catch prefix;
    return sendTextResponse(request, status, message);
}

const RequestOutcome = enum {
    normal,
    timed_out,
    drained_shutdown,
};

fn requestOutcomeLabel(outcome: RequestOutcome) []const u8 {
    return switch (outcome) {
        .normal => "normal",
        .timed_out => "timed_out",
        .drained_shutdown => "drained_shutdown",
    };
}

fn timeoutPhaseLabel(phase: upstream_client.TimeoutPhase) []const u8 {
    return switch (phase) {
        .connect => "connect",
        .read => "read",
        .request => "request",
    };
}

fn timeoutResponseMessage(phase: upstream_client.TimeoutPhase) []const u8 {
    return switch (phase) {
        .connect => "Gateway Timeout: upstream connect timed out\n",
        .read => "Gateway Timeout: upstream response timed out\n",
        .request => "Gateway Timeout: upstream request exceeded configured timeout\n",
    };
}

fn logUpstreamTimeout(
    log: *Logger,
    session_id: []const u8,
    target_host: []const u8,
    phase: upstream_client.TimeoutPhase,
    timeout_ms: u64,
) void {
    log.log(.warn, "upstream_timeout", session_id, &.{
        .{ .key = "phase", .value = .{ .string = timeoutPhaseLabel(phase) } },
        .{ .key = "timeout_ms", .value = .{ .uint = timeout_ms } },
        .{ .key = "target_host", .value = .{ .string = target_host } },
    });
}

fn sendTimeoutResponse(
    request: *http.Server.Request,
    phase: upstream_client.TimeoutPhase,
) !usize {
    return sendTextResponse(request, .gateway_timeout, timeoutResponseMessage(phase));
}

fn identityOnlyAcceptEncoding() @TypeOf(http.Client.Request.default_accept_encoding) {
    var accept: @TypeOf(http.Client.Request.default_accept_encoding) = @splat(false);
    accept[@intFromEnum(http.ContentEncoding.identity)] = true;
    return accept;
}

fn configureIdentityAcceptEncoding(req: *http.Client.Request) void {
    req.accept_encoding = identityOnlyAcceptEncoding();
    req.headers.accept_encoding = .{ .override = "identity" };
}

fn forwardBodyBypass(
    request: *http.Server.Request,
    client_req: *http.Client.Request,
    max_body_size: usize,
    log: *Logger,
    session_id: []const u8,
) !usize {
    var req_body_transfer_buf: [8192]u8 = undefined;
    var req_body = try client_req.sendBodyUnflushed(&req_body_transfer_buf);

    var body_read_buf: [8192]u8 = undefined;
    var bytes_forwarded: usize = 0;
    if (request.readerExpectContinue(&body_read_buf)) |body_reader| {
        var raw_chunk_buf: [8192]u8 = undefined;
        while (true) {
            const bytes_read = try body_reader.readSliceShort(&raw_chunk_buf);
            if (bytes_read == 0) break;

            bytes_forwarded += bytes_read;
            if (bytes_forwarded > max_body_size) {
                log.log(.warn, "body_too_large", session_id, &.{
                    .{ .key = "max_body_size", .value = .{ .uint = max_body_size } },
                });
                return error.PayloadTooLarge;
            }

            try req_body.writer.writeAll(raw_chunk_buf[0..bytes_read]);
            if (bytes_read < raw_chunk_buf.len) break;
        }
    } else |err| {
        log.log(.warn, "body_read_failed", session_id, &.{
            .{ .key = "error", .value = .{ .string = @errorName(err) } },
        });
    }

    try req_body.end();
    if (client_req.connection) |conn| {
        try conn.flush();
    }
    return bytes_forwarded;
}

fn responseHasBody(method: http.Method, status: http.Status) bool {
    return method.responseHasBody() and
        status.class() != .informational and
        status != .no_content and
        status != .not_modified;
}

const ResponseForwardingMode = enum {
    no_body,
    stream_passthrough,
    stream_unmask,
    buffered,
};

fn responseModeLabel(mode: ResponseForwardingMode) []const u8 {
    return switch (mode) {
        .no_body => "no_body",
        .stream_passthrough => "stream_passthrough",
        .stream_unmask => "stream_unmask",
        .buffered => "buffered",
    };
}

fn responseBufferReason(mode: ResponseForwardingMode) []const u8 {
    return switch (mode) {
        .buffered => "json_unhash",
        else => "-",
    };
}

fn trimMediaType(raw: []const u8) []const u8 {
    const end = std.mem.indexOfScalar(u8, raw, ';') orelse raw.len;
    return std.mem.trim(u8, raw[0..end], " \t");
}

fn isEventStreamContentType(content_type: ?[]const u8) bool {
    const raw = content_type orelse return false;
    return std.ascii.eqlIgnoreCase(trimMediaType(raw), "text/event-stream");
}

fn shouldFlushResponsePerChunk(
    mode: ResponseForwardingMode,
    transfer_encoding: http.TransferEncoding,
    kind: body_policy.BodyKind,
    content_type: ?[]const u8,
) bool {
    return switch (mode) {
        .stream_passthrough, .stream_unmask => transfer_encoding == .chunked or
            kind == .ndjson or
            isEventStreamContentType(content_type),
        .no_body, .buffered => false,
    };
}

fn readAvailable(reader: *std.Io.Reader, buffer: []u8) !usize {
    var targets = [_][]u8{buffer};
    return reader.readVec(&targets) catch |err| switch (err) {
        error.EndOfStream => 0,
        else => |e| return e,
    };
}

fn flushResponseChunk(writer: *http.BodyWriter) !void {
    // BodyWriter.flush() only flushes the protocol output stream. We also need
    // to drain the body writer buffer so chunked SSE/NDJSON data is emitted
    // immediately instead of waiting for end().
    try writer.writer.flush();
    try writer.flush();
}
/// Bundles all context needed by the proxy pipeline, replacing the previous
/// 14-parameter function signature for clarity and maintainability.
pub const ProxyContext = struct {
    allocator: std.mem.Allocator,
    client: *std.http.Client,
    target_host: []const u8,
    target_port: u16,
    target_tls: bool,
    session_entity_map: ?*const entity_mask.EntityMap,
    session_fuzzy_matcher: ?*const fuzzy_match.FuzzyMatcher,
    entity_set: ?*VersionedEntitySet,
    admin_config: admin.AdminConfig,
    max_body_size: usize,
    log: *Logger,
    observability: *Observability,
    session_id: []const u8,
    active_connections: *std.atomic.Value(u32),
    connections_total: *std.atomic.Value(u64),
    start_time: i64,
    unsupported_request_body_behavior: UnsupportedBodyBehavior,
    unsupported_response_body_behavior: UnsupportedBodyBehavior,
    // Pattern library enable flags
    enable_email: bool,
    enable_phone: bool,
    enable_credit_card: bool,
    enable_ip: bool,
    enable_healthcare: bool,
    // Schema-aware redaction (Epic 8)
    schema: ?*const schema_mod.Schema = null,
    hasher: ?*hasher_mod.Hasher = null,
    shutdown_state: *const shutdown_mod.ShutdownState,
    upstream_timeouts: upstream_client.UpstreamTimeouts,

    /// Build scanner flags from the proxy context's enable fields.
    pub fn patternFlags(self: ProxyContext) scanner.PatternFlags {
        return .{
            .email = self.enable_email,
            .phone = self.enable_phone,
            .credit_card = self.enable_credit_card,
            .ip = self.enable_ip,
            .healthcare = self.enable_healthcare,
        };
    }
};

pub fn handleRequest(
    request: *http.Server.Request,
    ctx: ProxyContext,
) !void {
    const allocator = ctx.allocator;
    var header_arena = std.heap.ArenaAllocator.init(allocator);
    defer header_arena.deinit();
    const header_allocator = header_arena.allocator();
    const target_host = ctx.target_host;
    const target_port = ctx.target_port;
    const target_tls = ctx.target_tls;
    const max_body_size = ctx.max_body_size;
    const log = ctx.log;
    const session_id = ctx.session_id;
    const client = ctx.client;
    const session_fuzzy_matcher = ctx.session_fuzzy_matcher;
    const entity_set = ctx.entity_set;
    const admin_config = ctx.admin_config;
    const request_start = std.time.nanoTimestamp();
    var route: Route = .proxy;
    var response_status: http.Status = .internal_server_error;
    var request_body_bytes: u64 = 0;
    var response_body_bytes: u64 = 0;
    var upstream_latency_us: u64 = 0;
    var upstream_latency_recorded = false;
    var request_outcome: RequestOutcome = .normal;
    var timeout_phase: ?upstream_client.TimeoutPhase = null;
    defer {
        const raw_total_latency = std.time.nanoTimestamp() - request_start;
        const total_latency_us: u64 = if (raw_total_latency < 0)
            0
        else
            @intCast(@divTrunc(raw_total_latency, 1000));
        ctx.observability.recordRequest(
            route,
            @intFromEnum(response_status),
            total_latency_us,
            request_body_bytes,
            response_body_bytes,
        );
        if (upstream_latency_recorded) {
            ctx.observability.recordUpstreamLatency(upstream_latency_us);
        }

        const draining = ctx.shutdown_state.isDraining();
        const effective_outcome: RequestOutcome = if (request_outcome == .normal and draining and route == .proxy)
            .drained_shutdown
        else
            request_outcome;

        var extra_buf: [5]Logger.KV = undefined;
        var extra_len: usize = 0;
        extra_buf[extra_len] = .{ .key = "status", .value = .{ .uint = @intFromEnum(response_status) } };
        extra_len += 1;
        extra_buf[extra_len] = .{ .key = "total_latency_us", .value = .{ .uint = total_latency_us } };
        extra_len += 1;
        extra_buf[extra_len] = .{ .key = "outcome", .value = .{ .string = requestOutcomeLabel(effective_outcome) } };
        extra_len += 1;
        extra_buf[extra_len] = .{ .key = "draining", .value = .{ .boolean = draining } };
        extra_len += 1;
        if (timeout_phase) |phase| {
            extra_buf[extra_len] = .{ .key = "timeout_phase", .value = .{ .string = timeoutPhaseLabel(phase) } };
            extra_len += 1;
        }
        log.log(.info, "response_sent", session_id, extra_buf[0..extra_len]);
    }
    const method = request.head.method;
    const uri_str = request.head.target;
    const has_body = method.requestHasBody();
    const request_class = body_policy.classifyRequest(
        has_body,
        request.head.content_type,
        request.head.transfer_compression,
        ctx.unsupported_request_body_behavior,
    );

    // --- Health check endpoint (before admin and proxying) ---
    if (method == .GET and std.mem.eql(u8, uri_str, "/healthz")) {
        route = .healthz;
        log.debug("healthz", session_id);
        // Clamp to zero if system clock jumped backward (NTP correction)
        // to avoid @intCast panic on negative delta.
        const raw_uptime = std.time.timestamp() - ctx.start_time;
        const uptime_s: u64 = if (raw_uptime < 0) 0 else @intCast(raw_uptime);
        const active = ctx.active_connections.load(.acquire);
        const total = ctx.connections_total.load(.acquire);

        var json_buf: [256]u8 = undefined;
        const body = std.fmt.bufPrint(&json_buf,
            \\{{"status":"ok","uptime_s":{d},"connections_active":{d},"connections_total":{d},"version":"{s}"}}
        , .{ uptime_s, active, total, Config.version }) catch unreachable;
        response_status = .ok;
        response_body_bytes = body.len;

        var resp_buf: [2048]u8 = undefined;
        var response_writer = try request.respondStreaming(&resp_buf, .{
            .respond_options = .{
                .status = .ok,
                .extra_headers = &.{
                    .{ .name = "Content-Type", .value = "application/json" },
                },
            },
        });
        try response_writer.writer.writeAll(body);
        try response_writer.end();
        return;
    }

    if (method == .GET and std.mem.eql(u8, uri_str, "/readyz")) {
        route = .readyz;
        const readiness = ctx.observability.readinessSnapshot();
        const ready = readiness.isReady();

        var json_buf: [640]u8 = undefined;
        const body = std.fmt.bufPrint(
            &json_buf,
            \\{{"status":"{s}","startup":"{s}","entity_reload":"{s}","shutdown":"{s}","entity_reload_success_total":{d},"entity_reload_failure_total":{d},"version":"{s}"}}
        ,
            .{
                if (ready) "ready" else "not_ready",
                if (readiness.startup_ready) "ok" else "failed",
                if (readiness.entity_reload_ready) "ok" else "failed",
                if (readiness.shutdown_draining) "draining" else "running",
                readiness.entity_reload_success_total,
                readiness.entity_reload_failure_total,
                Config.version,
            },
        ) catch unreachable;
        response_status = if (ready) .ok else .service_unavailable;
        response_body_bytes = body.len;

        var resp_buf: [2048]u8 = undefined;
        var response_writer = try request.respondStreaming(&resp_buf, .{
            .respond_options = .{
                .status = response_status,
                .extra_headers = &.{
                    .{ .name = "Content-Type", .value = "application/json" },
                },
            },
        });
        try response_writer.writer.writeAll(body);
        try response_writer.end();
        return;
    }

    if (method == .GET and std.mem.eql(u8, uri_str, "/metrics")) {
        route = .metrics;
        const body = try ctx.observability.renderMetrics(allocator);
        defer allocator.free(body);
        response_status = .ok;
        response_body_bytes = body.len;

        var resp_buf: [2048]u8 = undefined;
        var response_writer = try request.respondStreaming(&resp_buf, .{
            .respond_options = .{
                .status = .ok,
                .extra_headers = &.{
                    .{ .name = "Content-Type", .value = "text/plain; version=0.0.4; charset=utf-8" },
                },
            },
        });
        try response_writer.writer.writeAll(body);
        try response_writer.end();
        return;
    }

    // --- Admin API interception (before proxying) ---
    if (try admin.handleAdminRequest(request, entity_set, admin_config, allocator)) |admin_status| {
        route = .admin;
        response_status = admin_status;
        log.log(.info, "admin_request", session_id, &.{
            .{ .key = "method", .value = .{ .string = @tagName(method) } },
            .{ .key = "path", .value = .{ .string = uri_str } },
        });
        return;
    }

    // --- Collect end-to-end request headers for forwarding (NMV2-002) ---
    const req_e2e_headers = try http_util.collectEndToEndHeaders(
        header_allocator,
        request.head_buffer,
        &.{},
    );

    var header_names_buf: [512]u8 = undefined;
    log.log(.info, "request_received", session_id, &.{
        .{ .key = "method", .value = .{ .string = @tagName(method) } },
        .{ .key = "path", .value = .{ .string = uri_str } },
        .{ .key = "body_policy", .value = .{ .string = @tagName(request_class.policy) } },
        .{ .key = "content_type", .value = .{ .string = body_policy.contentTypeForLog(request_class.content_type) } },
        .{ .key = "content_encoding", .value = .{ .string = body_policy.contentEncodingForLog(request_class.content_encoding) } },
        .{ .key = "forwarded_headers", .value = .{ .string = http_util.headerNamesForLog(req_e2e_headers, &header_names_buf) } },
    });

    // --- Security: reject absolute-form URIs and non-path targets ---
    if (uri_str.len == 0 or uri_str[0] != '/') {
        response_status = .bad_request;
        response_body_bytes = try sendTextResponse(request, .bad_request, "Bad Request: invalid URI\n");
        return;
    }

    if (request_class.policy == .reject) {
        log.log(.warn, "request_body_rejected", session_id, &.{
            .{ .key = "body_policy", .value = .{ .string = @tagName(request_class.policy) } },
            .{ .key = "content_type", .value = .{ .string = body_policy.contentTypeForLog(request_class.content_type) } },
            .{ .key = "content_encoding", .value = .{ .string = body_policy.contentEncodingForLog(request_class.content_encoding) } },
        });
        response_status = .unsupported_media_type;
        response_body_bytes = try sendBodyPolicyResponse(request, .unsupported_media_type, "Unsupported request body", request_class);
        return;
    }
    // --- Determine entity map: per-request header overrides session default ---
    var per_request_map: ?entity_mask.EntityMap = null;
    defer if (per_request_map) |*m| m.deinit();

    const active_entity_map: ?*const entity_mask.EntityMap = blk: {
        // Check for X-ZPG-Entities header
        if (findHeader(request.head_buffer, "X-ZPG-Entities")) |header_val| {
            const names = parseEntityHeader(header_val, allocator) catch |err| {
                log.log(.warn, "entity_header_parse_failed", session_id, &.{
                    .{ .key = "error", .value = .{ .string = @errorName(err) } },
                });
                break :blk ctx.session_entity_map;
            };
            defer allocator.free(names);

            if (names.len > max_header_entities) {
                log.log(.warn, "entity_header_capped", session_id, &.{
                    .{ .key = "provided", .value = .{ .uint = names.len } },
                    .{ .key = "max", .value = .{ .uint = max_header_entities } },
                });
            }

            const capped_len = @min(names.len, max_header_entities);
            if (capped_len > 0) {
                per_request_map = entity_mask.EntityMap.init(allocator, names[0..capped_len]) catch |err| {
                    log.log(.warn, "entity_map_build_failed", session_id, &.{
                        .{ .key = "error", .value = .{ .string = @errorName(err) } },
                    });
                    break :blk ctx.session_entity_map;
                };
                break :blk &per_request_map.?;
            }
        }
        break :blk ctx.session_entity_map;
    };

    // --- Forward request to upstream ---
    var url_buf: [max_url_len]u8 = undefined;
    const scheme = if (target_tls) "https" else "http";
    const target_url_str = try std.fmt.bufPrint(&url_buf, "{s}://{s}:{d}{s}", .{ scheme, target_host, target_port, uri_str });
    const target_uri = try std.Uri.parse(target_url_str);
    var upstream_deadline = upstream_client.RequestDeadline.init(ctx.upstream_timeouts);
    const content_type_override: http.Client.Request.Headers.Value = if (request.head.content_type) |ct|
        .{ .override = ct }
    else
        .omit;

    // Build the forwarded header set: all collected end-to-end headers plus
    // Content-Encoding if present. User-Agent is carried via extra_headers while
    // the stdlib default is explicitly disabled below to preserve fidelity.
    var request_headers = std.ArrayListUnmanaged(http.Header).empty;
    for (req_e2e_headers) |h| {
        try request_headers.append(header_allocator, h);
    }

    // Add Content-Encoding if the inbound request had one
    if (request.head.transfer_compression != .identity) {
        try request_headers.append(header_allocator, .{
            .name = "Content-Encoding",
            .value = @tagName(request.head.transfer_compression),
        });
    }

    var client_req = upstream_client.requestWithTimeouts(client, method, target_uri, .{
        .headers = .{
            .content_type = content_type_override,
            .user_agent = .omit,
        },
        .extra_headers = request_headers.items,
    }, &upstream_deadline) catch |err| {
        if (err == error.ConnectionTimedOut) {
            request_outcome = .timed_out;
            timeout_phase = .connect;
            response_status = .gateway_timeout;
            logUpstreamTimeout(log, session_id, target_host, .connect, ctx.upstream_timeouts.connect_timeout_ms);
            response_body_bytes = try sendTimeoutResponse(request, .connect);
            return;
        }

        log.log(.error_, "upstream_connect_failed", session_id, &.{
            .{ .key = "error", .value = .{ .string = @errorName(err) } },
            .{ .key = "target_host", .value = .{ .string = target_host } },
        });
        return err;
    };
    defer client_req.deinit();
    // Sets both the accept_encoding bitmask and the header string to identity
    configureIdentityAcceptEncoding(&client_req);
    client_req.transfer_encoding = if (has_body) .chunked else .none;

    // --- Request path: apply privacy pipeline to outbound body ---
    if (has_body) {
        if (request_class.policy == .bypass) {
            request_body_bytes = try forwardBodyBypass(request, &client_req, max_body_size, log, session_id);
        } else {
            const active_schema_for_request = if (ctx.schema != null and request_class.kind.supportsSchemaJson())
                ctx.schema
            else
                null;

            // Schema-aware mode: buffer full body, apply entity masking, then JSON redactor.
            if (active_schema_for_request) |active_schema| {
                var req_body_transfer_buf: [8192]u8 = undefined;
                var req_body = try client_req.sendBodyUnflushed(&req_body_transfer_buf);

                var body_read_buf: [8192]u8 = undefined;
                if (request.readerExpectContinue(&body_read_buf)) |body_reader| {
                    // Buffer entire body for JSON parsing
                    var full_body = std.ArrayListUnmanaged(u8).empty;
                    defer full_body.deinit(allocator);

                    var chunk_buf: [8192]u8 = undefined;
                    while (true) {
                        const bytes_read = try body_reader.readSliceShort(&chunk_buf);
                        if (bytes_read == 0) break;

                        if (full_body.items.len + bytes_read > max_body_size) {
                            log.log(.warn, "body_too_large", session_id, &.{
                                .{ .key = "max_body_size", .value = .{ .uint = max_body_size } },
                            });
                            return error.PayloadTooLarge;
                        }
                        try full_body.appendSlice(allocator, chunk_buf[0..bytes_read]);

                        if (bytes_read < chunk_buf.len) break;
                    }
                    request_body_bytes = full_body.items.len;

                    // Stage 0: Entity masking on the full body (same as chunked path).
                    // Runs Aho-Corasick replacement so named entities are masked before
                    // the JSON redactor sees them.
                    var masked_body: []u8 = undefined;
                    var masked_allocated = false;
                    if (active_entity_map) |em| {
                        masked_body = try em.mask(full_body.items, allocator);
                        masked_allocated = true;
                    } else {
                        masked_body = try allocator.dupe(u8, full_body.items);
                        masked_allocated = true;
                    }
                    defer if (masked_allocated) allocator.free(masked_body);

                    // Build hasher interface if a hasher is present
                    const hasher_iface: ?json_redactor.HasherInterface = if (ctx.hasher) |h| .{
                        .hash_fn = &struct {
                            fn call(orig: []const u8, ctx_ptr: *anyopaque) anyerror![]const u8 {
                                const hh: *hasher_mod.Hasher = @ptrCast(@alignCast(ctx_ptr));
                                return hh.hash(orig);
                            }
                        }.call,
                        .ctx_ptr = @ptrCast(@alignCast(h)),
                    } else null;

                    // --- Inline audit: emit events during the primary redaction pass
                    //     instead of re-running the pipeline afterwards (see observation #1).
                    var emitter = redaction_audit.AuditEmitter.init(log, session_id, ctx.observability);
                    defer emitter.finish();

                    // Emit entity-mask audit events before schema processing
                    if (active_entity_map) |em| {
                        try redaction_audit.emitEntityMaskAuditEvents(
                            em,
                            full_body.items,
                            &emitter,
                            allocator,
                        );
                    }

                    // Build ScanContext to run SCAN-action values through the
                    // full SSN + pattern + fuzzy redaction pipeline with inline
                    // audit event emission.
                    const ScanAuditState = struct {
                        const Self = @This();

                        proxy_ctx: *const ProxyContext,
                        emitter: *redaction_audit.AuditEmitter,

                        fn doScan(input_val: []const u8, field_path: []const u8, ctx_ptr: *anyopaque, alloc: std.mem.Allocator) anyerror![]u8 {
                            const self: *Self = @ptrCast(@alignCast(ctx_ptr));

                            return redaction_audit.runTextStages(
                                input_val,
                                field_path,
                                .{
                                    .ssn = true,
                                    .patterns = true,
                                    .fuzzy = true,
                                },
                                self.proxy_ctx.session_entity_map,
                                self.proxy_ctx.session_fuzzy_matcher,
                                self.proxy_ctx.patternFlags(),
                                self.emitter,
                                alloc,
                            );
                        }

                        fn onSchemaAction(event: json_redactor.AuditEvent, ctx_ptr: *anyopaque) anyerror!void {
                            const self: *Self = @ptrCast(@alignCast(ctx_ptr));
                            self.emitter.emit(.{
                                .stage = "schema",
                                .match_type = switch (event.action) {
                                    .redact => "schema_redact",
                                    .hash => "schema_hash",
                                    .scan => "schema_scan",
                                    .keep => "schema_keep",
                                },
                                .field_path = event.field_path,
                                .original_length = event.original_length,
                                .replacement_type = event.replacement_type,
                            });
                        }
                    };

                    var scan_audit_state = ScanAuditState{
                        .proxy_ctx = &ctx,
                        .emitter = &emitter,
                    };

                    const scan_ctx_iface: ?json_redactor.ScanContext = .{
                        .scan_fn = &ScanAuditState.doScan,
                        .ctx_ptr = @ptrCast(&scan_audit_state),
                    };

                    const audit_ctx: ?json_redactor.AuditContext = .{
                        .audit_fn = &ScanAuditState.onSchemaAction,
                        .ctx_ptr = @ptrCast(&scan_audit_state),
                    };

                    const redacted = try json_redactor.redactJsonWithAudit(
                        masked_body,
                        active_schema,
                        hasher_iface,
                        scan_ctx_iface,
                        audit_ctx,
                        allocator,
                    );
                    defer allocator.free(redacted);

                    try req_body.writer.writeAll(redacted);
                } else |err| {
                    log.log(.warn, "body_read_failed", session_id, &.{
                        .{ .key = "error", .value = .{ .string = @errorName(err) } },
                    });
                }

                try req_body.end();
                if (client_req.connection) |conn| {
                    try conn.flush();
                }
            } else {
                // --- Chunked streaming pipeline (non-schema mode) ---
                var ac_state: ?entity_mask.AcChunkState = null;
                if (active_entity_map) |em| ac_state = em.initChunkState();
                defer if (ac_state) |*s| s.deinit(allocator);

                var ssn_state = redact.SsnChunkState{};

                var fuzzy_state: ?fuzzy_match.FuzzyMatcher.FuzzyChunkState = null;
                if (session_fuzzy_matcher) |fm| fuzzy_state = fm.initChunkState();
                defer if (fuzzy_state) |*s| s.deinit(allocator);

                var req_body_transfer_buf: [8192]u8 = undefined;
                var req_body = try client_req.sendBodyUnflushed(&req_body_transfer_buf);

                var body_read_buf: [8192]u8 = undefined;
                var bytes_forwarded: usize = 0;
                var audit_body: std.ArrayListUnmanaged(u8) = .empty;
                defer audit_body.deinit(allocator);
                if (request.readerExpectContinue(&body_read_buf)) |body_reader| {
                    var raw_chunk_buf: [8192]u8 = undefined;
                    while (true) {
                        const bytes_read = try body_reader.readSliceShort(&raw_chunk_buf);
                        if (bytes_read == 0) break;

                        bytes_forwarded += bytes_read;
                        if (bytes_forwarded > max_body_size) {
                            log.log(.warn, "body_too_large", session_id, &.{
                                .{ .key = "max_body_size", .value = .{ .uint = max_body_size } },
                            });
                            return error.PayloadTooLarge;
                        }

                        const raw_chunk = raw_chunk_buf[0..bytes_read];
                        try audit_body.appendSlice(allocator, raw_chunk);

                        var masked_chunk: []u8 = undefined;
                        var masked_allocated = false;
                        if (active_entity_map) |em| {
                            masked_chunk = try em.maskChunked(raw_chunk, &ac_state.?, allocator);
                            masked_allocated = true;
                        } else {
                            masked_chunk = try allocator.dupe(u8, raw_chunk);
                            masked_allocated = true;
                        }
                        defer if (masked_allocated) allocator.free(masked_chunk);

                        const ssn_res = redact.redactSsnChunked(masked_chunk, &ssn_state);

                        // --- Pattern library: single-pass scan (after SSN, before fuzzy) ---
                        const scanner_flags = ctx.patternFlags();
                        var pattern_finalized = ssn_res.finalized;
                        var pattern_emitted = ssn_res.emitted;

                        var pf_alloc: ?[]u8 = null;
                        var pe_alloc: ?[]u8 = null;
                        defer if (pf_alloc) |a| allocator.free(a);
                        defer if (pe_alloc) |a| allocator.free(a);

                        if (scanner_flags.anyEnabled()) {
                            if (pattern_finalized.len > 0) {
                                const buf = try scanner.redact(pattern_finalized, scanner_flags, allocator);
                                pf_alloc = buf;
                                pattern_finalized = buf;
                            }
                            if (pattern_emitted.len > 0) {
                                const buf = try scanner.redact(pattern_emitted, scanner_flags, allocator);
                                pe_alloc = buf;
                                pattern_emitted = buf;
                            }
                        }

                        if (session_fuzzy_matcher) |fm| {
                            const em_aliases = if (active_entity_map) |em| em.getAliases() else &.{};
                            if (pattern_finalized.len > 0) {
                                const f1 = try fm.fuzzyRedactChunked(pattern_finalized, &fuzzy_state.?, em_aliases, &.{}, allocator);
                                defer allocator.free(f1);
                                if (f1.len > 0) try req_body.writer.writeAll(f1);
                            }
                            if (pattern_emitted.len > 0) {
                                const f2 = try fm.fuzzyRedactChunked(pattern_emitted, &fuzzy_state.?, em_aliases, &.{}, allocator);
                                defer allocator.free(f2);
                                if (f2.len > 0) try req_body.writer.writeAll(f2);
                            }
                        } else {
                            if (pattern_finalized.len > 0) try req_body.writer.writeAll(pattern_finalized);
                            if (pattern_emitted.len > 0) try req_body.writer.writeAll(pattern_emitted);
                        }

                        // readSliceShort returns < buffer.len if and only if it reached EOF.
                        // Breaking here prevents another read call that panics if the stream is already .ready
                        if (bytes_read < raw_chunk_buf.len) break;
                    }
                    request_body_bytes = bytes_forwarded;

                    // Flushes
                    var ac_flushed: ?[]u8 = null;
                    if (active_entity_map) |em| {
                        ac_flushed = try ac_state.?.flush(em, allocator);
                    }
                    defer if (ac_flushed) |f| allocator.free(f);

                    var ssn_final_emissions: std.ArrayListUnmanaged(u8) = .empty;
                    defer ssn_final_emissions.deinit(allocator);

                    if (ac_flushed) |f| {
                        if (f.len > 0) {
                            const ssn_res = redact.redactSsnChunked(f, &ssn_state);
                            if (ssn_res.finalized.len > 0) try ssn_final_emissions.appendSlice(allocator, ssn_res.finalized);
                            if (ssn_res.emitted.len > 0) try ssn_final_emissions.appendSlice(allocator, ssn_res.emitted);
                        }
                    }

                    const ssn_flushed = ssn_state.flush();
                    if (ssn_flushed.len > 0) {
                        try ssn_final_emissions.appendSlice(allocator, ssn_flushed);
                    }

                    if (session_fuzzy_matcher) |fm| {
                        const em_aliases = if (active_entity_map) |em| em.getAliases() else &.{};

                        const pattern_result = if (ssn_final_emissions.items.len > 0 and ctx.patternFlags().anyEnabled())
                            try scanner.redact(ssn_final_emissions.items, ctx.patternFlags(), allocator)
                        else
                            null;
                        defer if (pattern_result) |pr| allocator.free(pr);

                        const final_buf = pattern_result orelse ssn_final_emissions.items;
                        if (final_buf.len > 0) {
                            const f_res = try fm.fuzzyRedactChunked(final_buf, &fuzzy_state.?, em_aliases, &.{}, allocator);
                            defer allocator.free(f_res);
                            if (f_res.len > 0) try req_body.writer.writeAll(f_res);
                        }
                        const fuzzy_flushed = try fuzzy_state.?.flush(fm, em_aliases, &.{}, allocator);
                        defer allocator.free(fuzzy_flushed);
                        if (fuzzy_flushed.len > 0) try req_body.writer.writeAll(fuzzy_flushed);
                    } else {
                        const pattern_result = if (ssn_final_emissions.items.len > 0 and ctx.patternFlags().anyEnabled())
                            try scanner.redact(ssn_final_emissions.items, ctx.patternFlags(), allocator)
                        else
                            null;
                        defer if (pattern_result) |pr| allocator.free(pr);

                        const final_buf = pattern_result orelse ssn_final_emissions.items;
                        if (final_buf.len > 0) {
                            try req_body.writer.writeAll(final_buf);
                        }
                    }
                } else |err| {
                    log.log(.warn, "body_read_failed", session_id, &.{
                        .{ .key = "error", .value = .{ .string = @errorName(err) } },
                    });
                }

                try redaction_audit.emitRequestAuditEvents(
                    allocator,
                    log,
                    session_id,
                    audit_body.items,
                    active_entity_map,
                    session_fuzzy_matcher,
                    ctx.patternFlags(),
                    null,
                    null,
                    ctx.observability,
                );

                try req_body.end();
                if (client_req.connection) |conn| {
                    try conn.flush();
                }
            }
        }
    } else {
        try client_req.sendBodilessUnflushed();
        if (client_req.connection) |conn| {
            try conn.flush();
        }
    }

    upstream_deadline.ensureWithinOverall() catch {
        request_outcome = .timed_out;
        timeout_phase = .request;
        if (client_req.connection) |conn| conn.closing = true;
        response_status = .gateway_timeout;
        logUpstreamTimeout(log, session_id, target_host, .request, ctx.upstream_timeouts.request_timeout_ms);
        response_body_bytes = try sendTimeoutResponse(request, .request);
        return;
    };

    // --- Read upstream response ---
    var redirect_buffer: [4096]u8 = undefined;
    if (client_req.connection) |conn| {
        upstream_deadline.armReadOperation(conn) catch {
            request_outcome = .timed_out;
            timeout_phase = .request;
            conn.closing = true;
            response_status = .gateway_timeout;
            logUpstreamTimeout(log, session_id, target_host, .request, ctx.upstream_timeouts.request_timeout_ms);
            response_body_bytes = try sendTimeoutResponse(request, .request);
            return;
        };
    }
    var downstream_res = client_req.receiveHead(&redirect_buffer) catch |err| {
        const raw_upstream_latency = std.time.nanoTimestamp() - request_start;
        upstream_latency_us = if (raw_upstream_latency < 0)
            0
        else
            @intCast(@divTrunc(raw_upstream_latency, 1000));
        upstream_latency_recorded = true;

        if (err == error.WouldBlock or err == error.UpstreamRequestTimedOut) {
            const phase: upstream_client.TimeoutPhase = if (err == error.UpstreamRequestTimedOut)
                .request
            else
                upstream_deadline.readTimeoutPhase();
            request_outcome = .timed_out;
            timeout_phase = phase;
            if (client_req.connection) |conn| conn.closing = true;
            response_status = .gateway_timeout;
            logUpstreamTimeout(
                log,
                session_id,
                target_host,
                phase,
                switch (phase) {
                    .connect => ctx.upstream_timeouts.connect_timeout_ms,
                    .read => ctx.upstream_timeouts.read_timeout_ms,
                    .request => ctx.upstream_timeouts.request_timeout_ms,
                },
            );
            response_body_bytes = sendTimeoutResponse(request, phase) catch 0;
            return;
        }

        log.log(.warn, "upstream_response_head_failed", session_id, &.{
            .{ .key = "error", .value = .{ .string = @errorName(err) } },
            .{ .key = "target_host", .value = .{ .string = target_host } },
        });
        response_status = .bad_gateway;
        response_body_bytes = try sendTextResponse(request, .bad_gateway, "Bad Gateway: upstream response headers or encodings are unsupported\n");
        return;
    };

    const raw_upstream_latency = std.time.nanoTimestamp() - request_start;
    upstream_latency_us = if (raw_upstream_latency < 0)
        0
    else
        @intCast(@divTrunc(raw_upstream_latency, 1000));
    upstream_latency_recorded = true;
    response_status = downstream_res.head.status;
    const response_has_body = responseHasBody(method, downstream_res.head.status);
    const response_kind = body_policy.classifyContentType(downstream_res.head.content_type);
    const can_unmask = active_entity_map != null and response_kind.supportsInlineTransform();
    const can_unhash = ctx.hasher != null and response_kind.supportsJsonResponseTransform();
    const response_class = body_policy.classifyResponse(
        response_has_body,
        downstream_res.head.content_type,
        downstream_res.head.content_encoding,
        can_unmask or can_unhash,
        ctx.unsupported_response_body_behavior,
    );
    const should_buffer_response = response_class.policy != .bypass and can_unhash;
    const should_unmask_response = response_class.policy != .bypass and can_unmask and !should_buffer_response;
    const response_mode: ResponseForwardingMode = if (!response_has_body)
        .no_body
    else if (should_buffer_response)
        .buffered
    else if (should_unmask_response)
        .stream_unmask
    else
        .stream_passthrough;
    const flush_response_per_chunk = shouldFlushResponsePerChunk(
        response_mode,
        downstream_res.head.transfer_encoding,
        response_kind,
        downstream_res.head.content_type,
    );

    log.log(.info, "upstream_forwarded", session_id, &.{
        .{ .key = "status", .value = .{ .uint = @intFromEnum(downstream_res.head.status) } },
        .{ .key = "target_host", .value = .{ .string = target_host } },
        .{ .key = "upstream_latency_us", .value = .{ .uint = upstream_latency_us } },
        .{ .key = "body_policy", .value = .{ .string = @tagName(response_class.policy) } },
        .{ .key = "content_type", .value = .{ .string = body_policy.contentTypeForLog(response_class.content_type) } },
        .{ .key = "content_encoding", .value = .{ .string = body_policy.contentEncodingForLog(response_class.content_encoding) } },
        .{ .key = "response_mode", .value = .{ .string = responseModeLabel(response_mode) } },
        .{ .key = "buffer_reason", .value = .{ .string = responseBufferReason(response_mode) } },
        .{ .key = "flush_per_chunk", .value = .{ .boolean = flush_response_per_chunk } },
    });

    if (response_class.policy == .reject) {
        if (client_req.connection) |conn| conn.closing = true;
        log.log(.warn, "upstream_response_rejected", session_id, &.{
            .{ .key = "body_policy", .value = .{ .string = @tagName(response_class.policy) } },
            .{ .key = "content_type", .value = .{ .string = body_policy.contentTypeForLog(response_class.content_type) } },
            .{ .key = "content_encoding", .value = .{ .string = body_policy.contentEncodingForLog(response_class.content_encoding) } },
        });
        response_status = .bad_gateway;
        response_body_bytes = try sendBodyPolicyResponse(request, .bad_gateway, "Bad Gateway: unsupported upstream response body", response_class);
        return;
    }

    // --- Collect end-to-end response headers for forwarding (NMV2-002) ---
    // Duplicate headers before calling downstream_res.reader(), which invalidates
    // the parsed head string slices in the stdlib response object.
    const resp_e2e_headers = try http_util.collectEndToEndHeaders(
        header_allocator,
        downstream_res.head.bytes,
        &.{},
    );

    // Merge managed response headers with collected end-to-end headers.
    // Managed: Content-Type, Content-Disposition, Content-Encoding are set
    // explicitly because they affect proxy pipeline behavior.
    var response_headers_list = std.ArrayListUnmanaged(http.Header).empty;
    if (downstream_res.head.content_type) |ct| {
        try response_headers_list.append(header_allocator, .{ .name = "Content-Type", .value = ct });
    }
    if (downstream_res.head.content_disposition) |cd| {
        try response_headers_list.append(header_allocator, .{ .name = "Content-Disposition", .value = cd });
    }
    if (response_class.policy == .bypass and downstream_res.head.content_encoding != .identity) {
        try response_headers_list.append(header_allocator, .{
            .name = "Content-Encoding",
            .value = @tagName(downstream_res.head.content_encoding),
        });
    }
    // Append all collected end-to-end response headers
    for (resp_e2e_headers) |h| {
        try response_headers_list.append(header_allocator, h);
    }
    const response_headers = response_headers_list.items;

    if (response_has_body and should_buffer_response) {
        var transfer_buf: [8192]u8 = undefined;
        const downstream_reader = downstream_res.reader(&transfer_buf);
        var resp_body = std.ArrayListUnmanaged(u8).empty;
        defer resp_body.deinit(allocator);

        var unmask_state: ?entity_mask.AcChunkState = null;
        if (can_unmask) {
            unmask_state = active_entity_map.?.initUnmaskChunkState();
        }
        defer if (unmask_state) |*s| s.deinit(allocator);

        var resp_buf: [8192]u8 = undefined;
        while (true) {
            if (client_req.connection) |conn| {
                upstream_deadline.armReadOperation(conn) catch {
                    request_outcome = .timed_out;
                    timeout_phase = .request;
                    conn.closing = true;
                    response_status = .gateway_timeout;
                    logUpstreamTimeout(log, session_id, target_host, .request, ctx.upstream_timeouts.request_timeout_ms);
                    response_body_bytes = try sendTimeoutResponse(request, .request);
                    return;
                };
            }

            const bytes_read = readAvailable(downstream_reader, &resp_buf) catch |err| {
                if (err == error.WouldBlock or err == error.UpstreamRequestTimedOut) {
                    const phase: upstream_client.TimeoutPhase = if (err == error.UpstreamRequestTimedOut)
                        .request
                    else
                        upstream_deadline.readTimeoutPhase();
                    request_outcome = .timed_out;
                    timeout_phase = phase;
                    if (client_req.connection) |conn| conn.closing = true;
                    response_status = .gateway_timeout;
                    logUpstreamTimeout(
                        log,
                        session_id,
                        target_host,
                        phase,
                        if (phase == .read) ctx.upstream_timeouts.read_timeout_ms else ctx.upstream_timeouts.request_timeout_ms,
                    );
                    response_body_bytes = try sendTimeoutResponse(request, phase);
                    return;
                }
                return err;
            };
            if (bytes_read == 0) break;

            if (resp_body.items.len + bytes_read > max_body_size) {
                if (client_req.connection) |conn| conn.closing = true;
                log.log(.warn, "response_body_too_large", session_id, &.{
                    .{ .key = "max_body_size", .value = .{ .uint = max_body_size } },
                });
                response_status = .bad_gateway;
                response_body_bytes = try sendTextResponse(request, .bad_gateway, "Bad Gateway: upstream response body too large\n");
                return;
            }

            const raw_chunk = resp_buf[0..bytes_read];
            if (can_unmask) {
                const unmasked = try active_entity_map.?.unmaskChunked(raw_chunk, &unmask_state.?, allocator);
                defer allocator.free(unmasked);
                try resp_body.appendSlice(allocator, unmasked);
            } else {
                try resp_body.appendSlice(allocator, raw_chunk);
            }
        }

        if (can_unmask) {
            const flushed = try unmask_state.?.flushUnmask(active_entity_map.?, allocator);
            defer allocator.free(flushed);
            try resp_body.appendSlice(allocator, flushed);
        }

        const unhashed = ctx.hasher.?.unhashJson(resp_body.items, allocator) catch |err| {
            if (client_req.connection) |conn| conn.closing = true;
            log.log(.warn, "response_unhash_failed", session_id, &.{
                .{ .key = "error", .value = .{ .string = @errorName(err) } },
            });
            response_status = .bad_gateway;
            response_body_bytes = try sendTextResponse(request, .bad_gateway, "Bad Gateway: upstream JSON response could not be restored\n");
            return;
        };
        defer allocator.free(unhashed);

        var resp_buf8: [8192]u8 = undefined;
        var response_writer = try request.respondStreaming(&resp_buf8, .{
            .content_length = unhashed.len,
            .respond_options = .{
                .status = downstream_res.head.status,
                .extra_headers = response_headers,
            },
        });
        if (unhashed.len > 0) try response_writer.writer.writeAll(unhashed);
        try response_writer.end();
        response_body_bytes = unhashed.len;
    } else {
        const response_content_length: ?u64 = switch (response_mode) {
            .stream_passthrough => downstream_res.head.content_length,
            .buffered, .stream_unmask, .no_body => null,
        };
        var resp_buf8: [8192]u8 = undefined;
        var response_writer = try request.respondStreaming(&resp_buf8, .{
            .content_length = response_content_length,
            .respond_options = .{
                .status = downstream_res.head.status,
                .extra_headers = response_headers,
                .transfer_encoding = if (response_mode == .no_body) .none else null,
            },
        });

        if (response_has_body) {
            var transfer_buf: [8192]u8 = undefined;
            const downstream_reader = downstream_res.reader(&transfer_buf);

            if (response_class.policy == .bypass or !should_unmask_response) {
                var resp_buf: [8192]u8 = undefined;
                while (true) {
                    if (client_req.connection) |conn| {
                        upstream_deadline.armReadOperation(conn) catch {
                            request_outcome = .timed_out;
                            timeout_phase = .request;
                            conn.closing = true;
                            logUpstreamTimeout(log, session_id, target_host, .request, ctx.upstream_timeouts.request_timeout_ms);
                            return;
                        };
                    }

                    const bytes_read = readAvailable(downstream_reader, &resp_buf) catch |err| {
                        if (err == error.WouldBlock or err == error.UpstreamRequestTimedOut) {
                            const phase: upstream_client.TimeoutPhase = if (err == error.UpstreamRequestTimedOut)
                                .request
                            else
                                upstream_deadline.readTimeoutPhase();
                            request_outcome = .timed_out;
                            timeout_phase = phase;
                            if (client_req.connection) |conn| conn.closing = true;
                            logUpstreamTimeout(
                                log,
                                session_id,
                                target_host,
                                phase,
                                if (phase == .read) ctx.upstream_timeouts.read_timeout_ms else ctx.upstream_timeouts.request_timeout_ms,
                            );
                            return;
                        }
                        return err;
                    };
                    if (bytes_read == 0) break;
                    try response_writer.writer.writeAll(resp_buf[0..bytes_read]);
                    response_body_bytes += bytes_read;
                    if (flush_response_per_chunk) try flushResponseChunk(&response_writer);
                }
            } else {
                var unmask_state = active_entity_map.?.initUnmaskChunkState();
                defer unmask_state.deinit(allocator);

                var resp_buf: [8192]u8 = undefined;
                while (true) {
                    if (client_req.connection) |conn| {
                        upstream_deadline.armReadOperation(conn) catch {
                            request_outcome = .timed_out;
                            timeout_phase = .request;
                            conn.closing = true;
                            logUpstreamTimeout(log, session_id, target_host, .request, ctx.upstream_timeouts.request_timeout_ms);
                            return;
                        };
                    }

                    const bytes_read = readAvailable(downstream_reader, &resp_buf) catch |err| {
                        if (err == error.WouldBlock or err == error.UpstreamRequestTimedOut) {
                            const phase: upstream_client.TimeoutPhase = if (err == error.UpstreamRequestTimedOut)
                                .request
                            else
                                upstream_deadline.readTimeoutPhase();
                            request_outcome = .timed_out;
                            timeout_phase = phase;
                            if (client_req.connection) |conn| conn.closing = true;
                            logUpstreamTimeout(
                                log,
                                session_id,
                                target_host,
                                phase,
                                if (phase == .read) ctx.upstream_timeouts.read_timeout_ms else ctx.upstream_timeouts.request_timeout_ms,
                            );
                            return;
                        }
                        return err;
                    };
                    if (bytes_read == 0) break;

                    const unmasked = try active_entity_map.?.unmaskChunked(resp_buf[0..bytes_read], &unmask_state, allocator);
                    defer allocator.free(unmasked);
                    if (unmasked.len > 0) {
                        try response_writer.writer.writeAll(unmasked);
                        response_body_bytes += unmasked.len;
                        if (flush_response_per_chunk) try flushResponseChunk(&response_writer);
                    }
                }

                const flushed = try unmask_state.flushUnmask(active_entity_map.?, allocator);
                defer allocator.free(flushed);
                if (flushed.len > 0) {
                    try response_writer.writer.writeAll(flushed);
                    response_body_bytes += flushed.len;
                    if (flush_response_per_chunk) try flushResponseChunk(&response_writer);
                }
            }
        }

        try response_writer.end();
    }

}

// ===========================================================================
// Unit Tests
// ===========================================================================

test "parseEntityHeader - typical comma-separated names" {
    const allocator = std.testing.allocator;
    const result = try parseEntityHeader("John Doe, Jane Smith, Dr. Johnson", allocator);
    defer allocator.free(result);

    try std.testing.expectEqual(@as(usize, 3), result.len);
    try std.testing.expectEqualStrings("John Doe", result[0]);
    try std.testing.expectEqualStrings("Jane Smith", result[1]);
    try std.testing.expectEqualStrings("Dr. Johnson", result[2]);
}

test "parseEntityHeader - single name" {
    const allocator = std.testing.allocator;
    const result = try parseEntityHeader("John Doe", allocator);
    defer allocator.free(result);

    try std.testing.expectEqual(@as(usize, 1), result.len);
    try std.testing.expectEqualStrings("John Doe", result[0]);
}

test "parseEntityHeader - empty string" {
    const allocator = std.testing.allocator;
    const result = try parseEntityHeader("", allocator);
    defer allocator.free(result);

    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "parseEntityHeader - trailing and leading commas with whitespace" {
    const allocator = std.testing.allocator;
    const result = try parseEntityHeader(" , John Doe , , Jane Smith , ", allocator);
    defer allocator.free(result);

    try std.testing.expectEqual(@as(usize, 2), result.len);
    try std.testing.expectEqualStrings("John Doe", result[0]);
    try std.testing.expectEqualStrings("Jane Smith", result[1]);
}
