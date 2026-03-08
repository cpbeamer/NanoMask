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
    session_id: []const u8,
    active_connections: *std.atomic.Value(u32),
    connections_total: *std.atomic.Value(u64),
    start_time: i64,
    // Pattern library enable flags
    enable_email: bool,
    enable_phone: bool,
    enable_credit_card: bool,
    enable_ip: bool,
    enable_healthcare: bool,
    // Schema-aware redaction (Epic 8)
    schema: ?*const schema_mod.Schema = null,
    hasher: ?*hasher_mod.Hasher = null,

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
    const method = request.head.method;
    const uri_str = request.head.target;

    // --- Health check endpoint (before admin and proxying) ---
    if (method == .GET and std.mem.eql(u8, uri_str, "/healthz")) {
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

    // --- Admin API interception (before proxying) ---
    if (try admin.handleAdminRequest(request, entity_set, admin_config, allocator)) {
        log.log(.info, "admin_request", session_id, &.{
            .{ .key = "method", .value = .{ .string = @tagName(method) } },
            .{ .key = "path", .value = .{ .string = uri_str } },
        });
        return;
    }

    log.log(.info, "request_received", session_id, &.{
        .{ .key = "method", .value = .{ .string = @tagName(method) } },
        .{ .key = "path", .value = .{ .string = uri_str } },
    });

    // --- Security: reject absolute-form URIs and non-path targets ---
    if (uri_str.len == 0 or uri_str[0] != '/') {
        var err_buf: [2048]u8 = undefined;
        var err_writer = try request.respondStreaming(&err_buf, .{
            .respond_options = .{
                .status = .bad_request,
            },
        });
        try err_writer.writer.writeAll("Bad Request: invalid URI\n");
        try err_writer.end();
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

    // Forward Content-Type so upstream APIs receive the correct media type.
    const content_type_override: http.Client.Request.Headers.Value = blk: {
        if (findHeader(request.head_buffer, "Content-Type")) |ct| {
            break :blk .{ .override = ct };
        }
        break :blk .default;
    };

    const has_body = method.requestHasBody();

    var client_req = client.request(method, target_uri, .{
        .headers = .{ .content_type = content_type_override },
    }) catch |e| {
        log.log(.error_, "upstream_connect_failed", session_id, &.{});
        return e;
    };
    defer client_req.deinit();
    client_req.transfer_encoding = if (has_body) .chunked else .none;

    // --- Request path: apply privacy pipeline to outbound body ---
    if (has_body) {
        // Schema-aware mode: buffer full body and run JSON redactor
        if (ctx.schema) |active_schema| {
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

                // Build ScanContext to run SCAN-action values through the
                // full SSN + pattern redaction pipeline. This adapter runs
                // the same redaction stages as the chunked pipeline, but on
                // individual field values extracted by the JSON redactor.
                const ScanAdapter = struct {
                    fn doScan(input_val: []const u8, ctx_ptr: *anyopaque, alloc: std.mem.Allocator) anyerror![]u8 {
                        const proxy_ctx: *const ProxyContext = @ptrCast(@alignCast(ctx_ptr));

                        // Stage 1: SSN redaction (in-place on a mutable copy)
                        const mutable = try alloc.dupe(u8, input_val);

                        redact.redactSsn(mutable);

                        // Stage 2: Pattern library scan
                        const pflags = proxy_ctx.patternFlags();
                        if (pflags.anyEnabled()) {
                            const scanned = try scanner.redact(mutable, pflags, alloc);
                            alloc.free(mutable);
                            return scanned;
                        }

                        // No patterns enabled — return the SSN-redacted buffer
                        return mutable;
                    }
                };

                const scan_ctx_iface: ?json_redactor.ScanContext = .{
                    .scan_fn = &ScanAdapter.doScan,
                    .ctx_ptr = @ptrCast(@constCast(&ctx)),
                };

                const redacted = try json_redactor.redactJson(
                    full_body.items,
                    active_schema,
                    hasher_iface,
                    scan_ctx_iface,
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

            try req_body.end();
            if (client_req.connection) |conn| {
                try conn.flush();
            }
        }
    } else {
        try client_req.sendBodilessUnflushed();
        if (client_req.connection) |conn| {
            try conn.flush();
        }
    }

    // --- Read upstream response ---
    var redirect_buffer: [4096]u8 = undefined;
    var downstream_res = try client_req.receiveHead(&redirect_buffer);

    const upstream_latency_us: u64 = @intCast(@divTrunc(std.time.nanoTimestamp() - request_start, 1000));

    log.log(.info, "upstream_forwarded", session_id, &.{
        .{ .key = "status", .value = .{ .uint = @intFromEnum(downstream_res.head.status) } },
        .{ .key = "target_host", .value = .{ .string = target_host } },
        .{ .key = "upstream_latency_us", .value = .{ .uint = upstream_latency_us } },
    });

    // Extract Content-Type before calling .reader() because .reader() invalidates response.head strings!
    const upstream_ct = downstream_res.head.content_type;
    var ct_headers = [_]http.Header{.{ .name = "Content-Type", .value = "" }};
    var extra_headers: []const http.Header = &.{};

    if (upstream_ct) |ct| {
        ct_headers[0].value = ct;
        extra_headers = ct_headers[0..1];
    }

    var transfer_buf: [8192]u8 = undefined;
    var downstream_reader = downstream_res.reader(&transfer_buf);

    // --- Response path: unmask aliases and unhash PSEUDO_ tokens ---
    var resp_buf8: [8192]u8 = undefined;
    var response_writer = try request.respondStreaming(&resp_buf8, .{
        .respond_options = .{
            .status = downstream_res.head.status,
            .extra_headers = extra_headers,
        },
    });

    if (method.responseHasBody()) {
        // When a hasher is active, buffer the full response so we can
        // replace PSEUDO_ tokens with their originals before sending.
        const has_hasher = ctx.hasher != null;

        var unmask_state: ?entity_mask.AcChunkState = null;
        if (active_entity_map) |em| {
            unmask_state = em.initUnmaskChunkState();
        }
        defer if (unmask_state) |*s| s.deinit(allocator);

        if (has_hasher) {
            // Buffer full response for unhashing
            var resp_body = std.ArrayListUnmanaged(u8).empty;
            defer resp_body.deinit(allocator);

            var resp_buf: [8192]u8 = undefined;
            while (true) {
                const bytes_read = try downstream_reader.readSliceShort(&resp_buf);
                if (bytes_read == 0) break;

                const raw_chunk = resp_buf[0..bytes_read];

                if (active_entity_map) |em| {
                    const unmasked = try em.unmaskChunked(raw_chunk, &unmask_state.?, allocator);
                    defer allocator.free(unmasked);
                    if (unmasked.len > 0) try resp_body.appendSlice(allocator, unmasked);
                } else {
                    try resp_body.appendSlice(allocator, raw_chunk);
                }

                if (bytes_read < resp_buf.len) break;
            }

            // Flush unmask state
            if (active_entity_map) |em| {
                const flushed = try unmask_state.?.flushUnmask(em, allocator);
                defer allocator.free(flushed);
                if (flushed.len > 0) try resp_body.appendSlice(allocator, flushed);
            }

            // Unhash PSEUDO_ tokens in the buffered response
            const unhashed = try ctx.hasher.?.unhashJson(resp_body.items, allocator);
            defer allocator.free(unhashed);
            if (unhashed.len > 0) try response_writer.writer.writeAll(unhashed);
        } else {
            // No hasher — stream response directly (existing behavior)
            var resp_buf: [8192]u8 = undefined;
            while (true) {
                const bytes_read = try downstream_reader.readSliceShort(&resp_buf);
                if (bytes_read == 0) break;

                const raw_chunk = resp_buf[0..bytes_read];

                if (active_entity_map) |em| {
                    const unmasked = try em.unmaskChunked(raw_chunk, &unmask_state.?, allocator);
                    defer allocator.free(unmasked);
                    if (unmasked.len > 0) try response_writer.writer.writeAll(unmasked);
                } else {
                    try response_writer.writer.writeAll(raw_chunk);
                }

                if (bytes_read < resp_buf.len) break;
            }

            // Flush unmask state
            if (active_entity_map) |em| {
                const flushed = try unmask_state.?.flushUnmask(em, allocator);
                defer allocator.free(flushed);
                if (flushed.len > 0) try response_writer.writer.writeAll(flushed);
            }
        }
    }
    
    try response_writer.end();

    const total_latency_us: u64 = @intCast(@divTrunc(std.time.nanoTimestamp() - request_start, 1000));
    log.log(.info, "response_sent", session_id, &.{
        .{ .key = "total_latency_us", .value = .{ .uint = total_latency_us } },
    });
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
