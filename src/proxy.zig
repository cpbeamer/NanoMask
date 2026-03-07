const std = @import("std");
const http = std.http;
const redact = @import("redact.zig");
const entity_mask = @import("entity_mask.zig");
const fuzzy_match = @import("fuzzy_match.zig");

/// Maximum length for the constructed target URL (stack-allocated).
const max_url_len = 2048;

/// Find a custom header value by name (case-insensitive) using the HeaderIterator.
fn findHeader(head_buffer: []const u8, target_name: []const u8) ?[]const u8 {
    var it = http.HeaderIterator.init(head_buffer);
    while (it.next()) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, target_name)) {
            return header.value;
        }
    }
    return null;
}

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

pub fn handleRequest(
    allocator: std.mem.Allocator,
    request: *http.Server.Request,
    client: *std.http.Client,
    target_host: []const u8,
    target_port: u16,
    session_entity_map: ?*const entity_mask.EntityMap,
    session_fuzzy_matcher: ?*const fuzzy_match.FuzzyMatcher,
) !void {
    const method = request.head.method;
    const uri_str = request.head.target;

    std.debug.print("[PRX] {s} {s}\n", .{ @tagName(method), uri_str });

    // --- Determine entity map: per-request header overrides session default ---
    var per_request_map: ?entity_mask.EntityMap = null;
    defer if (per_request_map) |*m| m.deinit();

    const active_entity_map: ?*const entity_mask.EntityMap = blk: {
        // Check for X-ZPG-Entities header
        if (findHeader(request.head_buffer, "X-ZPG-Entities")) |header_val| {
            const names = parseEntityHeader(header_val, allocator) catch |err| {
                std.debug.print("[WARN] Failed to parse X-ZPG-Entities header: {}\n", .{err});
                break :blk session_entity_map;
            };
            defer allocator.free(names);

            if (names.len > 0) {
                per_request_map = entity_mask.EntityMap.init(allocator, names) catch |err| {
                    std.debug.print("[WARN] Failed to build entity map from header: {}\n", .{err});
                    break :blk session_entity_map;
                };
                break :blk &per_request_map.?;
            }
        }
        break :blk session_entity_map;
    };

    // --- Forward request to upstream ---
    var url_buf: [max_url_len]u8 = undefined;
    const target_url_str = try std.fmt.bufPrint(&url_buf, "http://{s}:{d}{s}", .{ target_host, target_port, uri_str });
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
        std.debug.print("client.request failed: {}\n", .{e});
        return e;
    };
    defer client_req.deinit();
    client_req.transfer_encoding = if (has_body) .chunked else .none;

    // --- Request path: apply privacy pipeline to outbound body ---
    if (has_body) {
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
        if (request.readerExpectContinue(&body_read_buf)) |body_reader| {
            var raw_chunk_buf: [8192]u8 = undefined;
            while (true) {
                const bytes_read = try body_reader.readSliceShort(&raw_chunk_buf);
                if (bytes_read == 0) break;
                
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

                if (session_fuzzy_matcher) |fm| {
                    const em_aliases = if (active_entity_map) |em| em.getAliases() else &.{};
                    if (ssn_res.finalized.len > 0) {
                        const f1 = try fm.fuzzyRedactChunked(ssn_res.finalized, &fuzzy_state.?, em_aliases, &.{}, allocator);
                        defer allocator.free(f1);
                        if (f1.len > 0) try req_body.writer.writeAll(f1);
                    }
                    if (ssn_res.emitted.len > 0) {
                        const f2 = try fm.fuzzyRedactChunked(ssn_res.emitted, &fuzzy_state.?, em_aliases, &.{}, allocator);
                        defer allocator.free(f2);
                        if (f2.len > 0) try req_body.writer.writeAll(f2);
                    }
                } else {
                    if (ssn_res.finalized.len > 0) try req_body.writer.writeAll(ssn_res.finalized);
                    if (ssn_res.emitted.len > 0) try req_body.writer.writeAll(ssn_res.emitted);
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
                if (ssn_final_emissions.items.len > 0) {
                    const f_res = try fm.fuzzyRedactChunked(ssn_final_emissions.items, &fuzzy_state.?, em_aliases, &.{}, allocator);
                    defer allocator.free(f_res);
                    if (f_res.len > 0) try req_body.writer.writeAll(f_res);
                }
                const fuzzy_flushed = try fuzzy_state.?.flush(fm, em_aliases, &.{}, allocator);
                defer allocator.free(fuzzy_flushed);
                if (fuzzy_flushed.len > 0) try req_body.writer.writeAll(fuzzy_flushed);
            } else {
                if (ssn_final_emissions.items.len > 0) {
                    try req_body.writer.writeAll(ssn_final_emissions.items);
                }
            }
        } else |err| {
            std.debug.print("[WARN] Failed to read request body: {}\n", .{err});
        }
        
        try req_body.end();
        if (client_req.connection) |conn| {
            try conn.flush();
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

    std.debug.print("[PRX] <- {d}\n", .{@intFromEnum(downstream_res.head.status)});

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

    // --- Response path: unmask aliases back to real names ---
    var resp_buf8: [8192]u8 = undefined;
    var response_writer = try request.respondStreaming(&resp_buf8, .{
        .respond_options = .{
            .status = downstream_res.head.status,
            .extra_headers = extra_headers,
        },
    });

    if (method.responseHasBody()) {
        var unmask_state: ?entity_mask.AcChunkState = null;
        if (active_entity_map) |em| {
            unmask_state = em.initUnmaskChunkState();
        }
        defer if (unmask_state) |*s| s.deinit(allocator);

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
    
    try response_writer.end();
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
