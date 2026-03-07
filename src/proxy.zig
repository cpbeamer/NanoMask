const std = @import("std");
const http = std.http;
const redact = @import("redact.zig");
const entity_mask = @import("entity_mask.zig");

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

    // --- Read incoming request body (if present) ---
    var req_body: std.ArrayListUnmanaged(u8) = .empty;
    defer req_body.deinit(allocator);

    const has_body = method.requestHasBody();
    if (has_body) {
        var body_read_buf: [8192]u8 = undefined;
        if (request.readerExpectContinue(&body_read_buf)) |body_reader| {
            try body_reader.appendRemainingUnlimited(allocator, &req_body);
        } else |err| {
            std.debug.print("[WARN] Failed to read request body: {}\n", .{err});
        }
    }

    // --- Request path: apply privacy pipeline to outbound body ---
    // sanitized_body is always a mutable owned allocation so that
    // sendBodyComplete (which requires []u8) can use it directly
    // without @constCast.
    var sanitized_body: ?[]u8 = null;
    defer if (sanitized_body) |sb| allocator.free(sb);

    if (req_body.items.len > 0) {
        // 1. Entity mask: names -> aliases
        if (active_entity_map) |em| {
            const masked = try em.mask(req_body.items, allocator);
            // 2. SSN redact: digits -> * (in-place on the masked buffer)
            redact.redactSsn(masked);
            sanitized_body = masked;
        } else {
            // No entity map — SSN redact in-place on a mutable copy
            const duped = try allocator.dupe(u8, req_body.items);
            redact.redactSsn(duped);
            sanitized_body = duped;
        }
    }

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

    var client_req = try client.request(method, target_uri, .{
        .headers = .{ .content_type = content_type_override },
    });
    defer client_req.deinit();

    if (has_body and sanitized_body != null) {
        // Send with body — sendBodyComplete sets content-length and flushes.
        // sanitized_body is always a mutable owned []u8, satisfying the API.
        try client_req.sendBodyComplete(sanitized_body.?);
    } else {
        // Bodiless request (GET, DELETE, etc.)
        try client_req.sendBodilessUnflushed();
        if (client_req.connection) |conn| {
            try conn.flush();
        }
    }

    // --- Read upstream response ---
    var redirect_buffer: [4096]u8 = undefined;
    var downstream_res = try client_req.receiveHead(&redirect_buffer);

    var transfer_buf: [8192]u8 = undefined;
    var downstream_reader = downstream_res.reader(&transfer_buf);

    var resp_body: std.ArrayListUnmanaged(u8) = .empty;
    defer resp_body.deinit(allocator);
    try downstream_reader.appendRemainingUnlimited(allocator, &resp_body);

    // --- Response path: unmask aliases back to real names ---
    var final_response: []const u8 = resp_body.items;
    var unmasked_buf: ?[]u8 = null;
    defer if (unmasked_buf) |ub| allocator.free(ub);

    if (active_entity_map) |em| {
        if (resp_body.items.len > 0) {
            unmasked_buf = try em.unmask(resp_body.items, allocator);
            final_response = unmasked_buf.?;
        }
    }

    std.debug.print("[PRX] <- {d} ({} bytes)\n", .{
        @intFromEnum(downstream_res.head.status),
        final_response.len,
    });

    // Forward upstream Content-Type so the client receives the correct media type.
    const upstream_ct = downstream_res.head.content_type;
    var ct_headers = [_]http.Header{.{ .name = "Content-Type", .value = "" }};

    if (upstream_ct != .default) {
        ct_headers[0].value = switch (upstream_ct) {
            .override => |v| v,
            .default => "",
        };
        try request.respond(final_response, .{
            .status = downstream_res.head.status,
            .extra_headers = &ct_headers,
        });
    } else {
        try request.respond(final_response, .{
            .status = downstream_res.head.status,
        });
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
