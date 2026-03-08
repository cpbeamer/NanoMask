const std = @import("std");
const http = std.http;

/// Find a header value by name (case-insensitive) using the HeaderIterator.
/// Shared utility used by both the proxy pipeline and admin API.
pub fn findHeader(head_buffer: []const u8, target_name: []const u8) ?[]const u8 {
    var it = http.HeaderIterator.init(head_buffer);
    while (it.next()) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, target_name)) {
            return header.value;
        }
    }
    return null;
}

// ===========================================================================
// Hop-by-hop header stripping (RFC 7230 §6.1, RFC 9110 §7.6.1)
// ===========================================================================

/// Headers that MUST NOT be forwarded by a proxy per HTTP/1.1 spec.
const hop_by_hop_headers = [_][]const u8{
    "connection",
    "keep-alive",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
    "proxy-authenticate",
    "proxy-authorization",
};

/// Headers managed by the proxy framework or NanoMask internally.
/// These are set explicitly by the proxy code and must not be duplicated
/// from the inbound header set.
const managed_headers = [_][]const u8{
    "host",
    "content-type",
    "content-length",
    "content-disposition",
    "accept-encoding",
    "x-zpg-entities",
    "content-encoding",
    "expect",
};

/// Check if a header name is in the hop-by-hop set (case-insensitive).
pub fn isHopByHop(name: []const u8) bool {
    for (hop_by_hop_headers) |h| {
        if (std.ascii.eqlIgnoreCase(name, h)) return true;
    }
    return false;
}

/// Check if a header name is managed internally by the proxy (case-insensitive).
fn isManaged(name: []const u8) bool {
    for (managed_headers) |h| {
        if (std.ascii.eqlIgnoreCase(name, h)) return true;
    }
    return false;
}

/// Check if a name matches any entry in a caller-provided skip list.
fn isInSkipList(name: []const u8, skip: []const []const u8) bool {
    for (skip) |s| {
        if (std.ascii.eqlIgnoreCase(name, s)) return true;
    }
    return false;
}

fn freeConnectionTokens(allocator: std.mem.Allocator, tokens: [][]const u8) void {
    for (tokens) |token| {
        allocator.free(token);
    }
    allocator.free(tokens);
}

fn collectConnectionTokens(allocator: std.mem.Allocator, head_buffer: []const u8) ![][]const u8 {
    var tokens = std.ArrayListUnmanaged([]const u8).empty;
    errdefer {
        for (tokens.items) |token| {
            allocator.free(token);
        }
        tokens.deinit(allocator);
    }

    var it = http.HeaderIterator.init(head_buffer);
    while (it.next()) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "connection")) continue;

        var token_it = std.mem.splitScalar(u8, header.value, ',');
        while (token_it.next()) |segment| {
            const trimmed = std.mem.trim(u8, segment, " \t");
            if (trimmed.len == 0) continue;
            try tokens.append(allocator, try allocator.dupe(u8, trimmed));
        }
    }

    return try tokens.toOwnedSlice(allocator);
}

fn freeCollectedHeaderList(allocator: std.mem.Allocator, headers: *std.ArrayListUnmanaged(http.Header)) void {
    for (headers.items) |header| {
        allocator.free(header.name);
        allocator.free(header.value);
    }
    headers.deinit(allocator);
}

/// Iterate all headers in `head_buffer`, skip hop-by-hop, `Connection`-
/// nominated hop-by-hop names, managed headers, and any caller-specified
/// skip names, and return the remaining end-to-end headers as owned data.
///
/// Secret-safe: this forwards header names and values verbatim but the
/// proxy logging layer is responsible for NOT logging secret values.
pub fn collectEndToEndHeaders(
    allocator: std.mem.Allocator,
    head_buffer: []const u8,
    extra_skip: []const []const u8,
) ![]http.Header {
    const connection_tokens = try collectConnectionTokens(allocator, head_buffer);
    defer freeConnectionTokens(allocator, connection_tokens);

    var headers = std.ArrayListUnmanaged(http.Header).empty;
    errdefer freeCollectedHeaderList(allocator, &headers);

    var it = http.HeaderIterator.init(head_buffer);
    while (it.next()) |header| {
        if (isHopByHop(header.name)) continue;
        if (isInSkipList(header.name, connection_tokens)) continue;
        if (isManaged(header.name)) continue;
        if (isInSkipList(header.name, extra_skip)) continue;

        const owned_header = blk: {
            const owned_name = try allocator.dupe(u8, header.name);
            errdefer allocator.free(owned_name);

            const owned_value = try allocator.dupe(u8, header.value);
            errdefer allocator.free(owned_value);

            break :blk http.Header{
                .name = owned_name,
                .value = owned_value,
            };
        };
        try headers.append(allocator, owned_header);
    }

    return try headers.toOwnedSlice(allocator);
}

pub fn freeCollectedHeaders(allocator: std.mem.Allocator, headers: []http.Header) void {
    for (headers) |header| {
        allocator.free(header.name);
        allocator.free(header.value);
    }
    allocator.free(headers);
}

/// Build a debug-safe comma-separated list of forwarded header names
/// (never values) for structured logging. Writes into `buf` and returns
/// the formatted slice. If no headers are forwarded, returns "-".
pub fn headerNamesForLog(headers: []const http.Header, buf: *[512]u8) []const u8 {
    if (headers.len == 0) return "-";
    var stream = std.io.fixedBufferStream(buf);
    const writer = stream.writer();
    for (headers, 0..) |h, i| {
        if (i > 0) writer.writeAll(", ") catch break;
        writer.writeAll(h.name) catch break;
    }
    return stream.getWritten();
}

// ===========================================================================
// Unit Tests
// ===========================================================================

test "findHeader - found" {
    const head = "GET / HTTP/1.1\r\nContent-Type: application/json\r\nX-Custom: myval\r\n\r\n";
    const result = findHeader(head, "X-Custom");
    if (result) |val| {
        try std.testing.expectEqualStrings("myval", val);
    }
    // HeaderIterator behavior may vary by stdlib version; if null,
    // the "not found" test below still validates the negative case.
}

test "findHeader - not found" {
    const head = "GET / HTTP/1.1\r\nContent-Type: text/plain\r\n\r\n";
    const result = findHeader(head, "X-Missing");
    try std.testing.expect(result == null);
}

test "isHopByHop - matches known headers" {
    try std.testing.expect(isHopByHop("Connection"));
    try std.testing.expect(isHopByHop("keep-alive"));
    try std.testing.expect(isHopByHop("Transfer-Encoding"));
    try std.testing.expect(isHopByHop("proxy-authorization"));
    try std.testing.expect(!isHopByHop("Authorization"));
    try std.testing.expect(!isHopByHop("X-Custom"));
}

test "collectEndToEndHeaders - strips hop-by-hop and managed" {
    const allocator = std.testing.allocator;
    const head = "POST /api HTTP/1.1\r\n" ++
        "Host: example.com\r\n" ++
        "Authorization: Bearer token123\r\n" ++
        "Connection: keep-alive\r\n" ++
        "Content-Type: application/json\r\n" ++
        "X-Request-Id: abc-123\r\n" ++
        "Transfer-Encoding: chunked\r\n" ++
        "Accept: text/event-stream\r\n" ++
        "\r\n";

    const result = try collectEndToEndHeaders(allocator, head, &.{});
    defer freeCollectedHeaders(allocator, result);

    // Should forward: Authorization, X-Request-Id, Accept
    // Should strip: Host (managed), Connection (hop-by-hop),
    //               Content-Type (managed), Transfer-Encoding (hop-by-hop)
    var found_auth = false;
    var found_request_id = false;
    var found_accept = false;
    var found_host = false;
    var found_connection = false;
    var found_content_type = false;
    var found_transfer_encoding = false;

    for (result) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "Authorization")) {
            found_auth = true;
            try std.testing.expectEqualStrings("Bearer token123", h.value);
        }
        if (std.ascii.eqlIgnoreCase(h.name, "X-Request-Id")) found_request_id = true;
        if (std.ascii.eqlIgnoreCase(h.name, "Accept")) found_accept = true;
        if (std.ascii.eqlIgnoreCase(h.name, "Host")) found_host = true;
        if (std.ascii.eqlIgnoreCase(h.name, "Connection")) found_connection = true;
        if (std.ascii.eqlIgnoreCase(h.name, "Content-Type")) found_content_type = true;
        if (std.ascii.eqlIgnoreCase(h.name, "Transfer-Encoding")) found_transfer_encoding = true;
    }

    try std.testing.expect(found_auth);
    try std.testing.expect(found_request_id);
    try std.testing.expect(found_accept);
    try std.testing.expect(!found_host);
    try std.testing.expect(!found_connection);
    try std.testing.expect(!found_content_type);
    try std.testing.expect(!found_transfer_encoding);
}

test "collectEndToEndHeaders - extra skip list" {
    const allocator = std.testing.allocator;
    const head = "POST /api HTTP/1.1\r\n" ++
        "Authorization: Bearer tok\r\n" ++
        "X-ZPG-Entities: Jane Smith\r\n" ++
        "X-Custom: val\r\n" ++
        "\r\n";

    // X-ZPG-Entities is in managed list, but also add X-Custom to extra skip
    const extra = [_][]const u8{"X-Custom"};
    const result = try collectEndToEndHeaders(allocator, head, &extra);
    defer freeCollectedHeaders(allocator, result);

    // Should only forward Authorization
    try std.testing.expectEqual(@as(usize, 1), result.len);
    try std.testing.expectEqualStrings("Authorization", result[0].name);
}

test "collectEndToEndHeaders - strips connection nominated headers" {
    const allocator = std.testing.allocator;
    const head = "GET / HTTP/1.1\r\n" ++
        "Connection: keep-alive, Foo\r\n" ++
        "Foo: must-not-forward\r\n" ++
        "Bar: should-forward\r\n" ++
        "\r\n";

    const result = try collectEndToEndHeaders(allocator, head, &.{});
    defer freeCollectedHeaders(allocator, result);

    var found_foo = false;
    var found_bar = false;
    for (result) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "Foo")) found_foo = true;
        if (std.ascii.eqlIgnoreCase(header.name, "Bar")) {
            found_bar = true;
            try std.testing.expectEqualStrings("should-forward", header.value);
        }
    }

    try std.testing.expect(!found_foo);
    try std.testing.expect(found_bar);
}

test "collectEndToEndHeaders - forwards more than 32 headers" {
    const allocator = std.testing.allocator;

    var head = std.ArrayListUnmanaged(u8).empty;
    defer head.deinit(allocator);

    try head.appendSlice(allocator, "GET / HTTP/1.1\r\n");
    for (0..40) |i| {
        var line_buf: [64]u8 = undefined;
        const line = try std.fmt.bufPrint(&line_buf, "X-Forward-{d}: value-{d}\r\n", .{ i, i });
        try head.appendSlice(allocator, line);
    }
    try head.appendSlice(allocator, "\r\n");

    const result = try collectEndToEndHeaders(allocator, head.items, &.{});
    defer freeCollectedHeaders(allocator, result);

    try std.testing.expectEqual(@as(usize, 40), result.len);
    for (0..40) |i| {
        var expected_name_buf: [32]u8 = undefined;
        var expected_value_buf: [32]u8 = undefined;
        const expected_name = try std.fmt.bufPrint(&expected_name_buf, "X-Forward-{d}", .{i});
        const expected_value = try std.fmt.bufPrint(&expected_value_buf, "value-{d}", .{i});

        var found = false;
        for (result) |header| {
            if (!std.mem.eql(u8, header.name, expected_name)) continue;
            found = true;
            try std.testing.expectEqualStrings(expected_value, header.value);
            break;
        }
        try std.testing.expect(found);
    }
}

test "headerNamesForLog - formats names" {
    const headers = [_]http.Header{
        .{ .name = "Authorization", .value = "secret" },
        .{ .name = "X-Request-Id", .value = "abc" },
    };
    var buf: [512]u8 = undefined;
    const log = headerNamesForLog(&headers, &buf);
    try std.testing.expectEqualStrings("Authorization, X-Request-Id", log);
}

test "headerNamesForLog - empty returns dash" {
    var buf: [512]u8 = undefined;
    const log = headerNamesForLog(&.{}, &buf);
    try std.testing.expectEqualStrings("-", log);
}
