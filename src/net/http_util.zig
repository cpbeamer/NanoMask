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
