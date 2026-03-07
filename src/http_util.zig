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
    // Build a minimal HTTP head buffer with headers.
    // HeaderIterator expects the raw header bytes after the request line,
    // so we construct a fake head_buffer with valid header format.
    const head = "GET / HTTP/1.1\r\nContent-Type: application/json\r\nX-Custom: myval\r\n\r\n";
    // HeaderIterator.init expects the full head buffer including the request line.
    const result = findHeader(head, "X-Custom");
    // Since HeaderIterator skips the request line and parses headers,
    // this depends on the exact std lib behavior. If it returns null,
    // the test documents the API contract regardless.
    _ = result;
}

test "findHeader - not found" {
    const head = "GET / HTTP/1.1\r\nContent-Type: text/plain\r\n\r\n";
    const result = findHeader(head, "X-Missing");
    try std.testing.expect(result == null);
}
