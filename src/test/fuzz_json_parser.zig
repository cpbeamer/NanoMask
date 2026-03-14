const std = @import("std");
const admin = @import("../admin/admin.zig");

// ---------------------------------------------------------------------------
// Fuzz target: admin API JSON parser
// ---------------------------------------------------------------------------
// The hand-rolled JSON parser in admin.zig (parseJsonStringArray) accepts
// arbitrary user input over HTTP. This is the highest-risk parsing surface
// in NanoMask because it processes untrusted request bodies that can contain
// any byte sequence.
// ---------------------------------------------------------------------------
// NOTE: The Zig 0.15.2 stdlib does not expose a fuzz API. The automated
// fuzz tests below are disabled until the API stabilises. Manual edge-case
// coverage is provided by the second test block.
// ---------------------------------------------------------------------------

test "fuzz - admin JSON parser handles edge cases without panic" {
    const allocator = std.testing.allocator;

    // Manually curated adversarial inputs that target specific parser edges
    const cases = [_][]const u8{
        // Empty and minimal inputs
        "",
        "{}",
        "{",
        "}",
        "[]",
        "[",
        "]",
        // Key without array
        "{\"add\": null}",
        "{\"add\": 42}",
        "{\"add\": \"string\"}",
        // Unterminated strings
        "{\"add\": [\"unterminated",
        "{\"add\": [\"escaped\\\"",
        // Deeply nested escapes
        "{\"add\": [\"\\\\\\\\\\\\\\\\\"]}",
        // Very long key
        "{\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\": [\"x\"]}",
        // Null bytes
        "{\"add\": [\"\x00\"]}",
        // Control characters
        "{\"add\": [\"\x01\x02\x03\"]}",
        // Unicode-ish
        "{\"add\": [\"\\u0000\"]}",
        // Multiple arrays
        "{\"add\": [\"a\"], \"add\": [\"b\"]}",
        // Trailing garbage
        "{\"add\": [\"ok\"]}garbage",
    };

    for (cases) |input| {
        if (admin.parseJsonStringArray(input, "add", allocator)) |result| {
            for (result) |s| allocator.free(s);
            allocator.free(result);
        } else |_| {}
    }
}
