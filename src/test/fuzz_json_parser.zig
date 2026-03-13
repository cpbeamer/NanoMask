const std = @import("std");
const admin = @import("../admin/admin.zig");

// ---------------------------------------------------------------------------
// Fuzz target: admin API JSON parser
// ---------------------------------------------------------------------------
// The hand-rolled JSON parser in admin.zig (parseJsonStringArray) accepts
// arbitrary user input over HTTP. This is the highest-risk parsing surface
// in NanoMask because it processes untrusted request bodies that can contain
// any byte sequence. This fuzz target ensures no panics, hangs, or undefined
// behavior on adversarial inputs.
// ---------------------------------------------------------------------------

test "fuzz - admin JSON parser does not panic on arbitrary input" {
    // Zig 0.15's built-in fuzz testing: the framework generates random
    // byte sequences and calls this function. Any panic, safety check
    // failure, or undefined behavior is flagged as a finding.
    try std.testing.fuzz(.{}, .{}, struct {
        fn run(_: void, input: []const u8) !void {
            const allocator = std.testing.allocator;

            // Fuzz parseJsonStringArray with the "add" key (POST endpoint)
            if (admin.parseJsonStringArray(input, "add", allocator)) |result| {
                for (result) |s| allocator.free(s);
                allocator.free(result);
            } else |_| {
                // Expected: most random inputs will produce errors.
                // The important thing is that no input causes a panic.
            }

            // Fuzz with the "remove" key (DELETE endpoint)
            if (admin.parseJsonStringArray(input, "remove", allocator)) |result| {
                for (result) |s| allocator.free(s);
                allocator.free(result);
            } else |_| {}

            // Fuzz with the "entities" key (PUT endpoint)
            if (admin.parseJsonStringArray(input, "entities", allocator)) |result| {
                for (result) |s| allocator.free(s);
                allocator.free(result);
            } else |_| {}
        }
    }.run);
}

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
