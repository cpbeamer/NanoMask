const std = @import("std");
const schema_mod = @import("../schema/schema.zig");

// ---------------------------------------------------------------------------
// Fuzz target: schema definition parser
// ---------------------------------------------------------------------------
// Schema.parseContent processes user-supplied schema files in a simple
// key=value line format. While simpler than JSON, it still parses untrusted
// input and must handle adversarial content without panics or UB.
// ---------------------------------------------------------------------------

test "fuzz - schema parser does not panic on arbitrary input" {
    try std.testing.fuzz(.{}, .{}, struct {
        fn run(_: void, input: []const u8) !void {
            const allocator = std.testing.allocator;

            if (schema_mod.Schema.parseContent(input, allocator)) |*result| {
                var s = result.*;
                s.deinit();
            } else |_| {
                // Expected: most random inputs produce parse errors.
            }
        }
    }.run);
}

test "fuzz - schema parser handles edge cases without panic" {
    const allocator = std.testing.allocator;

    const cases = [_][]const u8{
        // Empty and minimal
        "",
        "\n",
        "\r\n",
        "# comment only",
        // Valid minimal
        "field = REDACT",
        "field = KEEP",
        "field = SCAN",
        "field = HASH",
        // Metadata
        "schema.name = test\nschema.version = 1.0\nschema.default = KEEP",
        // Invalid action
        "field = INVALID_ACTION",
        // Missing separator
        "field REDACT",
        "no_equals_sign",
        // Empty key
        " = REDACT",
        // Very long key
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa = REDACT",
        // Very long value (not a valid action, should error)
        "field = REDACTREDACTREDACTREDACTREDACTREDACTREDACTREDACTREDACTREDACT",
        // Binary content
        "\x00\x01\x02\x03 = REDACT",
        // Many fields
        "a=REDACT\nb=KEEP\nc=SCAN\nd=HASH\ne=REDACT\nf=KEEP\ng=SCAN\nh=HASH",
        // Duplicate keys
        "field = REDACT\nfield = KEEP",
        // Equals in value
        "field = REDACT = KEEP",
        // Tabs
        "\tfield\t=\tREDACT\t",
        // Mixed line endings
        "a = REDACT\r\nb = KEEP\nc = SCAN\r\n",
    };

    for (cases) |input| {
        if (schema_mod.Schema.parseContent(input, allocator)) |*result| {
            var s = result.*;
            s.deinit();
        } else |_| {}
    }
}
