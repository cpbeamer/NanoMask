const std = @import("std");
const redact = @import("../redaction/redact.zig");
const scanner = @import("../patterns/scanner.zig");

// ---------------------------------------------------------------------------
// Fuzz target: redaction engines
// ---------------------------------------------------------------------------
// Tests the SSN SIMD redactor and unified pattern scanner against arbitrary
// byte sequences. These engines operate on untrusted HTTP body content and
// must never panic or exhibit undefined behavior regardless of input.
// ---------------------------------------------------------------------------
// NOTE: The Zig 0.15.2 stdlib does not expose a fuzz API. The automated
// fuzz tests are disabled until the API stabilises. Manual edge-case
// coverage is provided by the test block below.
// ---------------------------------------------------------------------------

test "fuzz - redaction engines handle edge cases" {
    const allocator = std.testing.allocator;

    const cases = [_][]const u8{
        // Empty
        "",
        // Single byte
        "-",
        "0",
        "*",
        // Minimum SSN length
        "000-00-0000",
        // Almost-SSN patterns
        "000-00-000",
        "000-0-00000",
        "00-000-0000",
        // All dashes (SIMD dash mask stress test)
        "----------------",
        "--------------------------------",
        // All digits
        "00000000000",
        "0000000000000000000000000000000000000000",
        // SSN at every alignment
        "123-45-6789",
        " 123-45-6789",
        "  123-45-6789",
        "   123-45-6789",
        // Multiple SSNs packed tight
        "111-22-3333444-55-6666777-88-9999",
        // SSN surrounded by dashes
        "---123-45-6789---",
        // Null bytes around SSN
        "\x00123-45-6789\x00",
        // High bytes
        "\xff\xff\xff123-45-6789\xff\xff\xff",
        // Very long (stress SIMD loop count)
        "a" ** 1024,
    };

    for (cases) |input| {
        const buf = try allocator.dupe(u8, input);
        defer allocator.free(buf);
        redact.redactSsn(buf);

        const matches = try redact.collectSsnMatches(input, allocator);
        allocator.free(matches);

        const flags = scanner.PatternFlags{ .email = true, .phone = true, .credit_card = true, .ip = true, .healthcare = true };
        const result = try scanner.redact(input, flags, allocator);
        allocator.free(result);
    }
}
