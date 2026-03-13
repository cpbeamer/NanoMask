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

test "fuzz - SSN redactor does not panic on arbitrary input" {
    try std.testing.fuzz(.{}, .{}, struct {
        fn run(_: void, input: []const u8) !void {
            const allocator = std.testing.allocator;

            // Copy input since redactSsn mutates in-place
            const buf = try allocator.dupe(u8, input);
            defer allocator.free(buf);
            redact.redactSsn(buf);

            // Also test scalar path for consistency
            const buf2 = try allocator.dupe(u8, input);
            defer allocator.free(buf2);
            redact.redactSsnScalar(buf2);

            // Verify SIMD and scalar produce identical results
            try std.testing.expectEqualStrings(buf2, buf);
        }
    }.run);
}

test "fuzz - chunked SSN redactor matches single-pass" {
    try std.testing.fuzz(.{}, .{}, struct {
        fn run(_: void, input: []const u8) !void {
            const allocator = std.testing.allocator;
            if (input.len == 0) return;

            // Single-pass reference
            const single_buf = try allocator.dupe(u8, input);
            defer allocator.free(single_buf);
            redact.redactSsn(single_buf);

            // Chunked: use first byte as chunk size (1-256)
            const chunk_size: usize = @as(usize, input[0]) + 1;
            const chunk_input = try allocator.dupe(u8, input);
            defer allocator.free(chunk_input);

            var output: std.ArrayListUnmanaged(u8) = .empty;
            defer output.deinit(allocator);

            var state = redact.SsnChunkState{};
            var offset: usize = 0;
            while (offset < chunk_input.len) {
                const end = @min(offset + chunk_size, chunk_input.len);
                const result = redact.redactSsnChunked(chunk_input[offset..end], &state);
                try output.appendSlice(allocator, result.finalized);
                try output.appendSlice(allocator, result.emitted);
                offset = end;
            }
            try output.appendSlice(allocator, state.flush());

            try std.testing.expectEqualStrings(single_buf, output.items);
        }
    }.run);
}

test "fuzz - pattern scanner does not panic on arbitrary input" {
    try std.testing.fuzz(.{}, .{}, struct {
        fn run(_: void, input: []const u8) !void {
            const allocator = std.testing.allocator;

            // Enable all patterns — maximum attack surface
            const flags = scanner.PatternFlags{
                .email = true,
                .phone = true,
                .credit_card = true,
                .ip = true,
                .healthcare = true,
            };

            const result = try scanner.redact(input, flags, allocator);
            allocator.free(result);
        }
    }.run);
}

test "fuzz - SSN match collection does not panic" {
    try std.testing.fuzz(.{}, .{}, struct {
        fn run(_: void, input: []const u8) !void {
            const allocator = std.testing.allocator;
            const matches = try redact.collectSsnMatches(input, allocator);
            allocator.free(matches);
        }
    }.run);
}

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
