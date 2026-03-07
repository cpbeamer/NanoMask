const std = @import("std");

// ---------------------------------------------------------------------------
// SIMD-accelerated SSN redaction engine
// ---------------------------------------------------------------------------
// Strategy: scan for '-' characters first (rare in typical payloads) using
// @Vector(16, u8) SIMD loads, then validate the full XXX-XX-XXXX digit
// pattern only at candidate positions. This avoids touching most bytes.
// ---------------------------------------------------------------------------

const vector_len = 16;
const Vector = @Vector(vector_len, u8);

/// Produce a bitmask where bit `i` is set if `vec[i] == needle`.
inline fn dashMask(vec: Vector) u16 {
    const dashes: Vector = @splat('-');
    const match_result: @Vector(vector_len, u1) = @bitCast(vec == dashes);
    return @bitCast(match_result);
}

/// Validate and redact a full SSN at `buf[start .. start+11]`.
/// Returns true (and mutates in-place) if the pattern matches XXX-XX-XXXX.
inline fn tryRedactAt(buf: []u8, start: usize) bool {
    if (start + 11 > buf.len) return false;

    const b = buf[start..][0..11];

    // Dashes at fixed offsets
    if (b[3] != '-' or b[6] != '-') return false;

    // All other positions must be ASCII digits
    inline for ([_]usize{ 0, 1, 2, 4, 5, 7, 8, 9, 10 }) |off| {
        if (!std.ascii.isDigit(b[off])) return false;
    }

    // Pattern confirmed — redact digits in-place
    inline for ([_]usize{ 0, 1, 2, 4, 5, 7, 8, 9, 10 }) |off| {
        b[off] = '*';
    }
    return true;
}

/// High-performance SSN redactor using SIMD dash scanning.
/// Falls back to scalar tail processing for the last < 16 bytes.
pub fn redactSsn(buffer: []u8) void {
    if (buffer.len < 11) return;

    var i: usize = 0;

    // --- SIMD pass: scan 16 bytes at a time for '-' candidates -----------
    while (i + vector_len + 10 <= buffer.len) {
        // We need dashes at relative offsets +3 and +6 from any SSN start.
        // A dash found at absolute position `d` could be offset +3 of an SSN
        // starting at `d - 3`, OR offset +6 of one starting at `d - 6`.
        const chunk: Vector = buffer[i..][0..vector_len].*;
        var mask = dashMask(chunk);

        if (mask == 0) {
            // No dashes in this 16-byte window — skip entirely.
            i += vector_len;
            continue;
        }

        // Process each dash position in the mask
        while (mask != 0) {
            const bit_pos: u4 = @truncate(@ctz(mask));
            const dash_abs = i + bit_pos;

            // This dash could be at SSN offset +3 → start = dash_abs - 3
            if (dash_abs >= 3) {
                const start = dash_abs - 3;
                if (tryRedactAt(buffer, start)) {
                    // Successfully redacted — jump past this SSN entirely.
                    // Set i to end of SSN so outer loop re-scans from there.
                    i = start + 11;
                    // Re-enter outer loop (mask is now stale).
                    break;
                }
            }

            // Clear this bit and move to next dash
            mask &= mask - 1;
        } else {
            // Exhausted all dashes in this chunk with no redaction — advance.
            i += 1;
        }
    }

    // --- Scalar tail: handle remaining bytes that don't fill a vector -----
    while (i + 11 <= buffer.len) {
        if (tryRedactAt(buffer, i)) {
            i += 11;
        } else {
            i += 1;
        }
    }
}

/// Scalar-only reference implementation (kept for benchmarking comparisons).
pub fn redactSsnScalar(buffer: []u8) void {
    var i: usize = 0;
    while (i + 11 <= buffer.len) {
        if (std.ascii.isDigit(buffer[i]) and std.ascii.isDigit(buffer[i + 1]) and std.ascii.isDigit(buffer[i + 2]) and
            buffer[i + 3] == '-' and
            std.ascii.isDigit(buffer[i + 4]) and std.ascii.isDigit(buffer[i + 5]) and
            buffer[i + 6] == '-' and
            std.ascii.isDigit(buffer[i + 7]) and std.ascii.isDigit(buffer[i + 8]) and std.ascii.isDigit(buffer[i + 9]) and std.ascii.isDigit(buffer[i + 10]))
        {
            buffer[i] = '*';
            buffer[i + 1] = '*';
            buffer[i + 2] = '*';
            buffer[i + 4] = '*';
            buffer[i + 5] = '*';
            buffer[i + 7] = '*';
            buffer[i + 8] = '*';
            buffer[i + 9] = '*';
            buffer[i + 10] = '*';
            i += 11;
        } else {
            i += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

test "redactSsn - basic multi-SSN redaction" {
    var buf = "Hello my SSN is 123-45-6789 and my friend is 987-65-4321!".*;
    redactSsn(&buf);
    try std.testing.expectEqualStrings("Hello my SSN is ***-**-**** and my friend is ***-**-****!", &buf);
}

test "redactSsn - no SSNs present" {
    var buf = "This string has no sensitive data at all.".*;
    const expected = "This string has no sensitive data at all.";
    redactSsn(&buf);
    try std.testing.expectEqualStrings(expected, &buf);
}

test "redactSsn - SSN at start of buffer" {
    var buf = "123-45-6789 is at the start".*;
    redactSsn(&buf);
    try std.testing.expectEqualStrings("***-**-**** is at the start", &buf);
}

test "redactSsn - SSN at end of buffer" {
    var buf = "SSN at end: 123-45-6789".*;
    redactSsn(&buf);
    try std.testing.expectEqualStrings("SSN at end: ***-**-****", &buf);
}

test "redactSsn - adjacent SSNs no separator" {
    var buf = "111-22-3333444-55-6666".*;
    redactSsn(&buf);
    try std.testing.expectEqualStrings("***-**-*******-**-****", &buf);
}

test "redactSsn - partial pattern is not redacted" {
    // Only 2 leading digits instead of 3 -- should NOT match.
    var buf = "12-34-5678 is not an SSN".*;
    const expected = "12-34-5678 is not an SSN";
    redactSsn(&buf);
    try std.testing.expectEqualStrings(expected, &buf);
}

test "redactSsn - empty buffer" {
    var buf: [0]u8 = .{};
    redactSsn(&buf); // must not panic
    try std.testing.expectEqual(@as(usize, 0), buf.len);
}

test "redactSsn - SSN with surrounding digits" {
    // "9123-45-67890" = 13 chars.
    // At i=0: buf[3]='3' (not '-'), no match.
    // At i=1: "123-45-6789" matches, gets redacted. i advances to 12.
    // Result: "9***-**-****0"
    var buf = "9123-45-67890".*;
    redactSsn(&buf);
    try std.testing.expectEqualStrings("9***-**-****0", &buf);
}

test "redactSsn - scalar fallback matches SIMD" {
    // Verify both implementations produce identical results on the same input.
    const input = "prefix 111-22-3333 mid 444-55-6666 end 777-88-9999 tail".*;
    var simd_buf = input;
    var scalar_buf = input;
    redactSsn(&simd_buf);
    redactSsnScalar(&scalar_buf);
    try std.testing.expectEqualStrings(&scalar_buf, &simd_buf);
}

test "redactSsn - large buffer with scattered SSNs" {
    // 80-byte buffer with SSNs at various offsets to exercise SIMD chunking.
    var buf = "aaaaaaaaaa123-45-6789bbbbbbbbbb987-65-4321cccccccccc555-12-9876ddddddddddeeeeee".*;
    redactSsn(&buf);
    try std.testing.expectEqualStrings("aaaaaaaaaa***-**-****bbbbbbbbbb***-**-****cccccccccc***-**-****ddddddddddeeeeee", &buf);
}

// ---------------------------------------------------------------------------
// Benchmark
// ---------------------------------------------------------------------------

test "bench - redactSsn throughput" {
    // 1 MB payload with SSNs every ~100 bytes.
    const payload_size = 1024 * 1024;
    var buf: [payload_size]u8 = undefined;

    // Fill with 'a' and plant SSNs every 100 bytes
    @memset(&buf, 'a');
    var pos: usize = 50;
    while (pos + 11 <= payload_size) {
        @memcpy(buf[pos..][0..11], "123-45-6789");
        pos += 100;
    }

    var timer = std.time.Timer.start() catch {
        // Timer not available on all platforms — skip silently.
        return;
    };

    const iterations = 100;
    var run: usize = 0;
    while (run < iterations) : (run += 1) {
        // Re-plant SSNs (they get masked each iteration)
        pos = 50;
        while (pos + 11 <= payload_size) {
            @memcpy(buf[pos..][0..11], "123-45-6789");
            pos += 100;
        }
        redactSsn(&buf);
    }

    const elapsed_ns = timer.read();
    const total_bytes = payload_size * iterations;
    const ns_per_byte = elapsed_ns / total_bytes;
    const mb_per_sec = (@as(f64, @floatFromInt(total_bytes)) / @as(f64, @floatFromInt(elapsed_ns))) * 1_000_000_000.0 / (1024.0 * 1024.0);

    std.debug.print("\n\n\n[BENCH] SIMD redactSsn: {d} ns/byte, {d:.1} MB/s ({} iterations x {} bytes)\n", .{
        ns_per_byte,
        mb_per_sec,
        iterations,
        payload_size,
    });
}
