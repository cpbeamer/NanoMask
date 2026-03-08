const std = @import("std");

// ---------------------------------------------------------------------------
// Credit card number redaction with Luhn validation
// ---------------------------------------------------------------------------
// Strategy: scan for digit-dense regions of length >= 13. Extract digit
// sequences (allowing dash/space separators every 4 digits). Validate
// using the Luhn checksum algorithm to dramatically reduce false positives.
// ---------------------------------------------------------------------------

const replacement = "[CC_REDACTED]";

/// Compute Luhn checksum on a digit sequence. Returns true if valid.
fn luhnValid(digits: []const u8) bool {
    if (digits.len < 13 or digits.len > 19) return false;

    var sum: u32 = 0;
    var double = false;

    // Process right-to-left
    var i = digits.len;
    while (i > 0) {
        i -= 1;
        var d: u32 = digits[i] - '0';
        if (double) {
            d *= 2;
            if (d > 9) d -= 9;
        }
        sum += d;
        double = !double;
    }

    return (sum % 10) == 0;
}

/// Check if the digit sequence has a known card prefix.
fn hasKnownPrefix(digits: []const u8) bool {
    if (digits.len < 13) return false;

    // Visa: starts with 4
    if (digits[0] == '4') return true;

    // Mastercard: 51-55 or 2221-2720
    if (digits[0] == '5' and digits[1] >= '1' and digits[1] <= '5') return true;
    if (digits.len >= 4) {
        const prefix4 = (@as(u16, digits[0] - '0') * 1000) +
            (@as(u16, digits[1] - '0') * 100) +
            (@as(u16, digits[2] - '0') * 10) +
            (@as(u16, digits[3] - '0'));
        if (prefix4 >= 2221 and prefix4 <= 2720) return true;
    }

    // Amex: 34 or 37
    if (digits[0] == '3' and (digits[1] == '4' or digits[1] == '7')) return true;

    // Discover: 6011, 65
    if (digits[0] == '6') {
        if (digits[1] == '5') return true;
        if (digits.len >= 4 and digits[1] == '0' and digits[2] == '1' and digits[3] == '1') return true;
    }

    return false;
}

/// Extract a credit card candidate starting at `start`.
/// Returns the digit sequence and the end position (pointing after the last digit,
/// NOT including any trailing separators).
fn extractCcCandidate(
    buf: []const u8,
    start: usize,
) ?struct { end: usize, digits: [19]u8, digit_count: u8 } {
    var digits: [19]u8 = undefined;
    var digit_count: u8 = 0;
    var pos = start;
    var last_digit_pos = start; // Track position after the last digit

    while (pos < buf.len and digit_count < 19) {
        const c = buf[pos];
        if (std.ascii.isDigit(c)) {
            digits[digit_count] = c;
            digit_count += 1;
            pos += 1;
            last_digit_pos = pos;
        } else if (c == '-' or c == ' ') {
            // Only allow a single separator between digit groups
            if (pos + 1 < buf.len and std.ascii.isDigit(buf[pos + 1])) {
                pos += 1;
            } else {
                break;
            }
        } else {
            break;
        }
    }

    if (digit_count < 13) return null;

    return .{
        .end = last_digit_pos,
        .digits = digits,
        .digit_count = digit_count,
    };
}

/// Single-position match for the unified scanner.
pub fn tryMatchAt(buf: []const u8, pos: usize) ?struct { start: usize, end: usize, redact_start: usize, replacement: []const u8 } {
    if (pos >= buf.len or !std.ascii.isDigit(buf[pos])) return null;
    if (pos > 0 and std.ascii.isDigit(buf[pos - 1])) return null;
    const candidate = extractCcCandidate(buf, pos) orelse return null;
    const digits = candidate.digits[0..candidate.digit_count];
    if (candidate.end < buf.len and std.ascii.isDigit(buf[candidate.end])) return null;
    if (!hasKnownPrefix(digits) or !luhnValid(digits)) return null;
    return .{ .start = pos, .end = candidate.end, .redact_start = pos, .replacement = replacement };
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

test "cc - Visa standard" {
    const input = "Card: 4111111111111111 end";
    const start = std.mem.indexOf(u8, input, "411").?;
    const m = tryMatchAt(input, start).?;
    try std.testing.expectEqualStrings("4111111111111111", input[m.start..m.end]);
}

test "cc - Visa dashed" {
    const input = "Card: 4111-1111-1111-1111 end";
    const start = std.mem.indexOf(u8, input, "4111-").?;
    const m = tryMatchAt(input, start).?;
    try std.testing.expectEqualStrings("4111-1111-1111-1111", input[m.start..m.end]);
}

test "cc - Visa spaced" {
    const input = "Card: 4111 1111 1111 1111 end";
    const start = std.mem.indexOf(u8, input, "4111 ").?;
    const m = tryMatchAt(input, start).?;
    try std.testing.expectEqualStrings("4111 1111 1111 1111", input[m.start..m.end]);
}

test "cc - Mastercard" {
    const input = "Card: 5500000000000004 end";
    const start = std.mem.indexOf(u8, input, "550").?;
    const m = tryMatchAt(input, start).?;
    try std.testing.expectEqualStrings("5500000000000004", input[m.start..m.end]);
}

test "cc - Amex 34" {
    const input = "Card: 340000000000009 end";
    const start = std.mem.indexOf(u8, input, "340").?;
    const m = tryMatchAt(input, start).?;
    try std.testing.expectEqualStrings("340000000000009", input[m.start..m.end]);
}

test "cc - Amex 37" {
    const input = "Card: 370000000000002 end";
    const start = std.mem.indexOf(u8, input, "370").?;
    const m = tryMatchAt(input, start).?;
    try std.testing.expectEqualStrings("370000000000002", input[m.start..m.end]);
}

test "cc - Discover" {
    const input = "Card: 6011000000000004 end";
    const start = std.mem.indexOf(u8, input, "601").?;
    const m = tryMatchAt(input, start).?;
    try std.testing.expectEqualStrings("6011000000000004", input[m.start..m.end]);
}

test "cc - fails Luhn (bad checksum)" {
    const input = "Card: 4111111111111112 end";
    const start = std.mem.indexOf(u8, input, "411").?;
    try std.testing.expect(tryMatchAt(input, start) == null);
}

test "cc - too short (12 digits)" {
    const input = "Number 411111111111 here";
    const start = std.mem.indexOf(u8, input, "411").?;
    try std.testing.expect(tryMatchAt(input, start) == null);
}

test "cc - Luhn validation correctness" {
    // Known valid test numbers
    try std.testing.expect(luhnValid("4111111111111111")); // Visa
    try std.testing.expect(luhnValid("5500000000000004")); // MC
    try std.testing.expect(luhnValid("340000000000009")); // Amex
    try std.testing.expect(luhnValid("6011000000000004")); // Discover

    // Invalid: last digit changed
    try std.testing.expect(!luhnValid("4111111111111112"));
    try std.testing.expect(!luhnValid("5500000000000005"));
}
