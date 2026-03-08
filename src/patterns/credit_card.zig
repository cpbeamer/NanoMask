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

/// Redact all credit card numbers in the input, replacing each with `[CC_REDACTED]`.
/// Returns an owned slice (caller must free).
pub fn redactCreditCards(input: []const u8, allocator: std.mem.Allocator) ![]u8 {
    if (input.len < 13) {
        return try allocator.dupe(u8, input);
    }

    // First pass: find all credit card spans
    var spans = std.ArrayListUnmanaged(struct { start: usize, end: usize }).empty;
    defer spans.deinit(allocator);

    var scan: usize = 0;
    while (scan < input.len) {
        if (std.ascii.isDigit(input[scan])) {
            const preceded_by_digit = scan > 0 and std.ascii.isDigit(input[scan - 1]);

            if (!preceded_by_digit) {
                if (extractCcCandidate(input, scan)) |candidate| {
                    const digits = candidate.digits[0..candidate.digit_count];

                    // Verify it's not followed by more digits
                    const followed_by_digit = candidate.end < input.len and std.ascii.isDigit(input[candidate.end]);

                    if (!followed_by_digit and hasKnownPrefix(digits) and luhnValid(digits)) {
                        try spans.append(allocator, .{ .start = scan, .end = candidate.end });
                        scan = candidate.end;
                        continue;
                    }
                }
            }
        }

        scan += 1;
    }

    if (spans.items.len == 0) {
        return try allocator.dupe(u8, input);
    }

    // Second pass: build result
    var result = std.ArrayListUnmanaged(u8).empty;
    errdefer result.deinit(allocator);

    var cursor: usize = 0;
    for (spans.items) |span| {
        if (span.start > cursor) {
            try result.appendSlice(allocator, input[cursor..span.start]);
        }
        try result.appendSlice(allocator, replacement);
        cursor = span.end;
    }
    if (cursor < input.len) {
        try result.appendSlice(allocator, input[cursor..]);
    }

    return try result.toOwnedSlice(allocator);
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

test "cc - Visa standard" {
    const allocator = std.testing.allocator;
    const result = try redactCreditCards("Card: 4111111111111111 end", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Card: [CC_REDACTED] end", result);
}

test "cc - Visa dashed" {
    const allocator = std.testing.allocator;
    const result = try redactCreditCards("Card: 4111-1111-1111-1111 end", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Card: [CC_REDACTED] end", result);
}

test "cc - Visa spaced" {
    const allocator = std.testing.allocator;
    const result = try redactCreditCards("Card: 4111 1111 1111 1111 end", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Card: [CC_REDACTED] end", result);
}

test "cc - Mastercard" {
    const allocator = std.testing.allocator;
    const result = try redactCreditCards("Card: 5500000000000004 end", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Card: [CC_REDACTED] end", result);
}

test "cc - Amex 34" {
    const allocator = std.testing.allocator;
    const result = try redactCreditCards("Card: 340000000000009 end", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Card: [CC_REDACTED] end", result);
}

test "cc - Amex 37" {
    const allocator = std.testing.allocator;
    const result = try redactCreditCards("Card: 370000000000002 end", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Card: [CC_REDACTED] end", result);
}

test "cc - Discover" {
    const allocator = std.testing.allocator;
    const result = try redactCreditCards("Card: 6011000000000004 end", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Card: [CC_REDACTED] end", result);
}

test "cc - fails Luhn (bad checksum)" {
    const allocator = std.testing.allocator;
    // 4111111111111112 does NOT pass Luhn
    const result = try redactCreditCards("Card: 4111111111111112 end", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Card: 4111111111111112 end", result);
}

test "cc - too short (12 digits)" {
    const allocator = std.testing.allocator;
    const result = try redactCreditCards("Number 411111111111 here", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Number 411111111111 here", result);
}

test "cc - no credit cards unchanged" {
    const allocator = std.testing.allocator;
    const result = try redactCreditCards("No cards in this text.", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("No cards in this text.", result);
}

test "cc - empty input" {
    const allocator = std.testing.allocator;
    const result = try redactCreditCards("", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("", result);
}

test "cc - multiple cards" {
    const allocator = std.testing.allocator;
    const result = try redactCreditCards("Visa: 4111111111111111 MC: 5500000000000004", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Visa: [CC_REDACTED] MC: [CC_REDACTED]", result);
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
