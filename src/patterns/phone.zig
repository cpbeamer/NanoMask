const std = @import("std");

// ---------------------------------------------------------------------------
// Phone number redaction engine
// ---------------------------------------------------------------------------
// Strategy: scan for digit-dense regions. When we find a digit or phone-start
// character, try to parse a US phone number in various formats. Validate
// against known rules (area code, exchange code) to reduce false positives.
//
// Supported formats:
//   (555) 123-4567      — parenthesized area code
//   555-123-4567        — dashed
//   555.123.4567        — dotted
//   5551234567          — 10 contiguous digits
//   +1-555-123-4567     — international prefix
//   1-555-123-4567      — domestic prefix
// ---------------------------------------------------------------------------

const replacement = "[PHONE_REDACTED]";

/// Extract a phone candidate starting at `start`.
/// Collects digits while allowing separators (dash, dot, space, parens).
/// Returns digits, digit count, and the span of the match.
fn extractPhoneCandidate(
    buf: []const u8,
    start: usize,
) ?struct { actual_start: usize, end: usize, digits: [15]u8, digit_count: u8 } {
    var digits: [15]u8 = undefined;
    var digit_count: u8 = 0;
    var pos = start;
    var actual_start = start;

    // Allow optional leading '+' for international prefix
    if (pos < buf.len and buf[pos] == '+') {
        pos += 1;
    }

    // Allow optional leading '('
    if (pos < buf.len and buf[pos] == '(') {
        if (actual_start == start) actual_start = pos;
        pos += 1;
    }

    while (pos < buf.len and digit_count < 15) {
        const c = buf[pos];
        if (std.ascii.isDigit(c)) {
            digits[digit_count] = c;
            digit_count += 1;
            pos += 1;
        } else if (c == '-' or c == '.' or c == ' ' or c == '(' or c == ')') {
            // Skip all consecutive separators, then check if there's a digit after
            var sep_end = pos + 1;
            while (sep_end < buf.len and (buf[sep_end] == '-' or buf[sep_end] == '.' or buf[sep_end] == ' ' or buf[sep_end] == '(' or buf[sep_end] == ')')) {
                sep_end += 1;
            }
            // Only continue if a digit follows the separators
            if (sep_end < buf.len and std.ascii.isDigit(buf[sep_end])) {
                pos = sep_end;
            } else {
                break;
            }
        } else {
            break;
        }
    }

    if (digit_count < 10) return null;

    return .{
        .actual_start = actual_start,
        .end = pos,
        .digits = digits,
        .digit_count = digit_count,
    };
}

/// Validate that extracted digits form a valid US phone number.
fn isValidUsPhone(digits: []const u8, count: u8) bool {
    if (count != 10 and count != 11) return false;

    // For 11-digit numbers, first digit must be '1' (US country code)
    const area_start: usize = if (count == 11) blk: {
        if (digits[0] != '1') return false;
        break :blk 1;
    } else 0;

    const area_code = digits[area_start..][0..3];

    // Area code must not start with 0 or 1
    if (area_code[0] == '0' or area_code[0] == '1') return false;

    // Reject all-same digits (e.g., 2222222222)
    const first = digits[area_start];
    var all_same = true;
    for (digits[area_start .. area_start + 10]) |d| {
        if (d != first) {
            all_same = false;
            break;
        }
    }
    if (all_same) return false;

    // Exchange code (digits 4-6 of the 10-digit number) must not start with 0 or 1
    const exchange_start = area_start + 3;
    if (digits[exchange_start] == '0' or digits[exchange_start] == '1') return false;

    return true;
}

/// Redact all US phone numbers in the input, replacing each with `[PHONE_REDACTED]`.
/// Returns an owned slice (caller must free).
pub fn redactPhones(input: []const u8, allocator: std.mem.Allocator) ![]u8 {
    if (input.len < 10) {
        return try allocator.dupe(u8, input);
    }

    // First pass: find all phone spans
    var spans = std.ArrayListUnmanaged(struct { start: usize, end: usize }).empty;
    defer spans.deinit(allocator);

    var scan: usize = 0;
    while (scan < input.len) {
        const c = input[scan];

        // Potential phone start: digit, '(', or '+'
        if (std.ascii.isDigit(c) or c == '(' or c == '+') {
            // Skip if preceded by a digit (part of a longer number)
            const preceded_by_digit = scan > 0 and std.ascii.isDigit(input[scan - 1]);

            if (!preceded_by_digit) {
                if (extractPhoneCandidate(input, scan)) |candidate| {
                    if (isValidUsPhone(candidate.digits[0..candidate.digit_count], candidate.digit_count)) {
                        // Check it's not followed by more digits
                        const followed_by_digit = candidate.end < input.len and std.ascii.isDigit(input[candidate.end]);
                        if (!followed_by_digit) {
                            try spans.append(allocator, .{ .start = candidate.actual_start, .end = candidate.end });
                            scan = candidate.end;
                            continue;
                        }
                    }
                }
            }
        }

        scan += 1;
    }

    if (spans.items.len == 0) {
        return try allocator.dupe(u8, input);
    }

    // Second pass: build result with replacements
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

test "phone - parenthesized format" {
    const allocator = std.testing.allocator;
    const result = try redactPhones("Call (555) 234-5678 now", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Call [PHONE_REDACTED] now", result);
}

test "phone - dashed format" {
    const allocator = std.testing.allocator;
    const result = try redactPhones("Call 555-234-5678 now", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Call [PHONE_REDACTED] now", result);
}

test "phone - dotted format" {
    const allocator = std.testing.allocator;
    const result = try redactPhones("Call 555.234.5678 now", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Call [PHONE_REDACTED] now", result);
}

test "phone - 10 contiguous digits" {
    const allocator = std.testing.allocator;
    const result = try redactPhones("Call 5552345678 now", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Call [PHONE_REDACTED] now", result);
}

test "phone - international prefix +1" {
    const allocator = std.testing.allocator;
    const result = try redactPhones("Call +1-555-234-5678 today", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Call [PHONE_REDACTED] today", result);
}

test "phone - domestic prefix 1" {
    const allocator = std.testing.allocator;
    const result = try redactPhones("Call 1-555-234-5678 today", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Call [PHONE_REDACTED] today", result);
}

test "phone - rejects area code starting with 0" {
    const allocator = std.testing.allocator;
    const result = try redactPhones("Number 055-234-5678 here", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Number 055-234-5678 here", result);
}

test "phone - rejects area code starting with 1" {
    const allocator = std.testing.allocator;
    const result = try redactPhones("Number 155-234-5678 here", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Number 155-234-5678 here", result);
}

test "phone - rejects all-same digits" {
    const allocator = std.testing.allocator;
    const result = try redactPhones("Number 2222222222 here", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Number 2222222222 here", result);
}

test "phone - no phones unchanged" {
    const allocator = std.testing.allocator;
    const result = try redactPhones("This text has no phone numbers.", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("This text has no phone numbers.", result);
}

test "phone - empty input" {
    const allocator = std.testing.allocator;
    const result = try redactPhones("", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("", result);
}

test "phone - multiple phones" {
    const allocator = std.testing.allocator;
    const result = try redactPhones("Home: 555-234-5678, Work: 555-876-5432", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Home: [PHONE_REDACTED], Work: [PHONE_REDACTED]", result);
}

test "phone - embedded in longer digit sequence rejected" {
    const allocator = std.testing.allocator;
    const result = try redactPhones("Order 99555234567800 ID", allocator);
    defer allocator.free(result);
    // Should not redact — digits are part of a longer number
    try std.testing.expectEqualStrings("Order 99555234567800 ID", result);
}
