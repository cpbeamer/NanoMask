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
const fax_replacement = "[FAX_REDACTED]";

const fax_keywords = [_][]const u8{ "fax", "facsimile" };

fn hasFaxContext(buf: []const u8, start: usize, end: usize) bool {
    const window_start = if (start > 15) start - 15 else 0;
    const window_before = buf[window_start..start];
    var lower_buf: [30]u8 = undefined;
    for (window_before, 0..) |col, i| lower_buf[i] = std.ascii.toLower(col);
    const lower_before = lower_buf[0..window_before.len];

    for (fax_keywords) |kw| {
        if (std.mem.indexOf(u8, lower_before, kw) != null) return true;
    }

    const window_end = if (end + 15 < buf.len) end + 15 else buf.len;
    const window_after = buf[end..window_end];
    for (window_after, 0..) |col, i| lower_buf[i] = std.ascii.toLower(col);
    const lower_after = lower_buf[0..window_after.len];

    for (fax_keywords) |kw| {
        if (std.mem.indexOf(u8, lower_after, kw) != null) return true;
    }

    return false;
}

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

/// Single-position match for the unified scanner.
pub fn tryMatchAt(buf: []const u8, pos: usize, allow_us: bool) ?struct { start: usize, end: usize, redact_start: usize, replacement: []const u8 } {
    if (pos >= buf.len) return null;
    const c = buf[pos];
    if (!std.ascii.isDigit(c) and c != '(' and c != '+') return null;
    // Skip if preceded by a digit (part of a longer number)
    if (pos > 0 and std.ascii.isDigit(buf[pos - 1])) return null;
    const candidate = extractPhoneCandidate(buf, pos) orelse return null;
    
    // Default phone scanning is currently strictly US-formatting
    if (allow_us) {
        if (!isValidUsPhone(candidate.digits[0..candidate.digit_count], candidate.digit_count)) return null;
    } else {
        // If not US or ALL, we don't apply the US phone logic
        // UK logic is in a different file/module in Phase 4.
        return null;
    }
    // Not followed by more digits
    if (candidate.end < buf.len and std.ascii.isDigit(buf[candidate.end])) return null;

    const is_fax = hasFaxContext(buf, candidate.actual_start, candidate.end);
    const repl = if (is_fax) fax_replacement else replacement;

    return .{ .start = candidate.actual_start, .end = candidate.end, .redact_start = candidate.actual_start, .replacement = repl };
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

test "phone - parenthesized format" {
    const input = "Call (555) 234-5678 now";
    const start = std.mem.indexOf(u8, input, "(555)").?;
    const m = tryMatchAt(input, start, true).?;
    try std.testing.expectEqualStrings("(555) 234-5678", input[m.start..m.end]);
}

test "phone - dashed format" {
    const input = "Call 555-234-5678 now";
    const start = std.mem.indexOf(u8, input, "555-").?;
    const m = tryMatchAt(input, start, true).?;
    try std.testing.expectEqualStrings("555-234-5678", input[m.start..m.end]);
}

test "phone - dotted format" {
    const input = "Call 555.234.5678 now";
    const start = std.mem.indexOf(u8, input, "555.").?;
    const m = tryMatchAt(input, start, true).?;
    try std.testing.expectEqualStrings("555.234.5678", input[m.start..m.end]);
}

test "phone - 10 contiguous digits" {
    const input = "Call 5552345678 now";
    const start = std.mem.indexOf(u8, input, "555").?;
    const m = tryMatchAt(input, start, true).?;
    try std.testing.expectEqualStrings("5552345678", input[m.start..m.end]);
}

test "phone - international prefix +1" {
    const input = "Call +1-555-234-5678 today";
    const start = std.mem.indexOfScalar(u8, input, '+').?;
    const m = tryMatchAt(input, start, true).?;
    try std.testing.expectEqualStrings("+1-555-234-5678", input[m.start..m.end]);
}

test "phone - domestic prefix 1" {
    const input = "Call 1-555-234-5678 today";
    const start = std.mem.indexOf(u8, input, "1-555").?;
    const m = tryMatchAt(input, start, true).?;
    try std.testing.expectEqualStrings("1-555-234-5678", input[m.start..m.end]);
}

test "phone - rejects area code starting with 0" {
    const input = "Number 055-234-5678 here";
    const start = std.mem.indexOf(u8, input, "055").?;
    try std.testing.expect(tryMatchAt(input, start, true) == null);
}

test "phone - rejects area code starting with 1" {
    const input = "Number 155-234-5678 here";
    const start = std.mem.indexOf(u8, input, "155").?;
    try std.testing.expect(tryMatchAt(input, start, true) == null);
}

test "phone - rejects all-same digits" {
    const input = "Number 2222222222 here";
    const start = std.mem.indexOf(u8, input, "222").?;
    try std.testing.expect(tryMatchAt(input, start, true) == null);
}

test "phone - embedded in longer digit sequence rejected" {
    const input = "Order 99555234567800 ID";
    // First digit '9' at position 6 is not preceded by digit, but the full
    // sequence has 14 digits which fails US phone validation.
    const start = std.mem.indexOf(u8, input, "99").?;
    try std.testing.expect(tryMatchAt(input, start, true) == null);
}

test "phone - fax context before" {
    const input = "Send fax to 555-234-5678 please";
    const start = std.mem.indexOf(u8, input, "555").?;
    const m = tryMatchAt(input, start, true).?;
    try std.testing.expectEqualStrings(fax_replacement, m.replacement);
}

test "phone - fax context after" {
    const input = "Number: (555) 234-5678 (Fax)";
    const start = std.mem.indexOf(u8, input, "(555)").?;
    const m = tryMatchAt(input, start, true).?;
    try std.testing.expectEqualStrings(fax_replacement, m.replacement);
}
