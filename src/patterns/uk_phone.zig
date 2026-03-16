const std = @import("std");

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

fn extractPhoneCandidate(
    buf: []const u8,
    start: usize,
) ?struct { actual_start: usize, end: usize, digits: [15]u8, digit_count: u8 } {
    var digits: [15]u8 = undefined;
    var digit_count: u8 = 0;
    var pos = start;
    var actual_start = start;

    if (pos < buf.len and buf[pos] == '+') {
        pos += 1;
    }

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
            var sep_end = pos + 1;
            while (sep_end < buf.len and (buf[sep_end] == '-' or buf[sep_end] == '.' or buf[sep_end] == ' ' or buf[sep_end] == '(' or buf[sep_end] == ')')) {
                sep_end += 1;
            }
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

fn isValidUkPhone(digits: []const u8, count: u8) bool {
    if (count != 10 and count != 11 and count != 12 and count != 13) return false;

    // Check for international +44 prefix
    if (digits[0] == '4' and count >= 11) {
        if (digits[1] != '4') return false;
        // The next digit usually shouldn't be 0
        if (digits[2] == '0') {
            // Wait, people sometimes write +44 (0) 7700 900123
            // So if it's 440, we just assume it's valid if it maps to 12 or 13 digits
            // (e.g. 4407700900123 is 13 digits)
            if (count != 12 and count != 13) return false;
        } else {
            // Valid UK without the trunk zero (e.g. 447700900123 = 12 digits, wait.
            // 07700 900123 is 11 digits. +44 7700 900123 is 12 digits.
            if (count != 12) return false;
        }
        return true;
    }

    // National format must start with 0 and be exactly 10 or 11 digits long.
    if (digits[0] != '0') return false;
    
    // Normal length is 11. Some specific areas use 10.
    if (count != 10 and count != 11) return false;

    return true;
}

pub fn tryMatchAt(buf: []const u8, pos: usize) ?struct { start: usize, end: usize, redact_start: usize, replacement: []const u8 } {
    if (pos >= buf.len) return null;
    const c = buf[pos];
    if (!std.ascii.isDigit(c) and c != '(' and c != '+') return null;
    if (pos > 0 and std.ascii.isDigit(buf[pos - 1])) return null;
    const candidate = extractPhoneCandidate(buf, pos) orelse return null;
    
    if (!isValidUkPhone(candidate.digits[0..candidate.digit_count], candidate.digit_count)) return null;

    if (candidate.end < buf.len and std.ascii.isDigit(buf[candidate.end])) return null;

    const is_fax = hasFaxContext(buf, candidate.actual_start, candidate.end);
    const repl = if (is_fax) fax_replacement else replacement;

    return .{ .start = candidate.actual_start, .end = candidate.end, .redact_start = candidate.actual_start, .replacement = repl };
}

test "uk phone - national format mobile" {
    const input = "Call 07700 900077 now";
    const start = std.mem.indexOf(u8, input, "07700").?;
    const m = tryMatchAt(input, start).?;
    try std.testing.expectEqualStrings("07700 900077", input[m.start..m.end]);
}

test "uk phone - international format" {
    const input = "Call +44 7700 900077 now";
    const start = std.mem.indexOf(u8, input, "+44").?;
    const m = tryMatchAt(input, start).?;
    try std.testing.expectEqualStrings("+44 7700 900077", input[m.start..m.end]);
}

test "uk phone - parenthesized trunk format" {
    const input = "Call +44 (0) 20 7946 0123 now";
    const start = std.mem.indexOf(u8, input, "+44").?;
    const m = tryMatchAt(input, start).?;
    try std.testing.expectEqualStrings("+44 (0) 20 7946 0123", input[m.start..m.end]);
}

test "uk phone - ignores US number" {
    const input = "Call 555-123-4567";
    const start = std.mem.indexOf(u8, input, "555").?;
    try std.testing.expect(tryMatchAt(input, start) == null);
}
