const std = @import("std");

const replacement = "[INTL_PHONE_REDACTED]";

const supported_country_codes = [_][]const u8{
    "44", // UK
    "33", // France
    "49", // Germany
    "34", // Spain
    "31", // Netherlands
    "353", // Ireland
};

fn isSupportedCountryCode(digits: []const u8) bool {
    for (supported_country_codes) |code| {
        if (digits.len >= code.len and std.mem.eql(u8, digits[0..code.len], code)) return true;
    }
    return false;
}

pub fn tryMatchAt(buf: []const u8, pos: usize) ?struct { start: usize, end: usize, redact_start: usize, replacement: []const u8 } {
    if (pos >= buf.len or buf[pos] != '+') return null;
    if (pos > 0 and std.ascii.isDigit(buf[pos - 1])) return null;

    var end = pos + 1;
    var digits: [15]u8 = undefined;
    var digit_count: usize = 0;
    while (end < buf.len) : (end += 1) {
        const byte = buf[end];
        if (std.ascii.isDigit(byte)) {
            if (digit_count >= digits.len) return null;
            digits[digit_count] = byte;
            digit_count += 1;
            continue;
        }
        if (byte == ' ' or byte == '-' or byte == '(' or byte == ')') continue;
        break;
    }

    while (end > pos and buf[end - 1] == ' ') end -= 1;
    if (digit_count < 9 or digit_count > 15) return null;
    if (!isSupportedCountryCode(digits[0..digit_count])) return null;
    if (end < buf.len and std.ascii.isDigit(buf[end])) return null;

    return .{
        .start = pos,
        .end = end,
        .redact_start = pos,
        .replacement = replacement,
    };
}

test "intl phone - uk mobile" {
    const input = "+44 7700 900123";
    const result = tryMatchAt(input, 0).?;
    try std.testing.expectEqualStrings(input, input[result.start..result.end]);
}

test "intl phone - france" {
    const input = "+33 6 12 34 56 78";
    const result = tryMatchAt(input, 0).?;
    try std.testing.expectEqualStrings(input, input[result.start..result.end]);
}

test "intl phone - rejects us prefix" {
    try std.testing.expect(tryMatchAt("+1 555 234 5678", 0) == null);
}
