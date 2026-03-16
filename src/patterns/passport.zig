const std = @import("std");

const replacement = "[PASSPORT_REDACTED]";

const labels = [_][]const u8{
    "passport number",
    "passport no",
    "passport #",
    "passport",
};

fn matchLabel(buf: []const u8, start: usize, needle: []const u8) bool {
    if (start + needle.len > buf.len) return false;
    for (needle, 0..) |byte, idx| {
        if (std.ascii.toLower(buf[start + idx]) != std.ascii.toLower(byte)) return false;
    }
    return true;
}

fn isBoundary(byte: u8) bool {
    return !(std.ascii.isAlphanumeric(byte) or byte == '_');
}

pub fn tryMatchAt(buf: []const u8, pos: usize) ?struct { start: usize, end: usize, redact_start: usize, replacement: []const u8 } {
    if (pos > 0 and !isBoundary(buf[pos - 1])) return null;

    for (labels) |label| {
        if (!matchLabel(buf, pos, label)) continue;

        var value_start = pos + label.len;
        while (value_start < buf.len and (buf[value_start] == ' ' or buf[value_start] == ':' or buf[value_start] == '#')) {
            value_start += 1;
        }

        var end = value_start;
        var token_len: usize = 0;
        var saw_digit = false;
        while (end < buf.len and token_len < 9) : (end += 1) {
            const byte = buf[end];
            if (!std.ascii.isAlphanumeric(byte)) break;
            if (std.ascii.isDigit(byte)) saw_digit = true;
            token_len += 1;
        }

        if (token_len < 6 or token_len > 9 or !saw_digit) continue;
        if (end < buf.len and !isBoundary(buf[end])) continue;

        return .{
            .start = pos,
            .end = end,
            .redact_start = value_start,
            .replacement = replacement,
        };
    }

    return null;
}

test "passport - label qualified value" {
    const input = "Passport Number: 123456789";
    const result = tryMatchAt(input, 0).?;
    try std.testing.expectEqualStrings("123456789", input[result.redact_start..result.end]);
    try std.testing.expectEqualStrings(replacement, result.replacement);
}

test "passport - short passport label" {
    const input = "passport no AB123456";
    const result = tryMatchAt(input, 0).?;
    try std.testing.expectEqualStrings("AB123456", input[result.redact_start..result.end]);
}

test "passport - rejects unlabeled number" {
    try std.testing.expect(tryMatchAt("AB123456", 0) == null);
}
