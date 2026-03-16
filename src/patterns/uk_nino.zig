const std = @import("std");

const replacement = "[UK_NINO_REDACTED]";

fn isBoundary(byte: u8) bool {
    return !(std.ascii.isAlphanumeric(byte) or byte == '_');
}

fn validFirstLetter(byte: u8) bool {
    const upper = std.ascii.toUpper(byte);
    return upper >= 'A' and upper <= 'Z' and
        upper != 'D' and upper != 'F' and upper != 'I' and upper != 'Q' and upper != 'U' and upper != 'V';
}

fn validSecondLetter(byte: u8) bool {
    const upper = std.ascii.toUpper(byte);
    return upper >= 'A' and upper <= 'Z' and
        upper != 'D' and upper != 'F' and upper != 'I' and upper != 'O' and upper != 'Q' and upper != 'U' and upper != 'V';
}

pub fn tryMatchAt(buf: []const u8, pos: usize) ?struct { start: usize, end: usize, redact_start: usize, replacement: []const u8 } {
    if (pos + 8 > buf.len) return null;
    if (pos > 0 and !isBoundary(buf[pos - 1])) return null;
    if (!validFirstLetter(buf[pos]) or !validSecondLetter(buf[pos + 1])) return null;

    var end = pos + 2;
    var digits: u8 = 0;
    while (end < buf.len and digits < 6) : (end += 1) {
        const byte = buf[end];
        if (byte == ' ') continue;
        if (!std.ascii.isDigit(byte)) return null;
        digits += 1;
    }
    if (digits != 6) return null;

    var suffix_len: usize = 0;
    if (end < buf.len and buf[end] == ' ') {
        end += 1;
    }
    if (end < buf.len) {
        const suffix = std.ascii.toUpper(buf[end]);
        if (suffix >= 'A' and suffix <= 'D') {
            suffix_len = 1;
            end += 1;
        }
    }

    if (suffix_len == 0) return null;
    if (end < buf.len and !isBoundary(buf[end])) return null;

    return .{
        .start = pos,
        .end = end,
        .redact_start = pos,
        .replacement = replacement,
    };
}

test "uk nino - spaced format" {
    const input = "AA 12 34 56 C";
    const result = tryMatchAt(input, 0).?;
    try std.testing.expectEqualStrings(input, input[result.start..result.end]);
}

test "uk nino - contiguous format" {
    const input = "AA123456A";
    const result = tryMatchAt(input, 0).?;
    try std.testing.expectEqualStrings(input, input[result.start..result.end]);
}

test "uk nino - rejects missing suffix" {
    try std.testing.expect(tryMatchAt("AA123456", 0) == null);
}
