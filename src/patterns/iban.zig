const std = @import("std");

const replacement = "[IBAN_REDACTED]";

fn isBoundary(byte: u8) bool {
    return !(std.ascii.isAlphanumeric(byte) or byte == '_');
}

fn isAsciiLetter(byte: u8) bool {
    return (byte >= 'A' and byte <= 'Z') or (byte >= 'a' and byte <= 'z');
}

fn ibanMod97(value: []const u8) bool {
    var remainder: u16 = 0;

    const reordered = [_][]const u8{
        value[4..],
        value[0..4],
    };
    for (reordered) |segment| {
        for (segment) |byte| {
            if (std.ascii.isDigit(byte)) {
                remainder = @intCast((remainder * 10 + (byte - '0')) % 97);
                continue;
            }
            const upper = std.ascii.toUpper(byte);
            const numeric = upper - 'A' + 10;
            remainder = @intCast((remainder * 10 + numeric / 10) % 97);
            remainder = @intCast((remainder * 10 + numeric % 10) % 97);
        }
    }

    return remainder == 1;
}

pub fn tryMatchAt(buf: []const u8, pos: usize) ?struct { start: usize, end: usize, redact_start: usize, replacement: []const u8 } {
    if (pos + 4 > buf.len) return null;
    if (!isAsciiLetter(buf[pos]) or !isAsciiLetter(buf[pos + 1])) return null;
    if (!std.ascii.isDigit(buf[pos + 2]) or !std.ascii.isDigit(buf[pos + 3])) return null;
    if (pos > 0 and !isBoundary(buf[pos - 1])) return null;

    var compact: [34]u8 = undefined;
    var compact_len: usize = 0;
    var end = pos;
    var token_len: usize = 0;
    var best_end: ?usize = null;
    while (end < buf.len) {
        const byte = buf[end];
        if (std.ascii.isAlphanumeric(byte)) {
            if (compact_len >= compact.len) break;
            compact[compact_len] = std.ascii.toUpper(byte);
            compact_len += 1;
            token_len += 1;
            end += 1;

            const at_boundary = end == buf.len or isBoundary(buf[end]);
            if (compact_len >= 15 and at_boundary and ibanMod97(compact[0..compact_len])) {
                best_end = end;
            }
            continue;
        }
        if (byte == ' ') {
            if (token_len == 0) break;
            token_len = 0;
            end += 1;
            continue;
        }
        break;
    }

    const match_end = best_end orelse return null;
    if (compact_len < 15 or compact_len > 34) return null;
    if (match_end < buf.len and !isBoundary(buf[match_end])) return null;

    for (compact[4..compact_len]) |byte| {
        if (!std.ascii.isAlphanumeric(byte)) return null;
    }

    return .{
        .start = pos,
        .end = match_end,
        .redact_start = pos,
        .replacement = replacement,
    };
}

test "iban - german iban with spaces" {
    const input = "DE89 3704 0044 0532 0130 00";
    const result = tryMatchAt(input, 0).?;
    try std.testing.expectEqualStrings(input, input[result.start..result.end]);
    try std.testing.expectEqualStrings(replacement, result.replacement);
}

test "iban - french iban contiguous" {
    const input = "FR1420041010050500013M02606";
    const result = tryMatchAt(input, 0).?;
    try std.testing.expectEqualStrings(input, input[result.start..result.end]);
}

test "iban - rejects invalid checksum" {
    try std.testing.expect(tryMatchAt("DE89 3704 0044 0532 0130 01", 0) == null);
}
