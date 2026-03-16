const std = @import("std");

const account_replacement = "[ACCOUNT_REDACTED]";
const routing_replacement = "[ROUTING_REDACTED]";

const account_labels = [_][]const u8{ "account", "acct", "acc" };

const routing_labels = [_][]const u8{ "routing", "aba" };

fn matchLabel(buf: []const u8, start: usize, needle: []const u8) bool {
    if (start + needle.len > buf.len) return false;
    for (0..needle.len) |i| {
        if (std.ascii.toLower(buf[start + i]) != std.ascii.toLower(needle[i])) return false;
    }
    return true;
}

fn skipSeparators(buf: []const u8, start: usize) usize {
    var pos = start;
    while (pos < buf.len and (buf[pos] == ':' or buf[pos] == '#' or buf[pos] == ' ' or buf[pos] == '\t' or buf[pos] == '-')) {
        pos += 1;
    }
    return pos;
}

fn matchAccount(buf: []const u8, cursor: usize) ?struct { value_start: usize, end: usize, is_routing: bool } {
    for (routing_labels) |label| {
        if (matchLabel(buf, cursor, label)) {
            const after_label = cursor + label.len;
            const value_start = skipSeparators(buf, after_label);

            if (value_start == after_label) continue; // need at least one separator

            var digit_end = value_start;
            while (digit_end < buf.len and std.ascii.isDigit(buf[digit_end])) {
                digit_end += 1;
            }

            const digit_count = digit_end - value_start;
            // Routing number is 9 digits
            if (digit_count == 9) {
                if (digit_end >= buf.len or !std.ascii.isDigit(buf[digit_end])) {
                    return .{ .value_start = value_start, .end = digit_end, .is_routing = true };
                }
            }
        }
    }

    for (account_labels) |label| {
        if (matchLabel(buf, cursor, label)) {
            const after_label = cursor + label.len;
            const value_start = skipSeparators(buf, after_label);

            if (value_start == after_label) continue;

            var digit_end = value_start;
            while (digit_end < buf.len and std.ascii.isDigit(buf[digit_end])) {
                digit_end += 1;
            }

            const digit_count = digit_end - value_start;
            // typical account numbers 8 to 17 digits
            if (digit_count >= 6 and digit_count <= 20) {
                if (digit_end >= buf.len or !std.ascii.isDigit(buf[digit_end])) {
                    return .{ .value_start = value_start, .end = digit_end, .is_routing = false };
                }
            }
        }
    }
    return null;
}

pub fn tryMatchAt(buf: []const u8, pos: usize, allow_us: bool) ?struct { start: usize, end: usize, redact_start: usize, replacement: []const u8 } {
    if (pos >= buf.len) return null;

    if (!allow_us) return null;

    const c = std.ascii.toLower(buf[pos]);
    if (c == 'a' or c == 'r') {
        if (matchAccount(buf, pos)) |m| {
            return .{
                .start = pos,
                .end = m.end,
                .redact_start = m.value_start,
                .replacement = if (m.is_routing) routing_replacement else account_replacement,
            };
        }
    }
    return null;
}

test "account - Routing Number" {
    const input = "Routing: 123456789 used";
    const m = tryMatchAt(input, 0, true).?;
    try std.testing.expectEqualStrings("Routing: 123456789", input[m.start..m.end]);
    try std.testing.expectEqualStrings(routing_replacement, m.replacement);
}

test "account - Account Number" {
    const input = "Acct# 9876543210 ok";
    const m = tryMatchAt(input, 0, true).?;
    try std.testing.expectEqualStrings("Acct# 9876543210", input[m.start..m.end]);
    try std.testing.expectEqualStrings(account_replacement, m.replacement);
}

test "account - ABA" {
    const input = "ABA 111000111";
    const m = tryMatchAt(input, 0, true).?;
    try std.testing.expectEqualStrings("ABA 111000111", input[m.start..m.end]);
    try std.testing.expectEqualStrings(routing_replacement, m.replacement);
}
