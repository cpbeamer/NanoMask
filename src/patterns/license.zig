const std = @import("std");

const dl_replacement = "[DL_REDACTED]";
const dea_replacement = "[DEA_REDACTED]";
const npi_replacement = "[NPI_REDACTED]";

const dl_labels = [_][]const u8{ "driver's license", "drivers license", "driver license", "dl", "lic" };

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

fn isValidDea(buf: []const u8) bool {
    if (buf.len != 9) return false;
    if (!std.ascii.isAlphabetic(buf[0]) or !std.ascii.isAlphabetic(buf[1])) return false;
    for (buf[2..9]) |c| {
        if (!std.ascii.isDigit(c)) return false;
    }

    const d1 = buf[2] - '0';
    const d2 = buf[3] - '0';
    const d3 = buf[4] - '0';
    const d4 = buf[5] - '0';
    const d5 = buf[6] - '0';
    const d6 = buf[7] - '0';
    const d7 = buf[8] - '0';

    const sum1 = d1 + d3 + d5;
    const sum2 = (d2 + d4 + d6) * 2;
    const total = sum1 + sum2;

    const expected = total % 10;
    return expected == d7;
}

fn isValidNpi(buf: []const u8) bool {
    if (buf.len != 10) return false;
    if (buf[0] != '1' and buf[0] != '2') return false;
    for (buf) |c| {
        if (!std.ascii.isDigit(c)) return false;
    }

    var sum: u32 = 24; // Base sum for prefix 80840
    var double = true;
    var i: isize = 8;
    while (i >= 0) : (i -= 1) {
        var n = buf[@as(usize, @intCast(i))] - '0';
        if (double) {
            n *= 2;
            if (n > 9) n -= 9;
        }
        sum += n;
        double = !double;
    }
    const check = buf[9] - '0';
    const rem = sum % 10;
    const expected = if (rem == 0) @as(u32, 0) else 10 - rem;
    return check == expected;
}

fn matchDl(buf: []const u8, cursor: usize) ?struct { value_start: usize, end: usize } {
    for (dl_labels) |label| {
        if (matchLabel(buf, cursor, label)) {
            const value_start = skipSeparators(buf, cursor + label.len);
            if (value_start == cursor + label.len) continue;

            var end = value_start;
            while (end < buf.len and std.ascii.isAlphanumeric(buf[end])) {
                end += 1;
            }
            const len = end - value_start;
            if (len >= 6 and len <= 16) {
                return .{ .value_start = value_start, .end = end };
            }
        }
    }
    return null;
}

pub fn tryMatchAt(buf: []const u8, pos: usize) ?struct { start: usize, end: usize, redact_start: usize, replacement: []const u8 } {
    if (pos >= buf.len) return null;

    // Word boundary start
    if (pos > 0 and std.ascii.isAlphanumeric(buf[pos - 1])) return null;

    const c = buf[pos];

    // DL labels typically start with D or L
    const lower_c = std.ascii.toLower(c);
    if (lower_c == 'd' or lower_c == 'l') {
        if (matchDl(buf, pos)) |m| {
            return .{ .start = pos, .end = m.end, .redact_start = m.value_start, .replacement = dl_replacement };
        }
    }

    // DEA pattern: 2 alpha + 7 digits
    if (std.ascii.isAlphabetic(c)) {
        if (pos + 9 <= buf.len) {
            const dea_slice = buf[pos .. pos + 9];
            if (isValidDea(dea_slice)) {
                // Check word boundary after
                if (pos + 9 >= buf.len or !std.ascii.isAlphanumeric(buf[pos + 9])) {
                    return .{ .start = pos, .end = pos + 9, .redact_start = pos, .replacement = dea_replacement };
                }
            }
        }
    }

    // NPI pattern: 10 digits starting with 1 or 2
    if (std.ascii.isDigit(c)) {
        if (pos + 10 <= buf.len) {
            const npi_slice = buf[pos .. pos + 10];
            if (isValidNpi(npi_slice)) {
                // Check word boundary after
                if (pos + 10 >= buf.len or !std.ascii.isAlphanumeric(buf[pos + 10])) {
                    return .{ .start = pos, .end = pos + 10, .redact_start = pos, .replacement = npi_replacement };
                }
            }
        }
    }

    return null;
}

test "license - DEA valid" {
    // Valid DEA format: AB1234563
    // 1+3+5 = 1+3+5 = 9
    // 2*(2+4+6) = 2*(2+4+6) = 24
    // 9+24 = 33 -> end digit 3.
    const input = "Doctor DEA AB1234563 ok";
    const start = std.mem.indexOf(u8, input, "AB").?;
    const m = tryMatchAt(input, start).?;
    try std.testing.expectEqualStrings("AB1234563", input[m.start..m.end]);
    try std.testing.expectEqualStrings(dea_replacement, m.replacement);
}

test "license - NPI valid" {
    // Let's create a valid NPI manually.
    // Base sum = 24
    // NPI: 123456789X
    // 9: *2 = 18-9=9
    // 8: *1 = 8
    // 7: *2 = 14-9=5
    // 6: *1 = 6
    // 5: *2 = 10-9=1
    // 4: *1 = 4
    // 3: *2 = 6
    // 2: *1 = 2
    // 1: *2 = 2
    // Sum = 24 + 9+8+5+6+1+4+6+2+2 = 24 + 43 = 67.
    // Remainder 10 - (67%10 = 7) = 3.
    // valid NPI: 1234567893
    const input = "Provider NPI 1234567893 assigned";
    const start = std.mem.indexOf(u8, input, "1234").?;
    const m = tryMatchAt(input, start).?;
    try std.testing.expectEqualStrings("1234567893", input[m.start..m.end]);
    try std.testing.expectEqualStrings(npi_replacement, m.replacement);
}

test "license - DL valid" {
    const input = "Driver's license: A1234567 ok";
    const m = tryMatchAt(input, 0).?;
    try std.testing.expectEqualStrings("A1234567", input[m.redact_start..m.end]);
    try std.testing.expectEqualStrings(dl_replacement, m.replacement);
}
