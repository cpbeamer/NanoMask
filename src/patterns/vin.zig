const std = @import("std");

const vin_replacement = "[VIN_REDACTED]";
const license_plate_replacement = "[LICENSE_PLATE_REDACTED]";

const vin_weights = [_]u32{ 8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2 };

fn getVinCharValue(c: u8) ?u32 {
    if (std.ascii.isDigit(c)) return c - '0';
    switch (std.ascii.toUpper(c)) {
        'A', 'J' => return 1,
        'B', 'K', 'S' => return 2,
        'C', 'L', 'T' => return 3,
        'D', 'M', 'U' => return 4,
        'E', 'N', 'V' => return 5,
        'F', 'W' => return 6,
        'G', 'P', 'X' => return 7,
        'H', 'Y' => return 8,
        'R', 'Z' => return 9,
        else => return null, // I, O, Q are invalid
    }
}

fn isValidVin(buf: []const u8) bool {
    if (buf.len != 17) return false;

    var sum: u32 = 0;
    for (buf, 0..) |c, i| {
        const val = getVinCharValue(c) orelse return false;
        sum += val * vin_weights[i];
    }

    const rem = sum % 11;
    const check_char = std.ascii.toUpper(buf[8]);

    if (rem == 10) {
        return check_char == 'X';
    } else {
        return check_char == ('0' + @as(u8, @intCast(rem)));
    }
}

const plate_keywords = [_][]const u8{ "plate", "license plate", "lic plate", "tag" };

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

fn matchLicensePlate(buf: []const u8, cursor: usize) ?struct { value_start: usize, end: usize } {
    for (plate_keywords) |label| {
        if (matchLabel(buf, cursor, label)) {
            const value_start = skipSeparators(buf, cursor + label.len);
            if (value_start == cursor + label.len) continue;

            var end = value_start;
            while (end < buf.len and std.ascii.isAlphanumeric(buf[end])) {
                end += 1;
            }
            const len = end - value_start;
            // License plates are usually 2 to 8 chars
            if (len >= 2 and len <= 8) {
                return .{ .value_start = value_start, .end = end };
            }
        }
    }
    return null;
}

pub fn tryMatchAt(buf: []const u8, pos: usize) ?struct { start: usize, end: usize, redact_start: usize, replacement: []const u8 } {
    if (pos >= buf.len) return null;

    // Check word boundary
    if (pos > 0 and std.ascii.isAlphanumeric(buf[pos - 1])) return null;

    const c = buf[pos];
    const lower_c = std.ascii.toLower(c);

    if (lower_c == 'p' or lower_c == 'l' or lower_c == 't') {
        if (matchLicensePlate(buf, pos)) |m| {
            return .{ .start = pos, .end = m.end, .redact_start = m.value_start, .replacement = license_plate_replacement };
        }
    }

    // VIN
    if (std.ascii.isAlphanumeric(c)) {
        if (pos + 17 <= buf.len) {
            const vin_slice = buf[pos .. pos + 17];
            if (isValidVin(vin_slice)) {
                // Word boundary after
                if (pos + 17 >= buf.len or !std.ascii.isAlphanumeric(buf[pos + 17])) {
                    return .{ .start = pos, .end = pos + 17, .redact_start = pos, .replacement = vin_replacement };
                }
            }
        }
    }

    return null;
}

test "vin - valid VIN" {
    var buf = "12345678901234567".*; // array of u8
    buf[8] = '0'; // placeholder

    var sum: u32 = 0;
    for (&buf, 0..) |col, i| {
        sum += getVinCharValue(col).? * vin_weights[i];
    }
    const rem = sum % 11;
    if (rem == 10) buf[8] = 'X' else buf[8] = '0' + @as(u8, @intCast(rem));

    const m = tryMatchAt(&buf, 0).?;
    try std.testing.expectEqualStrings(&buf, buf[m.start..m.end]);
    try std.testing.expectEqualStrings(vin_replacement, m.replacement);
}

test "vin - invalid VIN character" {
    // I, O, Q are invalid
    const input = "12345678I01234567";
    try std.testing.expect(tryMatchAt(input, 0) == null);
}

test "vin - license plate" {
    const input = "License Plate: 7ABC123 ok";
    const m = tryMatchAt(input, 0).?;
    try std.testing.expectEqualStrings("7ABC123", input[m.redact_start..m.end]);
    try std.testing.expectEqualStrings(license_plate_replacement, m.replacement);
}
