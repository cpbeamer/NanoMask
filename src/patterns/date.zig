const std = @import("std");

const date_replacement = "[DATE_REDACTED]";
const age_90_plus = "90+";

const date_keywords = [_][]const u8{ "dob", "born", "admitt", "discharg", "deceas", "date", "dt", "bday", "birthday" };

const month_names = [_][]const u8{ "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec", "january", "february", "march", "april", "june", "july", "august", "september", "october", "november", "december" };

fn hasDateContext(buf: []const u8, start: usize, end: usize) bool {
    const window_start = if (start > 30) start - 30 else 0;
    const window_before = buf[window_start..start];

    var lower_buf: [30]u8 = undefined;
    for (window_before, 0..) |col, i| lower_buf[i] = std.ascii.toLower(col);
    const lower_before = lower_buf[0..window_before.len];

    for (date_keywords) |kw| {
        if (std.mem.indexOf(u8, lower_before, kw) != null) return true;
    }

    const window_end = if (end + 20 < buf.len) end + 20 else buf.len;
    const window_after = buf[end..window_end];
    var lower_buf_a: [20]u8 = undefined;
    for (window_after, 0..) |col, i| lower_buf_a[i] = std.ascii.toLower(col);
    const lower_after = lower_buf_a[0..window_after.len];

    for (date_keywords) |kw| {
        if (std.mem.indexOf(u8, lower_after, kw) != null) return true;
    }

    return false;
}

const age_keywords = [_][]const u8{ "age", "years old", "yo", "yr", "yrs", "year old" };

fn hasAgeContext(buf: []const u8, start: usize, end: usize) bool {
    const window_start = if (start > 15) start - 15 else 0;
    const window_before = buf[window_start..start];
    var lower_buf: [30]u8 = undefined;
    for (window_before, 0..) |col, i| lower_buf[i] = std.ascii.toLower(col);
    const lower_before = lower_buf[0..window_before.len];

    for (age_keywords) |kw| {
        if (std.mem.indexOf(u8, lower_before, kw) != null) return true;
    }

    const window_end = if (end + 15 < buf.len) end + 15 else buf.len;
    const window_after = buf[end..window_end];
    for (window_after, 0..) |col, i| lower_buf[i] = std.ascii.toLower(col);
    const lower_after = lower_buf[0..window_after.len];

    for (age_keywords) |kw| {
        if (std.mem.indexOf(u8, lower_after, kw) != null) return true;
    }
    return false;
}

fn matchNumber(buf: []const u8, cursor: usize, min_len: usize, max_len: usize) ?usize {
    var pos = cursor;
    while (pos < buf.len and std.ascii.isDigit(buf[pos]) and pos - cursor < max_len) {
        pos += 1;
    }
    if (pos - cursor >= min_len) return pos;
    return null;
}

fn matchSep(buf: []const u8, cursor: usize) ?usize {
    if (cursor < buf.len) {
        const c = buf[cursor];
        if (c == '/' or c == '-' or c == '.') return cursor + 1;
    }
    return null;
}

fn skipSpaces(buf: []const u8, cursor: usize) usize {
    var pos = cursor;
    while (pos < buf.len and buf[pos] == ' ') pos += 1;
    return pos;
}

fn matchNumericDate(buf: []const u8, cursor: usize) ?usize {
    // YYYY-MM-DD or YYYY-MM
    if (matchNumber(buf, cursor, 4, 4)) |end_y| {
        if (matchSep(buf, end_y)) |sep1| {
            if (matchNumber(buf, sep1, 1, 2)) |end_m| {
                if (matchSep(buf, end_m)) |sep2| {
                    if (matchNumber(buf, sep2, 1, 2)) |end_d| {
                        return end_d;
                    }
                }
                return end_m; // Partial YYYY-MM
            }
        }
    }
    // MM-DD-YYYY or MM-YYYY
    if (matchNumber(buf, cursor, 1, 2)) |end_m| {
        if (matchSep(buf, end_m)) |sep1| {
            if (matchNumber(buf, sep1, 1, 4)) |end_d_or_y| {
                if (end_d_or_y - sep1 == 4) {
                    return end_d_or_y; // MM-YYYY
                }
                if (matchSep(buf, end_d_or_y)) |sep2| {
                    if (matchNumber(buf, sep2, 2, 4)) |end_y| {
                        return end_y;
                    }
                }
            }
        }
    }

    // DD Month YYYY
    if (matchNumber(buf, cursor, 1, 2)) |end_d| {
        if (end_d < buf.len and (buf[end_d] == ' ' or buf[end_d] == '-')) {
            if (matchMonthName(buf, end_d + 1)) |end_m| {
                if (end_m < buf.len and (buf[end_m] == ' ' or buf[end_m] == '-')) {
                    if (matchNumber(buf, end_m + 1, 4, 4)) |end_y| {
                        return end_y;
                    }
                } else {
                    return end_m; // DD Month
                }
            }
        }
    }

    return null;
}

fn matchMonthName(buf: []const u8, cursor: usize) ?usize {
    for (month_names) |m| {
        if (cursor + m.len <= buf.len) {
            var m_match = true;
            for (m, 0..) |c, i| {
                if (std.ascii.toLower(buf[cursor + i]) != c) {
                    m_match = false;
                    break;
                }
            }
            if (m_match) {
                // word boundary check
                if (cursor + m.len < buf.len and std.ascii.isAlphabetic(buf[cursor + m.len])) continue;
                return cursor + m.len;
            }
        }
    }
    return null;
}

fn matchMonthNameDate(buf: []const u8, cursor: usize) ?usize {
    if (matchMonthName(buf, cursor)) |end_m| {
        if (end_m < buf.len and buf[end_m] == ' ') {
            var pos = skipSpaces(buf, end_m + 1);
            if (matchNumber(buf, pos, 1, 2)) |end_d| {
                pos = end_d;
                if (pos < buf.len and buf[pos] == ',') {
                    pos += 1;
                }
                pos = skipSpaces(buf, pos);
                if (matchNumber(buf, pos, 4, 4)) |end_y| {
                    return end_y;
                }
            } else if (matchNumber(buf, pos, 4, 4)) |end_y| {
                // Month YYYY
                return end_y;
            }
        }
    }
    return null;
}

fn matchAge(buf: []const u8, cursor: usize) ?usize {
    var pos = cursor;
    var age_val: u32 = 0;
    while (pos < buf.len and std.ascii.isDigit(buf[pos])) {
        age_val = age_val * 10 + (buf[pos] - '0');
        pos += 1;
    }

    if (pos - cursor >= 2 and pos - cursor <= 3 and age_val > 89) {
        // Must be a word boundary at the end (not followed by another digit)
        if (pos < buf.len and std.ascii.isDigit(buf[pos])) return null;
        if (hasAgeContext(buf, cursor, pos)) {
            return pos;
        }
    }
    return null;
}

pub fn tryMatchAt(buf: []const u8, pos: usize) ?struct { start: usize, end: usize, redact_start: usize, replacement: []const u8 } {
    if (pos >= buf.len) return null;

    // Word boundary start
    if (pos > 0 and std.ascii.isAlphanumeric(buf[pos - 1])) return null;

    const c = buf[pos];

    if (std.ascii.isDigit(c)) {
        if (matchNumericDate(buf, pos)) |end| {
            if (hasDateContext(buf, pos, end)) {
                return .{ .start = pos, .end = end, .redact_start = pos, .replacement = date_replacement };
            }
        }
        if (matchAge(buf, pos)) |end| {
            return .{ .start = pos, .end = end, .redact_start = pos, .replacement = age_90_plus };
        }
    } else if (std.ascii.isAlphabetic(c)) {
        if (matchMonthNameDate(buf, pos)) |end| {
            if (hasDateContext(buf, pos, end)) {
                return .{ .start = pos, .end = end, .redact_start = pos, .replacement = date_replacement };
            }
        }
    }

    return null;
}

test "date - MM/DD/YYYY with context" {
    const input = "Patient DOB: 05/15/1990 is here";
    const start = std.mem.indexOf(u8, input, "05").?;
    const m = tryMatchAt(input, start).?;
    try std.testing.expectEqualStrings("05/15/1990", input[m.start..m.end]);
    try std.testing.expectEqualStrings(date_replacement, m.replacement);
}

test "date - YYYY-MM-DD JSON context" {
    const input = "{\"dob\":\"1985-10-31\"}";
    const start = std.mem.indexOf(u8, input, "1985").?;
    const m = tryMatchAt(input, start).?;
    try std.testing.expectEqualStrings("1985-10-31", input[m.start..m.end]);
}

test "date - Month DD, YYYY" {
    const input = "born on January 15, 1980.";
    const start = std.mem.indexOf(u8, input, "January").?;
    const m = tryMatchAt(input, start).?;
    try std.testing.expectEqualStrings("January 15, 1980", input[m.start..m.end]);
}

test "date - Partial MM/YYYY" {
    const input = "DOB: 05/1990";
    const start = std.mem.indexOf(u8, input, "05").?;
    const m = tryMatchAt(input, start).?;
    try std.testing.expectEqualStrings("05/1990", input[m.start..m.end]);
}

test "date - Age > 89" {
    const input = "Patient age is 95 years old";
    const start = std.mem.indexOf(u8, input, "95").?;
    const m = tryMatchAt(input, start).?;
    try std.testing.expectEqualStrings("95", input[m.start..m.end]);
    try std.testing.expectEqualStrings(age_90_plus, m.replacement);
}

test "date - Age < 90 not redacted" {
    const input = "Patient age is 85 years old";
    const start = std.mem.indexOf(u8, input, "85").?;
    try std.testing.expect(tryMatchAt(input, start) == null);
}

test "date - Generic date without context not redacted" {
    const input = "System started on 2024-01-01";
    const start = std.mem.indexOf(u8, input, "2024").?;
    try std.testing.expect(tryMatchAt(input, start) == null);
}
