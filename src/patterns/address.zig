const std = @import("std");

const address_replacement = "[ADDRESS_REDACTED]";
const zip_zero_replacement = "00000";

const restricted_zip3s = [_][]const u8{ "036", "059", "063", "102", "203", "556", "692", "790", "821", "823", "830", "831", "878", "879", "884", "890", "893" };

const street_suffixes = [_][]const u8{ "st", "street", "ave", "avenue", "blvd", "boulevard", "rd", "road", "ln", "lane", "dr", "drive", "ct", "court", "pl", "place", "sq", "square", "way", "cir", "circle", "pkwy" };

fn isRestrictedZip(zip3: []const u8) bool {
    for (restricted_zip3s) |rz| {
        if (std.mem.eql(u8, zip3, rz)) return true;
    }
    return false;
}

/// Matches a 5-digit ZIP code. Returns the end of the ZIP code.
fn matchZipCode(buf: []const u8, cursor: usize) ?usize {
    // Ensure word boundary before ZIP
    if (cursor > 0 and std.ascii.isAlphanumeric(buf[cursor - 1])) return null;

    if (cursor + 5 <= buf.len) {
        for (buf[cursor .. cursor + 5]) |c| {
            if (!std.ascii.isDigit(c)) return null;
        }
        // Word boundary after
        if (cursor + 5 < buf.len and std.ascii.isDigit(buf[cursor + 5])) return null;

        return cursor + 5;
    }
    return null;
}

fn skipSpacesBackwards(buf: []const u8, start: usize) usize {
    var pos = start;
    while (pos > 0) {
        const c = buf[pos - 1];
        if (c == ' ' or c == ',' or c == '\t') {
            pos -= 1;
        } else {
            break;
        }
    }
    return pos;
}

fn skipSpaces(buf: []const u8, start: usize) usize {
    var pos = start;
    while (pos < buf.len) {
        const c = buf[pos];
        if (c == ' ' or c == ',' or c == '\t') {
            pos += 1;
        } else {
            break;
        }
    }
    return pos;
}

fn matchStreetAddress(buf: []const u8, cursor: usize) ?usize {
    // A simple heuristic for street address: Number + space + Word(s) + Suffix
    // First, match house number (digits)
    var num_end = cursor;
    while (num_end < buf.len and std.ascii.isDigit(buf[num_end])) {
        num_end += 1;
    }
    const num_len = num_end - cursor;
    if (num_len < 1 or num_len > 6) return null; // Reasonable limit for house numbers

    if (num_end >= buf.len or buf[num_end] != ' ') return null;

    // Now, scan forward for a street suffix, within reasonable distance (e.g. 30 chars).
    var search_limit = num_end + 30;
    if (search_limit > buf.len) search_limit = buf.len;

    // Split into tokens safely
    var pos = skipSpaces(buf, num_end);
    var words_found = false;

    while (pos < search_limit) {
        var word_end = pos;
        while (word_end < search_limit and std.ascii.isAlphabetic(buf[word_end])) {
            word_end += 1;
        }

        if (word_end > pos) {
            words_found = true;
            const word = buf[pos..word_end];
            var lower_buf: [32]u8 = undefined;
            if (word.len < 32) {
                for (word, 0..) |c, i| lower_buf[i] = std.ascii.toLower(c);
                const lower_word = lower_buf[0..word.len];

                for (street_suffixes) |suffix| {
                    if (std.mem.eql(u8, lower_word, suffix)) {
                        return word_end;
                    }
                }
            }
        }

        if (word_end == pos) {
            // Check if it's a dot or comma or space
            if (buf[pos] == '.' or buf[pos] == ' ' or buf[pos] == ',') {
                pos += 1;
            } else {
                break;
            }
        } else {
            pos = skipSpaces(buf, word_end);
        }
    }

    return null;
}

const us_states = [_][]const u8{ "al", "ak", "az", "ar", "ca", "co", "ct", "de", "fl", "ga", "hi", "id", "il", "in", "ia", "ks", "ky", "la", "me", "md", "ma", "mi", "mn", "ms", "mo", "mt", "ne", "nv", "nh", "nj", "nm", "ny", "nc", "nd", "oh", "ok", "or", "pa", "ri", "sc", "sd", "tn", "tx", "ut", "vt", "va", "wa", "wv", "wi", "wy", "dc" };

fn isUsState(state: []const u8) bool {
    var lower_buf: [2]u8 = undefined;
    for (state, 0..) |c, i| lower_buf[i] = std.ascii.toLower(c);
    for (us_states) |us| {
        if (std.mem.eql(u8, &lower_buf, us)) return true;
    }
    return false;
}

fn matchCityStateZip(buf: []const u8, cursor: usize) ?usize {
    // Look forward up to 40 characters for ", ST 12345"
    var search_limit = cursor + 40;
    if (search_limit > buf.len) search_limit = buf.len;

    // We only need to find the state+zip, and we redact from `cursor` to the end of state.
    // So if we see `, CA 12345` or ` CA 12345`, we return the end of the state!
    var pos = cursor;
    while (pos < search_limit) {
        if (buf[pos] == ',') {
            const state_pos = skipSpaces(buf, pos + 1);
            if (state_pos + 2 < search_limit and std.ascii.isAlphabetic(buf[state_pos]) and std.ascii.isAlphabetic(buf[state_pos + 1])) {
                const state = buf[state_pos .. state_pos + 2];
                if (isUsState(state)) {
                    const zip_pos = skipSpaces(buf, state_pos + 2);
                    if (matchZipCode(buf, zip_pos)) |_| {
                        return state_pos + 2; // End of state. We redact City, State. ZIP is handled by the ZIP scanner.
                    }
                }
            }
        }
        pos += 1;
    }
    return null;
}

pub fn tryMatchAt(buf: []const u8, pos: usize, allow_us: bool) ?struct { start: usize, end: usize, redact_start: usize, replacement: []const u8 } {
    if (pos >= buf.len) return null;

    // Word boundary
    if (pos > 0 and std.ascii.isAlphanumeric(buf[pos - 1])) return null;

    const c = buf[pos];

    if (std.ascii.isDigit(c)) {
        // Zip code
        if (matchZipCode(buf, pos)) |end| {
            if (allow_us) {
                // Check for Safe Harbor ZIP-3
                const zip3 = buf[pos .. pos + 3];
                if (isRestrictedZip(zip3)) {
                    return .{ .start = pos, .end = end, .redact_start = pos, .replacement = zip_zero_replacement };
                } else {
                    return .{ .start = pos, .end = end, .redact_start = pos + 3, .replacement = "00" };
                }
            }
        }

        // Street Address
        if (matchStreetAddress(buf, pos)) |end| {
            return .{ .start = pos, .end = end, .redact_start = pos, .replacement = address_replacement };
        }
    } else if (std.ascii.isAlphabetic(c)) {
        // City, State adjacent to ZIP
        if (matchCityStateZip(buf, pos)) |end| {
            return .{ .start = pos, .end = end, .redact_start = pos, .replacement = address_replacement };
        }
    }

    return null;
}

test "address - Safe Harbor Restricted ZIP" {
    const input = "Living in 03605 area.";
    const start = std.mem.indexOf(u8, input, "03605").?;
    const m = tryMatchAt(input, start, true).?;
    try std.testing.expectEqualStrings("03605", input[m.start..m.end]);
    try std.testing.expectEqualStrings("00000", m.replacement);
}

test "address - Safe Harbor Normal ZIP" {
    const input = "My ZIP is 12345 right now.";
    const start = std.mem.indexOf(u8, input, "12345").?;
    const m = tryMatchAt(input, start, true).?;
    try std.testing.expectEqualStrings("12345", input[m.start..m.end]);
    try std.testing.expectEqual(start + 3, m.redact_start);
    try std.testing.expectEqualStrings("00", m.replacement);
}

test "address - Street address" {
    const input = "I live at 123 Main St.";
    const start = std.mem.indexOf(u8, input, "123").?;
    const m = tryMatchAt(input, start, true).?;
    try std.testing.expectEqualStrings("123 Main St", input[m.start..m.end]);
    try std.testing.expectEqualStrings(address_replacement, m.replacement);
}

test "address - Street address with avenue" {
    const input = "456 First Avenue in NY";
    const start = std.mem.indexOf(u8, input, "456").?;
    const m = tryMatchAt(input, start, true).?;
    try std.testing.expectEqualStrings("456 First Avenue", input[m.start..m.end]);
}

test "address - Street address fail without suffix" {
    const input = "123 Main";
    const start = std.mem.indexOf(u8, input, "123").?;
    try std.testing.expect(tryMatchAt(input, start, true) == null);
}

test "address - City, State ZIP" {
    const input = "I live in San Francisco, CA 94105 now";
    const start = std.mem.indexOf(u8, input, "San Francisco").?;
    const m = tryMatchAt(input, start, true).?;
    try std.testing.expectEqualStrings("San Francisco, CA", input[m.start..m.end]);
    try std.testing.expectEqualStrings(address_replacement, m.replacement);
}
