const std = @import("std");

const replacement = "[POSTCODE_REDACTED]";

fn isBoundary(byte: u8) bool {
    return !(std.ascii.isAlphanumeric(byte) or byte == '_');
}

/// Matches UK postcodes (e.g. SW1A 1AA, W1A 0AX, M1 1AE, B33 8TH, CR2 6XH, DN55 1PT)
/// Valid formats:
/// - A9 9AA
/// - A9A 9AA
/// - A99 9AA
/// - AA9 9AA
/// - AA9A 9AA
/// - AA99 9AA
/// A = Alphabetic character, 9 = Numeric digit.
pub fn tryMatchAt(buf: []const u8, pos: usize) ?struct { start: usize, end: usize, redact_start: usize, replacement: []const u8 } {
    if (pos + 5 > buf.len) return null;

    // Must start on a boundary
    if (pos > 0 and !isBoundary(buf[pos - 1])) return null;

    // Fast reject: First char must be a letter
    if (!std.ascii.isAlphabetic(buf[pos])) return null;

    var i = pos;
    var outward_len: usize = 0;

    // Scan up to 4 characters for the outward code
    while (i < buf.len and outward_len < 4) {
        if (buf[i] == ' ') break;
        if (!std.ascii.isAlphanumeric(buf[i])) break;
        outward_len += 1;
        i += 1;
    }

    if (outward_len < 2 or outward_len > 4) return null;

    // Outward code validation
    const out_view = buf[pos .. pos + outward_len];
    if (!std.ascii.isAlphabetic(out_view[0])) return null;
    if (outward_len == 2) {
        // e.g. M1
        if (!std.ascii.isDigit(out_view[1])) return null;
    } else if (outward_len == 3) {
        // e.g. A9A, A99, AA9
        const c1_alpha = std.ascii.isAlphabetic(out_view[1]);
        const c1_num = std.ascii.isDigit(out_view[1]);
        const c2_alpha = std.ascii.isAlphabetic(out_view[2]);
        const c2_num = std.ascii.isDigit(out_view[2]);

        if (!(c1_alpha and c2_num) and !(c1_num and c2_num) and !(c1_num and c2_alpha)) return null;
    } else if (outward_len == 4) {
        // e.g. AA9A, AA99
        if (!std.ascii.isAlphabetic(out_view[1])) return null;
        if (!std.ascii.isDigit(out_view[2])) return null;
        if (!std.ascii.isAlphanumeric(out_view[3])) return null;
    }

    // Must have a space divider
    if (i >= buf.len or buf[i] != ' ') return null;
    i += 1;

    // Inward code is strict 3 chars: 9AA
    if (i + 3 > buf.len) return null;
    if (!std.ascii.isDigit(buf[i])) return null;
    if (!std.ascii.isAlphabetic(buf[i + 1])) return null;
    if (!std.ascii.isAlphabetic(buf[i + 2])) return null;

    i += 3;

    // Must end on a boundary
    if (i < buf.len and !isBoundary(buf[i])) return null;

    return .{
        .start = pos,
        .end = i,
        .redact_start = pos,
        .replacement = replacement,
    };
}

test "uk postcode - A9 9AA" {
    const input = "Send to M1 1AA right away";
    const start = std.mem.indexOf(u8, input, "M1").?;
    const result = tryMatchAt(input, start).?;
    try std.testing.expectEqualStrings("M1 1AA", input[result.start..result.end]);
}

test "uk postcode - A9A 9AA" {
    const input = "W1A 0AX";
    const result = tryMatchAt(input, 0).?;
    try std.testing.expectEqualStrings("W1A 0AX", input[result.start..result.end]);
}

test "uk postcode - A99 9AA" {
    const input = "B33 8TH";
    const result = tryMatchAt(input, 0).?;
    try std.testing.expectEqualStrings("B33 8TH", input[result.start..result.end]);
}

test "uk postcode - AA9 9AA" {
    const input = "CR2 6XH";
    const result = tryMatchAt(input, 0).?;
    try std.testing.expectEqualStrings("CR2 6XH", input[result.start..result.end]);
}

test "uk postcode - AA9A 9AA" {
    const input = "EC1A 1BB";
    const result = tryMatchAt(input, 0).?;
    try std.testing.expectEqualStrings("EC1A 1BB", input[result.start..result.end]);
}

test "uk postcode - AA99 9AA" {
    const input = "DN55 1PT";
    const result = tryMatchAt(input, 0).?;
    try std.testing.expectEqualStrings("DN55 1PT", input[result.start..result.end]);
}

test "uk postcode - reject missing space" {
    try std.testing.expect(tryMatchAt("SW1A1AA", 0) == null);
}

test "uk postcode - reject bad outward" {
    try std.testing.expect(tryMatchAt("1W1 A0X", 0) == null);
    try std.testing.expect(tryMatchAt("AAAA 1AA", 0) == null);
}

test "uk postcode - reject bad inward" {
    try std.testing.expect(tryMatchAt("SW1A A1A", 0) == null);
    try std.testing.expect(tryMatchAt("SW1A 11A", 0) == null);
}
