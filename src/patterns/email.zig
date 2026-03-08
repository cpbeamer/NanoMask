const std = @import("std");

// ---------------------------------------------------------------------------
// Email address redaction
// ---------------------------------------------------------------------------
// Strategy: linear scan for '@' characters. For each '@' hit, expand left
// for the local part and right for the domain+TLD. Validate minimum
// structure (a@b.cc) and replace with a fixed-length token.
// ---------------------------------------------------------------------------

const replacement = "[EMAIL_REDACTED]";

/// Check if a byte is valid in the local part of an email (before the @).
inline fn isLocalChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '.' or c == '+' or c == '-' or c == '_';
}

/// Check if a byte is valid in the domain part of an email (after the @).
inline fn isDomainChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '.' or c == '-';
}

/// Validate and measure an email address centered on the '@' at position `at_pos`.
/// Returns the start and end (exclusive) of the full email, or null if invalid.
fn findEmailBounds(buf: []const u8, at_pos: usize) ?struct { start: usize, end: usize } {
    // '@' must not be at the very start or end
    if (at_pos == 0 or at_pos + 1 >= buf.len) return null;

    // Reject '@@' (decorator pattern)
    if (at_pos > 0 and buf[at_pos - 1] == '@') return null;
    if (at_pos + 1 < buf.len and buf[at_pos + 1] == '@') return null;

    // --- Scan left for local part ---
    var local_start = at_pos;
    while (local_start > 0 and isLocalChar(buf[local_start - 1])) {
        local_start -= 1;
    }
    const local_len = at_pos - local_start;
    if (local_len == 0) return null;

    // Local part must not start or end with a dot
    if (buf[local_start] == '.' or buf[at_pos - 1] == '.') return null;

    // --- Scan right for domain ---
    var domain_end = at_pos + 1;
    while (domain_end < buf.len and isDomainChar(buf[domain_end])) {
        domain_end += 1;
    }
    const domain_len = domain_end - (at_pos + 1);
    if (domain_len < 4) return null; // minimum domain: "b.cc" = 4 chars

    const domain = buf[at_pos + 1 .. domain_end];

    // Domain must contain at least one dot
    const dot_pos = std.mem.lastIndexOfScalar(u8, domain, '.') orelse return null;

    // TLD must be at least 2 chars
    const tld_len = domain.len - dot_pos - 1;
    if (tld_len < 2) return null;

    // Domain label before dot must be at least 1 char
    if (dot_pos == 0) return null;

    // No consecutive dots in domain
    if (std.mem.indexOf(u8, domain, "..")) |_| return null;

    // Domain must not start or end with a dot or hyphen
    if (domain[0] == '.' or domain[0] == '-') return null;
    if (domain[domain.len - 1] == '.' or domain[domain.len - 1] == '-') return null;

    // TLD must be all alphabetic
    const tld = domain[dot_pos + 1 ..];
    for (tld) |c| {
        if (!std.ascii.isAlphabetic(c)) return null;
    }

    return .{ .start = local_start, .end = domain_end };
}

/// Single-position match for the unified scanner.
/// Triggers only when `buf[pos] == '@'`. Returns match bounds including
/// the local part (which starts before `pos`).
pub fn tryMatchAt(buf: []const u8, pos: usize) ?struct { start: usize, end: usize, redact_start: usize, replacement: []const u8 } {
    if (pos >= buf.len or buf[pos] != '@') return null;
    const bounds = findEmailBounds(buf, pos) orelse return null;
    return .{ .start = bounds.start, .end = bounds.end, .redact_start = bounds.start, .replacement = replacement };
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

test "email - standard email" {
    const input = "Contact john.doe@hospital.org for details";
    const at_pos = std.mem.indexOfScalar(u8, input, '@').?;
    const m = tryMatchAt(input, at_pos).?;
    try std.testing.expectEqualStrings("john.doe@hospital.org", input[m.start..m.end]);
    try std.testing.expectEqualStrings(replacement, m.replacement);
}

test "email - plus alias" {
    const input = "Send to user+tag@gmail.com please";
    const at_pos = std.mem.indexOfScalar(u8, input, '@').?;
    const m = tryMatchAt(input, at_pos).?;
    try std.testing.expectEqualStrings("user+tag@gmail.com", input[m.start..m.end]);
}

test "email - subdomain" {
    const input = "Email a@b.c.d.com works";
    const at_pos = std.mem.indexOfScalar(u8, input, '@').?;
    const m = tryMatchAt(input, at_pos).?;
    try std.testing.expectEqualStrings("a@b.c.d.com", input[m.start..m.end]);
}

test "email - long TLD (.museum)" {
    const input = "Visit admin@gallery.museum now";
    const at_pos = std.mem.indexOfScalar(u8, input, '@').?;
    const m = tryMatchAt(input, at_pos).?;
    try std.testing.expectEqualStrings("admin@gallery.museum", input[m.start..m.end]);
}

test "email - rejects @mention (no local part)" {
    const input = "Hey @username check this";
    const at_pos = std.mem.indexOfScalar(u8, input, '@').?;
    try std.testing.expect(tryMatchAt(input, at_pos) == null);
}

test "email - rejects @@decorator" {
    const input = "Use @@login decorator here";
    const at_pos = std.mem.indexOfScalar(u8, input, '@').?;
    try std.testing.expect(tryMatchAt(input, at_pos) == null);
}

test "email - no TLD rejected" {
    const input = "Invalid user@localhost here";
    const at_pos = std.mem.indexOfScalar(u8, input, '@').?;
    try std.testing.expect(tryMatchAt(input, at_pos) == null);
}

test "email - consecutive dots rejected" {
    const input = "Bad user@bad..domain.com ok";
    const at_pos = std.mem.indexOfScalar(u8, input, '@').?;
    try std.testing.expect(tryMatchAt(input, at_pos) == null);
}

test "email - adjacent to punctuation" {
    const input = "(user@domain.com)";
    const at_pos = std.mem.indexOfScalar(u8, input, '@').?;
    const m = tryMatchAt(input, at_pos).?;
    try std.testing.expectEqualStrings("user@domain.com", input[m.start..m.end]);
}

test "email - email at start" {
    const input = "user@domain.com is here";
    const at_pos = std.mem.indexOfScalar(u8, input, '@').?;
    const m = tryMatchAt(input, at_pos).?;
    try std.testing.expectEqual(@as(usize, 0), m.start);
    try std.testing.expectEqualStrings("user@domain.com", input[m.start..m.end]);
}

test "email - email at end" {
    const input = "Contact user@domain.com";
    const at_pos = std.mem.indexOfScalar(u8, input, '@').?;
    const m = tryMatchAt(input, at_pos).?;
    try std.testing.expectEqual(input.len, m.end);
    try std.testing.expectEqualStrings("user@domain.com", input[m.start..m.end]);
}

test "email - underscore in local part" {
    const input = "Send to first_last@work.co ok";
    const at_pos = std.mem.indexOfScalar(u8, input, '@').?;
    const m = tryMatchAt(input, at_pos).?;
    try std.testing.expectEqualStrings("first_last@work.co", input[m.start..m.end]);
}
