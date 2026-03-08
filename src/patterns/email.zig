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

/// Redact all email addresses in the buffer, replacing each with `[EMAIL_REDACTED]`.
/// Returns an owned slice with redacted content (caller must free).
pub fn redactEmails(input: []const u8, allocator: std.mem.Allocator) ![]u8 {
    if (input.len < 5) {
        return try allocator.dupe(u8, input);
    }

    // First pass: find all email spans so we can emit in one go without
    // complex rewinding logic.
    var spans = std.ArrayListUnmanaged(struct { start: usize, end: usize }).empty;
    defer spans.deinit(allocator);

    var scan: usize = 0;
    while (scan < input.len) {
        if (input[scan] == '@') {
            if (findEmailBounds(input, scan)) |bounds| {
                try spans.append(allocator, .{ .start = bounds.start, .end = bounds.end });
                scan = bounds.end;
                continue;
            }
        }
        scan += 1;
    }

    // No emails found — return a copy
    if (spans.items.len == 0) {
        return try allocator.dupe(u8, input);
    }

    // Second pass: build result with replacements
    var result = std.ArrayListUnmanaged(u8).empty;
    errdefer result.deinit(allocator);

    var cursor: usize = 0;
    for (spans.items) |span| {
        // Emit text before this email
        if (span.start > cursor) {
            try result.appendSlice(allocator, input[cursor..span.start]);
        }
        // Emit replacement
        try result.appendSlice(allocator, replacement);
        cursor = span.end;
    }
    // Emit remaining text
    if (cursor < input.len) {
        try result.appendSlice(allocator, input[cursor..]);
    }

    return try result.toOwnedSlice(allocator);
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

test "email - standard email redaction" {
    const allocator = std.testing.allocator;
    const result = try redactEmails("Contact john.doe@hospital.org for details", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Contact [EMAIL_REDACTED] for details", result);
}

test "email - plus alias" {
    const allocator = std.testing.allocator;
    const result = try redactEmails("Send to user+tag@gmail.com please", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Send to [EMAIL_REDACTED] please", result);
}

test "email - subdomain" {
    const allocator = std.testing.allocator;
    const result = try redactEmails("Email a@b.c.d.com works", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Email [EMAIL_REDACTED] works", result);
}

test "email - long TLD (.museum)" {
    const allocator = std.testing.allocator;
    const result = try redactEmails("Visit admin@gallery.museum now", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Visit [EMAIL_REDACTED] now", result);
}

test "email - rejects @mention (no local part)" {
    const allocator = std.testing.allocator;
    const result = try redactEmails("Hey @username check this", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Hey @username check this", result);
}

test "email - rejects @@decorator" {
    const allocator = std.testing.allocator;
    const result = try redactEmails("Use @@login decorator here", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Use @@login decorator here", result);
}

test "email - no TLD rejected" {
    const allocator = std.testing.allocator;
    const result = try redactEmails("Invalid user@localhost here", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Invalid user@localhost here", result);
}

test "email - consecutive dots rejected" {
    const allocator = std.testing.allocator;
    const result = try redactEmails("Bad user@bad..domain.com ok", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Bad user@bad..domain.com ok", result);
}

test "email - multiple emails" {
    const allocator = std.testing.allocator;
    const result = try redactEmails("From alice@example.com to bob@test.org done", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("From [EMAIL_REDACTED] to [EMAIL_REDACTED] done", result);
}

test "email - no emails unchanged" {
    const allocator = std.testing.allocator;
    const result = try redactEmails("This text has no sensitive data at all.", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("This text has no sensitive data at all.", result);
}

test "email - empty input" {
    const allocator = std.testing.allocator;
    const result = try redactEmails("", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("", result);
}

test "email - adjacent to punctuation" {
    const allocator = std.testing.allocator;
    const result = try redactEmails("(user@domain.com)", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("([EMAIL_REDACTED])", result);
}

test "email - email at start" {
    const allocator = std.testing.allocator;
    const result = try redactEmails("user@domain.com is here", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("[EMAIL_REDACTED] is here", result);
}

test "email - email at end" {
    const allocator = std.testing.allocator;
    const result = try redactEmails("Contact user@domain.com", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Contact [EMAIL_REDACTED]", result);
}

test "email - underscore in local part" {
    const allocator = std.testing.allocator;
    const result = try redactEmails("Send to first_last@work.co ok", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Send to [EMAIL_REDACTED] ok", result);
}
