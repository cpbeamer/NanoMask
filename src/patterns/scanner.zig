const std = @import("std");
const email_mod = @import("email.zig");
const phone_mod = @import("phone.zig");
const cc_mod = @import("credit_card.zig");
const ip_mod = @import("ip_address.zig");
const healthcare_mod = @import("healthcare.zig");

// ---------------------------------------------------------------------------
// Unified single-pass pattern scanner
// ---------------------------------------------------------------------------
// Replaces the sequential 5-pass `applyPatterns` chain with one linear scan.
// At each cursor position, tries enabled patterns in priority order. Each
// pattern's `tryMatchAt` bails in ~1 comparison for non-matching bytes,
// making the per-byte cost nearly constant regardless of pattern count.
// ---------------------------------------------------------------------------

/// A matched span within the input buffer.
pub const Match = struct {
    /// Start of the full matched region (for output building and overlap checks).
    start: usize,
    /// End of the full matched region (exclusive); the cursor advances here.
    end: usize,
    /// Start of the portion to redact. Bytes from `start..redact_start` are
    /// preserved verbatim (e.g., healthcare labels like "MRN: ").
    redact_start: usize,
    /// Fixed replacement token (e.g., "[EMAIL_REDACTED]").
    replacement: []const u8,
};

pub const RedactResult = struct {
    output: []u8,
    matches: []Match,

    pub fn deinit(self: *RedactResult, allocator: std.mem.Allocator) void {
        allocator.free(self.output);
        allocator.free(self.matches);
    }
};

/// Flags controlling which patterns are active in the scan.
pub const PatternFlags = struct {
    email: bool = false,
    phone: bool = false,
    credit_card: bool = false,
    ip: bool = false,
    healthcare: bool = false,

    pub fn anyEnabled(self: PatternFlags) bool {
        return self.email or self.phone or self.credit_card or self.ip or self.healthcare;
    }
};

/// Convert any pattern's anonymous-struct match into our canonical Match type.
inline fn toMatch(m: anytype) Match {
    return .{
        .start = m.start,
        .end = m.end,
        .redact_start = m.redact_start,
        .replacement = m.replacement,
    };
}

fn collectMatches(input: []const u8, flags: PatternFlags, allocator: std.mem.Allocator) ![]Match {
    if (!flags.anyEnabled() or input.len < 3) {
        return try allocator.alloc(Match, 0);
    }

    var spans = std.ArrayListUnmanaged(Match).empty;
    errdefer spans.deinit(allocator);

    var cursor: usize = 0;
    while (cursor < input.len) {
        if (flags.email and input[cursor] == '@') {
            if (email_mod.tryMatchAt(input, cursor)) |m| {
                const match = toMatch(m);
                if (spans.items.len == 0 or match.start >= spans.items[spans.items.len - 1].end) {
                    try spans.append(allocator, match);
                    cursor = match.end;
                    continue;
                }
            }
        }

        if (std.ascii.isDigit(input[cursor])) {
            if (flags.phone) {
                if (phone_mod.tryMatchAt(input, cursor)) |m| {
                    try spans.append(allocator, toMatch(m));
                    cursor = m.end;
                    continue;
                }
            }
            if (flags.credit_card) {
                if (cc_mod.tryMatchAt(input, cursor)) |m| {
                    try spans.append(allocator, toMatch(m));
                    cursor = m.end;
                    continue;
                }
            }
        }

        if (flags.ip) {
            if (ip_mod.tryMatchAt(input, cursor)) |m| {
                try spans.append(allocator, toMatch(m));
                cursor = m.end;
                continue;
            }
        }

        if (flags.phone and (input[cursor] == '(' or input[cursor] == '+')) {
            if (phone_mod.tryMatchAt(input, cursor)) |m| {
                try spans.append(allocator, toMatch(m));
                cursor = m.end;
                continue;
            }
        }

        if (flags.healthcare) {
            if (healthcare_mod.tryMatchAt(input, cursor)) |m| {
                try spans.append(allocator, toMatch(m));
                cursor = m.end;
                continue;
            }
        }

        cursor += 1;
    }

    return try spans.toOwnedSlice(allocator);
}

/// Redact all enabled patterns in a single pass over the input buffer.
/// Returns an owned slice with redacted content (caller must free).
pub fn redact(input: []const u8, flags: PatternFlags, allocator: std.mem.Allocator) ![]u8 {
    const result = try redactWithMatches(input, flags, allocator);
    defer allocator.free(result.matches);
    return result.output;
}

pub fn redactWithMatches(input: []const u8, flags: PatternFlags, allocator: std.mem.Allocator) !RedactResult {
    const spans = try collectMatches(input, flags, allocator);
    errdefer allocator.free(spans);

    if (spans.len == 0) {
        return .{
            .output = try allocator.dupe(u8, input),
            .matches = spans,
        };
    }

    var result = std.ArrayListUnmanaged(u8).empty;
    errdefer result.deinit(allocator);

    var prev_end: usize = 0;
    for (spans) |span| {
        // Emit text before this match
        if (span.start > prev_end) {
            try result.appendSlice(allocator, input[prev_end..span.start]);
        }
        // Emit preserved prefix (e.g., healthcare label)
        if (span.redact_start > span.start) {
            try result.appendSlice(allocator, input[span.start..span.redact_start]);
        }
        // Emit replacement token
        try result.appendSlice(allocator, span.replacement);
        prev_end = span.end;
    }
    // Emit remaining text after the last match
    if (prev_end < input.len) {
        try result.appendSlice(allocator, input[prev_end..]);
    }

    return .{
        .output = try result.toOwnedSlice(allocator),
        .matches = spans,
    };
}

// ===========================================================================
// Unit Tests
// ===========================================================================

test "scanner - no patterns enabled returns copy" {
    const allocator = std.testing.allocator;
    const result = try redact("user@example.com", .{}, allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("user@example.com", result);
}

test "scanner - email only" {
    const allocator = std.testing.allocator;
    const result = try redact("Contact user@example.com please", .{ .email = true }, allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Contact [EMAIL_REDACTED] please", result);
}

test "scanner - phone only" {
    const allocator = std.testing.allocator;
    const result = try redact("Call (555) 234-5678 now", .{ .phone = true }, allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Call [PHONE_REDACTED] now", result);
}

test "scanner - credit card only" {
    const allocator = std.testing.allocator;
    const result = try redact("Card: 4111111111111111 end", .{ .credit_card = true }, allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Card: [CC_REDACTED] end", result);
}

test "scanner - ip only" {
    const allocator = std.testing.allocator;
    const result = try redact("Server 192.168.1.1 up", .{ .ip = true }, allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Server [IPV4_REDACTED] up", result);
}

test "scanner - healthcare MRN" {
    const allocator = std.testing.allocator;
    const result = try redact("MRN: 1234567 found", .{ .healthcare = true }, allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("MRN: [MRN_REDACTED] found", result);
}

test "scanner - healthcare ICD-10" {
    const allocator = std.testing.allocator;
    const result = try redact("Diagnosis E11.65 noted", .{ .healthcare = true }, allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Diagnosis [ICD10_REDACTED] noted", result);
}

test "scanner - all patterns mixed" {
    const allocator = std.testing.allocator;
    const flags = PatternFlags{
        .email = true,
        .phone = true,
        .credit_card = true,
        .ip = true,
        .healthcare = true,
    };
    const result = try redact(
        "Email user@test.com phone 555-234-5678 card 4111111111111111 ip 10.0.0.1 MRN: 12345678 done",
        flags,
        allocator,
    );
    defer allocator.free(result);
    try std.testing.expectEqualStrings(
        "Email [EMAIL_REDACTED] phone [PHONE_REDACTED] card [CC_REDACTED] ip [IPV4_REDACTED] MRN: [MRN_REDACTED] done",
        result,
    );
}

test "scanner - empty input" {
    const allocator = std.testing.allocator;
    const result = try redact("", .{ .email = true, .phone = true }, allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("", result);
}

test "scanner - no matches returns copy" {
    const allocator = std.testing.allocator;
    const flags = PatternFlags{ .email = true, .phone = true, .credit_card = true, .ip = true, .healthcare = true };
    const result = try redact("This text has no PII at all.", flags, allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("This text has no PII at all.", result);
}

test "scanner - IPv6 compressed" {
    const allocator = std.testing.allocator;
    const result = try redact("Loopback ::1 here", .{ .ip = true }, allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Loopback [IPV6_REDACTED] here", result);
}

test "scanner - CIDR preserved" {
    const allocator = std.testing.allocator;
    const result = try redact("Subnet 192.168.1.0/24 ok", .{ .ip = true }, allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Subnet [IPV4_REDACTED]/24 ok", result);
}

test "scanner - insurance with label" {
    const allocator = std.testing.allocator;
    const result = try redact("Insurance ID: ABC12345678 ok", .{ .healthcare = true }, allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Insurance ID: [INSURANCE_REDACTED] ok", result);
}
