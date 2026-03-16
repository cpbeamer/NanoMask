const std = @import("std");
const config_mod = @import("../infra/config.zig");
const Locale = config_mod.Locale;
const email_mod = @import("email.zig");
const phone_mod = @import("phone.zig");
const cc_mod = @import("credit_card.zig");
const ip_mod = @import("ip_address.zig");
const healthcare_mod = @import("healthcare.zig");
const iban_mod = @import("iban.zig");
const uk_nino_mod = @import("uk_nino.zig");
const passport_mod = @import("passport.zig");
const intl_phone_mod = @import("intl_phone.zig");
const date_mod = @import("date.zig");
const address_mod = @import("address.zig");
const account_mod = @import("account.zig");
const uk_nhs_mod = @import("uk_nhs.zig");
const uk_phone_mod = @import("uk_phone.zig");
const uk_postcode_mod = @import("uk_postcode.zig");
const ca_sin_mod = @import("ca_sin.zig");
const license_mod = @import("license.zig");
const url_mod = @import("url.zig");
const vin_mod = @import("vin.zig");

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
    iban: bool = false,
    uk_nino: bool = false,
    uk_nhs: bool = false,
    uk_phone: bool = false,
    uk_postcode: bool = false,
    ca_sin: bool = false,
    passport: bool = false,
    intl_phone: bool = false,
    dates: bool = false,
    addresses: bool = false,
    accounts: bool = false,
    licenses: bool = false,
    urls: bool = false,
    vehicle_ids: bool = false,
    locale: Locale = .us,

    pub fn anyEnabled(self: PatternFlags) bool {
        return self.email or self.phone or self.credit_card or self.ip or self.healthcare or
            self.iban or self.uk_nino or self.uk_nhs or self.uk_phone or self.uk_postcode or self.ca_sin or self.passport or self.intl_phone or self.dates or self.addresses or self.accounts or self.licenses or self.urls or self.vehicle_ids;
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
        const is_word_start = cursor == 0 or !std.ascii.isAlphanumeric(input[cursor - 1]);

        if (is_word_start and (flags.dates or flags.addresses or flags.vehicle_ids) and (std.ascii.isDigit(input[cursor]) or std.ascii.isAlphabetic(input[cursor]))) {
            if (flags.dates) {
                if (date_mod.tryMatchAt(input, cursor)) |m| {
                    const match = toMatch(m);
                    if (spans.items.len == 0 or match.start >= spans.items[spans.items.len - 1].end) {
                        try spans.append(allocator, match);
                        cursor = match.end;
                        continue;
                    }
                }
            }
            if (flags.addresses) {
                const allow_us = (flags.locale == .us or flags.locale == .all);
                if (address_mod.tryMatchAt(input, cursor, allow_us)) |m| {
                    const match = toMatch(m);
                    if (spans.items.len == 0 or match.start >= spans.items[spans.items.len - 1].end) {
                        try spans.append(allocator, match);
                        cursor = match.end;
                        continue;
                    }
                }
            }
            if (flags.uk_postcode and (flags.locale == .uk or flags.locale == .all)) {
                if (uk_postcode_mod.tryMatchAt(input, cursor)) |m| {
                    const match = toMatch(m);
                    if (spans.items.len == 0 or match.start >= spans.items[spans.items.len - 1].end) {
                        try spans.append(allocator, match);
                        cursor = match.end;
                        continue;
                    }
                }
            }
            if (flags.vehicle_ids) {
                if (vin_mod.tryMatchAt(input, cursor)) |m| {
                    const match = toMatch(m);
                    if (spans.items.len == 0 or match.start >= spans.items[spans.items.len - 1].end) {
                        try spans.append(allocator, match);
                        cursor = match.end;
                        continue;
                    }
                }
            }
        }

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

        if (is_word_start and flags.urls and (input[cursor] == 'h' or input[cursor] == 'w' or input[cursor] == 'H' or input[cursor] == 'W')) {
            if (url_mod.tryMatchAt(input, cursor)) |m| {
                try spans.append(allocator, toMatch(m));
                cursor = m.end;
                continue;
            }
        }

        if (std.ascii.isDigit(input[cursor])) {
            if (flags.phone) {
                const allow_us = (flags.locale == .us or flags.locale == .all);
                if (phone_mod.tryMatchAt(input, cursor, allow_us)) |m| {
                    try spans.append(allocator, toMatch(m));
                    cursor = m.end;
                    continue;
                }
            }
            if (flags.uk_phone and (flags.locale == .uk or flags.locale == .all)) {
                if (uk_phone_mod.tryMatchAt(input, cursor)) |m| {
                    try spans.append(allocator, toMatch(m));
                    cursor = m.end;
                    continue;
                }
            }
            if (flags.ca_sin and (flags.locale == .ca or flags.locale == .all)) {
                if (ca_sin_mod.tryMatchAt(input, cursor)) |m| {
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
            if (is_word_start and flags.licenses) {
                if (license_mod.tryMatchAt(input, cursor)) |m| {
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
            const allow_us = (flags.locale == .us or flags.locale == .all);
            if (phone_mod.tryMatchAt(input, cursor, allow_us)) |m| {
                try spans.append(allocator, toMatch(m));
                cursor = m.end;
                continue;
            }
        }
        
        if (flags.uk_phone and (input[cursor] == '(' or input[cursor] == '+')) {
            if (uk_phone_mod.tryMatchAt(input, cursor)) |m| {
                try spans.append(allocator, toMatch(m));
                cursor = m.end;
                continue;
            }
        }

        // intl_phone is a fallback for `+` prefixes that phone_mod does not
        // recognise (e.g. +44 UK, +33 France). Both check `+` but only one
        // fires per cursor position: if phone_mod consumes the match its
        // `continue` advances the cursor and intl_phone is never reached.
        if (flags.intl_phone and input[cursor] == '+') {
            if (intl_phone_mod.tryMatchAt(input, cursor)) |m| {
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

        if ((flags.iban or flags.uk_nino or flags.accounts or flags.licenses) and std.ascii.isAlphabetic(input[cursor])) {
            if (is_word_start and flags.licenses) {
                if (license_mod.tryMatchAt(input, cursor)) |m| {
                    try spans.append(allocator, toMatch(m));
                    cursor = m.end;
                    continue;
                }
            }
            if (is_word_start and flags.accounts) {
                const allow_us = (flags.locale == .us or flags.locale == .all);
                if (account_mod.tryMatchAt(input, cursor, allow_us)) |m| {
                    try spans.append(allocator, toMatch(m));
                    cursor = m.end;
                    continue;
                }
            }
            if (flags.iban and (flags.locale == .eu or flags.locale == .all)) {
                if (iban_mod.tryMatchAt(input, cursor)) |m| {
                    try spans.append(allocator, toMatch(m));
                    cursor = m.end;
                    continue;
                }
            }
            if (flags.uk_nino and (flags.locale == .uk or flags.locale == .all)) {
                if (uk_nino_mod.tryMatchAt(input, cursor)) |m| {
                    try spans.append(allocator, toMatch(m));
                    cursor = m.end;
                    continue;
                }
            }
            if (flags.uk_nhs and (flags.locale == .uk or flags.locale == .all)) {
                if (uk_nhs_mod.tryMatchAt(input, cursor)) |m| {
                    try spans.append(allocator, toMatch(m));
                    cursor = m.end;
                    continue;
                }
            }
        }

        if (flags.passport and (input[cursor] == 'P' or input[cursor] == 'p') and (flags.locale == .eu or flags.locale == .all)) {
            if (passport_mod.tryMatchAt(input, cursor)) |m| {
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

test "scanner - iban" {
    const allocator = std.testing.allocator;
    const result = try redact("IBAN DE89 3704 0044 0532 0130 00 recorded", .{ .iban = true, .locale = .eu }, allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("IBAN [IBAN_REDACTED] recorded", result);
}

test "scanner - uk nino" {
    const allocator = std.testing.allocator;
    const result = try redact("Employee AA 12 34 56 C onboarded", .{ .uk_nino = true, .locale = .uk }, allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Employee [UK_NINO_REDACTED] onboarded", result);
}

test "scanner - passport label" {
    const allocator = std.testing.allocator;
    const result = try redact("Passport Number: 123456789 verified", .{ .passport = true, .locale = .eu }, allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Passport Number: [PASSPORT_REDACTED] verified", result);
}

test "scanner - intl phone" {
    const allocator = std.testing.allocator;
    const result = try redact("Call +44 7700 900123 today", .{ .intl_phone = true }, allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Call [INTL_PHONE_REDACTED] today", result);
}
