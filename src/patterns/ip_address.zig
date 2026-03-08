const std = @import("std");

// ---------------------------------------------------------------------------
// IP address redaction (IPv4 and IPv6)
// ---------------------------------------------------------------------------
// Strategy:
//   IPv4: scan for sequences matching N.N.N.N where each octet is 0–255.
//     Skip version numbers by checking for preceding 'v' or 'V'.
//   IPv6: scan for sequences with multiple colons containing hex digits.
//     Handle standard, compressed (::), and IPv4-mapped formats.
// ---------------------------------------------------------------------------

const ipv4_replacement = "[IPV4_REDACTED]";
const ipv6_replacement = "[IPV6_REDACTED]";

/// Validate and measure an IPv4 address starting at `start`.
/// Returns the end position (exclusive) or null if invalid.
fn matchIpv4(buf: []const u8, start: usize) ?usize {
    var pos = start;
    var octet_count: u8 = 0;

    while (octet_count < 4) {
        if (pos >= buf.len or !std.ascii.isDigit(buf[pos])) return null;

        // Parse octet value
        var val: u16 = 0;
        var digit_count: u8 = 0;
        while (pos < buf.len and std.ascii.isDigit(buf[pos]) and digit_count < 4) {
            val = val * 10 + @as(u16, buf[pos] - '0');
            digit_count += 1;
            pos += 1;
        }

        if (digit_count == 0 or val > 255) return null;
        // Reject leading zeros (e.g., "01", "001") unless the value is 0 and single digit
        if (digit_count > 1 and buf[pos - digit_count] == '0') return null;

        octet_count += 1;

        // Expect a dot between octets (but not after the last)
        if (octet_count < 4) {
            if (pos >= buf.len or buf[pos] != '.') return null;
            pos += 1;
        }
    }

    return pos;
}

/// Check if a byte is a valid hex digit.
inline fn isHexDigit(c: u8) bool {
    return std.ascii.isDigit(c) or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F');
}

/// Validate and measure an IPv6 address starting at `start`.
/// Returns the end position (exclusive) or null if invalid.
fn matchIpv6(buf: []const u8, start: usize) ?usize {
    var pos = start;
    var group_count: u8 = 0;
    var has_double_colon = false;

    // Handle leading ::
    if (pos + 1 < buf.len and buf[pos] == ':' and buf[pos + 1] == ':') {
        has_double_colon = true;
        pos += 2;

        // :: alone is valid (loopback)
        if (pos >= buf.len or (!isHexDigit(buf[pos]) and buf[pos] != ':')) {
            if (group_count == 0) return pos;
            return null;
        }
    }

    while (pos < buf.len and group_count < 8) {
        // Parse hex group (1-4 hex digits)
        const hex_start = pos;
        while (pos < buf.len and isHexDigit(buf[pos]) and (pos - hex_start) < 4) {
            pos += 1;
        }
        const hex_len = pos - hex_start;

        if (hex_len == 0) {
            if (has_double_colon) break;
            return null;
        }

        group_count += 1;

        // Check for :: or : separator
        if (pos < buf.len and buf[pos] == ':') {
            if (pos + 1 < buf.len and buf[pos + 1] == ':') {
                if (has_double_colon) return null; // only one :: allowed
                has_double_colon = true;
                pos += 2;

                // Check if we're at the end
                if (pos >= buf.len or (!isHexDigit(buf[pos]))) {
                    break;
                }
            } else {
                pos += 1;
                // Must be followed by hex digit
                if (pos >= buf.len or !isHexDigit(buf[pos])) {
                    // Rewind the colon — it's not part of the address
                    pos -= 1;
                    break;
                }
            }
        } else {
            break;
        }
    }

    // Validate group count: exactly 8 groups without ::, or fewer with ::
    if (has_double_colon) {
        if (group_count > 7) return null;
    } else {
        if (group_count != 8) return null;
    }

    // Must have at least 2 groups (or :: which represents multiple)
    if (!has_double_colon and group_count < 2) return null;

    return pos;
}

/// Redact all IP addresses in the input, replacing with type-specific tokens.
/// Returns an owned slice (caller must free).
pub fn redactIpAddresses(input: []const u8, allocator: std.mem.Allocator) ![]u8 {
    if (input.len < 3) {
        return try allocator.dupe(u8, input);
    }

    var result = std.ArrayListUnmanaged(u8).empty;
    errdefer result.deinit(allocator);

    var cursor: usize = 0;

    while (cursor < input.len) {
        const c = input[cursor];

        // --- IPv4 detection ---
        if (std.ascii.isDigit(c)) {
            // Skip if preceded by a version indicator 'v' or 'V'
            const preceded_by_version = cursor > 0 and (input[cursor - 1] == 'v' or input[cursor - 1] == 'V');
            // Skip if preceded by another digit (part of a larger number)
            const preceded_by_digit = cursor > 0 and std.ascii.isDigit(input[cursor - 1]);
            // Skip if preceded by '.' (we're in the middle of something)
            const preceded_by_dot = cursor > 0 and input[cursor - 1] == '.';

            if (!preceded_by_version and !preceded_by_digit and !preceded_by_dot) {
                if (matchIpv4(input, cursor)) |end| {
                    // Make sure it's not followed by more digits or dots
                    const followed_by_alnum = end < input.len and (std.ascii.isDigit(input[end]) or input[end] == '.');

                    if (!followed_by_alnum) {
                        // Handle optional CIDR notation
                        if (end < input.len and input[end] == '/') {
                            var cidr_end = end + 1;
                            while (cidr_end < input.len and std.ascii.isDigit(input[cidr_end])) {
                                cidr_end += 1;
                            }
                            if (cidr_end > end + 1) {
                                try result.appendSlice(allocator, ipv4_replacement);
                                // Preserve the CIDR suffix
                                try result.appendSlice(allocator, input[end..cidr_end]);
                                cursor = cidr_end;
                                continue;
                            }
                        }

                        try result.appendSlice(allocator, ipv4_replacement);
                        cursor = end;
                        continue;
                    }
                }
            }
        }

        // --- IPv6 detection ---
        if (isHexDigit(c) or c == ':') {
            // Only attempt IPv6 if it looks plausible: hex digit or starts with ::
            const is_start_of_ipv6 = (c == ':' and cursor + 1 < input.len and input[cursor + 1] == ':') or
                (isHexDigit(c) and !std.ascii.isAlphabetic(c));

            // Don't try if preceded by alphanumeric (part of a word)
            const preceded_by_alnum = cursor > 0 and (std.ascii.isAlphanumeric(input[cursor - 1]) or input[cursor - 1] == ':');

            if (is_start_of_ipv6 and !preceded_by_alnum) {
                if (matchIpv6(input, cursor)) |end| {
                    // Ensure we found a long enough match (at least "::1" style)
                    if (end - cursor >= 3) {
                        // Not followed by hex or colon
                        const followed_by_hex = end < input.len and (isHexDigit(input[end]) or input[end] == ':');
                        if (!followed_by_hex) {
                            try result.appendSlice(allocator, ipv6_replacement);
                            cursor = end;
                            continue;
                        }
                    }
                }
            }
        }

        try result.append(allocator, input[cursor]);
        cursor += 1;
    }

    return try result.toOwnedSlice(allocator);
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

test "ipv4 - standard address" {
    const allocator = std.testing.allocator;
    const result = try redactIpAddresses("Server at 192.168.1.1 is up", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Server at [IPV4_REDACTED] is up", result);
}

test "ipv4 - loopback" {
    const allocator = std.testing.allocator;
    const result = try redactIpAddresses("Connect to 127.0.0.1 now", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Connect to [IPV4_REDACTED] now", result);
}

test "ipv4 - max values" {
    const allocator = std.testing.allocator;
    const result = try redactIpAddresses("IP 255.255.255.255 broadcast", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("IP [IPV4_REDACTED] broadcast", result);
}

test "ipv4 - rejects version number v1.2.3.4" {
    const allocator = std.testing.allocator;
    const result = try redactIpAddresses("Running v1.2.3.4 release", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Running v1.2.3.4 release", result);
}

test "ipv4 - rejects V2.1.0.3 uppercase" {
    const allocator = std.testing.allocator;
    const result = try redactIpAddresses("Version V2.1.0.3 here", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Version V2.1.0.3 here", result);
}

test "ipv4 - rejects octet > 255" {
    const allocator = std.testing.allocator;
    const result = try redactIpAddresses("Bad 999.999.999.999 data", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Bad 999.999.999.999 data", result);
}

test "ipv4 - CIDR notation preserved" {
    const allocator = std.testing.allocator;
    const result = try redactIpAddresses("Subnet 192.168.1.0/24 ok", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Subnet [IPV4_REDACTED]/24 ok", result);
}

test "ipv4 - multiple addresses" {
    const allocator = std.testing.allocator;
    const result = try redactIpAddresses("From 10.0.0.1 to 10.0.0.2 done", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("From [IPV4_REDACTED] to [IPV4_REDACTED] done", result);
}

test "ipv6 - full address" {
    const allocator = std.testing.allocator;
    const result = try redactIpAddresses("Addr 2001:0db8:85a3:0000:0000:8a2e:0370:7334 here", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Addr [IPV6_REDACTED] here", result);
}

test "ipv6 - compressed loopback" {
    const allocator = std.testing.allocator;
    const result = try redactIpAddresses("Loopback ::1 here", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Loopback [IPV6_REDACTED] here", result);
}

test "ip - no IPs unchanged" {
    const allocator = std.testing.allocator;
    const result = try redactIpAddresses("This text has no IP addresses.", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("This text has no IP addresses.", result);
}

test "ip - empty input" {
    const allocator = std.testing.allocator;
    const result = try redactIpAddresses("", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("", result);
}

test "ipv4 - rejects leading zeros" {
    const allocator = std.testing.allocator;
    const result = try redactIpAddresses("Bad 192.168.01.1 here", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Bad 192.168.01.1 here", result);
}
