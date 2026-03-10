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

/// Single-position match for the unified scanner.
/// Tries IPv4 first (digit trigger), then IPv6 (hex digit or `::` trigger).
/// CIDR suffixes are excluded from the match so they pass through in the output.
pub fn tryMatchAt(buf: []const u8, pos: usize) ?struct { start: usize, end: usize, redact_start: usize, replacement: []const u8 } {
    if (pos >= buf.len) return null;
    const c = buf[pos];

    // --- IPv4 ---
    if (std.ascii.isDigit(c)) {
        const preceded_by_version = pos > 0 and (buf[pos - 1] == 'v' or buf[pos - 1] == 'V');
        const preceded_by_digit = pos > 0 and std.ascii.isDigit(buf[pos - 1]);
        const preceded_by_dot = pos > 0 and buf[pos - 1] == '.';

        if (!preceded_by_version and !preceded_by_digit and !preceded_by_dot) {
            if (matchIpv4(buf, pos)) |end| {
                const followed_by_alnum = end < buf.len and (std.ascii.isDigit(buf[end]) or buf[end] == '.');
                if (!followed_by_alnum) {
                    return .{ .start = pos, .end = end, .redact_start = pos, .replacement = ipv4_replacement };
                }
            }
        }
    }

    // --- IPv6 ---
    if (isHexDigit(c) or c == ':') {
        const is_start_of_ipv6 = (c == ':' and pos + 1 < buf.len and buf[pos + 1] == ':') or
            (isHexDigit(c) and !std.ascii.isAlphabetic(c));
        const preceded_by_alnum = pos > 0 and (std.ascii.isAlphanumeric(buf[pos - 1]) or buf[pos - 1] == ':');

        if (is_start_of_ipv6 and !preceded_by_alnum) {
            if (matchIpv6(buf, pos)) |end| {
                if (end - pos >= 3) {
                    const followed_by_hex = end < buf.len and (isHexDigit(buf[end]) or buf[end] == ':');
                    if (!followed_by_hex) {
                        return .{ .start = pos, .end = end, .redact_start = pos, .replacement = ipv6_replacement };
                    }
                }
            }
        }
    }

    return null;
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

test "ipv4 - standard address" {
    const input = "Server at 192.168.1.1 is up";
    const start = std.mem.indexOf(u8, input, "192").?;
    const m = tryMatchAt(input, start).?;
    try std.testing.expectEqualStrings("192.168.1.1", input[m.start..m.end]);
    try std.testing.expectEqualStrings(ipv4_replacement, m.replacement);
}

test "ipv4 - loopback" {
    const input = "Connect to 127.0.0.1 now";
    const start = std.mem.indexOf(u8, input, "127").?;
    const m = tryMatchAt(input, start).?;
    try std.testing.expectEqualStrings("127.0.0.1", input[m.start..m.end]);
}

test "ipv4 - max values" {
    const input = "IP 255.255.255.255 broadcast";
    const start = std.mem.indexOf(u8, input, "255").?;
    const m = tryMatchAt(input, start).?;
    try std.testing.expectEqualStrings("255.255.255.255", input[m.start..m.end]);
}

test "ipv4 - rejects version number v1.2.3.4" {
    const input = "Running v1.2.3.4 release";
    // 'v' precedes the digit, so tryMatchAt at the digit position should reject
    const start = std.mem.indexOf(u8, input, "1.2.3.4").?;
    try std.testing.expect(tryMatchAt(input, start) == null);
}

test "ipv4 - rejects V2.1.0.3 uppercase" {
    const input = "Version V2.1.0.3 here";
    const start = std.mem.indexOf(u8, input, "2.1.0.3").?;
    try std.testing.expect(tryMatchAt(input, start) == null);
}

test "ipv4 - rejects octet > 255" {
    const input = "Bad 999.999.999.999 data";
    const start = std.mem.indexOf(u8, input, "999").?;
    try std.testing.expect(tryMatchAt(input, start) == null);
}

test "ipv4 - CIDR suffix excluded from match" {
    const input = "Subnet 192.168.1.0/24 ok";
    const start = std.mem.indexOf(u8, input, "192").?;
    const m = tryMatchAt(input, start).?;
    try std.testing.expectEqualStrings("192.168.1.0", input[m.start..m.end]);
    // Verify CIDR suffix is NOT consumed by the match
    try std.testing.expect(input[m.end] == '/');
}

test "ipv6 - full address" {
    const input = "Addr 2001:0db8:85a3:0000:0000:8a2e:0370:7334 here";
    const start = std.mem.indexOf(u8, input, "2001").?;
    const m = tryMatchAt(input, start).?;
    try std.testing.expectEqualStrings("2001:0db8:85a3:0000:0000:8a2e:0370:7334", input[m.start..m.end]);
    try std.testing.expectEqualStrings(ipv6_replacement, m.replacement);
}

test "ipv6 - compressed loopback" {
    const input = "Loopback ::1 here";
    const start = std.mem.indexOfScalar(u8, input, ':').?;
    const m = tryMatchAt(input, start).?;
    try std.testing.expectEqualStrings("::1", input[m.start..m.end]);
    try std.testing.expectEqualStrings(ipv6_replacement, m.replacement);
}

test "ipv4 - rejects leading zeros" {
    const input = "Bad 192.168.01.1 here";
    const start = std.mem.indexOf(u8, input, "192").?;
    try std.testing.expect(tryMatchAt(input, start) == null);
}
