const std = @import("std");

const replacement = "[SIN_REDACTED]";
const health_replacement = "[HEALTH_REDACTED]";

fn isBoundary(byte: u8) bool {
    return !(std.ascii.isAlphanumeric(byte) or byte == '_');
}

/// Validates a Canadian SIN using the Luhn algorithm.
/// Input must be exactly 9 digits.
fn isValidSin(digits: []const u8) bool {
    if (digits.len != 9) return false;

    // Reject all-zeroes or prefixes that are explicitly invalid
    if (digits[0] == '0' and digits[1] == '0' and digits[2] == '0') return false;

    var sum: u32 = 0;
    for (digits, 0..) |d, i| {
        if (!std.ascii.isDigit(d)) return false;
        const val: u32 = d - '0';

        if (i % 2 == 1) { // Every second digit (1, 3, 5, 7) is doubled
            const doubled = val * 2;
            sum += if (doubled > 9) doubled - 9 else doubled;
        } else {
            sum += val;
        }
    }

    return sum % 10 == 0;
}

pub fn tryMatchAt(buf: []const u8, pos: usize) ?struct { start: usize, end: usize, redact_start: usize, replacement: []const u8 } {
    if (pos >= buf.len) return null;
    if (pos > 0 and !isBoundary(buf[pos - 1])) return null;

    const c = buf[pos];

    // Check for SIN (9 digits, often 999 999 999 or 999-999-999)
    if (std.ascii.isDigit(c)) {
        var digits: [9]u8 = undefined;
        var digit_count: usize = 0;
        var i = pos;
        var last_was_sep = false;
        var invalid = false;

        while (i < buf.len and digit_count < 9) {
            const b = buf[i];
            if (std.ascii.isDigit(b)) {
                digits[digit_count] = b;
                digit_count += 1;
                last_was_sep = false;
            } else if (b == ' ' or b == '-') {
                if (digit_count == 0 or last_was_sep) {
                    invalid = true;
                    break;
                }
                if (digit_count != 3 and digit_count != 6) {
                    invalid = true;
                    break;
                }
                last_was_sep = true;
            } else {
                break;
            }
            i += 1;
        }

        if (!invalid and digit_count == 9 and !last_was_sep) {
            if (i >= buf.len or isBoundary(buf[i])) {
                if (isValidSin(digits[0..9])) {
                    return .{
                        .start = pos,
                        .end = i,
                        .redact_start = pos,
                        .replacement = replacement,
                    };
                }
            }
        }
    }

    // Check for provincial health card formats, e.g. OHIP (10 digits)
    if (std.ascii.isDigit(c)) {
        var digits: [10]u8 = undefined;
        var digit_count: usize = 0;
        var i = pos;
        var last_was_sep = false;
        var invalid = false;

        while (i < buf.len and digit_count < 10) {
            const b = buf[i];
            if (std.ascii.isDigit(b)) {
                digits[digit_count] = b;
                digit_count += 1;
                last_was_sep = false;
            } else if (b == ' ' or b == '-') {
                if (digit_count == 0 or last_was_sep) {
                    invalid = true;
                    break;
                }
                if (digit_count != 4 and digit_count != 7) {
                    invalid = true;
                    break;
                }
                last_was_sep = true;
            } else {
                break;
            }
            i += 1;
        }

        if (!invalid and digit_count == 10 and !last_was_sep) {
            if (i >= buf.len or isBoundary(buf[i])) {
                return .{
                    .start = pos,
                    .end = i,
                    .redact_start = pos,
                    .replacement = health_replacement,
                };
            }
        }
    }

    return null;
}

test "ca sin - contiguous valid" {
    // 046454286 is a known valid test SIN
    const result = tryMatchAt("046454286", 0);
    try std.testing.expect(result != null);
    try std.testing.expectEqualStrings("046454286", "046454286"[result.?.start..result.?.end]);
}

test "ca sin - hyphens valid" {
    const result = tryMatchAt("046-454-286", 0);
    try std.testing.expect(result != null);
}

test "ca sin - spaces valid" {
    const result = tryMatchAt("046 454 286", 0);
    try std.testing.expect(result != null);
}

test "ca sin - invalid checksum" {
    // Modify last digit
    try std.testing.expect(tryMatchAt("046454287", 0) == null);
}

test "ca health - ohip 4-3-3" {
    const result = tryMatchAt("1234-567-890", 0);
    try std.testing.expect(result != null);
    try std.testing.expectEqualStrings(health_replacement, result.?.replacement);
}
