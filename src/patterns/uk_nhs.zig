const std = @import("std");

const replacement = "[NHS_REDACTED]";

fn isBoundary(byte: u8) bool {
    return !(std.ascii.isAlphanumeric(byte) or byte == '_');
}

/// Computes the Modulo 11 check digit for a 9-digit NHS number payload.
/// The 10th digit is the check digit.
fn computeNhsCheckDigit(digits: [9]u8) ?u8 {
    var sum: u32 = 0;
    // Weights are 10 down to 2
    for (digits, 0..) |d, i| {
        sum += d * @as(u32, 10 - @as(u32, @intCast(i)));
    }
    
    const rem = sum % 11;
    const check = 11 - rem;
    
    if (check == 11) return 0;
    if (check == 10) return null; // Invalid NHS number
    return @intCast(check);
}

pub fn tryMatchAt(buf: []const u8, pos: usize) ?struct { start: usize, end: usize, redact_start: usize, replacement: []const u8 } {
    // Need at least 10 digits
    if (pos + 10 > buf.len) return null;
    
    // Must be preceded by boundary
    if (pos > 0 and !isBoundary(buf[pos - 1])) return null;

    // Fast reject: first char must be a digit
    if (!std.ascii.isDigit(buf[pos])) return null;

    // Supported formats:
    // 1. 1234567890 (Contiguous)
    // 2. 123 456 7890 (Spaced)
    // 3. 123-456-7890 (Dashed)

    var digits: [10]u8 = undefined;
    var digit_count: usize = 0;
    
    var i: usize = pos;
    var last_was_sep = false;

    while (i < buf.len and digit_count < 10) {
        const c = buf[i];
        if (std.ascii.isDigit(c)) {
            digits[digit_count] = c - '0';
            digit_count += 1;
            last_was_sep = false;
        } else if (c == ' ' or c == '-') {
            // Cannot have leading sep or consecutive seps
            if (digit_count == 0 or last_was_sep) return null;
            // Spacing must be 3-3-4
            if (digit_count != 3 and digit_count != 6) return null;
            last_was_sep = true;
        } else {
            break;
        }
        i += 1;
    }

    if (digit_count != 10) return null;
    
    // Cannot end with a separator
    if (last_was_sep) return null;

    // Must be followed by boundary
    if (i < buf.len and !isBoundary(buf[i])) return null;

    // Validate check digit
    const expected_check = computeNhsCheckDigit(digits[0..9].*);
    if (expected_check == null or expected_check.? != digits[9]) return null;

    return .{
        .start = pos,
        .end = i,
        .redact_start = pos,
        .replacement = replacement,
    };
}

test "nhs number - contiguous valid" {
    // 9434765919 is a commonly used NHS test number
    const result = tryMatchAt("9434765919", 0);
    try std.testing.expect(result != null);
    try std.testing.expectEqualStrings("9434765919", "9434765919"[result.?.start..result.?.end]);
}

test "nhs number - spaced valid" {
    const result = tryMatchAt("943 476 5919", 0);
    try std.testing.expect(result != null);
}

test "nhs number - dashed valid" {
    const result = tryMatchAt("943-476-5919", 0);
    try std.testing.expect(result != null);
}

test "nhs number - invalid check digit" {
    // Ends with 0 instead of 9
    try std.testing.expect(tryMatchAt("9434765910", 0) == null);
}

test "nhs number - bad spacing" {
    try std.testing.expect(tryMatchAt("94 347 65919", 0) == null);
}
