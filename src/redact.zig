const std = @import("std");

/// Redacts SSNs in-place in the given buffer.
/// Matches any sequence of XXX-XX-XXXX (digits only) and replaces the digits with '*'.
pub fn redactSsn(buffer: []u8) void {
    var i: usize = 0;
    while (i + 11 <= buffer.len) {
        if (std.ascii.isDigit(buffer[i]) and std.ascii.isDigit(buffer[i + 1]) and std.ascii.isDigit(buffer[i + 2]) and
            buffer[i + 3] == '-' and
            std.ascii.isDigit(buffer[i + 4]) and std.ascii.isDigit(buffer[i + 5]) and
            buffer[i + 6] == '-' and
            std.ascii.isDigit(buffer[i + 7]) and std.ascii.isDigit(buffer[i + 8]) and std.ascii.isDigit(buffer[i + 9]) and std.ascii.isDigit(buffer[i + 10]))
        {
            buffer[i] = '*';
            buffer[i + 1] = '*';
            buffer[i + 2] = '*';
            buffer[i + 4] = '*';
            buffer[i + 5] = '*';
            buffer[i + 7] = '*';
            buffer[i + 8] = '*';
            buffer[i + 9] = '*';
            buffer[i + 10] = '*';
            i += 11;
        } else {
            i += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "redactSsn - basic multi-SSN redaction" {
    var buf = "Hello my SSN is 123-45-6789 and my friend is 987-65-4321!".*;
    redactSsn(&buf);
    try std.testing.expectEqualStrings("Hello my SSN is ***-**-**** and my friend is ***-**-****!", &buf);
}

test "redactSsn - no SSNs present" {
    var buf = "This string has no sensitive data at all.".*;
    const expected = "This string has no sensitive data at all.";
    redactSsn(&buf);
    try std.testing.expectEqualStrings(expected, &buf);
}

test "redactSsn - SSN at start of buffer" {
    var buf = "123-45-6789 is at the start".*;
    redactSsn(&buf);
    try std.testing.expectEqualStrings("***-**-**** is at the start", &buf);
}

test "redactSsn - SSN at end of buffer" {
    var buf = "SSN at end: 123-45-6789".*;
    redactSsn(&buf);
    try std.testing.expectEqualStrings("SSN at end: ***-**-****", &buf);
}

test "redactSsn - adjacent SSNs no separator" {
    var buf = "111-22-3333444-55-6666".*;
    redactSsn(&buf);
    try std.testing.expectEqualStrings("***-**-*******-**-****", &buf);
}

test "redactSsn - partial pattern is not redacted" {
    // Only 2 leading digits instead of 3 -- should NOT match.
    var buf = "12-34-5678 is not an SSN".*;
    const expected = "12-34-5678 is not an SSN";
    redactSsn(&buf);
    try std.testing.expectEqualStrings(expected, &buf);
}

test "redactSsn - empty buffer" {
    var buf: [0]u8 = .{};
    redactSsn(&buf); // must not panic
    try std.testing.expectEqual(@as(usize, 0), buf.len);
}

test "redactSsn - SSN with surrounding digits" {
    // "9123-45-67890" = 13 chars.
    // At i=0: buf[3]='3' (not '-'), no match.
    // At i=1: "123-45-6789" matches, gets redacted. i advances to 12.
    // Result: "9***-**-****0"
    var buf = "9123-45-67890".*;
    redactSsn(&buf);
    try std.testing.expectEqualStrings("9***-**-****0", &buf);
}
