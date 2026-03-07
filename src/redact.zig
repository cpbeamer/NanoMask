const std = @import("std");

fn isDigit(c: u8) bool {
    return std.ascii.isDigit(c);
}

/// Redacts SSNs in-place in the given buffer.
/// Matches any sequence of XXX-XX-XXXX (digits only) and replaces the digits with '*'.
pub fn redactSsn(buffer: []u8) void {
    var i: usize = 0;
    while (i + 11 <= buffer.len) {
        if (isDigit(buffer[i]) and isDigit(buffer[i+1]) and isDigit(buffer[i+2]) and
            buffer[i+3] == '-' and
            isDigit(buffer[i+4]) and isDigit(buffer[i+5]) and
            buffer[i+6] == '-' and
            isDigit(buffer[i+7]) and isDigit(buffer[i+8]) and isDigit(buffer[i+9]) and isDigit(buffer[i+10])) {
            
            buffer[i] = '*';
            buffer[i+1] = '*';
            buffer[i+2] = '*';
            buffer[i+4] = '*';
            buffer[i+5] = '*';
            buffer[i+7] = '*';
            buffer[i+8] = '*';
            buffer[i+9] = '*';
            buffer[i+10] = '*';
            i += 11;
        } else {
            i += 1;
        }
    }
}

test "redactSsn" {
    var buf = "Hello my SSN is 123-45-6789 and my friend is 987-65-4321!".*;
    redactSsn(&buf);
    try std.testing.expectEqualStrings("Hello my SSN is ***-**-**** and my friend is ***-**-****!", &buf);
}
