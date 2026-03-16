const std = @import("std");

const url_replacement = "[URL_REDACTED]";

const url_prefixes = [_][]const u8{ "http://", "https://", "www." };

fn matchLabel(buf: []const u8, start: usize, needle: []const u8) bool {
    if (start + needle.len > buf.len) return false;
    for (0..needle.len) |i| {
        if (std.ascii.toLower(buf[start + i]) != std.ascii.toLower(needle[i])) return false;
    }
    return true;
}

fn isValidUrlChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '-' or c == '.' or c == '_' or c == '~' or c == ':' or c == '/' or c == '?' or c == '#' or c == '[' or c == ']' or c == '@' or c == '!' or c == '$' or c == '&' or c == '\'' or c == '(' or c == ')' or c == '*' or c == '+' or c == ',' or c == ';' or c == '=';
}

fn matchUrl(buf: []const u8, cursor: usize) ?struct { start: usize, end: usize } {
    for (url_prefixes) |prefix| {
        if (matchLabel(buf, cursor, prefix)) {
            var end = cursor + prefix.len;
            while (end < buf.len and isValidUrlChar(buf[end])) {
                end += 1;
            }
            // Need at least one character after prefix
            if (end > cursor + prefix.len) {
                // Remove trailing punctuation that often finishes sentences
                while (end > cursor + prefix.len) {
                    const last_c = buf[end - 1];
                    if (last_c == '.' or last_c == ',' or last_c == '!' or last_c == '?' or last_c == ';') {
                        end -= 1;
                    } else {
                        break;
                    }
                }
                return .{ .start = cursor, .end = end };
            }
        }
    }
    return null;
}

pub fn tryMatchAt(buf: []const u8, pos: usize) ?struct { start: usize, end: usize, redact_start: usize, replacement: []const u8 } {
    if (pos >= buf.len) return null;

    // Check word boundary so we don't match inside another word if not expected,
    // actually for URLs it's safe to just check `isAlphanumeric` boundary,
    // but some apps might embed URLs like `href="http://..."`. Wait! Quotes are NOT alphanumeric. So word boundary is fine.
    if (pos > 0 and std.ascii.isAlphanumeric(buf[pos - 1])) return null;

    const c = std.ascii.toLower(buf[pos]);
    if (c == 'h' or c == 'w') {
        if (matchUrl(buf, pos)) |m| {
            return .{ .start = m.start, .end = m.end, .redact_start = m.start, .replacement = url_replacement };
        }
    }

    return null;
}

test "url - http" {
    const input = "Visit http://example.com/path today";
    const start = std.mem.indexOf(u8, input, "http").?;
    const m = tryMatchAt(input, start).?;
    try std.testing.expectEqualStrings("http://example.com/path", input[m.start..m.end]);
    try std.testing.expectEqualStrings(url_replacement, m.replacement);
}

test "url - https" {
    const input = "Go to https://securesite.org! ok";
    const start = std.mem.indexOf(u8, input, "https").?;
    const m = tryMatchAt(input, start).?;
    // The trailing exclamation mark should be excluded
    try std.testing.expectEqualStrings("https://securesite.org", input[m.start..m.end]);
}

test "url - www" {
    const input = "Check www.google.com, it works.";
    const start = std.mem.indexOf(u8, input, "www").?;
    const m = tryMatchAt(input, start).?;
    // The trailing comma should be excluded
    try std.testing.expectEqualStrings("www.google.com", input[m.start..m.end]);
}
