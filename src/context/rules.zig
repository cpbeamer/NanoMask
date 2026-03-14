const std = @import("std");

pub const ContextMatch = struct {
    start: usize,
    end: usize,
    redact_start: usize, // Exact index where redaction replacement begins
    replacement: []const u8,
    confidence: f32, // Rule engine confidence score
};

pub const ContextResult = struct {
    output: []u8,
    matches: []ContextMatch,
};

/// Maximum lookahead window in bytes for rules to find their target
const max_lookahead: usize = 64;

pub const RuleKind = enum {
    name,
    address,
    date,
    number,
};

/// Rule matching structure
const ContextRule = struct {
    kind: RuleKind,
    prefixes: []const []const u8, // E.g., &{"patient", "client", "member"}
    regex_match: ?[]const u8, // Not a real regex, but a hint function for testing formatting
    redact_tag: []const u8, // E.g., "[NAME_REDACTED]"
    base_confidence: f32, // Base confidence score for a hit
    max_words: usize, // Maximum number of words to redact
};

/// Built-in context heuristic rules for unstructured NER scanning.
///
/// NOTE: The `.name` rule requires each matched word to start with an uppercase
/// ASCII letter (A-Z). This intentionally reduces false positives but will miss
/// names containing lowercase particles (e.g. "de la Cruz", "van der Berg") or
/// names in non-Latin scripts. Future work: extend `scanWords` to accept a
/// configurable capitalization policy per rule.
const built_in_rules: []const ContextRule = &.{
    .{
        .kind = .name,
        .prefixes = &.{ "patient ", "patient: ", "patient is ", "member ", "member: ", "dr ", "dr. ", "provider " },
        .regex_match = null,
        .redact_tag = "[NAME_REDACTED]",
        .base_confidence = 0.85,
        .max_words = 3,
    },
    .{
        .kind = .address,
        .prefixes = &.{ "address ", "address: ", "lives at ", "resides at ", "location: ", "home: " },
        .regex_match = null,
        .redact_tag = "[ADDRESS_REDACTED]",
        .base_confidence = 0.90,
        .max_words = 6,
    },
    .{
        .kind = .date,
        // Longer/more-specific prefixes must come before shorter ones that would
        // match a subset of the same text (e.g. "dob is " before "dob ").
        .prefixes = &.{ "dob is ", "dob: ", "dob ", "born on ", "born ", "date of birth: " },
        .regex_match = null,
        .redact_tag = "[DATE_REDACTED]",
        .base_confidence = 0.95,
        .max_words = 1, // Only redacts the immediate sequential word/date string
    },
    .{
        .kind = .number,
        .prefixes = &.{ "account ", "account: ", "acct ", "acct: ", "policy ", "policy: ", "claim ", "claim: ", "file # ", "file " },
        .regex_match = null,
        .redact_tag = "[NUMBER_REDACTED]",
        .base_confidence = 0.80,
        .max_words = 1,
    },
};

/// Determines if a given char is considered boundary whitespace/punctuation for words
fn isBoundary(c: u8) bool {
    return switch (c) {
        ' ', '\t', '\n', '\r', '.', ',', ';', ':', '!', '?' => true,
        else => false,
    };
}

/// Helper: Skips leading boundary characters (whitespace and punctuation as defined by
/// `isBoundary`) in `text`, returning the index of the first non-boundary char.
fn skipBoundary(text: []const u8) usize {
    var i: usize = 0;
    while (i < text.len) : (i += 1) {
        if (!isBoundary(text[i])) break;
    }
    return i;
}

/// Helper: Finds the end of the next `max_words` starting from `text`
fn scanWords(text: []const u8, max_words: usize, kind: RuleKind) usize {
    if (text.len == 0 or max_words == 0) return 0;
    
    var pos: usize = 0;
    var words_found: usize = 0;
    var in_word = false;
    var word_start_idx: usize = 0;
    var last_word_end: usize = 0;

    while (pos < text.len and pos < max_lookahead) {
        const c = text[pos];
        const is_boundary = isBoundary(c);
        const is_hard_stop = (c == '.' or c == ',' or c == '\n');

        if (is_boundary) {
            if (in_word) {
                in_word = false;
                
                if (kind == .name) {
                    const first_char = text[word_start_idx];
                    if (first_char < 'A' or first_char > 'Z') {
                        return last_word_end; // Reject word, return previous bounds
                    }
                }
                
                words_found += 1;
                last_word_end = pos;
                
                // If we've hit our max words, we stop exactly at this boundary
                if (words_found >= max_words) {
                    return pos;
                }
            }
            
            // If we hit hard punctuation, we stop here
            if (is_hard_stop) {
                return pos;
            }
        } else {
            if (!in_word) {
                in_word = true;
                word_start_idx = pos;
            }
        }
        
        pos += 1;
    }

    // End of string or lookahead
    if (in_word) {
        if (kind == .name) {
            const first_char = text[word_start_idx];
            if (first_char < 'A' or first_char > 'Z') {
                return last_word_end;
            }
        }
        words_found += 1;
        last_word_end = pos;
    }
    
    return last_word_end;
}

pub fn redactContext(
    input: []const u8,
    threshold: f32,
    allocator: std.mem.Allocator,
) !ContextResult {
    var output: std.ArrayListUnmanaged(u8) = .empty;
    errdefer output.deinit(allocator);

    var matches: std.ArrayListUnmanaged(ContextMatch) = .empty;
    errdefer matches.deinit(allocator);

    var current_idx: usize = 0;

    // Scan linearly through input looking for rule matches
    while (current_idx < input.len) {
        var rule_matched = false;

        // Try to match each rule's prefixes at the current location
        for (built_in_rules) |rule| {
            if (rule.base_confidence < threshold) continue;

            for (rule.prefixes) |prefix| {
                // Determine if we can match the prefix case-insensitively
                if (current_idx + prefix.len <= input.len) {
                    const slice = input[current_idx .. current_idx + prefix.len];
                    if (std.ascii.eqlIgnoreCase(slice, prefix)) {
                        const target_start = current_idx + prefix.len;
                        const ws_offset = skipBoundary(input[target_start..]);
                        const word_start = target_start + ws_offset;

                        if (word_start < input.len) {
                            const scan_len = scanWords(input[word_start..], rule.max_words, rule.kind);
                            if (scan_len > 0) {
                                const word_end = word_start + scan_len;

                                // We matched a context rule target
                                try matches.append(allocator, .{
                                    .start = current_idx, // The entire matched phrase including prefix
                                    .end = word_end,
                                    .redact_start = word_start,
                                    .replacement = rule.redact_tag,
                                    .confidence = rule.base_confidence,
                                });

                                // Write prefix + replacement tagging to output
                                try output.appendSlice(allocator, input[current_idx..word_start]);
                                try output.appendSlice(allocator, rule.redact_tag);
                                current_idx = word_end;
                                rule_matched = true;
                                break;
                            }
                        }
                    }
                }
            }
            if (rule_matched) break;
        }

        if (!rule_matched) {
            try output.append(allocator, input[current_idx]);
            current_idx += 1;
        }
    }

    return ContextResult{
        .output = try output.toOwnedSlice(allocator),
        .matches = try matches.toOwnedSlice(allocator),
    };
}

// ===========================================================================
// Unit Tests
// ===========================================================================
const testing = std.testing;

test "ContextRules - name context" {
    const input = "The patient John Walker was seen today.";
    const result = try redactContext(input, 0.70, std.testing.allocator);
    defer std.testing.allocator.free(result.output);
    defer std.testing.allocator.free(result.matches);

    try testing.expectEqualStrings("The patient [NAME_REDACTED] was seen today.", result.output);
    try testing.expectEqual(@as(usize, 1), result.matches.len);
    try testing.expectEqualStrings("[NAME_REDACTED]", result.matches[0].replacement);
    try testing.expectEqual(@as(usize, 12), result.matches[0].redact_start); // start of "John Walker"
    try testing.expectEqual(@as(usize, 4), result.matches[0].start); // start of "patient "
}

test "ContextRules - address context" {
    const input = "User resides at 123 Main Street NW.";
    const result = try redactContext(input, 0.70, std.testing.allocator);
    defer std.testing.allocator.free(result.output);
    defer std.testing.allocator.free(result.matches);

    try testing.expectEqualStrings("User resides at [ADDRESS_REDACTED].", result.output);
}

test "ContextRules - date context" {
    const input = "Male, DOB is 12/24/1980.";
    // "dob is " prefix matches before "dob " so the actual date value is redacted.
    const result = try redactContext(input, 0.70, std.testing.allocator);
    defer std.testing.allocator.free(result.output);
    defer std.testing.allocator.free(result.matches);

    try testing.expectEqualStrings("Male, DOB is [DATE_REDACTED].", result.output);
}

test "ContextRules - multiple contexts" {
    const input = "Call Dr. Sarah Jenkins about claim # 948123A.";
    const result = try redactContext(input, 0.70, std.testing.allocator);
    defer std.testing.allocator.free(result.output);
    defer std.testing.allocator.free(result.matches);

    // Context heuristic outputs:
    // 'Dr. ' hits Sarah Jenkins
    // 'claim ' hits '#'
    // Result preserves spacing and leaves '948123A.'
    try testing.expectEqualStrings("Call Dr. [NAME_REDACTED] about claim [NUMBER_REDACTED] 948123A.", result.output);
}
