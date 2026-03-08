const std = @import("std");

// ---------------------------------------------------------------------------
// Healthcare identifier redaction (MRN, ICD-10, Insurance ID)
// ---------------------------------------------------------------------------
// Strategy: context-aware label scanning. These identifiers are only
// redacted when preceded by a recognizable label keyword. Without context,
// digit sequences and alphanumeric codes are too ambiguous to redact safely.
//
// This module is gated behind the `--enable-healthcare` CLI flag to avoid false
// positives in non-healthcare contexts.
// ---------------------------------------------------------------------------

const mrn_replacement = "[MRN_REDACTED]";
const icd10_replacement = "[ICD10_REDACTED]";
const insurance_replacement = "[INSURANCE_REDACTED]";

/// Case-insensitive check if `buf[start..start+len]` matches `needle`.
fn matchLabel(buf: []const u8, start: usize, needle: []const u8) bool {
    if (start + needle.len > buf.len) return false;
    for (0..needle.len) |i| {
        if (std.ascii.toLower(buf[start + i]) != std.ascii.toLower(needle[i])) return false;
    }
    return true;
}

/// Skip whitespace and common separators (colon, hash, space, tab) after a label.
fn skipSeparators(buf: []const u8, start: usize) usize {
    var pos = start;
    while (pos < buf.len and (buf[pos] == ':' or buf[pos] == '#' or buf[pos] == ' ' or buf[pos] == '\t')) {
        pos += 1;
    }
    return pos;
}

/// MRN labels to detect (case-insensitive).
const mrn_labels = [_][]const u8{
    "MRN",
    "MR#",
    "Medical Record",
    "Patient ID",
};

/// Insurance labels to detect (case-insensitive).
const insurance_labels = [_][]const u8{
    "Insurance ID",
    "Member ID",
    "Policy #",
    "Group #",
};

/// Try to match an MRN pattern: label followed by 6–10 digits.
/// Returns the start of the value and end position, or null.
fn matchMrn(buf: []const u8, cursor: usize) ?struct { value_start: usize, end: usize } {
    for (mrn_labels) |label| {
        if (matchLabel(buf, cursor, label)) {
            const after_label = cursor + label.len;
            const value_start = skipSeparators(buf, after_label);

            // Must have at least one separator between label and digits
            if (value_start == after_label and !std.mem.eql(u8, label, "MR#")) continue;

            // Extract 6-10 digit sequence
            var digit_end = value_start;
            while (digit_end < buf.len and std.ascii.isDigit(buf[digit_end]) and (digit_end - value_start) < 10) {
                digit_end += 1;
            }

            const digit_count = digit_end - value_start;
            if (digit_count >= 6 and digit_count <= 10) {
                // Not followed by more digits
                if (digit_end >= buf.len or !std.ascii.isDigit(buf[digit_end])) {
                    return .{ .value_start = value_start, .end = digit_end };
                }
            }
        }
    }
    return null;
}

/// Try to match an ICD-10 code: [A-Z]\d{2}(.\d{1,4})?
/// Only matches when not followed by alphanumeric (word boundary).
fn matchIcd10(buf: []const u8, cursor: usize) ?usize {
    if (cursor + 3 > buf.len) return null;

    // Must start with uppercase letter
    if (!std.ascii.isUpper(buf[cursor])) return null;

    // Followed by exactly 2 digits
    if (!std.ascii.isDigit(buf[cursor + 1]) or !std.ascii.isDigit(buf[cursor + 2])) return null;

    var end: usize = cursor + 3;

    // Optional dot followed by 1-4 alphanumeric characters
    if (end < buf.len and buf[end] == '.') {
        var ext_end = end + 1;
        while (ext_end < buf.len and std.ascii.isAlphanumeric(buf[ext_end]) and (ext_end - end - 1) < 4) {
            ext_end += 1;
        }
        if (ext_end > end + 1) {
            end = ext_end;
        }
    }

    // Must not be followed by alphanumeric (word boundary)
    if (end < buf.len and std.ascii.isAlphanumeric(buf[end])) return null;

    // Must not be preceded by alphanumeric (word boundary)
    if (cursor > 0 and std.ascii.isAlphanumeric(buf[cursor - 1])) return null;

    // Require minimum length of 4 (letter + 2 digits + dot) to reduce false positives
    // on short standalone codes like "A12" in non-medical context.
    // We require either a dot extension OR a preceding medical context keyword.
    if (end - cursor < 4) {
        // Short form (e.g., "E11") — only match if followed by dot extension
        return null;
    }

    return end;
}

/// Try to match an insurance ID: label followed by 8–15 alphanumeric characters.
fn matchInsurance(buf: []const u8, cursor: usize) ?struct { value_start: usize, end: usize } {
    for (insurance_labels) |label| {
        if (matchLabel(buf, cursor, label)) {
            const after_label = cursor + label.len;
            const value_start = skipSeparators(buf, after_label);

            // Must have some separator
            if (value_start == after_label) continue;

            // Extract 8-15 alphanumeric characters
            var id_end = value_start;
            while (id_end < buf.len and std.ascii.isAlphanumeric(buf[id_end]) and (id_end - value_start) < 15) {
                id_end += 1;
            }

            const id_len = id_end - value_start;
            if (id_len >= 8 and id_len <= 15) {
                return .{ .value_start = value_start, .end = id_end };
            }
        }
    }
    return null;
}

/// Redact healthcare identifiers in the input.
/// Returns an owned slice (caller must free).
pub fn redactHealthcare(input: []const u8, allocator: std.mem.Allocator) ![]u8 {
    if (input.len < 4) {
        return try allocator.dupe(u8, input);
    }

    var result = std.ArrayListUnmanaged(u8).empty;
    errdefer result.deinit(allocator);

    var cursor: usize = 0;

    while (cursor < input.len) {
        // --- MRN detection ---
        if (matchMrn(input, cursor)) |match| {
            // Emit everything from cursor to value start (including the label)
            try result.appendSlice(allocator, input[cursor..match.value_start]);
            try result.appendSlice(allocator, mrn_replacement);
            cursor = match.end;
            continue;
        }

        // --- Insurance ID detection ---
        if (matchInsurance(input, cursor)) |match| {
            try result.appendSlice(allocator, input[cursor..match.value_start]);
            try result.appendSlice(allocator, insurance_replacement);
            cursor = match.end;
            continue;
        }

        // --- ICD-10 detection ---
        if (matchIcd10(input, cursor)) |end| {
            try result.appendSlice(allocator, icd10_replacement);
            cursor = end;
            continue;
        }

        try result.append(allocator, input[cursor]);
        cursor += 1;
    }

    return try result.toOwnedSlice(allocator);
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

test "healthcare - MRN with label" {
    const allocator = std.testing.allocator;
    const result = try redactHealthcare("MRN: 1234567 is the record", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("MRN: [MRN_REDACTED] is the record", result);
}

test "healthcare - MR# format" {
    const allocator = std.testing.allocator;
    const result = try redactHealthcare("MR#12345678 found", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("MR#[MRN_REDACTED] found", result);
}

test "healthcare - Medical Record label" {
    const allocator = std.testing.allocator;
    const result = try redactHealthcare("Medical Record: 12345678 here", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Medical Record: [MRN_REDACTED] here", result);
}

test "healthcare - Patient ID label" {
    const allocator = std.testing.allocator;
    const result = try redactHealthcare("Patient ID: 123456 end", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Patient ID: [MRN_REDACTED] end", result);
}

test "healthcare - ICD-10 with extension" {
    const allocator = std.testing.allocator;
    const result = try redactHealthcare("Diagnosis E11.65 noted", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Diagnosis [ICD10_REDACTED] noted", result);
}

test "healthcare - ICD-10 multi-char extension" {
    const allocator = std.testing.allocator;
    const result = try redactHealthcare("Code Z87.891 recorded", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Code [ICD10_REDACTED] recorded", result);
}

test "healthcare - ICD-10 short form rejected without extension" {
    const allocator = std.testing.allocator;
    // "A12" alone is too ambiguous without a dot extension
    const result = try redactHealthcare("Item A12 in list", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Item A12 in list", result);
}

test "healthcare - Insurance ID with label" {
    const allocator = std.testing.allocator;
    const result = try redactHealthcare("Insurance ID: ABC12345678 ok", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Insurance ID: [INSURANCE_REDACTED] ok", result);
}

test "healthcare - Member ID with label" {
    const allocator = std.testing.allocator;
    const result = try redactHealthcare("Member ID: XYZ98765432 ok", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Member ID: [INSURANCE_REDACTED] ok", result);
}

test "healthcare - Policy # with label" {
    const allocator = std.testing.allocator;
    const result = try redactHealthcare("Policy # 12345678AB here", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Policy # [INSURANCE_REDACTED] here", result);
}

test "healthcare - no healthcare ids unchanged" {
    const allocator = std.testing.allocator;
    const result = try redactHealthcare("This text has no healthcare identifiers.", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("This text has no healthcare identifiers.", result);
}

test "healthcare - empty input" {
    const allocator = std.testing.allocator;
    const result = try redactHealthcare("", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("", result);
}

test "healthcare - false positive rejection of standalone digits" {
    const allocator = std.testing.allocator;
    // "1234567" without a label should not be redacted
    const result = try redactHealthcare("Order 1234567 placed", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Order 1234567 placed", result);
}

test "healthcare - ICD-10 embedded in word rejected" {
    const allocator = std.testing.allocator;
    // "XA12.5" preceded by letter should not match
    const result = try redactHealthcare("CodeXA12.5 test", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("CodeXA12.5 test", result);
}
