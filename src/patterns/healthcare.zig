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

/// Single-position match for the unified scanner.
/// Tries MRN labels, insurance labels, then ICD-10 codes.
/// For label-based matches, `redact_start` points past the label so the label
/// text is preserved in the output.
pub fn tryMatchAt(buf: []const u8, pos: usize) ?struct { start: usize, end: usize, redact_start: usize, replacement: []const u8 } {
    if (pos >= buf.len) return null;

    // Fast pre-check: bail immediately if the current byte cannot start any
    // healthcare pattern. Labels start with M/m, P/p, I/i, G/g; ICD-10
    // starts with uppercase A-Z. This avoids calling matchMrn/matchInsurance
    // on ~95% of bytes.
    const c = buf[pos];
    const lower = std.ascii.toLower(c);
    const can_start_label = (lower == 'm' or lower == 'p' or lower == 'i' or lower == 'g');
    const can_start_icd10 = std.ascii.isUpper(c);

    if (!can_start_label and !can_start_icd10) return null;

    // MRN detection (labels start with M/P)
    if (lower == 'm' or lower == 'p') {
        if (matchMrn(buf, pos)) |m| {
            return .{ .start = pos, .end = m.end, .redact_start = m.value_start, .replacement = mrn_replacement };
        }
    }

    // Insurance ID detection (labels start with I/M/P/G)
    if (can_start_label) {
        if (matchInsurance(buf, pos)) |m| {
            return .{ .start = pos, .end = m.end, .redact_start = m.value_start, .replacement = insurance_replacement };
        }
    }

    // ICD-10 detection (starts with uppercase letter)
    if (can_start_icd10) {
        if (matchIcd10(buf, pos)) |end| {
            return .{ .start = pos, .end = end, .redact_start = pos, .replacement = icd10_replacement };
        }
    }

    return null;
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

test "healthcare - MRN with label" {
    const input = "MRN: 1234567 is the record";
    const m = tryMatchAt(input, 0).?;
    try std.testing.expectEqualStrings("MRN: 1234567", input[m.start..m.end]);
    // Label is preserved: redact_start points past "MRN: "
    try std.testing.expectEqualStrings("1234567", input[m.redact_start..m.end]);
    try std.testing.expectEqualStrings(mrn_replacement, m.replacement);
}

test "healthcare - MR# format" {
    const input = "MR#12345678 found";
    const m = tryMatchAt(input, 0).?;
    try std.testing.expectEqualStrings("MR#12345678", input[m.start..m.end]);
    try std.testing.expectEqualStrings("12345678", input[m.redact_start..m.end]);
}

test "healthcare - Medical Record label" {
    const input = "Medical Record: 12345678 here";
    const m = tryMatchAt(input, 0).?;
    try std.testing.expectEqualStrings("12345678", input[m.redact_start..m.end]);
    try std.testing.expectEqualStrings(mrn_replacement, m.replacement);
}

test "healthcare - Patient ID label" {
    const input = "Patient ID: 123456 end";
    const m = tryMatchAt(input, 0).?;
    try std.testing.expectEqualStrings("123456", input[m.redact_start..m.end]);
    try std.testing.expectEqualStrings(mrn_replacement, m.replacement);
}

test "healthcare - ICD-10 with extension" {
    const input = "Diagnosis E11.65 noted";
    const start = std.mem.indexOf(u8, input, "E11").?;
    const m = tryMatchAt(input, start).?;
    try std.testing.expectEqualStrings("E11.65", input[m.start..m.end]);
    try std.testing.expectEqualStrings(icd10_replacement, m.replacement);
}

test "healthcare - ICD-10 multi-char extension" {
    const input = "Code Z87.891 recorded";
    const start = std.mem.indexOf(u8, input, "Z87").?;
    const m = tryMatchAt(input, start).?;
    try std.testing.expectEqualStrings("Z87.891", input[m.start..m.end]);
}

test "healthcare - ICD-10 short form rejected without extension" {
    const input = "Item A12 in list";
    const start = std.mem.indexOf(u8, input, "A12").?;
    // "A12" alone is too ambiguous without a dot extension
    try std.testing.expect(tryMatchAt(input, start) == null);
}

test "healthcare - Insurance ID with label" {
    const input = "Insurance ID: ABC12345678 ok";
    const m = tryMatchAt(input, 0).?;
    try std.testing.expectEqualStrings("ABC12345678", input[m.redact_start..m.end]);
    try std.testing.expectEqualStrings(insurance_replacement, m.replacement);
}

test "healthcare - Member ID with label" {
    const input = "Member ID: XYZ98765432 ok";
    const m = tryMatchAt(input, 0).?;
    try std.testing.expectEqualStrings("XYZ98765432", input[m.redact_start..m.end]);
    try std.testing.expectEqualStrings(insurance_replacement, m.replacement);
}

test "healthcare - Policy # with label" {
    const input = "Policy # 12345678AB here";
    const m = tryMatchAt(input, 0).?;
    try std.testing.expectEqualStrings("12345678AB", input[m.redact_start..m.end]);
}

test "healthcare - false positive rejection of standalone digits" {
    const input = "Order 1234567 placed";
    // '1' is a digit, not a label starter — tryMatchAt bails on pre-check
    const start = std.mem.indexOf(u8, input, "1234").?;
    try std.testing.expect(tryMatchAt(input, start) == null);
}

test "healthcare - ICD-10 embedded in word rejected" {
    const input = "CodeXA12.5 test";
    // 'X' at position 4 is preceded by 'e' (alphanumeric), so ICD-10 rejects
    const start = std.mem.indexOf(u8, input, "XA12").?;
    try std.testing.expect(tryMatchAt(input, start) == null);
}
