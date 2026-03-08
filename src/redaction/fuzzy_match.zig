const std = @import("std");
const entity_mask = @import("entity_mask.zig");

// ---------------------------------------------------------------------------
// Fuzzy Name Matching Engine — Stage 3 Pipeline
// ---------------------------------------------------------------------------
// OCR-resilient name matching using Myers' Bit-Vector Levenshtein algorithm.
// Catches corrupted or variant name forms (e.g. "J0hn Doe", "Mr. Doe",
// "john e doe") that slip past the exact-match Aho-Corasick engine.
//
// Positioned after deterministic entity masking (Stage 2) and SSN redaction.
// Only scans text gaps between already-masked regions to avoid wasted work.
// ---------------------------------------------------------------------------

/// A span in the input that has already been masked by a prior pipeline stage.
/// Used to skip over regions that don't need fuzzy scanning.
pub const MaskedRegion = struct {
    start: usize,
    end: usize, // exclusive
};

/// A fuzzy match found during scanning.
const FuzzyMatch = struct {
    start: usize,
    end: usize, // exclusive
    variant_owner: usize, // index of the entity that owns this variant
    confidence: f64,
};

// ---------------------------------------------------------------------------
// Text Normalization
// ---------------------------------------------------------------------------

/// Normalize text for fuzzy comparison: lowercase, strip punctuation, collapse
/// runs of whitespace into single spaces, and trim leading/trailing spaces.
/// Caller owns the returned slice.
pub fn normalize(input: []const u8, allocator: std.mem.Allocator) ![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    var last_was_space = true; // suppress leading spaces

    for (input) |ch| {
        if (isPunctuation(ch)) continue;

        if (ch == ' ' or ch == '\t' or ch == '\n' or ch == '\r') {
            if (!last_was_space) {
                try out.append(allocator, ' ');
                last_was_space = true;
            }
        } else {
            try out.append(allocator, std.ascii.toLower(ch));
            last_was_space = false;
        }
    }

    // Trim trailing space
    if (out.items.len > 0 and out.items[out.items.len - 1] == ' ') {
        _ = out.pop();
    }

    return try out.toOwnedSlice(allocator);
}

fn isPunctuation(ch: u8) bool {
    return switch (ch) {
        '.', ',', '\'', '"', '!', '?', ';', ':', '(', ')', '[', ']', '{', '}' => true,
        else => false,
    };
}

// ---------------------------------------------------------------------------
// Myers' Bit-Vector Levenshtein Distance
// ---------------------------------------------------------------------------
// Computes exact edit distance between two strings in O(n) time for patterns
// up to 64 characters, using bitwise operations on a single u64 register.
//
// Reference: Gene Myers (1999), "A Fast Bit-Vector Algorithm for Approximate
// String Matching Based on Dynamic Programming."
// ---------------------------------------------------------------------------

/// Compute the Levenshtein edit distance between `pattern` and `text`.
/// Pattern must be ≤ 64 characters; text can be any length.
/// Returns the exact edit distance.
pub fn myersDistance(pattern: []const u8, text: []const u8) error{PatternTooLong}!usize {
    return myersDistanceBounded(pattern, text, std.math.maxInt(usize));
}

/// Compute edit distance with Ukkonen cut-off: if the running score
/// exceeds `max_distance` at any column, returns `max_distance + 1`
/// immediately without processing the remaining text. This is the
/// key optimization for threshold-based fuzzy matching — most
/// non-matching windows terminate after just 2-3 characters.
pub fn myersDistanceBounded(
    pattern: []const u8,
    text: []const u8,
    max_distance: usize,
) error{PatternTooLong}!usize {
    const m = pattern.len;
    const n = text.len;

    // Saturating sentinel: max_distance + 1 without overflow
    const sentinel = max_distance +| 1;

    if (m == 0) return @min(n, sentinel);
    if (n == 0) return @min(m, sentinel);
    if (m > 64) return error.PatternTooLong;

    // Quick lower-bound check: if the length difference alone exceeds
    // max_distance, we can't possibly match.
    const len_diff = if (m > n) m - n else n - m;
    if (len_diff > max_distance) return sentinel;

    // Build position bitmasks: peq[c] has bit i set if pattern[i] == c
    var peq: [256]u64 = .{0} ** 256;
    for (pattern, 0..) |ch, i| {
        peq[std.ascii.toLower(ch)] |= @as(u64, 1) << @intCast(i);
    }

    // Myers' bit-vector state
    var pv: u64 = std.math.maxInt(u64);
    var mv: u64 = 0;
    var score: usize = m;

    const last_bit: u64 = @as(u64, 1) << @intCast(m - 1);

    for (text, 0..) |ch, j| {
        var eq = peq[std.ascii.toLower(ch)];

        const xv = eq | mv;
        eq |= ((eq & pv) +% pv) ^ pv;

        var ph = mv | ~(eq | pv);
        var mh = pv & eq;

        if ((ph & last_bit) != 0) {
            score += 1;
        }
        if ((mh & last_bit) != 0) {
            score -= 1;
        }

        // Ukkonen cut-off for Myers' bit-vector: the score at column j
        // can still improve by at most (n - j - 1) from remaining text.
        // If even that best case exceeds max_distance, abort early.
        const remaining = n - j - 1;
        if (score > max_distance +| remaining) return sentinel;

        ph = (ph << 1) | 1;
        mh = mh << 1;
        pv = mh | ~(xv | ph);
        mv = ph & xv;
    }

    return score;
}

/// Compute normalized similarity as a float in [0.0, 1.0].
/// Returns 1.0 for identical strings, 0.0 for completely different.
pub fn similarity(pattern: []const u8, text: []const u8) error{PatternTooLong}!f64 {
    const dist = try myersDistance(pattern, text);
    const max_len = @max(pattern.len, text.len);
    if (max_len == 0) return 1.0;
    return 1.0 - @as(f64, @floatFromInt(dist)) / @as(f64, @floatFromInt(max_len));
}

/// Compute similarity with early termination: uses bounded Myers to
/// avoid processing the full text when the result cannot meet threshold.
pub fn similarityBounded(
    pattern: []const u8,
    text: []const u8,
    threshold: f64,
) error{PatternTooLong}!f64 {
    const max_len = @max(pattern.len, text.len);
    if (max_len == 0) return 1.0;
    // max_distance is the largest edit distance that still meets threshold
    const max_dist_f = @floor(@as(f64, @floatFromInt(max_len)) * (1.0 - threshold));
    const max_distance: usize = @intFromFloat(max_dist_f);
    const dist = try myersDistanceBounded(pattern, text, max_distance);
    if (dist > max_distance) return 0.0; // early-terminated, below threshold
    return 1.0 - @as(f64, @floatFromInt(dist)) / @as(f64, @floatFromInt(max_len));
}

// ---------------------------------------------------------------------------
// Stack-Buffer Normalization
// ---------------------------------------------------------------------------

/// Maximum buffer size for stack-based normalization. Names are always
/// well under 128 characters, so this covers all realistic windows.
const stack_norm_max = 128;

/// Normalize text into a caller-provided stack buffer. Returns the
/// slice of `buf` that was written to, or null if the input exceeds
/// the buffer capacity. Zero heap allocations.
fn normalizeStackBuf(input: []const u8, buf: *[stack_norm_max]u8) ?[]const u8 {
    var len: usize = 0;
    var last_was_space = true;

    for (input) |ch| {
        if (isPunctuation(ch)) continue;

        if (ch == ' ' or ch == '\t' or ch == '\n' or ch == '\r') {
            if (!last_was_space) {
                if (len >= stack_norm_max) return null;
                buf[len] = ' ';
                len += 1;
                last_was_space = true;
            }
        } else {
            if (len >= stack_norm_max) return null;
            buf[len] = std.ascii.toLower(ch);
            len += 1;
            last_was_space = false;
        }
    }

    // Trim trailing space
    if (len > 0 and buf[len - 1] == ' ') {
        len -= 1;
    }

    return buf[0..len];
}

// ---------------------------------------------------------------------------
// Trigram Bloom Filter
// ---------------------------------------------------------------------------
// A compact 128-bit bloom filter seeded with character trigrams. Used to
// cheaply reject word windows that share zero trigrams with a name variant,
// eliminating the expensive normalize + Levenshtein path for ~95% of windows.
// ---------------------------------------------------------------------------

/// Hash a trigram (3 lowercase bytes) to a bit position in 0..127.
fn trigramHash(a: u8, b: u8, c: u8) u7 {
    // Simple multiplicative hash distributing across 128 bits
    const h = @as(u32, a) *% 31 +% @as(u32, b) *% 7 +% @as(u32, c);
    return @intCast(h & 0x7F);
}

/// Build a trigram bloom filter from normalized text.
fn buildTrigramFilter(text: []const u8) u128 {
    if (text.len < 3) {
        // For very short strings, set all bits to force comparison
        return std.math.maxInt(u128);
    }
    var filter: u128 = 0;
    for (0..text.len - 2) |i| {
        const bit = trigramHash(text[i], text[i + 1], text[i + 2]);
        filter |= @as(u128, 1) << bit;
    }
    return filter;
}

/// Build a trigram bloom filter directly from raw (non-normalized) text,
/// lowercasing on the fly and skipping punctuation. This avoids allocating
/// a normalized copy just for the pre-filter check.
fn buildRawTrigramFilter(text: []const u8) u128 {
    if (text.len < 3) return std.math.maxInt(u128);

    // Extract lowercase alphanumeric chars into a small stack buffer.
    // Names are short (< 64 chars) so this is safe on the stack.
    var clean: [64]u8 = undefined;
    var clen: usize = 0;
    for (text) |ch| {
        if (std.ascii.isAlphanumeric(ch)) {
            if (clen < clean.len) {
                clean[clen] = std.ascii.toLower(ch);
                clen += 1;
            }
        } else if (ch == ' ' or ch == '\t') {
            // Collapse spaces into single space
            if (clen > 0 and clen < clean.len and clean[clen - 1] != ' ') {
                clean[clen] = ' ';
                clen += 1;
            }
        }
    }

    if (clen < 3) return std.math.maxInt(u128);

    var filter: u128 = 0;
    for (0..clen - 2) |i| {
        const bit = trigramHash(clean[i], clean[i + 1], clean[i + 2]);
        filter |= @as(u128, 1) << bit;
    }
    return filter;
}

// ---------------------------------------------------------------------------
// Name Variant Generation
// ---------------------------------------------------------------------------

/// A name variant with its normalized form, trigram filter, and owning entity.
const NameVariant = struct {
    normalized: []u8, // owned, normalized text
    entity_idx: usize,
    trigram_filter: u128, // bloom filter for fast rejection
    word_count: usize, // pre-computed to avoid recounting in scanGap
};

/// Split a name into first/last components at the last space.
/// Returns null if no space is found (single-word name).
fn splitName(name: []const u8) ?struct { first: []const u8, last: []const u8 } {
    // Find last space for "first last" or "first middle last" splitting
    var last_space: ?usize = null;
    var first_space: ?usize = null;
    for (name, 0..) |ch, i| {
        if (ch == ' ') {
            if (first_space == null) first_space = i;
            last_space = i;
        }
    }
    if (last_space) |ls| {
        return .{
            .first = name[0..(first_space orelse ls)],
            .last = name[ls + 1 ..],
        };
    }
    return null;
}

pub const AuditMatch = struct {
    start: usize,
    end: usize,
    variant_owner: usize,
    confidence: f64,
};

pub const RedactResult = struct {
    output: []u8,
    matches: []AuditMatch,

    pub fn deinit(self: *RedactResult, allocator: std.mem.Allocator) void {
        allocator.free(self.output);
        allocator.free(self.matches);
    }
};

// ---------------------------------------------------------------------------
// FuzzyMatcher
// ---------------------------------------------------------------------------

/// Session-level fuzzy name matcher. Initialized with the same entity name set
/// as the `EntityMap`. Generates normalized variants for each entity and scans
/// text gaps using Myers' bit-vector Levenshtein distance.
///
/// Performance: uses a trigram bloom filter to reject ~95% of word windows
/// before any allocation or distance computation occurs.
///
/// Usage:
///   var fm = try FuzzyMatcher.init(allocator, &.{ "John Doe", "Dr. Smith" }, 0.80);
///   defer fm.deinit();
///   const result = try fm.fuzzyRedact("J0hn Doe was here", aliases, &.{}, allocator);
///   defer allocator.free(result);
pub const FuzzyMatcher = struct {
    variants: []NameVariant,
    threshold: f64,
    allocator: std.mem.Allocator,

    pub fn init(
        allocator: std.mem.Allocator,
        raw_names: []const []const u8,
        aliases: []const []const u8,
        threshold: f64,
    ) !FuzzyMatcher {
        _ = aliases; // aliases stored externally in EntityMap; we just need the index mapping

        var variants_list: std.ArrayListUnmanaged(NameVariant) = .empty;
        errdefer {
            for (variants_list.items) |v| allocator.free(v.normalized);
            variants_list.deinit(allocator);
        }

        for (raw_names, 0..) |name, entity_idx| {
            // Variant 1: full normalized name
            const full_norm = try normalize(name, allocator);
            try variants_list.append(allocator, .{
                .normalized = full_norm,
                .entity_idx = entity_idx,
                .trigram_filter = buildTrigramFilter(full_norm),
                .word_count = countWords(full_norm),
            });

            // Variant 2+3: first-only and last-only (if multi-word)
            if (splitName(name)) |parts| {
                const first_norm = try normalize(parts.first, allocator);
                // Only add first-name variant if it's ≥ 3 chars to avoid false positives
                if (first_norm.len >= 3) {
                    try variants_list.append(allocator, .{
                        .normalized = first_norm,
                        .entity_idx = entity_idx,
                        .trigram_filter = buildTrigramFilter(first_norm),
                        .word_count = countWords(first_norm),
                    });
                } else {
                    allocator.free(first_norm);
                }

                const last_norm = try normalize(parts.last, allocator);
                if (last_norm.len >= 3) {
                    try variants_list.append(allocator, .{
                        .normalized = last_norm,
                        .entity_idx = entity_idx,
                        .trigram_filter = buildTrigramFilter(last_norm),
                        .word_count = countWords(last_norm),
                    });
                } else {
                    allocator.free(last_norm);
                }
            }
        }

        return FuzzyMatcher{
            .variants = try variants_list.toOwnedSlice(allocator),
            .threshold = threshold,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *FuzzyMatcher) void {
        for (self.variants) |v| self.allocator.free(v.normalized);
        self.allocator.free(self.variants);
    }

    /// Scan `input` for fuzzy matches against all name variants, skipping
    /// regions already masked by prior stages. Returns a new buffer with
    /// fuzzy matches replaced by the corresponding alias.
    ///
    /// `aliases` must be the same alias slice used by the EntityMap so that
    /// entity indices map correctly to alias strings.
    pub fn fuzzyRedact(
        self: *const FuzzyMatcher,
        input: []const u8,
        aliases: []const []const u8,
        masked_regions: []const MaskedRegion,
        allocator: std.mem.Allocator,
    ) ![]u8 {
        const result = try self.fuzzyRedactWithMatches(input, aliases, masked_regions, allocator);
        defer allocator.free(result.matches);
        return result.output;
    }

    pub fn fuzzyRedactWithMatches(
        self: *const FuzzyMatcher,
        input: []const u8,
        aliases: []const []const u8,
        masked_regions: []const MaskedRegion,
        allocator: std.mem.Allocator,
    ) !RedactResult {
        const selected = try self.collectMatches(input, masked_regions, allocator);
        errdefer allocator.free(selected);

        if (selected.len == 0) {
            return .{
                .output = try allocator.dupe(u8, input),
                .matches = selected,
            };
        }

        var out: std.ArrayListUnmanaged(u8) = .empty;
        errdefer out.deinit(allocator);
        var pos: usize = 0;

        for (selected) |m| {
            try out.appendSlice(allocator, input[pos..m.start]);
            if (m.variant_owner < aliases.len) {
                try out.appendSlice(allocator, aliases[m.variant_owner]);
            }
            pos = m.end;
        }
        try out.appendSlice(allocator, input[pos..]);

        return .{
            .output = try out.toOwnedSlice(allocator),
            .matches = selected,
        };
    }

    pub fn collectMatches(
        self: *const FuzzyMatcher,
        input: []const u8,
        masked_regions: []const MaskedRegion,
        allocator: std.mem.Allocator,
    ) ![]AuditMatch {
        var matches: std.ArrayListUnmanaged(FuzzyMatch) = .empty;
        defer matches.deinit(allocator);

        const gaps = try buildGaps(input.len, masked_regions, allocator);
        defer allocator.free(gaps);

        for (gaps) |gap| {
            const gap_text = input[gap.start..gap.end];
            try self.scanGap(gap_text, gap.start, allocator, &matches);
        }

        if (matches.items.len == 0) return try allocator.alloc(AuditMatch, 0);

        std.sort.block(FuzzyMatch, matches.items, {}, struct {
            fn lessThan(_: void, a: FuzzyMatch, b: FuzzyMatch) bool {
                if (a.start != b.start) return a.start < b.start;
                return (a.end - a.start) > (b.end - b.start);
            }
        }.lessThan);

        var selected: std.ArrayListUnmanaged(FuzzyMatch) = .empty;
        defer selected.deinit(allocator);

        var last_end: usize = 0;
        for (matches.items) |m| {
            if (m.start >= last_end) {
                try selected.append(allocator, m);
                last_end = m.end;
            }
        }

        var audit_matches: std.ArrayListUnmanaged(AuditMatch) = .empty;
        errdefer audit_matches.deinit(allocator);
        try audit_matches.ensureTotalCapacity(allocator, selected.items.len);

        for (selected.items) |m| {
            audit_matches.appendAssumeCapacity(.{
                .start = m.start,
                .end = m.end,
                .variant_owner = m.variant_owner,
                .confidence = m.confidence,
            });
        }

        return try audit_matches.toOwnedSlice(allocator);
    }

    /// Scan a single gap region for fuzzy matches using a sliding window.
    /// Tries windows of both `variant_word_count` and `variant_word_count + 1`
    /// to catch middle-initial insertions (e.g. "John E Doe" matching "John Doe").
    ///
    /// Uses a trigram bloom filter as a cheap pre-filter: if the window shares
    /// zero character trigrams with the variant, it cannot possibly match at
    /// any reasonable threshold, so we skip the expensive normalize+Levenshtein.
    fn scanGap(
        self: *const FuzzyMatcher,
        gap_text: []const u8,
        gap_offset: usize, // absolute offset in the original input
        allocator: std.mem.Allocator,
        matches: *std.ArrayListUnmanaged(FuzzyMatch),
    ) !void {
        // Extract words from the gap for word-level comparison
        var words: std.ArrayListUnmanaged(WordSpan) = .empty;
        defer words.deinit(allocator);
        try extractWords(gap_text, &words, allocator);

        if (words.items.len == 0) return;

        for (self.variants) |variant| {
            if (variant.word_count == 0) continue;

            // Try windows of exact word count AND +1 to catch middle initials.
            const max_window = @min(variant.word_count + 1, words.items.len);

            var wsize: usize = variant.word_count;
            while (wsize <= max_window) : (wsize += 1) {
                if (words.items.len < wsize) continue;

                var wi: usize = 0;
                while (wi + wsize <= words.items.len) : (wi += 1) {
                    const window_start = words.items[wi].start;
                    const window_end = words.items[wi + wsize - 1].end;
                    const window_text = gap_text[window_start..window_end];

                    // --- Pre-filter 1: length check (no allocation) ---
                    // If the raw window length is wildly different from the
                    // variant, skip immediately.
                    const raw_len = window_text.len;
                    const var_len = variant.normalized.len;
                    const len_max = @max(raw_len, var_len);
                    const len_min = @min(raw_len, var_len);
                    if (len_max > 0) {
                        const ratio = @as(f64, @floatFromInt(len_min)) / @as(f64, @floatFromInt(len_max));
                        // Use a slightly relaxed check since raw text has
                        // punctuation that normalize will strip
                        if (ratio < self.threshold * 0.7) continue;
                    }

                    // --- Pre-filter 2: trigram bloom filter (no allocation) ---
                    // Build a trigram fingerprint from the raw window bytes,
                    // lowercasing on the fly. If no trigram overlaps with the
                    // variant's pre-computed filter, this window cannot match.
                    const window_filter = buildRawTrigramFilter(window_text);
                    if ((window_filter & variant.trigram_filter) == 0) continue;

                    // --- Full comparison (stack-buffer, zero alloc) ---
                    var norm_buf: [stack_norm_max]u8 = undefined;
                    const window_norm = normalizeStackBuf(window_text, &norm_buf) orelse continue;

                    const norm_max = @max(variant.normalized.len, window_norm.len);
                    const norm_min = @min(variant.normalized.len, window_norm.len);
                    if (norm_max == 0) continue;

                    const len_ratio = @as(f64, @floatFromInt(norm_min)) / @as(f64, @floatFromInt(norm_max));
                    if (len_ratio < self.threshold) continue;

                    // Use bounded similarity for Ukkonen early-exit
                    const sim = similarityBounded(variant.normalized, window_norm, self.threshold) catch continue;

                    if (sim >= self.threshold) {
                        try matches.append(allocator, .{
                            .start = gap_offset + window_start,
                            .end = gap_offset + window_end,
                            .variant_owner = variant.entity_idx,
                            .confidence = sim,
                        });
                    }
                }
            }
        }
    }

    /// Compute the maximum word count across all name variants.
    /// Used to size the overlap buffer for chunked processing.
    pub fn maxVariantWordCount(self: *const FuzzyMatcher) usize {
        var max_wc: usize = 0;
        for (self.variants) |v| {
            if (v.word_count > max_wc) max_wc = v.word_count;
        }
        return max_wc;
    }

    // -----------------------------------------------------------------------
    // Chunked fuzzy redaction — streaming-compatible interface
    // -----------------------------------------------------------------------

    /// Maximum overlap size for chunked fuzzy processing.
    const fuzzy_max_overlap = 256;

    /// Persistent state for chunked fuzzy redaction.
    pub const FuzzyChunkState = struct {
        pending: [fuzzy_max_overlap]u8 = undefined,
        len: usize = 0,
        overlap: usize,
        combined_buf: std.ArrayListUnmanaged(u8) = .empty,

        pub fn deinit(self: *FuzzyChunkState, allocator: std.mem.Allocator) void {
            self.combined_buf.deinit(allocator);
        }

        /// Emit remaining pending bytes after the last chunk.
        pub fn flush(
            self: *FuzzyChunkState,
            fm: *const FuzzyMatcher,
            aliases: []const []const u8,
            masked_regions: []const MaskedRegion,
            allocator: std.mem.Allocator,
        ) ![]u8 {
            if (self.len == 0) return try allocator.alloc(u8, 0);
            const result = try fm.fuzzyRedact(self.pending[0..self.len], aliases, masked_regions, allocator);
            self.len = 0;
            return result;
        }
    };

    /// Create initial chunk state for streaming fuzzy redaction.
    pub fn initChunkState(self: *const FuzzyMatcher) FuzzyChunkState {
        const max_wc = self.maxVariantWordCount();
        const overlap = @min((max_wc + 1) * 20, fuzzy_max_overlap);
        return FuzzyChunkState{
            .overlap = if (overlap > 0) overlap else 20,
        };
    }

    /// Like `fuzzyRedact`, but only applies matches starting before `safe_end`.
    fn fuzzyRedactBounded(
        self: *const FuzzyMatcher,
        input: []const u8,
        aliases: []const []const u8,
        masked_regions: []const MaskedRegion,
        safe_end: usize,
        consumed_out: *usize,
        allocator: std.mem.Allocator,
    ) ![]u8 {
        consumed_out.* = safe_end;

        var matches: std.ArrayListUnmanaged(FuzzyMatch) = .empty;
        defer matches.deinit(allocator);

        const gaps = try buildGaps(input.len, masked_regions, allocator);
        defer allocator.free(gaps);

        for (gaps) |gap| {
            const gap_text = input[gap.start..gap.end];
            try self.scanGap(gap_text, gap.start, allocator, &matches);
        }

        var filtered: std.ArrayListUnmanaged(FuzzyMatch) = .empty;
        defer filtered.deinit(allocator);

        for (matches.items) |m| {
            if (m.start < safe_end) {
                try filtered.append(allocator, m);
            }
        }

        if (filtered.items.len == 0) {
            return try allocator.dupe(u8, input[0..safe_end]);
        }

        std.sort.block(FuzzyMatch, filtered.items, {}, struct {
            fn lessThan(_: void, a: FuzzyMatch, b: FuzzyMatch) bool {
                if (a.start != b.start) return a.start < b.start;
                return (a.end - a.start) > (b.end - b.start);
            }
        }.lessThan);

        var selected: std.ArrayListUnmanaged(FuzzyMatch) = .empty;
        defer selected.deinit(allocator);

        var last_end: usize = 0;
        for (filtered.items) |m| {
            if (m.start >= last_end) {
                try selected.append(allocator, m);
                last_end = m.end;
            }
        }

        var consumed: usize = safe_end;
        if (selected.items.len > 0) {
            const last_match = selected.items[selected.items.len - 1];
            if (last_match.end > consumed) consumed = last_match.end;
        }
        consumed_out.* = consumed;

        var out: std.ArrayListUnmanaged(u8) = .empty;
        var pos: usize = 0;

        for (selected.items) |m| {
            try out.appendSlice(allocator, input[pos..m.start]);
            if (m.variant_owner < aliases.len) {
                try out.appendSlice(allocator, aliases[m.variant_owner]);
            }
            pos = m.end;
        }
        try out.appendSlice(allocator, input[pos..consumed]);

        return try out.toOwnedSlice(allocator);
    }

    /// Process one chunk for fuzzy redaction in streaming mode.
    pub fn fuzzyRedactChunked(
        self: *const FuzzyMatcher,
        chunk: []const u8,
        state: *FuzzyChunkState,
        aliases: []const []const u8,
        masked_regions: []const MaskedRegion,
        allocator: std.mem.Allocator,
    ) ![]u8 {
        if (chunk.len == 0) {
            return try allocator.alloc(u8, 0);
        }

        const old_pending_len = state.len;
        const total = old_pending_len + chunk.len;

        if (total <= state.overlap) {
            @memcpy(state.pending[old_pending_len..][0..chunk.len], chunk);
            state.len = total;
            return try allocator.alloc(u8, 0);
        }

        try state.combined_buf.resize(allocator, total);
        const combined = state.combined_buf.items;

        if (old_pending_len > 0) {
            @memcpy(combined[0..old_pending_len], state.pending[0..old_pending_len]);
        }
        @memcpy(combined[old_pending_len..], chunk);

        const new_pending_len = @min(state.overlap, total);
        const safe_end = total - new_pending_len;

        var consumed: usize = undefined;
        const result = try self.fuzzyRedactBounded(
            combined,
            aliases,
            masked_regions,
            safe_end,
            &consumed,
            allocator,
        );

        const actual_pending = total - consumed;
        state.len = actual_pending;
        if (actual_pending > 0) {
            @memcpy(state.pending[0..actual_pending], combined[consumed..][0..actual_pending]);
        }

        return result;
    }
};

// ---------------------------------------------------------------------------
// Helper: Word extraction
// ---------------------------------------------------------------------------

const WordSpan = struct {
    start: usize,
    end: usize,
};

fn extractWords(text: []const u8, words: *std.ArrayListUnmanaged(WordSpan), allocator: std.mem.Allocator) !void {
    var i: usize = 0;
    while (i < text.len) {
        // Skip non-word characters
        while (i < text.len and !isWordChar(text[i])) : (i += 1) {}
        if (i >= text.len) break;

        const start = i;
        // Consume word characters
        while (i < text.len and isWordChar(text[i])) : (i += 1) {}
        try words.append(allocator, .{ .start = start, .end = i });
    }
}

fn isWordChar(ch: u8) bool {
    return std.ascii.isAlphanumeric(ch) or ch == '\'';
}

fn countWords(text: []const u8) usize {
    var count: usize = 0;
    var in_word = false;
    for (text) |ch| {
        if (isWordChar(ch)) {
            if (!in_word) {
                count += 1;
                in_word = true;
            }
        } else {
            in_word = false;
        }
    }
    return count;
}

// ---------------------------------------------------------------------------
// Helper: Gap building from masked regions
// ---------------------------------------------------------------------------

fn buildGaps(input_len: usize, regions: []const MaskedRegion, allocator: std.mem.Allocator) ![]MaskedRegion {
    var gaps: std.ArrayListUnmanaged(MaskedRegion) = .empty;

    if (regions.len == 0) {
        if (input_len > 0) {
            try gaps.append(allocator, .{ .start = 0, .end = input_len });
        }
        return try gaps.toOwnedSlice(allocator);
    }

    // Sort regions by start position
    const sorted = try allocator.alloc(MaskedRegion, regions.len);
    defer allocator.free(sorted);
    @memcpy(sorted, regions);

    std.sort.block(MaskedRegion, sorted, {}, struct {
        fn lessThan(_: void, a: MaskedRegion, b: MaskedRegion) bool {
            return a.start < b.start;
        }
    }.lessThan);

    var pos: usize = 0;
    for (sorted) |region| {
        if (region.start > pos) {
            try gaps.append(allocator, .{ .start = pos, .end = region.start });
        }
        if (region.end > pos) {
            pos = region.end;
        }
    }

    if (pos < input_len) {
        try gaps.append(allocator, .{ .start = pos, .end = input_len });
    }

    return try gaps.toOwnedSlice(allocator);
}

// ===========================================================================
// Unit Tests
// ===========================================================================

// ---------------------------------------------------------------------------
// Myers' Distance Tests
// ---------------------------------------------------------------------------

test "myersDistance - identical strings" {
    const dist = try myersDistance("hello", "hello");
    try std.testing.expectEqual(@as(usize, 0), dist);
}

test "myersDistance - single substitution" {
    // OCR: '0' instead of 'o'
    const dist = try myersDistance("john", "j0hn");
    try std.testing.expectEqual(@as(usize, 1), dist);
}

test "myersDistance - single insertion" {
    const dist = try myersDistance("john", "johhn");
    try std.testing.expectEqual(@as(usize, 1), dist);
}

test "myersDistance - single deletion" {
    const dist = try myersDistance("john", "jhn");
    try std.testing.expectEqual(@as(usize, 1), dist);
}

test "myersDistance - completely different" {
    const dist = try myersDistance("abc", "xyz");
    try std.testing.expectEqual(@as(usize, 3), dist);
}

test "myersDistance - empty pattern" {
    const dist = try myersDistance("", "hello");
    try std.testing.expectEqual(@as(usize, 5), dist);
}

test "myersDistance - empty text" {
    const dist = try myersDistance("hello", "");
    try std.testing.expectEqual(@as(usize, 5), dist);
}

test "myersDistance - case insensitive" {
    const dist = try myersDistance("John", "JOHN");
    try std.testing.expectEqual(@as(usize, 0), dist);
}

// ---------------------------------------------------------------------------
// Normalization Tests
// ---------------------------------------------------------------------------

test "normalize - punctuation and case" {
    const allocator = std.testing.allocator;
    const result = try normalize("John E. Doe", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("john e doe", result);
}

test "normalize - collapse whitespace" {
    const allocator = std.testing.allocator;
    const result = try normalize("john   doe", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("john doe", result);
}

test "normalize - leading and trailing whitespace" {
    const allocator = std.testing.allocator;
    const result = try normalize("  John Doe  ", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("john doe", result);
}

test "normalize - all punctuation stripped" {
    const allocator = std.testing.allocator;
    const result = try normalize("Dr. O'Brien", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("dr obrien", result);
}

test "normalize - empty string" {
    const allocator = std.testing.allocator;
    const result = try normalize("", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("", result);
}

// ---------------------------------------------------------------------------
// Similarity Tests
// ---------------------------------------------------------------------------

test "similarity - identical" {
    const sim = try similarity("john doe", "john doe");
    try std.testing.expect(sim == 1.0);
}

test "similarity - OCR corrupted name" {
    // "j0hn doe" vs "john doe" — 1 substitution in 8 chars = 87.5% similar
    const sim = try similarity("john doe", "j0hn doe");
    try std.testing.expect(sim >= 0.85);
}

// ---------------------------------------------------------------------------
// FuzzyMatcher Integration Tests
// ---------------------------------------------------------------------------

test "FuzzyMatcher - OCR corrupted full name" {
    const allocator = std.testing.allocator;

    const names = [_][]const u8{"John Doe"};
    const aliases = [_][]const u8{"Entity_A"};

    var fm = try FuzzyMatcher.init(allocator, &names, &aliases, 0.80);
    defer fm.deinit();

    const result = try fm.fuzzyRedact("Patient J0hn Doe was seen today.", &aliases, &.{}, allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Patient Entity_A was seen today.", result);
}

test "FuzzyMatcher - collectMatches captures confidence" {
    const allocator = std.testing.allocator;

    const names = [_][]const u8{"John Doe"};
    const aliases = [_][]const u8{"Entity_A"};

    var fm = try FuzzyMatcher.init(allocator, &names, &aliases, 0.80);
    defer fm.deinit();

    const matches = try fm.collectMatches("Patient J0hn Doe was seen today.", &.{}, allocator);
    defer allocator.free(matches);

    try std.testing.expectEqual(@as(usize, 1), matches.len);
    try std.testing.expect(matches[0].confidence >= 0.80);
}

test "FuzzyMatcher - ALL CAPS name" {
    const allocator = std.testing.allocator;

    const names = [_][]const u8{"John Doe"};
    const aliases = [_][]const u8{"Entity_A"};

    var fm = try FuzzyMatcher.init(allocator, &names, &aliases, 0.80);
    defer fm.deinit();

    const result = try fm.fuzzyRedact("Patient JOHN DOE was seen today.", &aliases, &.{}, allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Patient Entity_A was seen today.", result);
}

test "FuzzyMatcher - partial last name only" {
    const allocator = std.testing.allocator;

    const names = [_][]const u8{"John Doe"};
    const aliases = [_][]const u8{"Entity_A"};

    // "Doe" alone (3 chars) should match as a variant if it meets threshold.
    // Exact match of a generated variant → similarity = 1.0
    var fm = try FuzzyMatcher.init(allocator, &names, &aliases, 0.80);
    defer fm.deinit();

    const result = try fm.fuzzyRedact("Mr. Doe was discharged.", &aliases, &.{}, allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Mr. Entity_A was discharged.", result);
}

test "FuzzyMatcher - no match for unrelated text" {
    const allocator = std.testing.allocator;

    const names = [_][]const u8{"John Doe"};
    const aliases = [_][]const u8{"Entity_A"};

    var fm = try FuzzyMatcher.init(allocator, &names, &aliases, 0.80);
    defer fm.deinit();

    const result = try fm.fuzzyRedact("The weather is nice today.", &aliases, &.{}, allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("The weather is nice today.", result);
}

test "FuzzyMatcher - gap-aware skipping" {
    const allocator = std.testing.allocator;

    const names = [_][]const u8{"John Doe"};
    const aliases = [_][]const u8{"Entity_A"};

    var fm = try FuzzyMatcher.init(allocator, &names, &aliases, 0.80);
    defer fm.deinit();

    // Simulate that positions 8..16 ("Entity_A") are already masked from Stage 2.
    // The fuzzy matcher should skip that region entirely.
    const input = "Patient Entity_A also known as J0hn Doe.";
    const regions = [_]MaskedRegion{.{ .start = 8, .end = 16 }};

    const result = try fm.fuzzyRedact(input, &aliases, &regions, allocator);
    defer allocator.free(result);

    // Only the second occurrence (J0hn Doe at position 31) should be caught
    try std.testing.expectEqualStrings("Patient Entity_A also known as Entity_A.", result);
}

test "FuzzyMatcher - empty input" {
    const allocator = std.testing.allocator;

    const names = [_][]const u8{"John Doe"};
    const aliases = [_][]const u8{"Entity_A"};

    var fm = try FuzzyMatcher.init(allocator, &names, &aliases, 0.80);
    defer fm.deinit();

    const result = try fm.fuzzyRedact("", &aliases, &.{}, allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("", result);
}

test "FuzzyMatcher - name with middle initial variants" {
    const allocator = std.testing.allocator;

    const names = [_][]const u8{"John Doe"};
    const aliases = [_][]const u8{"Entity_A"};

    // "John E Doe" normalized → "john e doe" (10 chars) vs "john doe" (8 chars)
    // Edit distance = 2, similarity = 1 - 2/10 = 0.80
    // Use threshold 0.75 to avoid float precision issues at exact boundary.
    var fm = try FuzzyMatcher.init(allocator, &names, &aliases, 0.75);
    defer fm.deinit();

    const result = try fm.fuzzyRedact("Patient John E Doe was seen.", &aliases, &.{}, allocator);
    defer allocator.free(result);

    // The 3-word window "John E Doe" should fuzzy-match against "john doe"
    try std.testing.expectEqualStrings("Patient Entity_A was seen.", result);
}

// ---------------------------------------------------------------------------
// Chunked Fuzzy Matching Tests
// ---------------------------------------------------------------------------

/// Test helper: run chunked fuzzy redaction collecting all output.
fn runChunkedFuzzy(
    fm: *const FuzzyMatcher,
    input: []const u8,
    aliases: []const []const u8,
    chunk_size: usize,
    allocator: std.mem.Allocator,
) ![]u8 {
    var output: std.ArrayListUnmanaged(u8) = .empty;
    errdefer output.deinit(allocator);

    var state = fm.initChunkState();
    defer state.deinit(allocator); // Cleanup memory
    var offset: usize = 0;

    while (offset < input.len) {
        const end = @min(offset + chunk_size, input.len);
        const result = try fm.fuzzyRedactChunked(input[offset..end], &state, aliases, &.{}, allocator);
        defer allocator.free(result);
        try output.appendSlice(allocator, result);
        offset = end;
    }

    const flushed = try state.flush(fm, aliases, &.{}, allocator);
    defer allocator.free(flushed);
    try output.appendSlice(allocator, flushed);

    return try output.toOwnedSlice(allocator);
}

test "fuzzyRedactChunked - round-trip equivalence vs fuzzyRedact()" {
    const allocator = std.testing.allocator;

    const names = [_][]const u8{ "John Doe", "Dr. Smith" };
    const aliases = [_][]const u8{ "Entity_A", "Entity_B" };

    var fm = try FuzzyMatcher.init(allocator, &names, &aliases, 0.80);
    defer fm.deinit();

    const input = "Patient J0hn Doe was seen by Dr Smlth. J0hn Doe returned later.";

    // Reference: single-pass fuzzy redaction
    const reference = try fm.fuzzyRedact(input, &aliases, &.{}, allocator);
    defer allocator.free(reference);

    // Test with various chunk sizes
    for ([_]usize{ 7, 16, 32, 64 }) |cs| {
        const chunked = try runChunkedFuzzy(&fm, input, &aliases, cs, allocator);
        defer allocator.free(chunked);
        try std.testing.expectEqualStrings(reference, chunked);
    }
}

test "fuzzyRedactChunked - boundary-spanning multi-word match" {
    const allocator = std.testing.allocator;

    const names = [_][]const u8{"John Doe"};
    const aliases = [_][]const u8{"Entity_A"};

    var fm = try FuzzyMatcher.init(allocator, &names, &aliases, 0.80);
    defer fm.deinit();

    // Place "J0hn Doe" so "J0hn" is at end of one chunk and "Doe" at start of next
    const input = "xxxxxxxxx J0hn Doe yyyyy";

    const reference = try fm.fuzzyRedact(input, &aliases, &.{}, allocator);
    defer allocator.free(reference);

    // Chunk size 14: first chunk = "xxxxxxxxx J0hn", second = " Doe yyyyy"
    const chunked = try runChunkedFuzzy(&fm, input, &aliases, 14, allocator);
    defer allocator.free(chunked);
    try std.testing.expectEqualStrings(reference, chunked);
}

test "fuzzyRedactChunked - empty and small chunks" {
    const allocator = std.testing.allocator;

    const names = [_][]const u8{"John Doe"};
    const aliases = [_][]const u8{"Entity_A"};

    var fm = try FuzzyMatcher.init(allocator, &names, &aliases, 0.80);
    defer fm.deinit();

    // Empty input
    const empty_result = try runChunkedFuzzy(&fm, "", &aliases, 16, allocator);
    defer allocator.free(empty_result);
    try std.testing.expectEqualStrings("", empty_result);

    // Input with no matches, small chunks
    const input = "The weather is nice today.";
    const reference = try fm.fuzzyRedact(input, &aliases, &.{}, allocator);
    defer allocator.free(reference);
    const chunked = try runChunkedFuzzy(&fm, input, &aliases, 5, allocator);
    defer allocator.free(chunked);
    try std.testing.expectEqualStrings(reference, chunked);
}

// ---------------------------------------------------------------------------
// Benchmark (opt-in via `zig build bench`)
// ---------------------------------------------------------------------------

const is_benchmark: bool = blk: {
    if (@hasDecl(@import("root"), "build_options")) {
        break :blk @field(@import("root").build_options, "is_benchmark");
    }
    break :blk false;
};

test "bench - FuzzyMatcher throughput" {
    if (!is_benchmark) return;
    const allocator = std.testing.allocator;

    const names = [_][]const u8{
        "John Doe",      "Jane Smith",   "Dr. Johnson",
        "Mary Williams", "Robert Brown",
    };
    const aliases = [_][]const u8{
        "Entity_A", "Entity_B", "Entity_C",
        "Entity_D", "Entity_E",
    };

    var fm = try FuzzyMatcher.init(allocator, &names, &aliases, 0.80);
    defer fm.deinit();

    // Build a ~256KB payload with OCR-corrupted names scattered
    const payload_size = 256 * 1024;
    const payload = try allocator.alloc(u8, payload_size);
    defer allocator.free(payload);
    @memset(payload, 'a');

    // Plant corrupted names every ~200 bytes (space-padded for word boundaries)
    const corrupted = " J0hn Doe ";
    var pos: usize = 100;
    while (pos + corrupted.len <= payload_size) {
        @memcpy(payload[pos..][0..corrupted.len], corrupted);
        pos += 200;
    }

    var timer = std.time.Timer.start() catch return;

    const iterations = 10;
    var run: usize = 0;
    while (run < iterations) : (run += 1) {
        const result = try fm.fuzzyRedact(payload, &aliases, &.{}, allocator);
        allocator.free(result);
    }

    const elapsed_ns = timer.read();
    const total_bytes = payload_size * iterations;
    const mb_per_sec = (@as(f64, @floatFromInt(total_bytes)) /
        @as(f64, @floatFromInt(elapsed_ns))) * 1_000_000_000.0 / (1024.0 * 1024.0);

    std.debug.print("\n\n\n[BENCH] FuzzyMatcher: {d:.1} MB/s ({} iterations x {} bytes)\n", .{
        mb_per_sec,
        iterations,
        payload_size,
    });
}
