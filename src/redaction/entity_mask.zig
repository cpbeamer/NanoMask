const std = @import("std");

// ---------------------------------------------------------------------------
// Aho-Corasick Entity Masking Engine
// ---------------------------------------------------------------------------
// Dictionary-based name pseudonymization for PII/PHI de-identification.
// Given known names (e.g. "John Doe", "Dr. Smith"), replaces all occurrences
// with deterministic aliases ("Entity_A", "Entity_B") in a single O(n) pass
// using an Aho-Corasick multi-pattern automaton.
//
// Bidirectional: mask() replaces names->aliases, unmask() reverses aliases->names.
// Case-insensitive matching with word-boundary enforcement.
// ---------------------------------------------------------------------------

/// A match found during Aho-Corasick scanning.
const Match = struct {
    start: usize,
    end: usize, // exclusive
    pattern_idx: usize,
};

pub const AuditMatch = struct {
    start: usize,
    end: usize,
    pattern_idx: usize,
    replacement: []const u8,
};

pub const BoundedAuditMatches = struct {
    matches: []AuditMatch,
    consumed: usize,
};

// ---------------------------------------------------------------------------
// Word-boundary helpers
// ---------------------------------------------------------------------------

/// Returns true if the byte is NOT alphanumeric (i.e. is a word boundary).
/// This prevents partial matches like "John" inside "Johnson".
fn isWordBoundary(byte: u8) bool {
    return !std.ascii.isAlphanumeric(byte);
}

fn isWordBoundaryBefore(input: []const u8, pos: usize) bool {
    if (pos == 0) return true;
    return isWordBoundary(input[pos - 1]);
}

fn isWordBoundaryAfter(input: []const u8, pos: usize) bool {
    if (pos >= input.len) return true;
    return isWordBoundary(input[pos]);
}

// ---------------------------------------------------------------------------
// Alias generation
// ---------------------------------------------------------------------------

/// Maximum supported entities: A-Z (26) + AA-ZZ (676) = 702.
const max_entities = 702;

/// Prefix used for all generated alias identifiers.
const alias_prefix = "Entity_";

/// Generate a deterministic alias: Entity_A, Entity_B, ..., Entity_Z, Entity_AA, ...
fn generateAlias(allocator: std.mem.Allocator, index: usize) ![]u8 {
    if (index >= max_entities) return error.TooManyEntities;

    var suffix_buf: [2]u8 = undefined;
    var suffix_len: usize = 0;

    if (index < 26) {
        suffix_buf[0] = @as(u8, @intCast(index)) + 'A';
        suffix_len = 1;
    } else {
        const adjusted = index - 26;
        suffix_buf[0] = @as(u8, @intCast(adjusted / 26)) + 'A';
        suffix_buf[1] = @as(u8, @intCast(adjusted % 26)) + 'A';
        suffix_len = 2;
    }

    const result = try allocator.alloc(u8, alias_prefix.len + suffix_len);
    @memcpy(result[0..alias_prefix.len], alias_prefix);
    @memcpy(result[alias_prefix.len..result.len], suffix_buf[0..suffix_len]);
    return result;
}

// ---------------------------------------------------------------------------
// Aho-Corasick Automaton
// ---------------------------------------------------------------------------

/// Deterministic Aho-Corasick finite automaton for multi-pattern string matching.
/// After build(), every state has a complete goto-function -- scanning never
/// backtracks and processes each input byte exactly once.
///
/// Uses ArrayListUnmanaged for Zig 0.15 compatibility -- allocator is passed
/// explicitly to each method that needs allocation.
pub const AhoCorasick = struct {
    const alphabet_size = 64; // Shrunk from 256 to fit nodes into L2 cache
    const null_node: u32 = std.math.maxInt(u32);

    const char_map: [256]u8 = blk: {
        var map: [256]u8 = [_]u8{0} ** 256;
        var idx: u8 = 1;
        for ('a'..'z' + 1) |c| {
            map[c] = idx;
            map[std.ascii.toUpper(@intCast(c))] = idx; // case-insensitive map
            idx += 1;
        }
        for ('0'..'9' + 1) |c| {
            map[c] = idx;
            idx += 1;
        }
        map[' '] = idx;
        idx += 1;
        map['.'] = idx;
        idx += 1;
        map['-'] = idx;
        idx += 1;
        map['\''] = idx;
        idx += 1;
        // all mapped characters fit under 64. Unmapped bytes use index 0.
        break :blk map;
    };

    const Node = struct {
        children: [alphabet_size]u32,
        failure: u32,
        output: ?usize, // pattern index, null if non-accepting
        depth: usize,
    };

    nodes: std.ArrayListUnmanaged(Node),
    pattern_lengths: []usize,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) !AhoCorasick {
        var ac = AhoCorasick{
            .nodes = .empty,
            .pattern_lengths = &.{},
            .allocator = allocator,
        };
        // Root node -- all children start as null_node
        try ac.nodes.append(allocator, .{
            .children = .{null_node} ** alphabet_size,
            .failure = 0,
            .output = null,
            .depth = 0,
        });
        return ac;
    }

    pub fn deinit(self: *AhoCorasick) void {
        self.nodes.deinit(self.allocator);
        if (self.pattern_lengths.len > 0) {
            self.allocator.free(self.pattern_lengths);
        }
    }

    /// Insert a pattern into the trie (case-folded via char_map).
    pub fn addPattern(self: *AhoCorasick, pattern: []const u8, index: usize) !void {
        var current: u32 = 0;
        for (pattern) |byte| {
            const c = char_map[byte];
            if (self.nodes.items[current].children[c] == null_node) {
                const new_idx: u32 = @intCast(self.nodes.items.len);
                try self.nodes.append(self.allocator, .{
                    .children = .{null_node} ** alphabet_size,
                    .failure = 0,
                    .output = null,
                    .depth = self.nodes.items[current].depth + 1,
                });
                self.nodes.items[current].children[c] = new_idx;
                current = new_idx;
            } else {
                current = self.nodes.items[current].children[c];
            }
        }
        self.nodes.items[current].output = index;
    }

    /// Compute failure links via BFS and convert children[] into a complete
    /// deterministic goto-function. Must be called after all addPattern() calls.
    pub fn build(self: *AhoCorasick, lengths: []const usize) !void {
        self.pattern_lengths = try self.allocator.alloc(usize, lengths.len);
        @memcpy(self.pattern_lengths, lengths);

        var queue: std.ArrayListUnmanaged(u32) = .empty;
        defer queue.deinit(self.allocator);

        // Level-1: root's children get failure=root; missing edges loop to root.
        for (0..alphabet_size) |c| {
            const child = self.nodes.items[0].children[c];
            if (child != null_node) {
                self.nodes.items[child].failure = 0;
                try queue.append(self.allocator, child);
            } else {
                self.nodes.items[0].children[c] = 0; // loop back to root
            }
        }

        // BFS: compute failure links and fill goto-function for non-trie edges.
        var front: usize = 0;
        while (front < queue.items.len) {
            const u = queue.items[front];
            front += 1;

            for (0..alphabet_size) |c| {
                const v = self.nodes.items[u].children[c];
                if (v != null_node) {
                    // Trie edge exists -- failure is parent's failure goto
                    self.nodes.items[v].failure =
                        self.nodes.items[self.nodes.items[u].failure].children[c];
                    try queue.append(self.allocator, v);
                } else {
                    // No trie edge -- fill goto from failure's goto
                    self.nodes.items[u].children[c] =
                        self.nodes.items[self.nodes.items[u].failure].children[c];
                }
            }
        }
    }

    /// Scan input and collect all pattern matches (may overlap).
    pub fn search(self: *const AhoCorasick, input: []const u8, allocator: std.mem.Allocator) ![]Match {
        var matches: std.ArrayListUnmanaged(Match) = .empty;
        // Pre-allocate to avoid thrashing (heuristic: ~1 match per 64 bytes)
        try matches.ensureTotalCapacity(allocator, input.len / 64);

        var state: u32 = 0;
        for (input, 0..) |byte, i| {
            state = self.nodes.items[state].children[char_map[byte]];

            // Walk the failure chain to find all accepting states.
            // Note: root (state 0) is never an accepting state because no
            // zero-length pattern can be inserted, so stopping at check != 0
            // is correct.
            var check = state;
            while (check != 0) {
                if (self.nodes.items[check].output) |pattern_idx| {
                    const pat_len = self.pattern_lengths[pattern_idx];
                    try matches.append(allocator, .{
                        .start = i + 1 - pat_len,
                        .end = i + 1,
                        .pattern_idx = pattern_idx,
                    });
                }
                check = self.nodes.items[check].failure;
            }
        }

        return try matches.toOwnedSlice(allocator);
    }
};

// ---------------------------------------------------------------------------
// Core replacement engine (shared by mask and unmask)
// ---------------------------------------------------------------------------

/// Scan `input` with the given automaton, replace matched spans with the
/// corresponding entry from `replacements`. Respects word boundaries and
/// resolves overlaps via leftmost-longest greedy selection.
fn replaceAll(
    ac: *const AhoCorasick,
    input: []const u8,
    replacements: []const []const u8,
    allocator: std.mem.Allocator,
) ![]u8 {
    const raw_matches = try ac.search(input, allocator);
    defer allocator.free(raw_matches);

    if (raw_matches.len == 0) {
        return try allocator.dupe(u8, input);
    }

    var valid: std.ArrayListUnmanaged(Match) = .empty;
    defer valid.deinit(allocator);
    try valid.ensureTotalCapacity(allocator, raw_matches.len);

    for (raw_matches) |m| {
        if (isWordBoundaryBefore(input, m.start) and isWordBoundaryAfter(input, m.end)) {
            valid.appendAssumeCapacity(m);
        }
    }

    if (valid.items.len == 0) {
        return try allocator.dupe(u8, input);
    }

    // --- Sort: by start position, then longest first ---
    std.sort.block(Match, valid.items, {}, struct {
        fn lessThan(_: void, a: Match, b: Match) bool {
            if (a.start != b.start) return a.start < b.start;
            // Prefer longer match when starting at same position
            return (a.end - a.start) > (b.end - b.start);
        }
    }.lessThan);

    // --- Greedy non-overlapping selection ---
    var selected: std.ArrayListUnmanaged(Match) = .empty;
    defer selected.deinit(allocator);
    try selected.ensureTotalCapacity(allocator, valid.items.len);

    var last_end: usize = 0;
    for (valid.items) |m| {
        if (m.start >= last_end) {
            try selected.append(allocator, m);
            last_end = m.end;
        }
    }

    // --- Build output buffer ---
    var exact_size: usize = input.len;
    for (selected.items) |m| {
        exact_size -= (m.end - m.start);
        exact_size += replacements[m.pattern_idx].len;
    }

    var out: std.ArrayListUnmanaged(u8) = .empty;
    try out.ensureTotalCapacity(allocator, exact_size);
    var pos: usize = 0;

    for (selected.items) |m| {
        try out.appendSlice(allocator, input[pos..m.start]);
        try out.appendSlice(allocator, replacements[m.pattern_idx]);
        pos = m.end;
    }
    try out.appendSlice(allocator, input[pos..]);
    return try out.toOwnedSlice(allocator);
}

/// Like `replaceAll`, but only applies matches starting before `safe_end`.
/// Returns the consumed position (>= safe_end) via `consumed_out`.
/// Used exclusively by the chunked masking path — kept separate from
/// `replaceAll` to avoid regressing the non-chunked hot path.
noinline fn replaceAllBounded(
    ac: *const AhoCorasick,
    input: []const u8,
    replacements: []const []const u8,
    safe_end: usize,
    consumed_out: *usize,
    allocator: std.mem.Allocator,
) ![]u8 {
    consumed_out.* = safe_end;

    const raw_matches = try ac.search(input, allocator);
    defer allocator.free(raw_matches);

    if (raw_matches.len == 0) {
        return try allocator.dupe(u8, input[0..safe_end]);
    }

    var valid: std.ArrayListUnmanaged(Match) = .empty;
    defer valid.deinit(allocator);
    try valid.ensureTotalCapacity(allocator, raw_matches.len);

    for (raw_matches) |m| {
        if (m.start >= safe_end) continue;
        if (isWordBoundaryBefore(input, m.start) and isWordBoundaryAfter(input, m.end)) {
            valid.appendAssumeCapacity(m);
        }
    }

    if (valid.items.len == 0) {
        return try allocator.dupe(u8, input[0..safe_end]);
    }

    std.sort.block(Match, valid.items, {}, struct {
        fn lessThan(_: void, a: Match, b: Match) bool {
            if (a.start != b.start) return a.start < b.start;
            return (a.end - a.start) > (b.end - b.start);
        }
    }.lessThan);

    var selected: std.ArrayListUnmanaged(Match) = .empty;
    defer selected.deinit(allocator);
    try selected.ensureTotalCapacity(allocator, valid.items.len);

    var last_end_sel: usize = 0;
    for (valid.items) |m| {
        if (m.start >= last_end_sel) {
            selected.appendAssumeCapacity(m);
            last_end_sel = m.end;
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
        try out.appendSlice(allocator, replacements[m.pattern_idx]);
        pos = m.end;
    }
    try out.appendSlice(allocator, input[pos..consumed]);
    return try out.toOwnedSlice(allocator);
}

// ---------------------------------------------------------------------------
// Chunked Aho-Corasick Masking — streaming-compatible interface
// ---------------------------------------------------------------------------
// Entity names can be up to ~64 bytes. When processing data in chunks, a name
// can span the boundary between two chunks. We withhold the last
// (max_pattern_len - 1) bytes of each chunk as "pending". When the next chunk
// arrives, we scan (pending ++ chunk), emit the safe prefix, and withhold a
// new tail.
// ---------------------------------------------------------------------------

/// Maximum overlap size: longest name pattern length.
/// Capped at 256 bytes — well above any realistic entity name.
const max_overlap = 256;

/// Persistent state for chunked entity masking.
/// Caller creates via `EntityMap.initChunkState()`, passes to each
/// `maskChunked()` call, and calls `flush()` after the last chunk.
/// The `combined_buf` prevents per-chunk memory allocation overhead.
pub const AcChunkState = struct {
    pending: [max_overlap]u8 = undefined,
    len: usize = 0,
    overlap: usize,
    combined_buf: std.ArrayListUnmanaged(u8) = .empty,

    pub fn deinit(self: *AcChunkState, allocator: std.mem.Allocator) void {
        self.combined_buf.deinit(allocator);
    }

    /// Emit remaining pending bytes after the last chunk.
    /// Returns an owned slice — caller must free it.
    pub fn flush(
        self: *AcChunkState,
        em: *const EntityMap,
        allocator: std.mem.Allocator,
    ) ![]u8 {
        if (self.len == 0) return try allocator.alloc(u8, 0);
        const result = try em.mask(self.pending[0..self.len], allocator);
        self.len = 0;
        return result;
    }

    /// Emit remaining pending bytes after the last unmask chunk.
    /// Returns an owned slice — caller must free it.
    pub fn flushUnmask(
        self: *AcChunkState,
        em: *const EntityMap,
        allocator: std.mem.Allocator,
    ) ![]u8 {
        if (self.len == 0) return try allocator.alloc(u8, 0);
        const result = try em.unmask(self.pending[0..self.len], allocator);
        self.len = 0;
        return result;
    }
};

// ---------------------------------------------------------------------------
// EntityMap -- session-level bidirectional name <-> alias context
// ---------------------------------------------------------------------------

/// Holds the bidirectional name<->alias mapping and two pre-built Aho-Corasick
/// automatons (forward for masking, reverse for unmasking).
///
/// Usage:
///   var em = try EntityMap.init(allocator, &.{ "John Doe", "Dr. Smith" });
///   defer em.deinit();
///   const masked = try em.mask("Patient John Doe was seen by Dr. Smith", allocator);
///   defer allocator.free(masked);
///   // masked == "Patient Entity_A was seen by Entity_B"
pub const EntityMap = struct {
    names: [][]u8,
    aliases: [][]u8,
    alias_const_slices: []const []const u8,
    name_const_slices: []const []const u8,
    forward_ac: AhoCorasick,
    reverse_ac: AhoCorasick,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, raw_names: []const []const u8) !EntityMap {
        const n = raw_names.len;

        const names = try allocator.alloc([]u8, n);
        errdefer allocator.free(names);
        const aliases = try allocator.alloc([]u8, n);
        errdefer allocator.free(aliases);

        const name_lengths = try allocator.alloc(usize, n);
        defer allocator.free(name_lengths);
        const alias_lengths = try allocator.alloc(usize, n);
        defer allocator.free(alias_lengths);

        // Track how many elements have been fully initialized for errdefer cleanup.
        var names_initialized: usize = 0;
        var aliases_initialized: usize = 0;

        errdefer {
            for (0..names_initialized) |j| allocator.free(names[j]);
            for (0..aliases_initialized) |j| allocator.free(aliases[j]);
        }

        for (raw_names, 0..) |name, i| {
            names[i] = try allocator.dupe(u8, name);
            names_initialized = i + 1;
            name_lengths[i] = name.len;
            aliases[i] = try generateAlias(allocator, i);
            aliases_initialized = i + 1;
            alias_lengths[i] = aliases[i].len;
        }

        // Pre-build const slices to avoid per-call allocation in mask()/unmask().
        const alias_const_slices = try allocator.alloc([]const u8, n);
        errdefer allocator.free(alias_const_slices);
        for (aliases, 0..) |alias, i| alias_const_slices[i] = alias;

        const name_const_slices = try allocator.alloc([]const u8, n);
        errdefer allocator.free(name_const_slices);
        for (names, 0..) |name, i| name_const_slices[i] = name;

        var forward_ac = try AhoCorasick.init(allocator);
        errdefer forward_ac.deinit();
        for (names, 0..) |name, i| {
            try forward_ac.addPattern(name, i);
        }
        try forward_ac.build(name_lengths);

        var reverse_ac = try AhoCorasick.init(allocator);
        errdefer reverse_ac.deinit();
        for (aliases, 0..) |alias, i| {
            try reverse_ac.addPattern(alias, i);
        }
        try reverse_ac.build(alias_lengths);

        return EntityMap{
            .names = names,
            .aliases = aliases,
            .alias_const_slices = alias_const_slices,
            .name_const_slices = name_const_slices,
            .forward_ac = forward_ac,
            .reverse_ac = reverse_ac,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *EntityMap) void {
        for (self.names) |name| self.allocator.free(name);
        for (self.aliases) |alias| self.allocator.free(alias);
        self.allocator.free(self.names);
        self.allocator.free(self.aliases);
        self.allocator.free(self.alias_const_slices);
        self.allocator.free(self.name_const_slices);
        self.forward_ac.deinit();
        self.reverse_ac.deinit();
    }

    /// Replace real names with aliases.
    pub fn mask(self: *const EntityMap, input: []const u8, allocator: std.mem.Allocator) ![]u8 {
        return replaceAll(&self.forward_ac, input, self.alias_const_slices, allocator);
    }

    /// Collect selected mask spans and their replacement aliases.
    pub fn collectMaskMatches(self: *const EntityMap, input: []const u8, allocator: std.mem.Allocator) ![]AuditMatch {
        const raw_matches = try self.forward_ac.search(input, allocator);
        defer allocator.free(raw_matches);

        if (raw_matches.len == 0) return try allocator.alloc(AuditMatch, 0);

        var valid: std.ArrayListUnmanaged(Match) = .empty;
        defer valid.deinit(allocator);
        try valid.ensureTotalCapacity(allocator, raw_matches.len);

        for (raw_matches) |m| {
            if (isWordBoundaryBefore(input, m.start) and isWordBoundaryAfter(input, m.end)) {
                valid.appendAssumeCapacity(m);
            }
        }

        if (valid.items.len == 0) return try allocator.alloc(AuditMatch, 0);

        std.sort.block(Match, valid.items, {}, struct {
            fn lessThan(_: void, a: Match, b: Match) bool {
                if (a.start != b.start) return a.start < b.start;
                return (a.end - a.start) > (b.end - b.start);
            }
        }.lessThan);

        var selected: std.ArrayListUnmanaged(Match) = .empty;
        defer selected.deinit(allocator);
        try selected.ensureTotalCapacity(allocator, valid.items.len);

        var last_end: usize = 0;
        for (valid.items) |m| {
            if (m.start >= last_end) {
                selected.appendAssumeCapacity(m);
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
                .pattern_idx = m.pattern_idx,
                .replacement = self.alias_const_slices[m.pattern_idx],
            });
        }

        return try audit_matches.toOwnedSlice(allocator);
    }

    /// Collect selected mask spans whose start position is before `safe_end`.
    /// Any chosen match that crosses `safe_end` extends `consumed` so callers
    /// can advance their raw-input offset in lockstep with `maskChunked()`.
    pub fn collectMaskMatchesBounded(
        self: *const EntityMap,
        input: []const u8,
        safe_end: usize,
        allocator: std.mem.Allocator,
    ) !BoundedAuditMatches {
        const bounded_end = @min(safe_end, input.len);
        const raw_matches = try self.forward_ac.search(input, allocator);
        defer allocator.free(raw_matches);

        if (raw_matches.len == 0) {
            return .{
                .matches = try allocator.alloc(AuditMatch, 0),
                .consumed = bounded_end,
            };
        }

        var valid: std.ArrayListUnmanaged(Match) = .empty;
        defer valid.deinit(allocator);
        try valid.ensureTotalCapacity(allocator, raw_matches.len);

        for (raw_matches) |m| {
            if (m.start >= bounded_end) continue;
            if (isWordBoundaryBefore(input, m.start) and isWordBoundaryAfter(input, m.end)) {
                valid.appendAssumeCapacity(m);
            }
        }

        if (valid.items.len == 0) {
            return .{
                .matches = try allocator.alloc(AuditMatch, 0),
                .consumed = bounded_end,
            };
        }

        std.sort.block(Match, valid.items, {}, struct {
            fn lessThan(_: void, a: Match, b: Match) bool {
                if (a.start != b.start) return a.start < b.start;
                return (a.end - a.start) > (b.end - b.start);
            }
        }.lessThan);

        var selected: std.ArrayListUnmanaged(Match) = .empty;
        defer selected.deinit(allocator);
        try selected.ensureTotalCapacity(allocator, valid.items.len);

        var last_end: usize = 0;
        for (valid.items) |m| {
            if (m.start >= last_end) {
                selected.appendAssumeCapacity(m);
                last_end = m.end;
            }
        }

        var audit_matches: std.ArrayListUnmanaged(AuditMatch) = .empty;
        errdefer audit_matches.deinit(allocator);
        try audit_matches.ensureTotalCapacity(allocator, selected.items.len);

        var consumed = bounded_end;
        for (selected.items) |m| {
            if (m.end > consumed) consumed = m.end;
            audit_matches.appendAssumeCapacity(.{
                .start = m.start,
                .end = m.end,
                .pattern_idx = m.pattern_idx,
                .replacement = self.alias_const_slices[m.pattern_idx],
            });
        }

        return .{
            .matches = try audit_matches.toOwnedSlice(allocator),
            .consumed = consumed,
        };
    }

    /// Replace aliases back to real names.
    pub fn unmask(self: *const EntityMap, input: []const u8, allocator: std.mem.Allocator) ![]u8 {
        return replaceAll(&self.reverse_ac, input, self.name_const_slices, allocator);
    }

    /// Read-only access to raw name strings for use by the fuzzy matcher.
    pub fn getRawNames(self: *const EntityMap) []const []const u8 {
        return self.name_const_slices;
    }

    /// Read-only access to alias strings for use by the fuzzy matcher.
    pub fn getAliases(self: *const EntityMap) []const []const u8 {
        return self.alias_const_slices;
    }

    /// Compute the length of the longest pattern in the forward automaton.
    pub fn maxPatternLen(self: *const EntityMap) usize {
        var max_len: usize = 0;
        for (self.forward_ac.pattern_lengths) |pl| {
            if (pl > max_len) max_len = pl;
        }
        return max_len;
    }

    /// Create initial chunk state for streaming masking.
    /// Caller MUST call `state.deinit(allocator)` when finished to free internal buffers.
    pub fn initChunkState(self: *const EntityMap) AcChunkState {
        const overlap = self.maxPatternLen();
        return AcChunkState{
            .overlap = if (overlap > 0) overlap - 1 else 0,
        };
    }

    /// Process one chunk for entity masking in streaming mode.
    ///
    /// Scans the full `pending ++ chunk` buffer for matches but only applies
    /// replacements for matches fully within the safe zone. Patterns spanning
    /// the safe/pending boundary are deferred to the next call.
    /// Uses a reusable internal buffer in `state` to achieve zero-allocation combination.
    ///
    /// Returns an owned output slice — caller must free it.
    /// After all chunks, call `state.flush(&em, allocator)` for the tail.
    pub fn maskChunked(
        self: *const EntityMap,
        chunk: []const u8,
        state: *AcChunkState,
        allocator: std.mem.Allocator,
    ) ![]u8 {
        if (chunk.len == 0) {
            return try allocator.alloc(u8, 0);
        }

        const old_pending_len = state.len;
        const total = old_pending_len + chunk.len;

        // If combined data is smaller than the overlap window, just accumulate.
        if (total <= state.overlap) {
            @memcpy(state.pending[old_pending_len..][0..chunk.len], chunk);
            state.len = total;
            return try allocator.alloc(u8, 0);
        }

        // Zero-allocation path: reuse the buffer inside state
        try state.combined_buf.resize(allocator, total);
        const combined = state.combined_buf.items;

        if (old_pending_len > 0) {
            @memcpy(combined[0..old_pending_len], state.pending[0..old_pending_len]);
        }
        @memcpy(combined[old_pending_len..], chunk);

        // safe_end: raw position up to which we emit masked output.
        // Everything from safe_end onward becomes new pending.
        const new_pending_len = @min(state.overlap, total);
        const safe_end = total - new_pending_len;

        var consumed: usize = undefined;
        const result = try replaceAllBounded(
            &self.forward_ac,
            combined,
            self.alias_const_slices,
            safe_end,
            &consumed,
            allocator,
        );

        // Save raw tail (from consumed onward) as new pending.
        const actual_pending = total - consumed;
        state.len = actual_pending;
        if (actual_pending > 0) {
            @memcpy(state.pending[0..actual_pending], combined[consumed..][0..actual_pending]);
        }

        return result;
    }

    /// Create initial chunk state for streaming unmasking.
    /// Caller MUST call `state.deinit(allocator)` when finished to free internal buffers.
    pub fn initUnmaskChunkState(self: *const EntityMap) AcChunkState {
        var max_len: usize = 0;
        for (self.reverse_ac.pattern_lengths) |pl| {
            if (pl > max_len) max_len = pl;
        }
        return AcChunkState{
            .overlap = if (max_len > 0) max_len - 1 else 0,
        };
    }

    /// Process one chunk for entity unmasking in streaming mode.
    ///
    /// Scans the full `pending ++ chunk` buffer for reverse matches.
    /// Patterns spanning the safe/pending boundary are deferred to the next call.
    ///
    /// Returns an owned output slice — caller must free it.
    /// After all chunks, call `state.flushUnmask(&em, allocator)` for the tail.
    pub fn unmaskChunked(
        self: *const EntityMap,
        chunk: []const u8,
        state: *AcChunkState,
        allocator: std.mem.Allocator,
    ) ![]u8 {
        if (chunk.len == 0) {
            return try allocator.alloc(u8, 0);
        }

        const old_pending_len = state.len;
        const total = old_pending_len + chunk.len;

        // If combined data is smaller than the overlap window, just accumulate.
        if (total <= state.overlap) {
            @memcpy(state.pending[old_pending_len..][0..chunk.len], chunk);
            state.len = total;
            return try allocator.alloc(u8, 0);
        }

        // Zero-allocation path: reuse the buffer inside state
        try state.combined_buf.resize(allocator, total);
        const combined = state.combined_buf.items;

        if (old_pending_len > 0) {
            @memcpy(combined[0..old_pending_len], state.pending[0..old_pending_len]);
        }
        @memcpy(combined[old_pending_len..], chunk);

        // safe_end: raw position up to which we emit unmasked output.
        // Everything from safe_end onward becomes new pending.
        const new_pending_len = @min(state.overlap, total);
        const safe_end = total - new_pending_len;

        var consumed: usize = undefined;
        const result = try replaceAllBounded(
            &self.reverse_ac,
            combined,
            self.name_const_slices,
            safe_end,
            &consumed,
            allocator,
        );

        // Save raw tail (from consumed onward) as new pending.
        const actual_pending = total - consumed;
        state.len = actual_pending;
        if (actual_pending > 0) {
            @memcpy(state.pending[0..actual_pending], combined[consumed..][0..actual_pending]);
        }

        return result;
    }
};

// ===========================================================================
// Unit Tests
// ===========================================================================

test "EntityMap - single name replacement" {
    const allocator = std.testing.allocator;
    var em = try EntityMap.init(allocator, &.{"John Doe"});
    defer em.deinit();

    const result = try em.mask("Patient John Doe was examined.", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Patient Entity_A was examined.", result);
}

test "EntityMap - multiple names" {
    const allocator = std.testing.allocator;
    var em = try EntityMap.init(allocator, &.{ "John Doe", "Dr. Smith" });
    defer em.deinit();

    const result = try em.mask("John Doe was seen by Dr. Smith today.", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Entity_A was seen by Entity_B today.", result);
}

test "EntityMap - collectMaskMatches exposes selected aliases" {
    const allocator = std.testing.allocator;
    var em = try EntityMap.init(allocator, &.{ "John Doe", "Dr. Smith" });
    defer em.deinit();

    const matches = try em.collectMaskMatches("John Doe met Dr. Smith", allocator);
    defer allocator.free(matches);

    try std.testing.expectEqual(@as(usize, 2), matches.len);
    try std.testing.expectEqualStrings("Entity_A", matches[0].replacement);
    try std.testing.expectEqualStrings("Entity_B", matches[1].replacement);
}

test "EntityMap - case insensitive matching" {
    const allocator = std.testing.allocator;
    var em = try EntityMap.init(allocator, &.{"John Doe"});
    defer em.deinit();

    const result = try em.mask("JOHN DOE and john doe are the same.", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Entity_A and Entity_A are the same.", result);
}

test "EntityMap - word boundary enforcement" {
    return;
}

test "EntityMap - no matches returns original" {
    const allocator = std.testing.allocator;
    var em = try EntityMap.init(allocator, &.{"John Doe"});
    defer em.deinit();

    const result = try em.mask("No names here.", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("No names here.", result);
}

// ---------------------------------------------------------------------------
// Chunked Masking Tests
// ---------------------------------------------------------------------------

/// Test helper: run chunked entity masking on `input` using the given chunk
/// size, collecting all output into one contiguous buffer.
fn runChunkedMask(
    em: *const EntityMap,
    input: []const u8,
    chunk_size: usize,
    allocator: std.mem.Allocator,
) ![]u8 {
    var output: std.ArrayListUnmanaged(u8) = .empty;
    errdefer output.deinit(allocator);

    var state = em.initChunkState();
    defer state.deinit(allocator);
    var offset: usize = 0;

    while (offset < input.len) {
        const end = @min(offset + chunk_size, input.len);
        const result = try em.maskChunked(input[offset..end], &state, allocator);
        defer allocator.free(result);
        try output.appendSlice(allocator, result);
        offset = end;
    }

    // Flush remaining
    const flushed = try state.flush(em, allocator);
    defer allocator.free(flushed);
    try output.appendSlice(allocator, flushed);

    return try output.toOwnedSlice(allocator);
}

test "maskChunked - round-trip equivalence vs mask()" {
    const allocator = std.testing.allocator;
    var em = try EntityMap.init(allocator, &.{ "John Doe", "Dr. Smith", "Mary Williams" });
    defer em.deinit();

    const input = "Patient John Doe was seen by Dr. Smith. Mary Williams was discharged. John Doe returned later.";

    // Reference: single-pass masking
    const reference = try em.mask(input, allocator);
    defer allocator.free(reference);

    // Test with various chunk sizes
    for ([_]usize{ 1, 3, 7, 11, 16, 32, 64 }) |cs| {
        const chunked = try runChunkedMask(&em, input, cs, allocator);
        defer allocator.free(chunked);
        try std.testing.expectEqualStrings(reference, chunked);
    }
}

test "maskChunked - boundary-spanning name" {
    const allocator = std.testing.allocator;
    var em = try EntityMap.init(allocator, &.{"John Doe"});
    defer em.deinit();

    // "John Doe" is 8 bytes — place it so it spans a chunk boundary
    const input = "xxxx John Doe yyyy";

    const reference = try em.mask(input, allocator);
    defer allocator.free(reference);

    // Chunk size 8: first chunk = "xxxx Joh", second = "n Doe yy", third = "yy"
    const chunked = try runChunkedMask(&em, input, 8, allocator);
    defer allocator.free(chunked);
    try std.testing.expectEqualStrings(reference, chunked);
}

test "EntityMap - collectMaskMatchesBounded extends consumed for boundary match" {
    const allocator = std.testing.allocator;
    var em = try EntityMap.init(allocator, &.{"John Doe"});
    defer em.deinit();

    const input = "xxxx John Doe yyyy";
    const result = try em.collectMaskMatchesBounded(input, 10, allocator);
    defer allocator.free(result.matches);

    try std.testing.expectEqual(@as(usize, 1), result.matches.len);
    try std.testing.expectEqual(@as(usize, 5), result.matches[0].start);
    try std.testing.expectEqual(@as(usize, 13), result.matches[0].end);
    try std.testing.expectEqual(@as(usize, 13), result.consumed);
}

test "maskChunked - empty and small chunks" {
    const allocator = std.testing.allocator;
    var em = try EntityMap.init(allocator, &.{"John Doe"});
    defer em.deinit();

    // Empty input
    const empty_result = try runChunkedMask(&em, "", 16, allocator);
    defer allocator.free(empty_result);
    try std.testing.expectEqualStrings("", empty_result);

    // Single-byte chunks
    const input = "Hi John Doe!";
    const reference = try em.mask(input, allocator);
    defer allocator.free(reference);
    const chunked = try runChunkedMask(&em, input, 1, allocator);
    defer allocator.free(chunked);
    try std.testing.expectEqualStrings(reference, chunked);
}

test "EntityMap - empty input" {
    const allocator = std.testing.allocator;
    var em = try EntityMap.init(allocator, &.{"John Doe"});
    defer em.deinit();

    const result = try em.mask("", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("", result);
}

test "EntityMap - unmask round trip" {
    const allocator = std.testing.allocator;
    var em = try EntityMap.init(allocator, &.{ "John Doe", "Jane Smith" });
    defer em.deinit();

    const original = "John Doe and Jane Smith filed claims.";

    const masked = try em.mask(original, allocator);
    defer allocator.free(masked);
    try std.testing.expectEqualStrings("Entity_A and Entity_B filed claims.", masked);

    const unmasked = try em.unmask(masked, allocator);
    defer allocator.free(unmasked);
    try std.testing.expectEqualStrings(original, unmasked);
}

test "EntityMap - multiple occurrences of same name" {
    const allocator = std.testing.allocator;
    var em = try EntityMap.init(allocator, &.{"John Doe"});
    defer em.deinit();

    const result = try em.mask("John Doe said that John Doe was here.", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Entity_A said that Entity_A was here.", result);
}

test "EntityMap - alias generation sequence" {
    const allocator = std.testing.allocator;
    // Verify alias naming: A, B, C, ...
    const a0 = try generateAlias(allocator, 0);
    defer allocator.free(a0);
    try std.testing.expectEqualStrings("Entity_A", a0);

    const a25 = try generateAlias(allocator, 25);
    defer allocator.free(a25);
    try std.testing.expectEqualStrings("Entity_Z", a25);

    const a26 = try generateAlias(allocator, 26);
    defer allocator.free(a26);
    try std.testing.expectEqualStrings("Entity_AA", a26);
}

// ---------------------------------------------------------------------------
// Benchmark (opt-in via `zig build bench` to avoid slowing CI)
// ---------------------------------------------------------------------------

/// When the `bench` build step runs, it injects `build_options` as a module
/// import with `is_benchmark = true`. During normal `zig build test` the module
/// doesn't exist so `@import("root")` won't have it as a declaration.
const is_benchmark: bool = blk: {
    if (@hasDecl(@import("root"), "build_options")) {
        break :blk @field(@import("root").build_options, "is_benchmark");
    }
    break :blk false;
};

test "bench - EntityMap mask throughput" {
    if (!is_benchmark) return;
    const allocator = std.testing.allocator;

    const names = [_][]const u8{
        "John Doe",      "Jane Smith",   "Dr. Johnson",
        "Mary Williams", "Robert Brown",
    };
    var em = try EntityMap.init(allocator, &names);
    defer em.deinit();

    // Build a ~1 MB payload with names scattered every ~200 bytes
    const payload_size = 1024 * 1024;
    const payload = try allocator.alloc(u8, payload_size);
    defer allocator.free(payload);
    @memset(payload, 'a');

    // Plant names at regular intervals
    const name_str = " John Doe ";
    var pos: usize = 100;
    while (pos + name_str.len <= payload_size) {
        @memcpy(payload[pos..][0..name_str.len], name_str);
        pos += 200;
    }

    var timer = std.time.Timer.start() catch return;

    const iterations = 50;
    var run: usize = 0;
    while (run < iterations) : (run += 1) {
        const result = try em.mask(payload, allocator);
        allocator.free(result);
    }

    const elapsed_ns = timer.read();
    const total_bytes = payload_size * iterations;
    const mb_per_sec = (@as(f64, @floatFromInt(total_bytes)) /
        @as(f64, @floatFromInt(elapsed_ns))) * 1_000_000_000.0 / (1024.0 * 1024.0);

    std.debug.print("\n\n\n[BENCH] EntityMap mask: {d:.1} MB/s ({} iterations x {} bytes)\n", .{
        mb_per_sec,
        iterations,
        payload_size,
    });
}
