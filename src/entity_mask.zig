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
    const alphabet_size = 256;
    const null_node: u32 = std.math.maxInt(u32);

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

    /// Insert a pattern into the trie (case-folded to lowercase).
    pub fn addPattern(self: *AhoCorasick, pattern: []const u8, index: usize) !void {
        var current: u32 = 0;
        for (pattern) |byte| {
            const c = std.ascii.toLower(byte);
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

        var state: u32 = 0;
        for (input, 0..) |byte, i| {
            state = self.nodes.items[state].children[std.ascii.toLower(byte)];

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

    // --- Filter: only keep matches at word boundaries ---
    var valid: std.ArrayListUnmanaged(Match) = .empty;
    defer valid.deinit(allocator);

    for (raw_matches) |m| {
        if (isWordBoundaryBefore(input, m.start) and isWordBoundaryAfter(input, m.end)) {
            try valid.append(allocator, m);
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

    var last_end: usize = 0;
    for (valid.items) |m| {
        if (m.start >= last_end) {
            try selected.append(allocator, m);
            last_end = m.end;
        }
    }

    // --- Build output buffer ---
    var out: std.ArrayListUnmanaged(u8) = .empty;
    var pos: usize = 0;

    for (selected.items) |m| {
        try out.appendSlice(allocator, input[pos..m.start]);
        try out.appendSlice(allocator, replacements[m.pattern_idx]);
        pos = m.end;
    }
    try out.appendSlice(allocator, input[pos..]);

    return try out.toOwnedSlice(allocator);
}

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

    /// Replace aliases back to real names.
    pub fn unmask(self: *const EntityMap, input: []const u8, allocator: std.mem.Allocator) ![]u8 {
        return replaceAll(&self.reverse_ac, input, self.name_const_slices, allocator);
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

test "EntityMap - case insensitive matching" {
    const allocator = std.testing.allocator;
    var em = try EntityMap.init(allocator, &.{"John Doe"});
    defer em.deinit();

    const result = try em.mask("JOHN DOE and john doe are the same.", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Entity_A and Entity_A are the same.", result);
}

test "EntityMap - word boundary enforcement" {
    const allocator = std.testing.allocator;
    // "John" should NOT match inside "Johnson"
    var em = try EntityMap.init(allocator, &.{"John"});
    defer em.deinit();

    const result = try em.mask("Johnson and John went home.", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Johnson and Entity_A went home.", result);
}

test "EntityMap - no matches returns original" {
    const allocator = std.testing.allocator;
    var em = try EntityMap.init(allocator, &.{"John Doe"});
    defer em.deinit();

    const result = try em.mask("No names here.", allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("No names here.", result);
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
        "John Doe",      "Jane Smith",    "Dr. Johnson",
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

    std.debug.print("\n[BENCH] EntityMap mask: {d:.1} MB/s ({} iterations x {} bytes)\n", .{
        mb_per_sec,
        iterations,
        payload_size,
    });
}
