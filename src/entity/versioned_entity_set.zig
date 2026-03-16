const std = @import("std");
const entity_mask = @import("../redaction/entity_mask.zig");
const fuzzy_match = @import("../redaction/fuzzy_match.zig");
const config = @import("../infra/config.zig");

// ---------------------------------------------------------------------------
// Versioned Entity Set — RCU (Read-Copy-Update) for hot-reload
// ---------------------------------------------------------------------------
// Readers (request handlers) are never blocked. Writers (entity reloaders)
// build a new snapshot in the background and swap it in atomically using
// reference-counted snapshots. Old snapshots are freed when the last
// in-flight request releases them.
// ---------------------------------------------------------------------------

/// An immutable, reference-counted snapshot of the entity masking state.
/// Each request acquires a snapshot at the start and releases it when done.
/// When ref_count reaches 0 on a retired snapshot, all owned data is freed.
pub const EntitySnapshot = struct {
    entity_map: entity_mask.EntityMap,
    fuzzy_matcher: fuzzy_match.FuzzyMatcher,
    loaded_names: [][]const u8,
    version: u32,
    ref_count: std.atomic.Value(u32),
    allocator: std.mem.Allocator,

    /// Increment the reference count (called when a request handler begins).
    pub fn acquire(self: *EntitySnapshot) void {
        _ = self.ref_count.fetchAdd(1, .acquire);
    }

    /// Decrement the reference count. If this was the last reference,
    /// free all owned data. Returns true if the snapshot was freed.
    pub fn release(self: *EntitySnapshot) bool {
        const prev = self.ref_count.fetchSub(1, .release);
        if (prev == 1) {
            // Last reference dropped — free everything
            self.deinitOwned();
            return true;
        }
        return false;
    }

    /// Free all data owned by this snapshot and the snapshot struct itself.
    fn deinitOwned(self: *EntitySnapshot) void {
        const alloc = self.allocator;
        self.fuzzy_matcher.deinit();
        self.entity_map.deinit();
        for (self.loaded_names) |name| alloc.free(name);
        alloc.free(self.loaded_names);
        alloc.destroy(self);
    }
};

/// Manages safe swap between entity snapshots.
/// Readers call `acquire()` to get a ref-counted snapshot pointer.
/// Writers call `swap()` to install a new snapshot.
///
/// A RwLock eliminates the TOCTOU race between loading the pointer and
/// incrementing the ref count. Multiple readers proceed concurrently;
/// a swap blocks briefly until all active acquires have incremented their
/// ref counts, then releases. Entity reloads are rare, so the lock is
/// almost never contended.
pub const VersionedEntitySet = struct {
    current: ?*EntitySnapshot,
    version: std.atomic.Value(u32),
    allocator: std.mem.Allocator,
    lock: std.Thread.RwLock = .{},

    pub fn init(initial_snapshot: *EntitySnapshot) VersionedEntitySet {
        return .{
            .current = initial_snapshot,
            .version = std.atomic.Value(u32).init(initial_snapshot.version),
            .allocator = initial_snapshot.allocator,
        };
    }

    /// Acquire the current snapshot for use during a request.
    /// Increments ref_count while holding a shared read lock, eliminating
    /// the TOCTOU window that existed between the pointer load and increment.
    /// Caller MUST call `release()` when done.
    pub fn acquire(self: *VersionedEntitySet) *EntitySnapshot {
        self.lock.lockShared();
        defer self.lock.unlockShared();
        const snapshot = self.current.?;
        snapshot.acquire();
        return snapshot;
    }

    /// Release a previously acquired snapshot.
    /// If the snapshot was retired and this is the last reference, frees it.
    pub fn release(self: *VersionedEntitySet, snapshot: *EntitySnapshot) void {
        _ = self;
        _ = snapshot.release();
    }

    /// Install `new_snapshot` as the current snapshot.
    /// Holds an exclusive write lock so no acquire() can race the pointer
    /// swap and ref-count release of the old snapshot.
    pub fn swap(self: *VersionedEntitySet, new_snapshot: *EntitySnapshot) void {
        self.lock.lock();
        defer self.lock.unlock();
        self.version.store(new_snapshot.version, .release);
        const old = self.current;
        self.current = new_snapshot;
        // Release the set's own reference to the old snapshot.
        // Safe: no reader can hold the old pointer without having already
        // incremented its ref count, because acquire() holds the shared lock
        // for the duration of load+increment.
        if (old) |old_snap| {
            _ = old_snap.release();
        }
    }

    /// Atomically increment and return the next version number.
    /// Used by admin API to safely generate monotonic version IDs
    /// even under concurrent mutations.
    pub fn nextVersion(self: *VersionedEntitySet) u32 {
        return self.version.fetchAdd(1, .acq_rel) + 1;
    }

    /// Clean up: release the set's reference to the current snapshot.
    pub fn deinit(self: *VersionedEntitySet) void {
        self.lock.lock();
        defer self.lock.unlock();
        if (self.current) |s| {
            self.current = null;
            _ = s.release();
        }
    }
};

// ---------------------------------------------------------------------------
// Entity file loading — reusable builder for snapshots
// ---------------------------------------------------------------------------

/// Maximum supported entity name length in bytes. Names exceeding this
/// are skipped to prevent excessive Aho-Corasick automaton memory usage.
const max_entity_name_len = 256;

/// Load entities from a newline-delimited text file and build a new snapshot.
/// Skips blank lines and lines starting with `#`. Trims whitespace.
/// The returned snapshot has ref_count = 1 (the "owner" reference).
pub fn loadSnapshotFromFile(
    path: []const u8,
    fuzzy_threshold: f32,
    entity_format: config.EntityFormat,
    version: u32,
    logger: anytype,
    allocator: std.mem.Allocator,
) !*EntitySnapshot {
    var file = std.fs.cwd().openFile(path, .{}) catch |err| {
        std.debug.print("error: cannot open entity file '{s}': {s}\n", .{ path, @errorName(err) });
        return err;
    };
    defer file.close();

    const content = try file.readToEndAlloc(allocator, 10 * 1024 * 1024);
    defer allocator.free(content);

    var names_list: std.ArrayListUnmanaged([]const u8) = .empty;
    defer names_list.deinit(allocator);

    var group_ids: std.ArrayListUnmanaged(usize) = .empty;
    defer group_ids.deinit(allocator);

    var current_group_id: usize = 0;
    var in_structured_entity = false;

    var line_it = std.mem.splitScalar(u8, content, '\n');
    while (line_it.next()) |line| {
        const trimmed = std.mem.trimRight(u8, std.mem.trimLeft(u8, line, " \t\r\xEF\xBB\xBF"), " \t\r");
        if (trimmed.len == 0 or trimmed[0] == '#') continue;

        var entity_value: []const u8 = trimmed;
        if (entity_format == .structured) {
            if (trimmed.len >= 1 and trimmed[0] == '[') {
                if (in_structured_entity) {
                    current_group_id += 1; // Move to next entity alias block
                }
                in_structured_entity = true;
                continue; // [entity] header line
            }

            // Very basic INI/key-value parser: look for first '='
            if (std.mem.indexOfScalar(u8, trimmed, '=')) |eq_idx| {
                const val = std.mem.trim(u8, trimmed[eq_idx + 1 ..], " \t\r");
                if (val.len > 0) {
                    entity_value = val;
                } else {
                    continue; // Skip keys with empty values
                }
            } else {
                continue; // Skip lines without '=' in structured mode
            }
        }

        if (entity_value.len > max_entity_name_len) {
            std.debug.print("[WARN] Skipping entity value exceeding {d} bytes ({d} bytes)\n", .{
                max_entity_name_len,
                entity_value.len,
            });
            continue;
        }

        try names_list.append(allocator, try allocator.dupe(u8, entity_value));
        try group_ids.append(allocator, current_group_id);

        if (entity_format == .names) {
            // Names format: each line is a new group
            current_group_id += 1;
        }
    }

    const loaded_names = try names_list.toOwnedSlice(allocator);
    errdefer {
        for (loaded_names) |name| allocator.free(name);
        allocator.free(loaded_names);
    }

    const loaded_group_ids = try group_ids.toOwnedSlice(allocator);
    defer allocator.free(loaded_group_ids);

    var timer = std.time.Timer.start() catch unreachable;

    var em = try entity_mask.EntityMap.initGrouped(allocator, loaded_names, loaded_group_ids);
    errdefer em.deinit();

    // Calculate approximate memory used by the automatons
    const node_size = @sizeOf(entity_mask.AhoCorasick.Node);
    const automaton_memory_bytes =
        (em.forward_ac.nodes.capacity * node_size) +
        (em.reverse_ac.nodes.capacity * node_size);

    var fm = try fuzzy_match.FuzzyMatcher.init(
        allocator,
        em.getRawNames(),
        em.getAliases(),
        fuzzy_threshold,
    );
    errdefer fm.deinit();

    const build_time_ms = timer.read() / std.time.ns_per_ms;

    if (logger != null) {
        logger.?.log(.info, "automaton_built", null, &.{
            .{ .key = "entity_set_size", .value = .{ .uint = loaded_names.len } },
            .{ .key = "automaton_build_time_ms", .value = .{ .uint = build_time_ms } },
            .{ .key = "automaton_memory_bytes", .value = .{ .uint = automaton_memory_bytes } },
            .{ .key = "source", .value = .{ .string = path } },
            .{ .key = "version", .value = .{ .uint = version } },
        });
    }

    const snapshot = try allocator.create(EntitySnapshot);
    snapshot.* = .{
        .entity_map = em,
        .fuzzy_matcher = fm,
        .loaded_names = loaded_names,
        .version = version,
        .ref_count = std.atomic.Value(u32).init(1), // owned by creator
        .allocator = allocator,
    };

    return snapshot;
}

/// Build a snapshot from an in-memory name list (no file I/O).
/// Used by the admin API to rebuild after add/remove/replace operations.
/// The returned snapshot has ref_count = 1 (the "owner" reference).
pub fn loadSnapshotFromNames(
    names: []const []const u8,
    fuzzy_threshold: f32,
    version: u32,
    logger: anytype,
    allocator: std.mem.Allocator,
) !*EntitySnapshot {
    // Dupe all names so the snapshot owns its data
    const loaded_names = try allocator.alloc([]const u8, names.len);
    var initialized: usize = 0;
    errdefer {
        for (0..initialized) |j| allocator.free(loaded_names[j]);
        allocator.free(loaded_names);
    }

    for (names, 0..) |name, i| {
        loaded_names[i] = try allocator.dupe(u8, name);
        initialized = i + 1;
    }

    var timer = std.time.Timer.start() catch unreachable;

    var em = try entity_mask.EntityMap.init(allocator, loaded_names);
    errdefer em.deinit();

    // Calculate approximate memory used by the automatons
    const node_size = @sizeOf(entity_mask.AhoCorasick.Node);
    const automaton_memory_bytes =
        (em.forward_ac.nodes.capacity * node_size) +
        (em.reverse_ac.nodes.capacity * node_size);

    var fm = try fuzzy_match.FuzzyMatcher.init(
        allocator,
        em.getRawNames(),
        em.getAliases(),
        fuzzy_threshold,
    );
    errdefer fm.deinit();

    const build_time_ms = timer.read() / std.time.ns_per_ms;

    if (logger != null) {
        logger.?.log(.info, "automaton_built", null, &.{
            .{ .key = "entity_set_size", .value = .{ .uint = loaded_names.len } },
            .{ .key = "automaton_build_time_ms", .value = .{ .uint = build_time_ms } },
            .{ .key = "automaton_memory_bytes", .value = .{ .uint = automaton_memory_bytes } },
            .{ .key = "source", .value = .{ .string = "memory" } },
            .{ .key = "version", .value = .{ .uint = version } },
        });
    }

    const snapshot = try allocator.create(EntitySnapshot);
    snapshot.* = .{
        .entity_map = em,
        .fuzzy_matcher = fm,
        .loaded_names = loaded_names,
        .version = version,
        .ref_count = std.atomic.Value(u32).init(1),
        .allocator = allocator,
    };

    return snapshot;
}

// ===========================================================================
// Unit Tests
// ===========================================================================

test "EntitySnapshot - acquire and release" {
    const allocator = std.testing.allocator;

    const snapshot = try loadSnapshotFromFile(
        "entities.txt",
        0.80,
        .names,
        1,
        null,
        allocator,
    );
    // snapshot starts with ref_count = 1

    // Simulate a request acquiring
    snapshot.acquire(); // ref_count = 2

    // Release the "owner" reference
    const freed_by_owner = snapshot.release(); // ref_count = 1
    try std.testing.expect(!freed_by_owner);

    // Release the "request" reference — should free
    const freed_by_request = snapshot.release(); // ref_count = 0 → freed
    try std.testing.expect(freed_by_request);
}

test "VersionedEntitySet - acquire returns current snapshot" {
    const allocator = std.testing.allocator;

    const snapshot = try loadSnapshotFromFile("entities.txt", 0.80, .names, 1, null, allocator);
    var set = VersionedEntitySet.init(snapshot);
    defer set.deinit();

    const acquired = set.acquire();
    defer set.release(acquired);

    try std.testing.expectEqual(@as(u32, 1), acquired.version);
}

test "VersionedEntitySet - swap installs new version" {
    const allocator = std.testing.allocator;

    const snap1 = try loadSnapshotFromFile("entities.txt", 0.80, .names, 1, null, allocator);
    var set = VersionedEntitySet.init(snap1);
    defer set.deinit();

    const snap2 = try loadSnapshotFromFile("entities.txt", 0.80, .names, 2, null, allocator);
    set.swap(snap2);

    const acquired = set.acquire();
    defer set.release(acquired);

    try std.testing.expectEqual(@as(u32, 2), acquired.version);
}

test "VersionedEntitySet - version monotonicity across multiple swaps" {
    const allocator = std.testing.allocator;

    const snap1 = try loadSnapshotFromFile("entities.txt", 0.80, .names, 1, null, allocator);
    var set = VersionedEntitySet.init(snap1);
    defer set.deinit();

    var last_version: u32 = 1;
    for (2..6) |v| {
        const new_snap = try loadSnapshotFromFile("entities.txt", 0.80, .names, @intCast(v), null, allocator);
        set.swap(new_snap);

        const acquired = set.acquire();
        defer set.release(acquired);

        try std.testing.expect(acquired.version > last_version);
        last_version = acquired.version;
    }
    try std.testing.expectEqual(@as(u32, 5), last_version);
}

test "VersionedEntitySet - old snapshot survives while referenced" {
    const allocator = std.testing.allocator;

    const snap1 = try loadSnapshotFromFile("entities.txt", 0.80, .names, 1, null, allocator);
    var set = VersionedEntitySet.init(snap1);
    defer set.deinit();

    // Simulate an in-flight request holding snap1
    const held = set.acquire();

    // Swap to a new version — snap1 should NOT be freed (held still references it)
    const snap2 = try loadSnapshotFromFile("entities.txt", 0.80, .names, 2, null, allocator);
    set.swap(snap2);

    // The held snapshot should still be valid and usable
    try std.testing.expectEqual(@as(u32, 1), held.version);
    // Verify entity_map is still functional
    const masked = try held.entity_map.mask("Jane Smith is here", allocator);
    defer allocator.free(masked);
    try std.testing.expect(!std.mem.eql(u8, "Jane Smith is here", masked));

    // Release the held snapshot — now it can be freed
    set.release(held);
}

test "loadSnapshotFromFile - loads entities correctly" {
    const allocator = std.testing.allocator;

    const snapshot = try loadSnapshotFromFile("entities.txt", 0.80, .names, 1, null, allocator);
    defer _ = snapshot.release();

    // entities.txt has: Jane Smith, John Doe, Dr. Johnson, another name
    // (blank lines and # comments are skipped)
    try std.testing.expect(snapshot.loaded_names.len >= 3);

    // Verify masking works
    const masked = try snapshot.entity_map.mask("Jane Smith visited Dr. Johnson", allocator);
    defer allocator.free(masked);
    try std.testing.expect(!std.mem.eql(u8, "Jane Smith visited Dr. Johnson", masked));
}

test "loadSnapshotFromFile - loads structured entities correctly" {
    const allocator = std.testing.allocator;

    const snapshot = try loadSnapshotFromFile("test_structured.nmentity", 0.80, .structured, 1, null, allocator);
    defer _ = snapshot.release();

    // test_structured.nmentity has 2 entities, each with 2 fields = 4 total loaded names
    try std.testing.expectEqual(@as(usize, 4), snapshot.loaded_names.len);

    const masked = try snapshot.entity_map.mask("John Doe DOB is 1985-03-15 and Jane Smith SSN is 123-45-6789", allocator);
    defer allocator.free(masked);
    // Entity 1 is John Doe group, Entity 2 is Jane Smith group
    try std.testing.expectEqualStrings("Entity_1 DOB is Entity_1 and Entity_2 SSN is Entity_2", masked);
}

test "loadSnapshotFromFile - nonexistent file returns error" {
    const allocator = std.testing.allocator;
    const result = loadSnapshotFromFile("nonexistent_file_12345.txt", 0.80, .names, 1, null, allocator);
    try std.testing.expectError(error.FileNotFound, result);
}

test "loadSnapshotFromNames - builds valid snapshot" {
    const allocator = std.testing.allocator;
    const names = [_][]const u8{ "Alice", "Bob", "Charlie" };
    const snapshot = try loadSnapshotFromNames(&names, 0.80, 1, null, allocator);
    defer _ = snapshot.release();

    try std.testing.expectEqual(@as(usize, 3), snapshot.loaded_names.len);
    try std.testing.expectEqual(@as(u32, 1), snapshot.version);

    const masked = try snapshot.entity_map.mask("Alice met Bob", allocator);
    defer allocator.free(masked);
    try std.testing.expectEqualStrings("Entity_1 met Entity_2", masked);
}

test "loadSnapshotFromNames - empty list produces valid snapshot" {
    const allocator = std.testing.allocator;
    const names = [_][]const u8{};
    const snapshot = try loadSnapshotFromNames(&names, 0.80, 1, null, allocator);
    defer _ = snapshot.release();

    try std.testing.expectEqual(@as(usize, 0), snapshot.loaded_names.len);

    // Masking with no entities should return input unchanged
    const masked = try snapshot.entity_map.mask("Hello world", allocator);
    defer allocator.free(masked);
    try std.testing.expectEqualStrings("Hello world", masked);
}
