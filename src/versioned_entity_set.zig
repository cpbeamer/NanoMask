const std = @import("std");
const entity_mask = @import("entity_mask.zig");
const fuzzy_match = @import("fuzzy_match.zig");

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

/// Manages atomic swap between entity snapshots using the RCU pattern.
/// Readers call `acquire()` to get a snapshot pointer (lock-free, no mutex).
/// Writers call `swap()` to atomically install a new snapshot.
pub const VersionedEntitySet = struct {
    current: std.atomic.Value(?*EntitySnapshot),
    version: std.atomic.Value(u32),
    allocator: std.mem.Allocator,

    pub fn init(initial_snapshot: *EntitySnapshot) VersionedEntitySet {
        return .{
            .current = std.atomic.Value(?*EntitySnapshot).init(initial_snapshot),
            .version = std.atomic.Value(u32).init(initial_snapshot.version),
            .allocator = initial_snapshot.allocator,
        };
    }

    /// Acquire the current snapshot for use during a request.
    /// Increments ref_count atomically — no mutex, no contention.
    /// Caller MUST call `release()` when done.
    pub fn acquire(self: *VersionedEntitySet) *EntitySnapshot {
        const snapshot = self.current.load(.acquire).?;
        snapshot.acquire();
        return snapshot;
    }

    /// Release a previously acquired snapshot.
    /// If the snapshot was retired and this is the last reference, frees it.
    pub fn release(self: *VersionedEntitySet, snapshot: *EntitySnapshot) void {
        _ = self;
        _ = snapshot.release();
    }

    /// Atomically swap the current snapshot with `new_snapshot`.
    /// The old snapshot's ref_count is decremented (for the "set owns it" ref).
    /// If no requests are using the old snapshot, it's freed immediately.
    /// Otherwise it's freed when the last request releases it.
    pub fn swap(self: *VersionedEntitySet, new_snapshot: *EntitySnapshot) void {
        self.version.store(new_snapshot.version, .release);
        const old = self.current.swap(new_snapshot, .acq_rel);
        // Release the set's own reference to the old snapshot
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
        const snap = self.current.swap(null, .acq_rel);
        if (snap) |s| {
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
    version: u32,
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

    var line_it = std.mem.splitScalar(u8, content, '\n');
    while (line_it.next()) |line| {
        const trimmed = std.mem.trimRight(u8, std.mem.trimLeft(u8, line, " \t\r"), " \t\r");
        if (trimmed.len == 0 or trimmed[0] == '#') continue;
        if (trimmed.len > max_entity_name_len) {
            std.debug.print("[WARN] Skipping entity name exceeding {d} bytes ({d} bytes)\n", .{
                max_entity_name_len,
                trimmed.len,
            });
            continue;
        }
        try names_list.append(allocator, try allocator.dupe(u8, trimmed));
    }

    const loaded_names = try names_list.toOwnedSlice(allocator);
    errdefer {
        for (loaded_names) |name| allocator.free(name);
        allocator.free(loaded_names);
    }

    var em = try entity_mask.EntityMap.init(allocator, loaded_names);
    errdefer em.deinit();

    var fm = try fuzzy_match.FuzzyMatcher.init(
        allocator,
        em.getRawNames(),
        em.getAliases(),
        fuzzy_threshold,
    );
    errdefer fm.deinit();

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

    var em = try entity_mask.EntityMap.init(allocator, loaded_names);
    errdefer em.deinit();

    var fm = try fuzzy_match.FuzzyMatcher.init(
        allocator,
        em.getRawNames(),
        em.getAliases(),
        fuzzy_threshold,
    );
    errdefer fm.deinit();

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
        1,
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

    const snapshot = try loadSnapshotFromFile("entities.txt", 0.80, 1, allocator);
    var set = VersionedEntitySet.init(snapshot);
    defer set.deinit();

    const acquired = set.acquire();
    defer set.release(acquired);

    try std.testing.expectEqual(@as(u32, 1), acquired.version);
}

test "VersionedEntitySet - swap installs new version" {
    const allocator = std.testing.allocator;

    const snap1 = try loadSnapshotFromFile("entities.txt", 0.80, 1, allocator);
    var set = VersionedEntitySet.init(snap1);
    defer set.deinit();

    const snap2 = try loadSnapshotFromFile("entities.txt", 0.80, 2, allocator);
    set.swap(snap2);

    const acquired = set.acquire();
    defer set.release(acquired);

    try std.testing.expectEqual(@as(u32, 2), acquired.version);
}

test "VersionedEntitySet - version monotonicity across multiple swaps" {
    const allocator = std.testing.allocator;

    const snap1 = try loadSnapshotFromFile("entities.txt", 0.80, 1, allocator);
    var set = VersionedEntitySet.init(snap1);
    defer set.deinit();

    var last_version: u32 = 1;
    for (2..6) |v| {
        const new_snap = try loadSnapshotFromFile("entities.txt", 0.80, @intCast(v), allocator);
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

    const snap1 = try loadSnapshotFromFile("entities.txt", 0.80, 1, allocator);
    var set = VersionedEntitySet.init(snap1);
    defer set.deinit();

    // Simulate an in-flight request holding snap1
    const held = set.acquire();

    // Swap to a new version — snap1 should NOT be freed (held still references it)
    const snap2 = try loadSnapshotFromFile("entities.txt", 0.80, 2, allocator);
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

    const snapshot = try loadSnapshotFromFile("entities.txt", 0.80, 1, allocator);
    defer _ = snapshot.release();

    // entities.txt has: Jane Smith, John Doe, Dr. Johnson, another name
    // (blank lines and # comments are skipped)
    try std.testing.expect(snapshot.loaded_names.len >= 3);

    // Verify masking works
    const masked = try snapshot.entity_map.mask("Jane Smith visited Dr. Johnson", allocator);
    defer allocator.free(masked);
    try std.testing.expect(!std.mem.eql(u8, "Jane Smith visited Dr. Johnson", masked));
}

test "loadSnapshotFromFile - nonexistent file returns error" {
    const allocator = std.testing.allocator;
    const result = loadSnapshotFromFile("nonexistent_file_12345.txt", 0.80, 1, allocator);
    try std.testing.expectError(error.FileNotFound, result);
}

test "loadSnapshotFromNames - builds valid snapshot" {
    const allocator = std.testing.allocator;
    const names = [_][]const u8{ "Alice", "Bob", "Charlie" };
    const snapshot = try loadSnapshotFromNames(&names, 0.80, 1, allocator);
    defer _ = snapshot.release();

    try std.testing.expectEqual(@as(usize, 3), snapshot.loaded_names.len);
    try std.testing.expectEqual(@as(u32, 1), snapshot.version);

    const masked = try snapshot.entity_map.mask("Alice met Bob", allocator);
    defer allocator.free(masked);
    try std.testing.expectEqualStrings("Entity_A met Entity_B", masked);
}

test "loadSnapshotFromNames - empty list produces valid snapshot" {
    const allocator = std.testing.allocator;
    const names = [_][]const u8{};
    const snapshot = try loadSnapshotFromNames(&names, 0.80, 1, allocator);
    defer _ = snapshot.release();

    try std.testing.expectEqual(@as(usize, 0), snapshot.loaded_names.len);

    // Masking with no entities should return input unchanged
    const masked = try snapshot.entity_map.mask("Hello world", allocator);
    defer allocator.free(masked);
    try std.testing.expectEqualStrings("Hello world", masked);
}
