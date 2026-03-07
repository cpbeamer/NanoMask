const std = @import("std");
const versioned_entity_set = @import("versioned_entity_set.zig");
const VersionedEntitySet = versioned_entity_set.VersionedEntitySet;

// ---------------------------------------------------------------------------
// File Watcher — poll-based entity file reload trigger
// ---------------------------------------------------------------------------
// Periodically checks the entity file for modification (mtime/size change).
// When a change is detected, rebuilds the EntityMap + FuzzyMatcher in the
// background and atomically swaps it into the VersionedEntitySet via RCU.
//
// Uses polling for cross-platform portability (Windows, Linux, macOS).
// ---------------------------------------------------------------------------

pub const FileWatcher = struct {
    path: []const u8,
    poll_interval_ms: u64,
    last_mtime: i128,
    last_size: u64,
    entity_set: *VersionedEntitySet,
    fuzzy_threshold: f64,
    allocator: std.mem.Allocator,
    running: std.atomic.Value(bool),

    pub fn init(
        path: []const u8,
        poll_interval_ms: u64,
        entity_set: *VersionedEntitySet,
        fuzzy_threshold: f64,
        allocator: std.mem.Allocator,
    ) FileWatcher {
        // Get initial file stat for baseline comparison
        const stat = getFileStat(path);

        return .{
            .path = path,
            .poll_interval_ms = poll_interval_ms,
            .last_mtime = stat.mtime,
            .last_size = stat.size,
            .entity_set = entity_set,
            .fuzzy_threshold = fuzzy_threshold,
            .allocator = allocator,
            .running = std.atomic.Value(bool).init(true),
        };
    }

    const FileStat = struct {
        mtime: i128,
        size: u64,
    };

    fn getFileStat(path: []const u8) FileStat {
        const file = std.fs.cwd().openFile(path, .{}) catch {
            return .{ .mtime = 0, .size = 0 };
        };
        defer file.close();

        const stat = file.stat() catch {
            return .{ .mtime = 0, .size = 0 };
        };

        return .{
            .mtime = stat.mtime,
            .size = stat.size,
        };
    }

    /// Start the watcher loop on a new detached thread.
    pub fn start(self: *FileWatcher) !void {
        const thread = try std.Thread.spawn(.{}, pollLoop, .{self});
        thread.detach();
    }

    /// Signal the watcher to stop on the next poll cycle.
    pub fn stop(self: *FileWatcher) void {
        self.running.store(false, .release);
    }

    /// Main poll loop — runs on a background thread.
    fn pollLoop(self: *FileWatcher) void {
        std.debug.print("[WATCH] File watcher started for '{s}' (poll every {}ms)\n", .{ self.path, self.poll_interval_ms });

        while (self.running.load(.acquire)) {
            std.Thread.sleep(self.poll_interval_ms * std.time.ns_per_ms);

            if (!self.running.load(.acquire)) break;

            const stat = getFileStat(self.path);

            if (stat.mtime != self.last_mtime or stat.size != self.last_size) {
                self.handleFileChange(stat);
            }
        }

        std.debug.print("[WATCH] File watcher stopped\n", .{});
    }

    /// Rebuild automaton and swap when entity file changes.
    fn handleFileChange(self: *FileWatcher, new_stat: FileStat) void {
        const old_version = self.entity_set.version;
        const new_version = old_version + 1;

        std.debug.print("[WATCH] Entity reload started (v{} → v{})\n", .{ old_version, new_version });

        var timer = std.time.Timer.start() catch {
            std.debug.print("[WATCH] WARNING: Failed to start timer for reload\n", .{});
            return;
        };

        const new_snapshot = versioned_entity_set.loadSnapshotFromFile(
            self.path,
            self.fuzzy_threshold,
            new_version,
            self.allocator,
        ) catch |err| {
            std.debug.print("[WATCH] WARNING: Entity reload failed: {s} — keeping current automaton (v{})\n", .{ @errorName(err), old_version });
            // Update stat anyway to avoid retrying every poll cycle on a
            // persistently broken file. Next real change will trigger retry.
            self.last_mtime = new_stat.mtime;
            self.last_size = new_stat.size;
            return;
        };

        self.entity_set.swap(new_snapshot);

        const elapsed_ns = timer.read();
        const elapsed_ms = elapsed_ns / std.time.ns_per_ms;

        std.debug.print("[WATCH] Entity reload complete (v{}, {} entities, rebuilt in {}ms)\n", .{
            new_version,
            new_snapshot.loaded_names.len,
            elapsed_ms,
        });

        self.last_mtime = new_stat.mtime;
        self.last_size = new_stat.size;
    }
};
