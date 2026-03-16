const std = @import("std");
const versioned_entity_set = @import("versioned_entity_set.zig");
const VersionedEntitySet = versioned_entity_set.VersionedEntitySet;
const observability_mod = @import("../infra/observability.zig");
const Observability = observability_mod.Observability;
const logger_mod = @import("../infra/logger.zig");
const Logger = logger_mod.Logger;
const config = @import("../infra/config.zig");

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
    fuzzy_threshold: f32,
    entity_format: config.EntityFormat,
    allocator: std.mem.Allocator,
    observability: ?*Observability,
    logger: ?*Logger,
    running: std.atomic.Value(bool),
    thread: ?std.Thread = null,

    pub fn init(
        path: []const u8,
        poll_interval_ms: u64,
        entity_set: *VersionedEntitySet,
        fuzzy_threshold: f32,
        entity_format: config.EntityFormat,
        allocator: std.mem.Allocator,
        observability: ?*Observability,
        logger: ?*Logger,
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
            .entity_format = entity_format,
            .allocator = allocator,
            .observability = observability,
            .logger = logger,
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

    /// Start the watcher loop on a background thread.
    pub fn start(self: *FileWatcher) !void {
        self.thread = try std.Thread.spawn(.{}, pollLoop, .{self});
    }

    /// Signal the watcher to stop and wait for the background thread to exit.
    /// Safe to call from a defer block — guarantees the poll loop has terminated
    /// before any resources it references (e.g. the VersionedEntitySet) are freed.
    pub fn join(self: *FileWatcher) void {
        self.running.store(false, .release);
        if (self.thread) |t| {
            t.join();
            self.thread = null;
        }
    }

    /// Main poll loop — runs on a background thread.
    fn pollLoop(self: *FileWatcher) void {
        if (self.logger) |log| {
            log.log(.info, "file_watcher_started", null, &.{
                .{ .key = "path", .value = .{ .string = self.path } },
                .{ .key = "poll_interval_ms", .value = .{ .uint = self.poll_interval_ms } },
            });
        }

        while (self.running.load(.acquire)) {
            std.Thread.sleep(self.poll_interval_ms * std.time.ns_per_ms);

            if (!self.running.load(.acquire)) break;

            const stat = getFileStat(self.path);

            if (stat.mtime != self.last_mtime or stat.size != self.last_size) {
                self.handleFileChange(stat);
            }
        }

        if (self.logger) |log| {
            log.info("file_watcher_stopped", null);
        }
    }

    /// Rebuild automaton and swap when entity file changes.
    fn handleFileChange(self: *FileWatcher, new_stat: FileStat) void {
        // Use nextVersion() for atomic, monotonic version generation.
        const new_version = self.entity_set.nextVersion();
        const old_version = new_version - 1;

        if (self.logger) |log| {
            log.log(.info, "entity_reload_started", null, &.{
                .{ .key = "old_version", .value = .{ .uint = old_version } },
                .{ .key = "new_version", .value = .{ .uint = new_version } },
            });
        }

        var timer = std.time.Timer.start() catch {
            if (self.logger) |log| {
                log.warn("entity_reload_timer_failed", null);
            }
            return;
        };

        const new_snapshot = versioned_entity_set.loadSnapshotFromFile(
            self.path,
            self.fuzzy_threshold,
            self.entity_format,
            new_version,
            self.logger,
            self.allocator,
        ) catch |err| {
            if (self.logger) |log| {
                log.log(.warn, "entity_reload_failed", null, &.{
                    .{ .key = "error", .value = .{ .string = @errorName(err) } },
                    .{ .key = "keeping_version", .value = .{ .uint = old_version } },
                });
            }
            if (self.observability) |obs| {
                obs.markEntityReloadFailure();
            }
            if (self.logger) |logger| {
                logger.auditAdmin(null, .{
                    .action = "entity_reload",
                    .source = "watcher",
                    .result = "failed",
                    .version = new_version,
                    .detail = @errorName(err),
                });
            }
            // Update stat anyway to avoid retrying every poll cycle on a
            // persistently broken file. Next real change will trigger retry.
            self.last_mtime = new_stat.mtime;
            self.last_size = new_stat.size;
            return;
        };

        self.entity_set.swap(new_snapshot);

        const elapsed_ns = timer.read();
        const elapsed_ms = elapsed_ns / std.time.ns_per_ms;

        if (self.logger) |log| {
            log.log(.info, "entity_reload_complete", null, &.{
                .{ .key = "version", .value = .{ .uint = new_version } },
                .{ .key = "entity_count", .value = .{ .uint = new_snapshot.loaded_names.len } },
                .{ .key = "rebuild_ms", .value = .{ .uint = elapsed_ms } },
            });
        }
        if (self.observability) |obs| {
            obs.markEntityReloadSuccess();
        }
        if (self.logger) |logger| {
            logger.auditAdmin(null, .{
                .action = "entity_reload",
                .source = "watcher",
                .result = "applied",
                .version = new_version,
                .entity_count_after = new_snapshot.loaded_names.len,
            });
        }

        self.last_mtime = new_stat.mtime;
        self.last_size = new_stat.size;
    }
};

// ===========================================================================
// Unit Tests
// ===========================================================================

test "getFileStat - valid file returns non-zero mtime and size" {
    const stat = FileWatcher.getFileStat("entities.txt");
    try std.testing.expect(stat.mtime != 0);
    try std.testing.expect(stat.size > 0);
}

test "getFileStat - missing file returns zeroes" {
    const stat = FileWatcher.getFileStat("nonexistent_file_12345.txt");
    try std.testing.expectEqual(@as(i128, 0), stat.mtime);
    try std.testing.expectEqual(@as(u64, 0), stat.size);
}

test "FileWatcher - start and join lifecycle" {
    const allocator = std.testing.allocator;

    const snapshot = try versioned_entity_set.loadSnapshotFromFile("entities.txt", 0.80, .names, 1, null, allocator);
    var set = VersionedEntitySet.init(snapshot);
    defer set.deinit();

    // Use a very short poll interval — the test only needs one cycle
    var watcher = FileWatcher.init("entities.txt", 10, &set, 0.80, .names, allocator, null, null);
    try watcher.start();

    // Let it run briefly, then join — verifies clean thread cleanup
    std.Thread.sleep(50 * std.time.ns_per_ms);
    watcher.join();

    // Thread should be null after join
    try std.testing.expect(watcher.thread == null);
}
