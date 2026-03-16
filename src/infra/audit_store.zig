const std = @import("std");
const logger_mod = @import("logger.zig");
const Logger = logger_mod.Logger;

// ---------------------------------------------------------------------------
// AuditStore — In-memory ring buffer for searchable audit event history
// ---------------------------------------------------------------------------
// Stores the last N audit events as serialized JSON lines. Thread-safe for
// concurrent writes from multiple request handlers. Supports filtered queries
// via the /_admin/audit endpoint.
// ---------------------------------------------------------------------------

pub const AuditEntry = struct {
    /// Monotonically increasing sequence number for ordering.
    seq: u64,
    /// Timestamp (unix millis) when the event was recorded.
    timestamp_ms: i64,
    /// Event type discriminator: "redaction", "admin", "request".
    event_type: []const u8,
    /// Session ID associated with this event.
    session_id: []const u8,
    /// Raw JSON line (owned, heap-allocated).
    json_line: []const u8,
};

pub const QueryFilters = struct {
    event_type: ?[]const u8 = null,
    session_id: ?[]const u8 = null,
    limit: u32 = 50,
};

pub const AuditStore = struct {
    entries: []OwnedEntry,
    capacity: u32,
    write_pos: u32,
    total_written: u64,
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex,

    const OwnedEntry = struct {
        seq: u64 = 0,
        timestamp_ms: i64 = 0,
        event_type: ?[]const u8 = null,
        session_id: ?[]const u8 = null,
        json_line: ?[]const u8 = null,

        fn deinit(self: *OwnedEntry, alloc: std.mem.Allocator) void {
            if (self.event_type) |et| alloc.free(et);
            if (self.session_id) |sid| alloc.free(sid);
            if (self.json_line) |jl| alloc.free(jl);
            self.* = .{};
        }
    };

    pub fn init(capacity: u32, allocator: std.mem.Allocator) !AuditStore {
        const cap = if (capacity == 0) 1 else capacity;
        const entries = try allocator.alloc(OwnedEntry, cap);
        @memset(entries, .{});
        return .{
            .entries = entries,
            .capacity = cap,
            .write_pos = 0,
            .total_written = 0,
            .allocator = allocator,
            .mutex = .{},
        };
    }

    pub fn deinit(self: *AuditStore) void {
        for (self.entries) |*entry| {
            entry.deinit(self.allocator);
        }
        self.allocator.free(self.entries);
    }

    /// Append an audit event to the ring buffer. Overwrites oldest entry
    /// when the buffer is full. All heap allocations happen before the
    /// lock is taken, so total_written is only incremented on success.
    pub fn append(
        self: *AuditStore,
        event_type: []const u8,
        session_id: []const u8,
        json_line: []const u8,
    ) void {
        // Pre-allocate all strings before acquiring the lock so that an
        // allocation failure never leaves the slot in a partial state and
        // never consumes a sequence number.
        const owned_et = self.allocator.dupe(u8, event_type) catch return;
        const owned_sid = self.allocator.dupe(u8, session_id) catch {
            self.allocator.free(owned_et);
            return;
        };
        const owned_jl = self.allocator.dupe(u8, json_line) catch {
            self.allocator.free(owned_et);
            self.allocator.free(owned_sid);
            return;
        };

        self.mutex.lock();
        defer self.mutex.unlock();

        const pos = self.write_pos;
        var entry = &self.entries[pos];

        // Free the previous occupant of this slot (ring-buffer overwrite).
        entry.deinit(self.allocator);

        self.total_written += 1;
        entry.seq = self.total_written;
        entry.timestamp_ms = std.time.milliTimestamp();
        entry.event_type = owned_et;
        entry.session_id = owned_sid;
        entry.json_line = owned_jl;

        self.write_pos = (pos + 1) % self.capacity;
    }

    /// Query the ring buffer with optional filters. Returns a JSON array.
    pub fn queryJson(self: *AuditStore, filters: QueryFilters, allocator: std.mem.Allocator) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        var buf: std.ArrayListUnmanaged(u8) = .empty;
        errdefer buf.deinit(allocator);
        const writer = buf.writer(allocator);

        try writer.writeByte('[');
        var count: u32 = 0;
        const n = @min(self.total_written, self.capacity);

        // Iterate from newest to oldest
        var i: u32 = 0;
        while (i < n and count < filters.limit) : (i += 1) {
            // Index of the i-th newest entry. Formula works for all values of
            // write_pos (including 0) without a special case.
            const idx = if (self.write_pos > i)
                self.write_pos - 1 - i
            else
                self.capacity - 1 - (i - self.write_pos);

            const entry = &self.entries[idx];
            if (entry.json_line == null) continue;

            // Apply filters
            if (filters.event_type) |et| {
                if (entry.event_type) |eet| {
                    if (!std.mem.eql(u8, eet, et)) continue;
                } else continue;
            }
            if (filters.session_id) |sid| {
                if (entry.session_id) |esid| {
                    if (!std.mem.startsWith(u8, esid, sid)) continue;
                } else continue;
            }

            if (count > 0) try writer.writeByte(',');
            try writer.writeAll(entry.json_line.?);
            count += 1;
        }

        try writer.writeByte(']');
        return try buf.toOwnedSlice(allocator);
    }

    /// Return the total number of events ever written (including overwritten ones).
    pub fn totalWritten(self: *AuditStore) u64 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.total_written;
    }

    /// Return the number of events currently stored in the buffer.
    pub fn currentCount(self: *AuditStore) u32 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return @intCast(@min(self.total_written, self.capacity));
    }
};

// ===========================================================================
// Unit Tests
// ===========================================================================

test "AuditStore - basic append and query" {
    var store = try AuditStore.init(10, std.testing.allocator);
    defer store.deinit();

    store.append("redaction", "sess1", "{\"event\":\"redaction\",\"id\":1}");
    store.append("admin", "sess2", "{\"event\":\"admin\",\"id\":2}");

    try std.testing.expectEqual(@as(u64, 2), store.totalWritten());
    try std.testing.expectEqual(@as(u32, 2), store.currentCount());

    const json = try store.queryJson(.{}, std.testing.allocator);
    defer std.testing.allocator.free(json);

    // Should contain both events
    try std.testing.expect(std.mem.indexOf(u8, json, "\"id\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"id\":2") != null);
}

test "AuditStore - ring buffer wrapping" {
    var store = try AuditStore.init(3, std.testing.allocator);
    defer store.deinit();

    store.append("redaction", "s1", "{\"seq\":1}");
    store.append("redaction", "s2", "{\"seq\":2}");
    store.append("redaction", "s3", "{\"seq\":3}");
    store.append("redaction", "s4", "{\"seq\":4}"); // overwrites seq 1

    try std.testing.expectEqual(@as(u64, 4), store.totalWritten());
    try std.testing.expectEqual(@as(u32, 3), store.currentCount());

    const json = try store.queryJson(.{}, std.testing.allocator);
    defer std.testing.allocator.free(json);

    // seq 1 should have been overwritten
    try std.testing.expect(std.mem.indexOf(u8, json, "\"seq\":1") == null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"seq\":4") != null);
}

test "AuditStore - filter by event_type" {
    var store = try AuditStore.init(10, std.testing.allocator);
    defer store.deinit();

    store.append("redaction", "s1", "{\"type\":\"redaction\"}");
    store.append("admin", "s2", "{\"type\":\"admin\"}");
    store.append("redaction", "s3", "{\"type\":\"redaction2\"}");

    const json = try store.queryJson(.{ .event_type = "admin" }, std.testing.allocator);
    defer std.testing.allocator.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"type\":\"admin\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"type\":\"redaction\"") == null);
}

test "AuditStore - filter by session_id prefix" {
    var store = try AuditStore.init(10, std.testing.allocator);
    defer store.deinit();

    store.append("redaction", "abc123", "{\"sid\":\"abc123\"}");
    store.append("redaction", "xyz789", "{\"sid\":\"xyz789\"}");

    const json = try store.queryJson(.{ .session_id = "abc" }, std.testing.allocator);
    defer std.testing.allocator.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"sid\":\"abc123\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"sid\":\"xyz789\"") == null);
}

test "AuditStore - limit parameter" {
    var store = try AuditStore.init(10, std.testing.allocator);
    defer store.deinit();

    var i: u32 = 0;
    while (i < 5) : (i += 1) {
        var buf: [32]u8 = undefined;
        const json_line = std.fmt.bufPrint(&buf, "{{\"n\":{d}}}", .{i}) catch unreachable;
        store.append("redaction", "s1", json_line);
    }

    const json = try store.queryJson(.{ .limit = 2 }, std.testing.allocator);
    defer std.testing.allocator.free(json);

    // Count the number of objects in the JSON array
    var count: u32 = 0;
    for (json) |c| {
        if (c == '{') count += 1;
    }
    try std.testing.expectEqual(@as(u32, 2), count);
}
