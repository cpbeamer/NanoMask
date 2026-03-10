const std = @import("std");

pub const ShutdownState = struct {
    requested: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),
    draining: std.atomic.Value(bool) = std.atomic.Value(bool).init(false),

    pub fn request(self: *ShutdownState) bool {
        return self.requested.cmpxchgStrong(false, true, .acq_rel, .acquire) == null;
    }

    pub fn beginDraining(self: *ShutdownState) bool {
        _ = self.request();
        return self.draining.cmpxchgStrong(false, true, .acq_rel, .acquire) == null;
    }

    pub fn isRequested(self: *const ShutdownState) bool {
        return self.requested.load(.acquire);
    }

    pub fn isDraining(self: *const ShutdownState) bool {
        return self.draining.load(.acquire);
    }
};

pub const DrainResult = struct {
    completed: bool,
    remaining_connections: u32,
};

pub fn waitForDrain(
    active_connections: *std.atomic.Value(u32),
    timeout_ms: u64,
) DrainResult {
    const start_ns = std.time.nanoTimestamp();
    const timeout_ns = timeout_ms * std.time.ns_per_ms;

    while (true) {
        const remaining = active_connections.load(.acquire);
        if (remaining == 0) {
            return .{
                .completed = true,
                .remaining_connections = 0,
            };
        }

        if (timeout_ms == 0) {
            return .{
                .completed = false,
                .remaining_connections = remaining,
            };
        }

        const elapsed_ns = std.time.nanoTimestamp() - start_ns;
        if (elapsed_ns >= timeout_ns) {
            return .{
                .completed = false,
                .remaining_connections = remaining,
            };
        }

        std.Thread.sleep(10 * std.time.ns_per_ms);
    }
}

test "ShutdownState - request and drain are idempotent" {
    var state = ShutdownState{};

    try std.testing.expect(state.request());
    try std.testing.expect(!state.request());
    try std.testing.expect(state.isRequested());
    try std.testing.expect(!state.isDraining());

    try std.testing.expect(state.beginDraining());
    try std.testing.expect(!state.beginDraining());
    try std.testing.expect(state.isDraining());
}

test "waitForDrain returns immediately when no work is active" {
    var active = std.atomic.Value(u32).init(0);
    const result = waitForDrain(&active, 1_000);

    try std.testing.expect(result.completed);
    try std.testing.expectEqual(@as(u32, 0), result.remaining_connections);
}

test "waitForDrain times out when work stays active" {
    var active = std.atomic.Value(u32).init(2);
    const result = waitForDrain(&active, 0);

    try std.testing.expect(!result.completed);
    try std.testing.expectEqual(@as(u32, 2), result.remaining_connections);
}
