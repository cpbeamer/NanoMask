const std = @import("std");
const builtin = @import("builtin");

pub const RuntimeModel = enum {
    thread_per_connection,
    worker_pool,
    io_uring,

    pub fn parse(value: []const u8) !RuntimeModel {
        if (std.mem.eql(u8, value, "thread-per-connection")) return .thread_per_connection;
        if (std.mem.eql(u8, value, "worker-pool")) return .worker_pool;
        if (std.mem.eql(u8, value, "io-uring")) return .io_uring;
        return error.InvalidRuntimeModel;
    }

    pub fn label(self: RuntimeModel) []const u8 {
        return switch (self) {
            .thread_per_connection => "thread-per-connection",
            .worker_pool => "worker-pool",
            .io_uring => "io-uring",
        };
    }

    /// Returns true if this runtime model is fully implemented and available.
    pub fn isAvailable(self: RuntimeModel) bool {
        return switch (self) {
            .thread_per_connection, .worker_pool => true,
            // io_uring event loop is scaffolded but not yet implemented.
            // Currently falls back to worker_pool on all platforms.
            // Track: NMV3-017 for the full std.Io event-driven implementation.
            .io_uring => false,
        };
    }

    /// Returns the effective runtime model, falling back to worker_pool
    /// if the requested model is unavailable or not yet implemented.
    pub fn effectiveModel(self: RuntimeModel) RuntimeModel {
        if (self.isAvailable()) return self;
        return .worker_pool;
    }
};

pub const worker_pool_stack_size_bytes: usize = 2 * 1024 * 1024;

pub fn resolveWorkerThreads(
    model: RuntimeModel,
    requested_threads: usize,
    max_connections: u32,
) usize {
    const effective = model.effectiveModel();
    if (effective != .worker_pool) return 0;

    const connection_limit = @max(@as(usize, 1), @as(usize, @intCast(max_connections)));
    if (requested_threads != 0) {
        return @min(requested_threads, connection_limit);
    }

    const cpu_count = std.Thread.getCpuCount() catch 1;
    const auto_threads = @max(@as(usize, 4), cpu_count * 2);
    return @min(auto_threads, connection_limit);
}

pub fn estimatedHandlerThreads(
    model: RuntimeModel,
    worker_threads: usize,
    concurrent_connections: usize,
) usize {
    return switch (model.effectiveModel()) {
        .thread_per_connection => concurrent_connections,
        .worker_pool => worker_threads,
        .io_uring => unreachable,
    };
}

pub fn estimatedReservedStackBytes(
    model: RuntimeModel,
    worker_threads: usize,
    concurrent_connections: usize,
) usize {
    const stack_size = switch (model.effectiveModel()) {
        .thread_per_connection => std.Thread.SpawnConfig.default_stack_size,
        .worker_pool => worker_pool_stack_size_bytes,
        .io_uring => unreachable,
    };
    return estimatedHandlerThreads(model, worker_threads, concurrent_connections) * stack_size;
}

test "runtime model parses supported values" {
    try std.testing.expectEqual(RuntimeModel.thread_per_connection, try RuntimeModel.parse("thread-per-connection"));
    try std.testing.expectEqual(RuntimeModel.worker_pool, try RuntimeModel.parse("worker-pool"));
    try std.testing.expectEqual(RuntimeModel.io_uring, try RuntimeModel.parse("io-uring"));
}

test "runtime model rejects unsupported values" {
    try std.testing.expectError(error.InvalidRuntimeModel, RuntimeModel.parse("reactor"));
}

test "resolve worker threads clamps to max connections" {
    try std.testing.expectEqual(@as(usize, 8), resolveWorkerThreads(.worker_pool, 12, 8));
    try std.testing.expectEqual(@as(usize, 0), resolveWorkerThreads(.thread_per_connection, 12, 8));
}

test "io_uring is not yet implemented — always falls back to worker_pool" {
    // io_uring is scaffolded but isAvailable() returns false on all platforms
    // until the std.Io event-driven implementation is complete (NMV3-017).
    const model = RuntimeModel.io_uring;
    try std.testing.expect(!model.isAvailable());
    try std.testing.expectEqual(RuntimeModel.worker_pool, model.effectiveModel());
}

test "io_uring resolves worker threads like worker_pool" {
    // On non-Linux, effectiveModel() falls back to worker_pool
    const threads = resolveWorkerThreads(.io_uring, 8, 16);
    try std.testing.expectEqual(@as(usize, 8), threads);
}
