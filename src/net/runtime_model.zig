const std = @import("std");

pub const RuntimeModel = enum {
    thread_per_connection,
    worker_pool,

    pub fn parse(value: []const u8) !RuntimeModel {
        if (std.mem.eql(u8, value, "thread-per-connection")) return .thread_per_connection;
        if (std.mem.eql(u8, value, "worker-pool")) return .worker_pool;
        return error.InvalidRuntimeModel;
    }

    pub fn label(self: RuntimeModel) []const u8 {
        return switch (self) {
            .thread_per_connection => "thread-per-connection",
            .worker_pool => "worker-pool",
        };
    }
};

pub const worker_pool_stack_size_bytes: usize = 2 * 1024 * 1024;

pub fn resolveWorkerThreads(
    model: RuntimeModel,
    requested_threads: usize,
    max_connections: u32,
) usize {
    if (model != .worker_pool) return 0;

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
    return switch (model) {
        .thread_per_connection => concurrent_connections,
        .worker_pool => worker_threads,
    };
}

pub fn estimatedReservedStackBytes(
    model: RuntimeModel,
    worker_threads: usize,
    concurrent_connections: usize,
) usize {
    const stack_size = switch (model) {
        .thread_per_connection => std.Thread.SpawnConfig.default_stack_size,
        .worker_pool => worker_pool_stack_size_bytes,
    };
    return estimatedHandlerThreads(model, worker_threads, concurrent_connections) * stack_size;
}

test "runtime model parses supported values" {
    try std.testing.expectEqual(RuntimeModel.thread_per_connection, try RuntimeModel.parse("thread-per-connection"));
    try std.testing.expectEqual(RuntimeModel.worker_pool, try RuntimeModel.parse("worker-pool"));
}

test "runtime model rejects unsupported values" {
    try std.testing.expectError(error.InvalidRuntimeModel, RuntimeModel.parse("reactor"));
}

test "resolve worker threads clamps to max connections" {
    try std.testing.expectEqual(@as(usize, 8), resolveWorkerThreads(.worker_pool, 12, 8));
    try std.testing.expectEqual(@as(usize, 0), resolveWorkerThreads(.thread_per_connection, 12, 8));
}
