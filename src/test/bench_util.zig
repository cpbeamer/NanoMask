const std = @import("std");

/// Convert nanoseconds to milliseconds as a floating-point value.
pub fn nsToMs(ns: u64) f64 {
    return @as(f64, @floatFromInt(ns)) / @as(f64, @floatFromInt(std.time.ns_per_ms));
}

/// Calculate the 0-based index for a given percentile (e.g. 50/100 for p50).
pub fn percentileIndex(len: usize, numerator: usize, denominator: usize) usize {
    if (len == 0) return 0;
    const rank = (len * numerator + denominator - 1) / denominator;
    return if (rank == 0) 0 else @min(len - 1, rank - 1);
}

/// Sort an array of latency samples in ascending order and return p50/p95.
pub fn sortAndSummarize(latencies_ns: []u64) struct { p50_ms: f64, p95_ms: f64 } {
    if (latencies_ns.len == 0) return .{ .p50_ms = 0.0, .p95_ms = 0.0 };

    std.sort.block(u64, latencies_ns, {}, std.sort.asc(u64));
    return .{
        .p50_ms = nsToMs(latencies_ns[percentileIndex(latencies_ns.len, 50, 100)]),
        .p95_ms = nsToMs(latencies_ns[percentileIndex(latencies_ns.len, 95, 100)]),
    };
}

/// Compute elapsed time in nanoseconds since a prior `nanoTimestamp()` snapshot.
/// Clamps negative deltas (possible with clock drift) to zero.
pub fn elapsedSince(start_ns: @TypeOf(std.time.nanoTimestamp())) u64 {
    const delta = std.time.nanoTimestamp() - start_ns;
    return if (delta < 0) 0 else @intCast(delta);
}

test "nsToMs converts correctly" {
    try std.testing.expectEqual(@as(f64, 1.0), nsToMs(1_000_000));
    try std.testing.expectEqual(@as(f64, 0.0), nsToMs(0));
}

test "percentileIndex edge cases" {
    try std.testing.expectEqual(@as(usize, 0), percentileIndex(0, 50, 100));
    try std.testing.expectEqual(@as(usize, 0), percentileIndex(1, 50, 100));
    try std.testing.expectEqual(@as(usize, 0), percentileIndex(2, 50, 100));
    try std.testing.expectEqual(@as(usize, 1), percentileIndex(2, 95, 100));
}

test "sortAndSummarize handles empty input" {
    var empty: [0]u64 = .{};
    const result = sortAndSummarize(&empty);
    try std.testing.expectEqual(@as(f64, 0.0), result.p50_ms);
    try std.testing.expectEqual(@as(f64, 0.0), result.p95_ms);
}
