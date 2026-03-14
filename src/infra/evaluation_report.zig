const std = @import("std");

/// Thread-safe evaluation report accumulator for report-only mode.
/// Tracks what *would* have been redacted without modifying traffic.
/// All counters use atomic operations for lock-free multi-threaded access.
const AtomicU64 = std.atomic.Value(u64);

pub const MatchStage = enum(u8) {
    entity_mask,
    ssn,
    pattern_library,
    fuzzy_match,
    schema,
};

pub const PayloadType = enum(u8) {
    text,
    json,
    unknown,
};

const stage_count = std.meta.fields(MatchStage).len;
const payload_type_count = std.meta.fields(PayloadType).len;

/// Confidence band boundaries for fuzzy matches.
/// Bands: [0.80–0.85), [0.85–0.90), [0.90–0.95), [0.95–1.00]
const confidence_band_count = 4;

fn stageLabel(stage: MatchStage) []const u8 {
    return switch (stage) {
        .entity_mask => "entity_mask",
        .ssn => "ssn",
        .pattern_library => "pattern_library",
        .fuzzy_match => "fuzzy_match",
        .schema => "schema",
    };
}

fn payloadTypeLabel(pt: PayloadType) []const u8 {
    return switch (pt) {
        .text => "text",
        .json => "json",
        .unknown => "unknown",
    };
}

fn initAtomicArray(comptime N: usize) [N]AtomicU64 {
    var values: [N]AtomicU64 = undefined;
    for (&values) |*slot| {
        slot.* = AtomicU64.init(0);
    }
    return values;
}

pub const EvaluationReport = struct {
    /// Total matches detected per stage.
    stage_counts: [stage_count]AtomicU64 = initAtomicArray(stage_count),

    /// Total matches detected per payload type.
    payload_type_counts: [payload_type_count]AtomicU64 = initAtomicArray(payload_type_count),

    /// Confidence band counts for fuzzy matches only.
    fuzzy_confidence_bands: [confidence_band_count]AtomicU64 = initAtomicArray(confidence_band_count),

    /// Total requests evaluated.
    requests_evaluated: AtomicU64 = AtomicU64.init(0),

    /// Total request bytes scanned.
    bytes_scanned: AtomicU64 = AtomicU64.init(0),

    /// Record a single match detection.
    pub fn recordMatch(
        self: *EvaluationReport,
        stage: MatchStage,
        payload_type: PayloadType,
        confidence: ?f64,
    ) void {
        _ = self.stage_counts[@intFromEnum(stage)].fetchAdd(1, .monotonic);
        _ = self.payload_type_counts[@intFromEnum(payload_type)].fetchAdd(1, .monotonic);

        // Track confidence bands for fuzzy matches
        if (stage == .fuzzy_match) {
            if (confidence) |c| {
                const band: usize = if (c < 0.85)
                    0
                else if (c < 0.90)
                    1
                else if (c < 0.95)
                    2
                else
                    3;
                _ = self.fuzzy_confidence_bands[band].fetchAdd(1, .monotonic);
            }
        }
    }

    /// Record that a request was evaluated.
    pub fn recordRequest(self: *EvaluationReport, body_bytes: u64) void {
        _ = self.requests_evaluated.fetchAdd(1, .monotonic);
        _ = self.bytes_scanned.fetchAdd(body_bytes, .monotonic);
    }

    /// Take a consistent snapshot of all counters.
    pub fn snapshot(self: *const EvaluationReport) EvaluationSnapshot {
        var stage_values: [stage_count]u64 = undefined;
        for (0..stage_count) |i| {
            stage_values[i] = self.stage_counts[i].load(.acquire);
        }

        var payload_type_values: [payload_type_count]u64 = undefined;
        for (0..payload_type_count) |i| {
            payload_type_values[i] = self.payload_type_counts[i].load(.acquire);
        }

        var fuzzy_bands: [confidence_band_count]u64 = undefined;
        for (0..confidence_band_count) |i| {
            fuzzy_bands[i] = self.fuzzy_confidence_bands[i].load(.acquire);
        }

        return .{
            .stage_counts = stage_values,
            .payload_type_counts = payload_type_values,
            .fuzzy_confidence_bands = fuzzy_bands,
            .requests_evaluated = self.requests_evaluated.load(.acquire),
            .bytes_scanned = self.bytes_scanned.load(.acquire),
        };
    }

    /// Reset all counters to zero for a new evaluation window.
    /// Uses seq_cst ordering so the zeroed state is immediately visible to all
    /// threads — a reader that observes any post-reset counter must observe all.
    pub fn reset(self: *EvaluationReport) void {
        for (0..stage_count) |i| {
            self.stage_counts[i].store(0, .seq_cst);
        }
        for (0..payload_type_count) |i| {
            self.payload_type_counts[i].store(0, .seq_cst);
        }
        for (0..confidence_band_count) |i| {
            self.fuzzy_confidence_bands[i].store(0, .seq_cst);
        }
        self.requests_evaluated.store(0, .seq_cst);
        self.bytes_scanned.store(0, .seq_cst);
    }
};

pub const EvaluationSnapshot = struct {
    stage_counts: [stage_count]u64,
    payload_type_counts: [payload_type_count]u64,
    fuzzy_confidence_bands: [confidence_band_count]u64,
    requests_evaluated: u64,
    bytes_scanned: u64,

    /// Total matches across all stages.
    pub fn totalMatches(self: EvaluationSnapshot) u64 {
        var total: u64 = 0;
        for (self.stage_counts) |c| total += c;
        return total;
    }

    /// Render the snapshot as a JSON string.
    pub fn renderJson(self: EvaluationSnapshot, allocator: std.mem.Allocator) ![]u8 {
        var buf: std.ArrayListUnmanaged(u8) = .empty;
        errdefer buf.deinit(allocator);
        const writer = buf.writer(allocator);

        try writer.writeAll("{");

        // Top-level summary
        try std.fmt.format(writer,
            "\"requests_evaluated\":{d},\"bytes_scanned\":{d},\"total_matches\":{d},",
            .{ self.requests_evaluated, self.bytes_scanned, self.totalMatches() },
        );

        // Per-stage counts
        try writer.writeAll("\"matches_by_stage\":{");
        for (0..stage_count) |i| {
            if (i > 0) try writer.writeByte(',');
            const stage: MatchStage = @enumFromInt(i);
            try std.fmt.format(writer, "\"{s}\":{d}", .{ stageLabel(stage), self.stage_counts[i] });
        }
        try writer.writeAll("},");

        // Per-payload-type counts
        try writer.writeAll("\"matches_by_payload_type\":{");
        for (0..payload_type_count) |i| {
            if (i > 0) try writer.writeByte(',');
            const pt: PayloadType = @enumFromInt(i);
            try std.fmt.format(writer, "\"{s}\":{d}", .{ payloadTypeLabel(pt), self.payload_type_counts[i] });
        }
        try writer.writeAll("},");

        // Fuzzy confidence bands
        try writer.writeAll("\"fuzzy_confidence_bands\":{");
        const band_labels = [_][]const u8{ "0.80-0.85", "0.85-0.90", "0.90-0.95", "0.95-1.00" };
        for (0..confidence_band_count) |i| {
            if (i > 0) try writer.writeByte(',');
            try std.fmt.format(writer, "\"{s}\":{d}", .{ band_labels[i], self.fuzzy_confidence_bands[i] });
        }
        try writer.writeAll("}");

        try writer.writeByte('}');
        return try buf.toOwnedSlice(allocator);
    }
};

// ===========================================================================
// Unit Tests
// ===========================================================================

test "EvaluationReport - record and snapshot" {
    var report = EvaluationReport{};

    report.recordMatch(.ssn, .text, null);
    report.recordMatch(.ssn, .text, null);
    report.recordMatch(.entity_mask, .json, null);
    report.recordMatch(.fuzzy_match, .text, 0.92);
    report.recordMatch(.fuzzy_match, .text, 0.87);
    report.recordRequest(1024);
    report.recordRequest(2048);

    const snap = report.snapshot();

    try std.testing.expectEqual(@as(u64, 2), snap.stage_counts[@intFromEnum(MatchStage.ssn)]);
    try std.testing.expectEqual(@as(u64, 1), snap.stage_counts[@intFromEnum(MatchStage.entity_mask)]);
    try std.testing.expectEqual(@as(u64, 2), snap.stage_counts[@intFromEnum(MatchStage.fuzzy_match)]);
    try std.testing.expectEqual(@as(u64, 5), snap.totalMatches());
    try std.testing.expectEqual(@as(u64, 2), snap.requests_evaluated);
    try std.testing.expectEqual(@as(u64, 3072), snap.bytes_scanned);

    // Fuzzy confidence bands: 0.87 → band 1, 0.92 → band 2
    try std.testing.expectEqual(@as(u64, 0), snap.fuzzy_confidence_bands[0]);
    try std.testing.expectEqual(@as(u64, 1), snap.fuzzy_confidence_bands[1]);
    try std.testing.expectEqual(@as(u64, 1), snap.fuzzy_confidence_bands[2]);
    try std.testing.expectEqual(@as(u64, 0), snap.fuzzy_confidence_bands[3]);
}

test "EvaluationReport - reset clears all counters" {
    var report = EvaluationReport{};

    report.recordMatch(.ssn, .text, null);
    report.recordMatch(.entity_mask, .json, null);
    report.recordRequest(512);

    report.reset();
    const snap = report.snapshot();

    try std.testing.expectEqual(@as(u64, 0), snap.totalMatches());
    try std.testing.expectEqual(@as(u64, 0), snap.requests_evaluated);
    try std.testing.expectEqual(@as(u64, 0), snap.bytes_scanned);
}

test "EvaluationSnapshot - renderJson produces valid output" {
    var report = EvaluationReport{};

    report.recordMatch(.ssn, .text, null);
    report.recordMatch(.entity_mask, .json, null);
    report.recordMatch(.fuzzy_match, .text, 0.96);
    report.recordRequest(1024);

    const snap = report.snapshot();
    const json = try snap.renderJson(std.testing.allocator);
    defer std.testing.allocator.free(json);

    // Verify key fields are present
    try std.testing.expect(std.mem.indexOf(u8, json, "\"requests_evaluated\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"bytes_scanned\":1024") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"total_matches\":3") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"ssn\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"entity_mask\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"fuzzy_match\":1") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"0.95-1.00\":1") != null);
}

test "EvaluationSnapshot - empty report renders zeros" {
    const report = EvaluationReport{};
    const snap = report.snapshot();
    const json = try snap.renderJson(std.testing.allocator);
    defer std.testing.allocator.free(json);

    try std.testing.expect(std.mem.indexOf(u8, json, "\"total_matches\":0") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"requests_evaluated\":0") != null);
}
