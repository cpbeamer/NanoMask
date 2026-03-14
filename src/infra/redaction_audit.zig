const std = @import("std");
const logger_mod = @import("logger.zig");
const Logger = logger_mod.Logger;
const observability_mod = @import("observability.zig");
const Observability = observability_mod.Observability;
const redact = @import("../redaction/redact.zig");
const entity_mask = @import("../redaction/entity_mask.zig");
const fuzzy_match = @import("../redaction/fuzzy_match.zig");
const scanner = @import("../patterns/scanner.zig");
const schema_mod = @import("../schema/schema.zig");
const json_redactor = @import("../schema/json_redactor.zig");
const hasher_mod = @import("../schema/hasher.zig");
const evaluation_report_mod = @import("evaluation_report.zig");
const EvaluationReport = evaluation_report_mod.EvaluationReport;
const PayloadType = evaluation_report_mod.PayloadType;

pub const max_events_per_request: usize = 256;

pub const TextStageConfig = struct {
    entity_mask: bool = false,
    ssn: bool = false,
    patterns: bool = false,
    fuzzy: bool = false,
};

pub const AuditEmitter = struct {
    log: *Logger,
    session_id: []const u8,
    observability: ?*Observability = null,
    emitted: usize = 0,
    dropped: usize = 0,
    limit: usize = max_events_per_request,
    evaluation_report: ?*EvaluationReport = null,
    payload_type: PayloadType = .text,

    pub fn init(log: *Logger, session_id: []const u8, observability: ?*Observability) AuditEmitter {
        return .{
            .log = log,
            .session_id = session_id,
            .observability = observability,
        };
    }

    /// Initialize with an evaluation report for report-only mode match tracking.
    pub fn initWithReport(
        log: *Logger,
        session_id: []const u8,
        observability: ?*Observability,
        eval_report: ?*EvaluationReport,
        payload_type: PayloadType,
    ) AuditEmitter {
        return .{
            .log = log,
            .session_id = session_id,
            .observability = observability,
            .evaluation_report = eval_report,
            .payload_type = payload_type,
        };
    }

    pub fn emit(self: *AuditEmitter, event: Logger.AuditEvent) void {
        if (self.observability) |obs| {
            // Map string stage to enum and filter non-countable events
            const stage: ?observability_mod.MatchStage = if (std.mem.eql(u8, event.stage, "entity_mask"))
                .entity_mask
            else if (std.mem.eql(u8, event.stage, "ssn"))
                .ssn
            else if (std.mem.eql(u8, event.stage, "pattern_library"))
                .pattern_library
            else if (std.mem.eql(u8, event.stage, "fuzzy_match"))
                .fuzzy_match
            else if (std.mem.eql(u8, event.stage, "schema"))
                // schema_keep actions are informational — don't count as redaction matches
                if (std.mem.eql(u8, event.match_type, "schema_keep")) null else observability_mod.MatchStage.schema
            else
                null;

            if (stage) |s| obs.recordAuditStage(s);
        }

        // Feed evaluation report when in report-only mode
        if (self.evaluation_report) |eval_report| {
            const eval_stage: ?evaluation_report_mod.MatchStage = if (std.mem.eql(u8, event.stage, "entity_mask"))
                .entity_mask
            else if (std.mem.eql(u8, event.stage, "ssn"))
                .ssn
            else if (std.mem.eql(u8, event.stage, "pattern_library"))
                .pattern_library
            else if (std.mem.eql(u8, event.stage, "fuzzy_match"))
                .fuzzy_match
            else if (std.mem.eql(u8, event.stage, "schema"))
                if (!std.mem.eql(u8, event.match_type, "schema_keep")) @as(?evaluation_report_mod.MatchStage, .schema) else null
            else
                null;

            if (eval_stage) |es| {
                eval_report.recordMatch(es, self.payload_type, event.confidence);
            }
        }

        if (!self.log.audit_enabled) return;

        if (self.emitted >= self.limit) {
            self.dropped += 1;
            return;
        }

        self.log.auditRedaction(self.session_id, event);
        self.emitted += 1;
    }

    pub fn finish(self: *AuditEmitter) void {
        if (!self.log.audit_enabled) return;
        if (self.dropped == 0) return;

        self.log.log(.warn, "audit_event_cap_reached", self.session_id, &.{
            .{ .key = "audit_events_emitted", .value = .{ .uint = self.emitted } },
            .{ .key = "audit_events_dropped", .value = .{ .uint = self.dropped } },
            .{ .key = "audit_event_limit", .value = .{ .uint = self.limit } },
        });
    }
};

pub fn emitRequestAuditEvents(
    allocator: std.mem.Allocator,
    log: *Logger,
    session_id: []const u8,
    body: []const u8,
    entity_map: ?*const entity_mask.EntityMap,
    fuzzy_matcher: ?*const fuzzy_match.FuzzyMatcher,
    pattern_flags: scanner.PatternFlags,
    schema: ?*const schema_mod.Schema,
    hasher: ?*hasher_mod.Hasher,
    observability: ?*Observability,
) !void {
    if (body.len == 0) return;
    if (!log.audit_enabled and observability == null) return;

    var emitter = AuditEmitter.init(log, session_id, observability);
    defer emitter.finish();

    if (schema) |active_schema| {
        try emitSchemaAuditEvents(
            allocator,
            body,
            entity_map,
            fuzzy_matcher,
            pattern_flags,
            active_schema,
            hasher,
            &emitter,
        );
    } else {
        const redacted = try runTextStages(
            body,
            null,
            .{
                .entity_mask = true,
                .ssn = true,
                .patterns = true,
                .fuzzy = true,
            },
            entity_map,
            fuzzy_matcher,
            pattern_flags,
            &emitter,
            allocator,
        );
        allocator.free(redacted);
    }
}

/// Like emitRequestAuditEvents but wires the evaluation report into the emitter
/// so match events flow into the EvaluationReport. Used by the report-only proxy path.
pub fn emitRequestAuditEventsWithReport(
    allocator: std.mem.Allocator,
    log: *Logger,
    session_id: []const u8,
    body: []const u8,
    entity_map: ?*const entity_mask.EntityMap,
    fuzzy_matcher: ?*const fuzzy_match.FuzzyMatcher,
    pattern_flags: scanner.PatternFlags,
    schema: ?*const schema_mod.Schema,
    hasher: ?*hasher_mod.Hasher,
    observability: ?*Observability,
    eval_report: ?*EvaluationReport,
) !void {
    if (body.len == 0) return;

    // Determine payload type from content: JSON if schema-aware path is active
    const payload_type: PayloadType = if (schema != null) .json else .text;

    var emitter = AuditEmitter.initWithReport(log, session_id, observability, eval_report, payload_type);
    defer emitter.finish();

    if (schema) |active_schema| {
        try emitSchemaAuditEvents(
            allocator,
            body,
            entity_map,
            fuzzy_matcher,
            pattern_flags,
            active_schema,
            hasher,
            &emitter,
        );
    } else {
        const redacted = try runTextStages(
            body,
            null,
            .{
                .entity_mask = true,
                .ssn = true,
                .patterns = true,
                .fuzzy = true,
            },
            entity_map,
            fuzzy_matcher,
            pattern_flags,
            &emitter,
            allocator,
        );
        allocator.free(redacted);
    }
}

/// Emit audit events for the schema-aware (buffered) redaction path.
///
/// Only entity masking runs as a text pre-stage before JSON schema processing.
/// This mirrors the actual proxy pipeline: entity mask → JSON schema redaction,
/// with SSN, pattern-library, and fuzzy matching handled per-field via SCAN
/// callback. Running all text stages globally would double-count matches on
/// fields that also have SCAN actions.
fn emitSchemaAuditEvents(
    allocator: std.mem.Allocator,
    body: []const u8,
    entity_map: ?*const entity_mask.EntityMap,
    fuzzy_matcher: ?*const fuzzy_match.FuzzyMatcher,
    pattern_flags: scanner.PatternFlags,
    schema: *const schema_mod.Schema,
    hasher: ?*hasher_mod.Hasher,
    emitter: *AuditEmitter,
) !void {
    const masked_body = try runTextStages(
        body,
        null,
        .{ .entity_mask = true },
        entity_map,
        fuzzy_matcher,
        pattern_flags,
        emitter,
        allocator,
    );
    defer allocator.free(masked_body);

    const hasher_iface: ?json_redactor.HasherInterface = if (hasher) |h| .{
        .hash_fn = &struct {
            fn call(original: []const u8, ctx_ptr: *anyopaque) anyerror![]const u8 {
                const active_hasher: *hasher_mod.Hasher = @ptrCast(@alignCast(ctx_ptr));
                return active_hasher.hash(original);
            }
        }.call,
        .ctx_ptr = @ptrCast(@alignCast(h)),
    } else null;

    const SchemaAuditState = struct {
        const Self = @This();

        emitter: *AuditEmitter,
        entity_map: ?*const entity_mask.EntityMap,
        fuzzy_matcher: ?*const fuzzy_match.FuzzyMatcher,
        pattern_flags: scanner.PatternFlags,

        fn onSchemaAction(event: json_redactor.AuditEvent, ctx_ptr: *anyopaque) anyerror!void {
            const self: *Self = @ptrCast(@alignCast(ctx_ptr));
            self.emitter.emit(.{
                .stage = "schema",
                .match_type = switch (event.action) {
                    .redact => "schema_redact",
                    .hash => "schema_hash",
                    .scan => "schema_scan",
                    .keep => "schema_keep",
                },
                .field_path = event.field_path,
                .original_length = event.original_length,
                .replacement_type = event.replacement_type,
            });
        }

        fn scanField(input: []const u8, field_path: []const u8, ctx_ptr: *anyopaque, alloc: std.mem.Allocator) anyerror![]u8 {
            const self: *Self = @ptrCast(@alignCast(ctx_ptr));
            return runTextStages(
                input,
                field_path,
                .{
                    .ssn = true,
                    .patterns = true,
                    .fuzzy = true,
                },
                self.entity_map,
                self.fuzzy_matcher,
                self.pattern_flags,
                self.emitter,
                alloc,
            );
        }
    };

    var schema_state = SchemaAuditState{
        .emitter = emitter,
        .entity_map = entity_map,
        .fuzzy_matcher = fuzzy_matcher,
        .pattern_flags = pattern_flags,
    };

    const scan_ctx = json_redactor.ScanContext{
        .scan_fn = &SchemaAuditState.scanField,
        .ctx_ptr = @ptrCast(&schema_state),
    };
    const audit_ctx = json_redactor.AuditContext{
        .audit_fn = &SchemaAuditState.onSchemaAction,
        .ctx_ptr = @ptrCast(&schema_state),
    };

    const output = try json_redactor.redactJsonWithAudit(
        masked_body,
        schema,
        hasher_iface,
        scan_ctx,
        audit_ctx,
        allocator,
    );
    allocator.free(output);
}

/// Emit audit events for entity-mask matches found in the input.
/// Call this from the proxy's buffered path *before* schema processing
/// to record entity-mask redactions without re-running the pipeline.
pub fn emitEntityMaskAuditEvents(
    em: *const entity_mask.EntityMap,
    input: []const u8,
    emitter: *AuditEmitter,
    allocator: std.mem.Allocator,
) !void {
    const matches = try em.collectMaskMatches(input, allocator);
    defer allocator.free(matches);

    for (matches) |match| {
        emitTextEvent(
            emitter,
            "entity_mask",
            "entity",
            null,
            match.start,
            match.end - match.start,
            "entity_alias",
            null,
        );
    }
}

/// Run text-stage redaction with inline audit event emission.
/// Public so the proxy ScanAdapter can emit audit events per-field during the
/// primary redaction pass, avoiding a separate re-processing pass.
pub fn runTextStages(
    input: []const u8,
    field_path: ?[]const u8,
    cfg: TextStageConfig,
    entity_map: ?*const entity_mask.EntityMap,
    fuzzy_matcher: ?*const fuzzy_match.FuzzyMatcher,
    pattern_flags: scanner.PatternFlags,
    emitter: *AuditEmitter,
    allocator: std.mem.Allocator,
) ![]u8 {
    var current = try allocator.dupe(u8, input);
    errdefer allocator.free(current);

    if (cfg.entity_mask) {
        if (entity_map) |em| {
            const matches = try em.collectMaskMatches(current, allocator);
            defer allocator.free(matches);

            for (matches) |match| {
                emitTextEvent(
                    emitter,
                    "entity_mask",
                    "entity",
                    field_path,
                    match.start,
                    match.end - match.start,
                    "entity_alias",
                    null,
                );
            }

            const masked = try em.mask(current, allocator);
            allocator.free(current);
            current = masked;
        }
    }

    if (cfg.ssn) {
        const matches = try redact.collectSsnMatches(current, allocator);
        defer allocator.free(matches);

        for (matches) |match| {
            emitTextEvent(
                emitter,
                "ssn",
                "ssn",
                field_path,
                match.start,
                match.end - match.start,
                "mask",
                null,
            );
        }

        redact.redactSsn(current);
    }

    if (cfg.patterns and pattern_flags.anyEnabled()) {
        const result = try scanner.redactWithMatches(current, pattern_flags, allocator);
        defer allocator.free(result.matches);

        for (result.matches) |match| {
            emitTextEvent(
                emitter,
                "pattern_library",
                patternMatchType(match.replacement),
                field_path,
                match.redact_start,
                match.end - match.redact_start,
                "pattern_token",
                null,
            );
        }

        allocator.free(current);
        current = result.output;
    }

    if (cfg.fuzzy) {
        if (fuzzy_matcher) |fm| {
            const aliases = if (entity_map) |em| em.getAliases() else &.{};
            const result = try fm.fuzzyRedactWithMatches(current, aliases, &.{}, allocator);
            defer allocator.free(result.matches);

            for (result.matches) |match| {
                emitTextEvent(
                    emitter,
                    "fuzzy_match",
                    "entity_variant",
                    field_path,
                    match.start,
                    match.end - match.start,
                    "entity_alias",
                    match.confidence,
                );
            }

            allocator.free(current);
            current = result.output;
        }
    }

    return current;
}

fn emitTextEvent(
    emitter: *AuditEmitter,
    stage: []const u8,
    match_type: []const u8,
    field_path: ?[]const u8,
    start: usize,
    original_length: usize,
    replacement_type: []const u8,
    confidence: ?f64,
) void {
    emitter.emit(.{
        .stage = stage,
        .match_type = match_type,
        .offset = if (field_path == null) @intCast(start) else null,
        .field_path = field_path,
        .original_length = original_length,
        .replacement_type = replacement_type,
        .confidence = confidence,
    });
}

const pattern_type_map = std.StaticStringMap([]const u8).initComptime(.{
    .{ "[EMAIL_REDACTED]", "email" },
    .{ "[PHONE_REDACTED]", "phone" },
    .{ "[CC_REDACTED]", "credit_card" },
    .{ "[IPV4_REDACTED]", "ipv4" },
    .{ "[IPV6_REDACTED]", "ipv6" },
    .{ "[MRN_REDACTED]", "mrn" },
    .{ "[ICD10_REDACTED]", "icd10" },
    .{ "[INSURANCE_REDACTED]", "insurance" },
});

fn patternMatchType(replacement: []const u8) []const u8 {
    return pattern_type_map.get(replacement) orelse "pattern";
}

// ===========================================================================
// Unit Tests
// ===========================================================================

test "AuditEmitter - cap enforcement at 256 events" {
    var log_buf: [64 * 1024]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&log_buf);
    var logger = Logger{
        .min_level = .info,
        .audit_enabled = true,
        .output_file = null,
        .mutex = .{},
        .test_writer = fbs.writer().any(),
        .owns_file = false,
    };

    var emitter = AuditEmitter.init(&logger, "cap_test", null);

    // Emit exactly max_events_per_request + 10 events
    const total = max_events_per_request + 10;
    for (0..total) |_| {
        emitter.emit(.{
            .stage = "ssn",
            .match_type = "ssn",
            .offset = 0,
            .original_length = 11,
            .replacement_type = "mask",
        });
    }

    try std.testing.expectEqual(max_events_per_request, emitter.emitted);
    try std.testing.expectEqual(@as(usize, 10), emitter.dropped);

    // Verify the buffer has output (256 events were written)
    try std.testing.expect(fbs.getWritten().len > 0);
}

test "AuditEmitter - finish logs dropped count" {
    var log_buf: [64 * 1024]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&log_buf);
    var logger = Logger{
        .min_level = .info,
        .audit_enabled = true,
        .output_file = null,
        .mutex = .{},
        .test_writer = fbs.writer().any(),
        .owns_file = false,
    };

    var emitter = AuditEmitter.init(&logger, "finish_test", null);
    emitter.limit = 2; // small limit to make test fast

    for (0..5) |_| {
        emitter.emit(.{
            .stage = "ssn",
            .match_type = "ssn",
            .offset = 0,
            .original_length = 11,
            .replacement_type = "mask",
        });
    }

    // Reset buffer to isolate finish() output
    fbs.reset();
    emitter.finish();

    const output = fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, output, "\"audit_event_cap_reached\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"audit_events_emitted\":2") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"audit_events_dropped\":3") != null);
}

test "AuditEmitter - no output when audit disabled" {
    var log_buf: [1024]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&log_buf);
    var logger = Logger{
        .min_level = .info,
        .audit_enabled = false,
        .output_file = null,
        .mutex = .{},
        .test_writer = fbs.writer().any(),
        .owns_file = false,
    };

    var emitter = AuditEmitter.init(&logger, "disabled_test", null);

    emitter.emit(.{
        .stage = "ssn",
        .match_type = "ssn",
        .offset = 0,
        .original_length = 11,
        .replacement_type = "mask",
    });

    emitter.finish();

    try std.testing.expectEqual(@as(usize, 0), fbs.getWritten().len);
    try std.testing.expectEqual(@as(usize, 0), emitter.emitted);
    try std.testing.expectEqual(@as(usize, 0), emitter.dropped);
}

test "patternMatchType - known tokens map correctly" {
    try std.testing.expectEqualStrings("email", patternMatchType("[EMAIL_REDACTED]"));
    try std.testing.expectEqualStrings("phone", patternMatchType("[PHONE_REDACTED]"));
    try std.testing.expectEqualStrings("credit_card", patternMatchType("[CC_REDACTED]"));
    try std.testing.expectEqualStrings("ipv4", patternMatchType("[IPV4_REDACTED]"));
    try std.testing.expectEqualStrings("ipv6", patternMatchType("[IPV6_REDACTED]"));
    try std.testing.expectEqualStrings("mrn", patternMatchType("[MRN_REDACTED]"));
    try std.testing.expectEqualStrings("icd10", patternMatchType("[ICD10_REDACTED]"));
    try std.testing.expectEqualStrings("insurance", patternMatchType("[INSURANCE_REDACTED]"));
    try std.testing.expectEqualStrings("pattern", patternMatchType("[UNKNOWN_TOKEN]"));
}
