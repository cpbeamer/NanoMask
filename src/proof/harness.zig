const std = @import("std");
const builtin = @import("builtin");
const redact = @import("../redaction/redact.zig");
const entity_mask = @import("../redaction/entity_mask.zig");
const fuzzy_match = @import("../redaction/fuzzy_match.zig");
const pattern_scanner = @import("../patterns/scanner.zig");
const schema_mod = @import("../schema/schema.zig");
const json_redactor = @import("../schema/json_redactor.zig");
const hasher_mod = @import("../schema/hasher.zig");
const e2e_harness = @import("../test/e2e_harness.zig");
const bench_util = @import("../test/bench_util.zig");
const runtime_bench_harness = @import("../test/runtime_bench_harness.zig");

pub const Status = enum {
    pass,
    fail,
    not_run,
};

const CaseKind = enum {
    positive,
    negative,
};

pub const Thresholds = struct {
    precision_min: f64,
    recall_min: f64,
    false_positive_rate_max: f64,
};

const CorpusCase = struct {
    id: []const u8,
    label: []const u8,
    kind: CaseKind,
    input: []const u8,
    expected: ?[]const u8 = null,
    must_contain: ?[]const []const u8 = null,
    must_not_contain: ?[]const []const u8 = null,
    entities: ?[]const []const u8 = null,
    fuzzy_threshold: ?f64 = null,
    schema: ?[]const u8 = null,
    hash_key: ?[]const u8 = null,
    enable_email: bool = false,
    enable_phone: bool = false,
    enable_credit_card: bool = false,
    enable_ip: bool = false,
    enable_healthcare: bool = false,
};

const CorpusFile = struct {
    suite: []const u8,
    label: []const u8,
    description: []const u8,
    thresholds: Thresholds,
    cases: []const CorpusCase,
};

pub const FailureExample = struct {
    case_id: []const u8,
    label: []const u8,
    reason: []const u8,
    actual_preview: []const u8,
};

pub const AccuracyResult = struct {
    id: []const u8,
    label: []const u8,
    description: []const u8,
    positives: usize,
    negatives: usize,
    true_positives: usize,
    false_negatives: usize,
    true_negatives: usize,
    false_positives: usize,
    precision: f64,
    recall: f64,
    false_positive_rate: f64,
    thresholds: Thresholds,
    status: Status,
    failures: []const FailureExample,
};

pub const BenchmarkResult = struct {
    id: []const u8,
    label: []const u8,
    mode: []const u8,
    status: Status,
    iterations: usize,
    payload_bytes: usize,
    throughput_mb_per_sec: ?f64 = null,
    min_throughput_mb_per_sec: ?f64 = null,
    p50_ms: ?f64 = null,
    p95_ms: ?f64 = null,
    max_p95_ms: ?f64 = null,
    first_chunk_p50_ms: ?f64 = null,
    first_chunk_p95_ms: ?f64 = null,
    max_first_chunk_p95_ms: ?f64 = null,
    observed_bytes: ?usize = null,
    max_bytes: ?usize = null,
    note: ?[]const u8 = null,
};

pub const Summary = struct {
    accuracy_suites: usize,
    accuracy_passed: usize,
    accuracy_failed: usize,
    benchmark_checks: usize,
    benchmark_passed: usize,
    benchmark_failed: usize,
    benchmark_skipped: usize,
    hard_failures: usize,
};

pub const ProofReport = struct {
    suite: []const u8,
    generated_at_unix: i64,
    host_os: []const u8,
    accuracy: []const AccuracyResult,
    benchmarks: []const BenchmarkResult,
    summary: Summary,
};

const SuiteKind = enum {
    ssn,
    entity_exact,
    entity_fuzzy,
    email,
    phone,
    credit_card,
    ip,
    healthcare,
    schema,
};

const SuiteDefinition = struct {
    kind: SuiteKind,
    path: []const u8,
};

const suite_definitions = [_]SuiteDefinition{
    .{ .kind = .ssn, .path = "proof/corpora/ssn.json" },
    .{ .kind = .entity_exact, .path = "proof/corpora/entity_exact.json" },
    .{ .kind = .entity_fuzzy, .path = "proof/corpora/entity_fuzzy.json" },
    .{ .kind = .email, .path = "proof/corpora/email.json" },
    .{ .kind = .phone, .path = "proof/corpora/phone.json" },
    .{ .kind = .credit_card, .path = "proof/corpora/credit_card.json" },
    .{ .kind = .ip, .path = "proof/corpora/ip.json" },
    .{ .kind = .healthcare, .path = "proof/corpora/healthcare.json" },
    .{ .kind = .schema, .path = "proof/corpora/schema.json" },
};

const max_failure_examples = 3;
const windows_benchmark_note = "E2E latency benchmarks are skipped on Windows hosts; run the manual GitHub Actions workflow on Linux for the full proof artifact.";

const SchemaScanRuntime = struct {
    entity_map: ?*const entity_mask.EntityMap = null,
    fuzzy_matcher: ?*const fuzzy_match.FuzzyMatcher = null,
    aliases: []const []const u8 = &.{},
    flags: pattern_scanner.PatternFlags = .{},

    fn scan(input: []const u8, _: []const u8, ctx_ptr: *anyopaque, allocator: std.mem.Allocator) ![]u8 {
        const self: *SchemaScanRuntime = @ptrCast(@alignCast(ctx_ptr));

        var current = try allocator.dupe(u8, input);
        redact.redactSsn(current);

        if (self.entity_map) |em| {
            const masked = try em.mask(current, allocator);
            allocator.free(current);
            current = masked;
        }

        if (self.fuzzy_matcher) |fm| {
            const fuzzy_output = try fm.fuzzyRedact(current, self.aliases, &.{}, allocator);
            allocator.free(current);
            current = fuzzy_output;
        }

        if (self.flags.anyEnabled()) {
            const scanned = try pattern_scanner.redact(current, self.flags, allocator);
            allocator.free(current);
            current = scanned;
        }

        return current;
    }
};

fn hashCallback(original: []const u8, ctx_ptr: *anyopaque) ![]const u8 {
    const hasher: *hasher_mod.Hasher = @ptrCast(@alignCast(ctx_ptr));
    return hasher.hash(original);
}

fn suiteKindString(kind: SuiteKind) []const u8 {
    return switch (kind) {
        .ssn => "ssn",
        .entity_exact => "entity_exact",
        .entity_fuzzy => "entity_fuzzy",
        .email => "email",
        .phone => "phone",
        .credit_card => "credit_card",
        .ip => "ip",
        .healthcare => "healthcare",
        .schema => "schema",
    };
}

fn statusString(status: Status) []const u8 {
    return switch (status) {
        .pass => "pass",
        .fail => "fail",
        .not_run => "not_run",
    };
}

fn ratio(numerator: usize, denominator: usize) f64 {
    if (denominator == 0) return 1.0;
    return @as(f64, @floatFromInt(numerator)) / @as(f64, @floatFromInt(denominator));
}

fn nsToMs(ns: u64) f64 {
    return bench_util.nsToMs(ns);
}

fn percentileIndex(len: usize, numerator: usize, denominator: usize) usize {
    return bench_util.percentileIndex(len, numerator, denominator);
}

fn previewText(allocator: std.mem.Allocator, text: []const u8, max_len: usize) ![]const u8 {
    if (text.len <= max_len) return allocator.dupe(u8, text);
    const clipped = text[0..max_len];
    return std.fmt.allocPrint(allocator, "{s}...", .{clipped});
}

fn duplicateFailureExample(
    allocator: std.mem.Allocator,
    case: CorpusCase,
    reason: []const u8,
    actual: []const u8,
) !FailureExample {
    return .{
        .case_id = try allocator.dupe(u8, case.id),
        .label = try allocator.dupe(u8, case.label),
        .reason = reason,
        .actual_preview = try previewText(allocator, actual, 160),
    };
}

fn validateCase(allocator: std.mem.Allocator, case: CorpusCase, actual: []const u8) !?[]const u8 {
    if (case.expected) |expected| {
        if (!std.mem.eql(u8, actual, expected)) {
            const expected_preview = if (expected.len <= 120) expected else expected[0..120];
            const reason = try std.fmt.allocPrint(
                allocator,
                "expected exact output {s}{s}",
                .{
                    expected_preview,
                    if (expected.len <= 120) "" else "...",
                },
            );
            return reason;
        }
    }

    for (case.must_contain orelse &.{}) |needle| {
        if (std.mem.indexOf(u8, actual, needle) == null) {
            const reason = try std.fmt.allocPrint(allocator, "missing required substring {s}", .{needle});
            return reason;
        }
    }

    for (case.must_not_contain orelse &.{}) |needle| {
        if (std.mem.indexOf(u8, actual, needle) != null) {
            const reason = try std.fmt.allocPrint(allocator, "still contains forbidden substring {s}", .{needle});
            return reason;
        }
    }

    if (case.expected == null and case.must_contain == null and case.must_not_contain == null) {
        return try allocator.dupe(u8, "case has no expectation");
    }

    return null;
}

fn applySsnCase(case: CorpusCase, allocator: std.mem.Allocator) ![]u8 {
    const output = try allocator.dupe(u8, case.input);
    redact.redactSsn(output);
    return output;
}

fn applyEntityExactCase(case: CorpusCase, allocator: std.mem.Allocator) ![]u8 {
    const entities = case.entities orelse return error.MissingEntities;
    var entity_map = try entity_mask.EntityMap.init(allocator, entities);
    defer entity_map.deinit();
    return entity_map.mask(case.input, allocator);
}

fn applyEntityFuzzyCase(case: CorpusCase, allocator: std.mem.Allocator) ![]u8 {
    const entities = case.entities orelse return error.MissingEntities;
    var entity_map = try entity_mask.EntityMap.init(allocator, entities);
    defer entity_map.deinit();

    var matcher = try fuzzy_match.FuzzyMatcher.init(
        allocator,
        entities,
        entity_map.getAliases(),
        case.fuzzy_threshold orelse 0.80,
    );
    defer matcher.deinit();

    return matcher.fuzzyRedact(case.input, entity_map.getAliases(), &.{}, allocator);
}

fn applyPatternCase(case: CorpusCase, flags: pattern_scanner.PatternFlags, allocator: std.mem.Allocator) ![]u8 {
    return pattern_scanner.redact(case.input, flags, allocator);
}

fn applySchemaCase(case: CorpusCase, allocator: std.mem.Allocator) ![]u8 {
    const schema_text = case.schema orelse return error.MissingSchema;

    var schema = try schema_mod.Schema.parseContent(schema_text, allocator);
    defer schema.deinit();

    var maybe_hasher: ?hasher_mod.Hasher = null;
    // Vault must outlive the hasher — declared at function scope.
    var mem_vault_backing: ?*@import("../vault/memory_vault.zig").MemoryVault = null;
    defer if (mem_vault_backing) |mv| mv.vaultInterface().deinit();
    defer if (maybe_hasher) |*hasher| hasher.deinit();

    if (case.hash_key) |hash_key| {
        mem_vault_backing = try @import("../vault/memory_vault.zig").MemoryVault.init(allocator);
        maybe_hasher = try hasher_mod.Hasher.init(hash_key, mem_vault_backing.?.vaultInterface(), allocator);
    }

    var entity_map: ?entity_mask.EntityMap = null;
    defer if (entity_map) |*map| map.deinit();

    if (case.entities) |entities| {
        entity_map = try entity_mask.EntityMap.init(allocator, entities);
    }

    var fuzzy_matcher: ?fuzzy_match.FuzzyMatcher = null;
    defer if (fuzzy_matcher) |*matcher| matcher.deinit();

    if (case.entities) |entities| {
        if (case.fuzzy_threshold) |threshold| {
            const aliases = if (entity_map) |*map| map.getAliases() else &.{};
            fuzzy_matcher = try fuzzy_match.FuzzyMatcher.init(allocator, entities, aliases, threshold);
        }
    }

    var scan_runtime = SchemaScanRuntime{
        .entity_map = if (entity_map) |*map| map else null,
        .fuzzy_matcher = if (fuzzy_matcher) |*matcher| matcher else null,
        .aliases = if (entity_map) |*map| map.getAliases() else &.{},
        .flags = .{
            .email = case.enable_email,
            .phone = case.enable_phone,
            .credit_card = case.enable_credit_card,
            .ip = case.enable_ip,
            .healthcare = case.enable_healthcare,
        },
    };

    const scan_ctx = json_redactor.ScanContext{
        .scan_fn = &SchemaScanRuntime.scan,
        .ctx_ptr = @ptrCast(&scan_runtime),
    };

    const hasher_iface = if (maybe_hasher) |*hasher| json_redactor.HasherInterface{
        .hash_fn = &hashCallback,
        .ctx_ptr = @ptrCast(hasher),
    } else null;

    return json_redactor.redactJson(case.input, &schema, hasher_iface, scan_ctx, allocator);
}

fn applyCase(kind: SuiteKind, case: CorpusCase, allocator: std.mem.Allocator) ![]u8 {
    return switch (kind) {
        .ssn => applySsnCase(case, allocator),
        .entity_exact => applyEntityExactCase(case, allocator),
        .entity_fuzzy => applyEntityFuzzyCase(case, allocator),
        .email => applyPatternCase(case, .{ .email = true }, allocator),
        .phone => applyPatternCase(case, .{ .phone = true }, allocator),
        .credit_card => applyPatternCase(case, .{ .credit_card = true }, allocator),
        .ip => applyPatternCase(case, .{ .ip = true }, allocator),
        .healthcare => applyPatternCase(case, .{ .healthcare = true }, allocator),
        .schema => applySchemaCase(case, allocator),
    };
}

fn evaluateCorpus(allocator: std.mem.Allocator, definition: SuiteDefinition) !AccuracyResult {
    var parse_arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer parse_arena.deinit();

    const corpus_json = try std.fs.cwd().readFileAlloc(parse_arena.allocator(), definition.path, 1024 * 1024);
    const corpus = try std.json.parseFromSliceLeaky(CorpusFile, parse_arena.allocator(), corpus_json, .{
        .ignore_unknown_fields = true,
    });

    if (!std.mem.eql(u8, corpus.suite, suiteKindString(definition.kind))) {
        return error.CorpusSuiteMismatch;
    }

    var true_positives: usize = 0;
    var false_negatives: usize = 0;
    var true_negatives: usize = 0;
    var false_positives: usize = 0;
    var positives: usize = 0;
    var negatives: usize = 0;
    var failures = std.ArrayListUnmanaged(FailureExample).empty;

    for (corpus.cases) |case| {
        const actual = try applyCase(definition.kind, case, parse_arena.allocator());

        const failure_reason = try validateCase(allocator, case, actual);
        const passed = failure_reason == null;

        switch (case.kind) {
            .positive => {
                positives += 1;
                if (passed) true_positives += 1 else false_negatives += 1;
            },
            .negative => {
                negatives += 1;
                if (passed) true_negatives += 1 else false_positives += 1;
            },
        }

        if (!passed and failures.items.len < max_failure_examples) {
            try failures.append(allocator, try duplicateFailureExample(allocator, case, failure_reason.?, actual));
        }
    }

    const precision = ratio(true_positives, true_positives + false_positives);
    const recall = ratio(true_positives, true_positives + false_negatives);
    const false_positive_rate = ratio(false_positives, negatives);
    const status: Status = if (precision >= corpus.thresholds.precision_min and
        recall >= corpus.thresholds.recall_min and
        false_positive_rate <= corpus.thresholds.false_positive_rate_max)
        .pass
    else
        .fail;

    return .{
        .id = try allocator.dupe(u8, corpus.suite),
        .label = try allocator.dupe(u8, corpus.label),
        .description = try allocator.dupe(u8, corpus.description),
        .positives = positives,
        .negatives = negatives,
        .true_positives = true_positives,
        .false_negatives = false_negatives,
        .true_negatives = true_negatives,
        .false_positives = false_positives,
        .precision = precision,
        .recall = recall,
        .false_positive_rate = false_positive_rate,
        .thresholds = corpus.thresholds,
        .status = status,
        .failures = try failures.toOwnedSlice(allocator),
    };
}

pub fn runAccuracySuites(allocator: std.mem.Allocator) ![]const AccuracyResult {
    var results = std.ArrayListUnmanaged(AccuracyResult).empty;
    errdefer results.deinit(allocator);

    for (suite_definitions) |definition| {
        try results.append(allocator, try evaluateCorpus(allocator, definition));
    }

    return try results.toOwnedSlice(allocator);
}

fn buildMixedPromptJson(allocator: std.mem.Allocator, approx_bytes: usize) ![]u8 {
    const snippet = "Patient Jane Smith with SSN 123-45-6789 email jane.smith@hospital.org phone (555) 123-4567 card 4111111111111111 ip 10.10.0.4 MRN: 7654321 diagnosis E11.65. ";

    var buffer = std.ArrayListUnmanaged(u8).empty;
    errdefer buffer.deinit(allocator);

    try buffer.appendSlice(allocator, "{\"prompt\":\"");
    while (buffer.items.len + snippet.len + 3 < approx_bytes) {
        try buffer.appendSlice(allocator, snippet);
    }
    try buffer.appendSlice(allocator, "\"}");

    return try buffer.toOwnedSlice(allocator);
}

fn buildSchemaPayload(allocator: std.mem.Allocator, approx_bytes: usize) ![]u8 {
    const snippet = "Patient Jane Smith with SSN 123-45-6789 and MRN: 7654321 diagnosis E11.65 requires follow up. ";

    var buffer = std.ArrayListUnmanaged(u8).empty;
    errdefer buffer.deinit(allocator);

    try buffer.appendSlice(allocator, "{\"patient_name\":\"Jane Smith\",\"internal_id\":\"PT-99001\",\"notes\":\"");
    while (buffer.items.len + snippet.len + 24 < approx_bytes) {
        try buffer.appendSlice(allocator, snippet);
    }
    try buffer.appendSlice(allocator, "\",\"status\":\"queued\"}");

    return try buffer.toOwnedSlice(allocator);
}

fn buildSchemaStreamingPayload(allocator: std.mem.Allocator, approx_bytes: usize) ![]u8 {
    var buffer = std.ArrayListUnmanaged(u8).empty;
    errdefer buffer.deinit(allocator);

    try buffer.appendSlice(allocator, "{\"records\":[");

    var index: usize = 0;
    while (buffer.items.len + 192 < approx_bytes) : (index += 1) {
        if (index != 0) try buffer.append(allocator, ',');
        try buffer.writer(allocator).print(
            "{{\"patient_name\":\"Patient {d}\",\"notes\":\"Patient SSN 123-45-6789 with MRN: 7654321 and diagnosis E11.65 requires follow up.\",\"details\":{{\"zip\":\"62704\",\"state\":\"IL\"}}}}",
            .{index},
        );
    }

    try buffer.appendSlice(allocator, "]}");
    return try buffer.toOwnedSlice(allocator);
}

fn sortAndSummarize(latencies_ns: []u64) struct { p50_ms: f64, p95_ms: f64 } {
    return bench_util.sortAndSummarize(latencies_ns);
}

fn benchmarkSsnThroughput() !BenchmarkResult {
    const allocator = std.heap.page_allocator;
    const payload_size = 1024 * 1024;
    var buffer = try allocator.alloc(u8, payload_size);
    defer allocator.free(buffer);

    const ssn = "123-45-6789";
    const iterations: usize = 50;

    var timer = try std.time.Timer.start();
    for (0..iterations) |_| {
        @memset(buffer, 'a');
        var pos: usize = 0;
        while (pos + ssn.len <= payload_size) : (pos += 100) {
            @memcpy(buffer[pos..][0..ssn.len], ssn);
        }
        redact.redactSsn(buffer);
    }

    const elapsed_ns = timer.read();
    const total_bytes = payload_size * iterations;
    const mb_per_sec = (@as(f64, @floatFromInt(total_bytes)) /
        @as(f64, @floatFromInt(elapsed_ns))) * 1_000_000_000.0 / (1024.0 * 1024.0);
    const min_target = 2_000.0;

    return .{
        .id = "stage_ssn_throughput",
        .label = "Stage 1 SSN throughput",
        .mode = "throughput_mb_per_sec",
        .status = if (mb_per_sec >= min_target) .pass else .fail,
        .iterations = iterations,
        .payload_bytes = payload_size,
        .throughput_mb_per_sec = mb_per_sec,
        .min_throughput_mb_per_sec = min_target,
    };
}

fn benchmarkEntityThroughput() !BenchmarkResult {
    const allocator = std.heap.page_allocator;
    const names = [_][]const u8{ "John Doe", "Jane Smith", "Mary Williams", "Robert Brown" };
    var entity_map = try entity_mask.EntityMap.init(allocator, &names);
    defer entity_map.deinit();

    const payload_size = 512 * 1024;
    const payload = try allocator.alloc(u8, payload_size);
    defer allocator.free(payload);
    @memset(payload, 'a');

    const name = " Jane Smith ";
    var pos: usize = 64;
    while (pos + name.len <= payload_size) : (pos += 160) {
        @memcpy(payload[pos..][0..name.len], name);
    }

    const iterations: usize = 25;
    var timer = try std.time.Timer.start();
    for (0..iterations) |_| {
        const result = try entity_map.mask(payload, allocator);
        allocator.free(result);
    }

    const elapsed_ns = timer.read();
    const total_bytes = payload_size * iterations;
    const mb_per_sec = (@as(f64, @floatFromInt(total_bytes)) /
        @as(f64, @floatFromInt(elapsed_ns))) * 1_000_000_000.0 / (1024.0 * 1024.0);
    const min_target = 200.0;

    return .{
        .id = "stage_entity_throughput",
        .label = "Stage 2 entity masking throughput",
        .mode = "throughput_mb_per_sec",
        .status = if (mb_per_sec >= min_target) .pass else .fail,
        .iterations = iterations,
        .payload_bytes = payload_size,
        .throughput_mb_per_sec = mb_per_sec,
        .min_throughput_mb_per_sec = min_target,
    };
}

fn benchmarkFuzzyThroughput() !BenchmarkResult {
    const allocator = std.heap.page_allocator;
    const names = [_][]const u8{ "John Doe", "Jane Smith", "Mary Williams" };
    const aliases = [_][]const u8{ "Entity_A", "Entity_B", "Entity_C" };

    var matcher = try fuzzy_match.FuzzyMatcher.init(allocator, &names, &aliases, 0.80);
    defer matcher.deinit();

    const payload_size = 256 * 1024;
    const payload = try allocator.alloc(u8, payload_size);
    defer allocator.free(payload);
    @memset(payload, 'a');

    const variant = " J0hn Doe ";
    var pos: usize = 64;
    while (pos + variant.len <= payload_size) : (pos += 200) {
        @memcpy(payload[pos..][0..variant.len], variant);
    }

    const iterations: usize = 8;
    var timer = try std.time.Timer.start();
    for (0..iterations) |_| {
        const result = try matcher.fuzzyRedact(payload, &aliases, &.{}, allocator);
        allocator.free(result);
    }

    const elapsed_ns = timer.read();
    const total_bytes = payload_size * iterations;
    const mb_per_sec = (@as(f64, @floatFromInt(total_bytes)) /
        @as(f64, @floatFromInt(elapsed_ns))) * 1_000_000_000.0 / (1024.0 * 1024.0);
    const min_target = 100.0;

    return .{
        .id = "stage_fuzzy_throughput",
        .label = "Stage 3 fuzzy matching throughput",
        .mode = "throughput_mb_per_sec",
        .status = if (mb_per_sec >= min_target) .pass else .fail,
        .iterations = iterations,
        .payload_bytes = payload_size,
        .throughput_mb_per_sec = mb_per_sec,
        .min_throughput_mb_per_sec = min_target,
    };
}

fn benchmarkPatternThroughput() !BenchmarkResult {
    const allocator = std.heap.page_allocator;
    const payload_size = 512 * 1024;
    const payload = try allocator.alloc(u8, payload_size);
    defer allocator.free(payload);
    @memset(payload, 'a');

    const snippet = " user@example.com (555) 123-4567 4111111111111111 10.0.0.1 MRN: 7654321 ";
    var pos: usize = 64;
    while (pos + snippet.len <= payload_size) : (pos += 192) {
        @memcpy(payload[pos..][0..snippet.len], snippet);
    }

    const flags = pattern_scanner.PatternFlags{
        .email = true,
        .phone = true,
        .credit_card = true,
        .ip = true,
        .healthcare = true,
    };

    const iterations: usize = 25;
    var timer = try std.time.Timer.start();
    for (0..iterations) |_| {
        const result = try pattern_scanner.redact(payload, flags, allocator);
        allocator.free(result);
    }

    const elapsed_ns = timer.read();
    const total_bytes = payload_size * iterations;
    const mb_per_sec = (@as(f64, @floatFromInt(total_bytes)) /
        @as(f64, @floatFromInt(elapsed_ns))) * 1_000_000_000.0 / (1024.0 * 1024.0);
    const min_target = 200.0;

    return .{
        .id = "stage_pattern_throughput",
        .label = "Pattern scanner throughput",
        .mode = "throughput_mb_per_sec",
        .status = if (mb_per_sec >= min_target) .pass else .fail,
        .iterations = iterations,
        .payload_bytes = payload_size,
        .throughput_mb_per_sec = mb_per_sec,
        .min_throughput_mb_per_sec = min_target,
    };
}

fn benchmarkMixedJsonLatency() !BenchmarkResult {
    if (builtin.os.tag == .windows) {
        return .{
            .id = "e2e_mixed_json_latency",
            .label = "E2E mixed JSON latency",
            .mode = "latency_ms",
            .status = .not_run,
            .iterations = 0,
            .payload_bytes = 0,
            .note = windows_benchmark_note,
        };
    }

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const payload = try buildMixedPromptJson(allocator, 8 * 1024);
    defer allocator.free(payload);

    const names = [_][]const u8{"Jane Smith"};
    const iterations: usize = 7;
    const samples = try allocator.alloc(u64, iterations);
    defer allocator.free(samples);

    for (0..iterations) |index| {
        var result = try e2e_harness.roundTrip(allocator, payload, .{
            .entity_names = &names,
            .enable_email = true,
            .enable_phone = true,
            .enable_credit_card = true,
            .enable_ip = true,
            .enable_healthcare = true,
            .upstream_content_type = "application/json",
        });
        defer result.deinit();
        samples[index] = result.total_response_latency_ns;
    }

    const stats = sortAndSummarize(samples);
    const max_p95 = 80.0;

    return .{
        .id = "e2e_mixed_json_latency",
        .label = "E2E mixed JSON latency",
        .mode = "latency_ms",
        .status = if (stats.p95_ms <= max_p95) .pass else .fail,
        .iterations = iterations,
        .payload_bytes = payload.len,
        .p50_ms = stats.p50_ms,
        .p95_ms = stats.p95_ms,
        .max_p95_ms = max_p95,
    };
}

fn benchmarkSchemaHashLatency() !BenchmarkResult {
    if (builtin.os.tag == .windows) {
        return .{
            .id = "e2e_schema_hash_latency",
            .label = "E2E schema HASH latency",
            .mode = "latency_ms",
            .status = .not_run,
            .iterations = 0,
            .payload_bytes = 0,
            .note = windows_benchmark_note,
        };
    }

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const payload = try buildSchemaPayload(allocator, 48 * 1024);
    defer allocator.free(payload);

    const schema_text =
        \\schema.default = KEEP
        \\patient_name = REDACT
        \\internal_id = HASH
        \\notes = SCAN
    ;

    var schema = try schema_mod.Schema.parseContent(schema_text, allocator);
    defer schema.deinit();

    const key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    var mem_vault = try @import("../vault/memory_vault.zig").MemoryVault.init(allocator);
    defer mem_vault.vaultInterface().deinit();
    var hasher = try hasher_mod.Hasher.init(key_hex, mem_vault.vaultInterface(), allocator);
    defer hasher.deinit();

    const token = try hasher.hash("PT-99001");
    defer allocator.free(token);
    const upstream_response = try std.fmt.allocPrint(allocator, "{{\"status\":\"ok\",\"id\":\"{s}\"}}", .{token});
    defer allocator.free(upstream_response);

    const iterations: usize = 5;
    const samples = try allocator.alloc(u64, iterations);
    defer allocator.free(samples);

    for (0..iterations) |index| {
        var result = try e2e_harness.roundTrip(allocator, payload, .{
            .schema = &schema,
            .hasher = &hasher,
            .enable_healthcare = true,
            .upstream_response = upstream_response,
            .upstream_content_type = "application/json",
        });
        defer result.deinit();
        samples[index] = result.total_response_latency_ns;
    }

    const stats = sortAndSummarize(samples);
    const max_p95 = 150.0;

    return .{
        .id = "e2e_schema_hash_latency",
        .label = "E2E schema HASH latency",
        .mode = "latency_ms",
        .status = if (stats.p95_ms <= max_p95) .pass else .fail,
        .iterations = iterations,
        .payload_bytes = payload.len,
        .p50_ms = stats.p50_ms,
        .p95_ms = stats.p95_ms,
        .max_p95_ms = max_p95,
    };
}

fn benchmarkSseFirstChunk() !BenchmarkResult {
    if (builtin.os.tag == .windows) {
        return .{
            .id = "e2e_sse_first_chunk",
            .label = "SSE first-chunk latency",
            .mode = "first_chunk_latency_ms",
            .status = .not_run,
            .iterations = 0,
            .payload_bytes = 0,
            .note = windows_benchmark_note,
        };
    }

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const payload = "{\"prompt\":\"hello\"}";
    const stream_chunks = [_][]const u8{
        "data: one\n\n",
        "data: two\n\n",
        "data: three\n\n",
    };

    const iterations: usize = 5;
    const total_latencies = try allocator.alloc(u64, iterations);
    defer allocator.free(total_latencies);
    const first_chunk_latencies = try allocator.alloc(u64, iterations);
    defer allocator.free(first_chunk_latencies);

    for (0..iterations) |index| {
        var result = try e2e_harness.roundTrip(allocator, payload, .{
            .request_extra_headers = &.{.{ .name = "Accept", .value = "text/event-stream" }},
            .upstream_stream_chunks = &stream_chunks,
            .upstream_inter_chunk_delay_ms = 60,
            .upstream_content_type = "text/event-stream",
        });
        defer result.deinit();
        total_latencies[index] = result.total_response_latency_ns;
        first_chunk_latencies[index] = result.first_chunk_latency_ns orelse result.total_response_latency_ns;
    }

    const total_stats = sortAndSummarize(total_latencies);
    const first_chunk_stats = sortAndSummarize(first_chunk_latencies);
    const max_first_chunk_p95 = 200.0;

    return .{
        .id = "e2e_sse_first_chunk",
        .label = "SSE first-chunk latency",
        .mode = "first_chunk_latency_ms",
        .status = if (first_chunk_stats.p95_ms <= max_first_chunk_p95) .pass else .fail,
        .iterations = iterations,
        .payload_bytes = payload.len,
        .p50_ms = total_stats.p50_ms,
        .p95_ms = total_stats.p95_ms,
        .first_chunk_p50_ms = first_chunk_stats.p50_ms,
        .first_chunk_p95_ms = first_chunk_stats.p95_ms,
        .max_first_chunk_p95_ms = max_first_chunk_p95,
    };
}

fn gatewayBenchmarkWorkerThreads(concurrent_clients: usize) usize {
    return @max(@as(usize, 1), concurrent_clients);
}

fn benchmarkGatewayRuntimeLatency(allocator: std.mem.Allocator) !BenchmarkResult {
    const concurrent_clients: usize = 64;
    const iterations: usize = 3;

    const baseline = try runtime_bench_harness.runProxyBurst(allocator, .{
        .runtime_model = .thread_per_connection,
        .concurrent_clients = concurrent_clients,
        .iterations = iterations,
        .payload_bytes = 4096,
        .upstream_delay_ms = 2,
        .max_connections = concurrent_clients,
    });
    const worker_threads = gatewayBenchmarkWorkerThreads(concurrent_clients);
    const candidate = try runtime_bench_harness.runProxyBurst(allocator, .{
        .runtime_model = .worker_pool,
        .runtime_worker_threads = worker_threads,
        .concurrent_clients = concurrent_clients,
        .iterations = iterations,
        .payload_bytes = 4096,
        .upstream_delay_ms = 2,
        .max_connections = concurrent_clients,
    });

    const max_p95 = @max(baseline.p95_ms * 4.0, baseline.p95_ms + 20.0);
    const note = try std.fmt.allocPrint(
        allocator,
        "baseline(tpc): {d}/{d} ok, p95 {d:.1} ms, ~{d} threads | candidate(pool): {d}/{d} ok, p95 {d:.1} ms, {d} workers | max_p95 {d:.1} ms",
        .{
            baseline.successful_requests,
            baseline.total_requests,
            baseline.p95_ms,
            baseline.estimated_handler_threads,
            candidate.successful_requests,
            candidate.total_requests,
            candidate.p95_ms,
            candidate.runtime_worker_threads,
            max_p95,
        },
    );

    return .{
        .id = "gateway_runtime_worker_pool_latency",
        .label = "Gateway worker-pool latency",
        .mode = "latency_ms",
        .status = if (candidate.successful_requests == candidate.total_requests and
            baseline.successful_requests == baseline.total_requests and
            candidate.p95_ms <= max_p95)
            .pass
        else
            .fail,
        .iterations = candidate.total_requests,
        .payload_bytes = candidate.payload_bytes,
        .p50_ms = candidate.p50_ms,
        .p95_ms = candidate.p95_ms,
        .max_p95_ms = max_p95,
        .note = note,
    };
}

fn benchmarkGatewayRuntimeStackReservation(allocator: std.mem.Allocator) !BenchmarkResult {
    const concurrent_clients: usize = 64;
    const baseline = try runtime_bench_harness.runProxyBurst(allocator, .{
        .runtime_model = .thread_per_connection,
        .concurrent_clients = concurrent_clients,
        .iterations = 1,
        .payload_bytes = 2048,
        .upstream_delay_ms = 1,
        .max_connections = concurrent_clients,
    });
    const candidate = try runtime_bench_harness.runProxyBurst(allocator, .{
        .runtime_model = .worker_pool,
        .runtime_worker_threads = gatewayBenchmarkWorkerThreads(concurrent_clients),
        .concurrent_clients = concurrent_clients,
        .iterations = 1,
        .payload_bytes = 2048,
        .upstream_delay_ms = 1,
        .max_connections = concurrent_clients,
    });

    const max_bytes = @max(@as(usize, 1), baseline.estimated_reserved_stack_bytes / 2);
    const note = try std.fmt.allocPrint(
        allocator,
        "baseline(tpc): ~{d} MiB for {d} threads | candidate(pool): ~{d} MiB for {d} workers | max {d} MiB",
        .{
            baseline.estimated_reserved_stack_bytes / (1024 * 1024),
            baseline.estimated_handler_threads,
            candidate.estimated_reserved_stack_bytes / (1024 * 1024),
            candidate.runtime_worker_threads,
            max_bytes / (1024 * 1024),
        },
    );

    return .{
        .id = "gateway_runtime_worker_pool_stack",
        .label = "Gateway worker-pool stack reservation",
        .mode = "peak_working_set_bytes",
        .status = if (candidate.estimated_reserved_stack_bytes <= max_bytes and
            candidate.successful_requests == candidate.total_requests)
            .pass
        else
            .fail,
        .iterations = candidate.total_requests,
        .payload_bytes = candidate.payload_bytes,
        .observed_bytes = candidate.estimated_reserved_stack_bytes,
        .max_bytes = max_bytes,
        .note = note,
    };
}

const SchemaStreamingMetrics = struct {
    payload_bytes: usize,
    p50_ms: f64,
    p95_ms: f64,
    peak_working_set_bytes: usize,
};

fn collectSchemaStreamingMetrics() !SchemaStreamingMetrics {
    const allocator = std.heap.page_allocator;
    const payload = try buildSchemaStreamingPayload(allocator, 512 * 1024);
    defer allocator.free(payload);

    const schema_text =
        \\schema.default = KEEP
        \\patient_name = REDACT
        \\notes = SCAN
        \\details.zip = REDACT
        \\details.state = KEEP
    ;

    var schema = try schema_mod.Schema.parseContent(schema_text, allocator);
    defer schema.deinit();

    var scan_runtime = SchemaScanRuntime{
        .flags = .{
            .healthcare = true,
        },
    };

    const scan_ctx = json_redactor.ScanContext{
        .scan_fn = &SchemaScanRuntime.scan,
        .ctx_ptr = @ptrCast(&scan_runtime),
    };

    const iterations: usize = 5;
    const samples = try allocator.alloc(u64, iterations);
    defer allocator.free(samples);

    var peak_working_set_bytes: usize = 0;
    for (0..iterations) |index| {
        var timer = try std.time.Timer.start();
        const result = try json_redactor.redactJsonStreaming(
            payload,
            4096,
            &schema,
            null,
            scan_ctx,
            null,
            allocator,
        );
        samples[index] = timer.read();
        if (result.stats.peak_working_set_bytes > peak_working_set_bytes) {
            peak_working_set_bytes = result.stats.peak_working_set_bytes;
        }
        allocator.free(result.output);
    }

    const stats = sortAndSummarize(samples);
    return .{
        .payload_bytes = payload.len,
        .p50_ms = stats.p50_ms,
        .p95_ms = stats.p95_ms,
        .peak_working_set_bytes = peak_working_set_bytes,
    };
}

fn benchmarkSchemaStreamingLatency() !BenchmarkResult {
    const metrics = try collectSchemaStreamingMetrics();
    const max_p95 = 250.0;

    return .{
        .id = "schema_streaming_latency",
        .label = "Schema streaming latency",
        .mode = "latency_ms",
        .status = if (metrics.p95_ms <= max_p95) .pass else .fail,
        .iterations = 5,
        .payload_bytes = metrics.payload_bytes,
        .p50_ms = metrics.p50_ms,
        .p95_ms = metrics.p95_ms,
        .max_p95_ms = max_p95,
    };
}

fn benchmarkSchemaStreamingMemory() !BenchmarkResult {
    const metrics = try collectSchemaStreamingMetrics();
    const max_peak_bytes: usize = 64 * 1024;

    return .{
        .id = "schema_streaming_peak_memory",
        .label = "Schema streaming peak memory",
        .mode = "peak_working_set_bytes",
        .status = if (metrics.peak_working_set_bytes <= max_peak_bytes) .pass else .fail,
        .iterations = 1,
        .payload_bytes = metrics.payload_bytes,
        .observed_bytes = metrics.peak_working_set_bytes,
        .max_bytes = max_peak_bytes,
    };
}

fn benchmarkFailure(id: []const u8, label: []const u8, mode: []const u8, note: []const u8) BenchmarkResult {
    return .{
        .id = id,
        .label = label,
        .mode = mode,
        .status = .fail,
        .iterations = 0,
        .payload_bytes = 0,
        .note = note,
    };
}

pub fn runBenchmarks(allocator: std.mem.Allocator) ![]const BenchmarkResult {
    var results = std.ArrayListUnmanaged(BenchmarkResult).empty;
    errdefer results.deinit(allocator);

    const ssn = benchmarkSsnThroughput() catch |err| benchmarkFailure(
        "stage_ssn_throughput",
        "Stage 1 SSN throughput",
        "throughput_mb_per_sec",
        @errorName(err),
    );
    try results.append(allocator, ssn);

    const entity = benchmarkEntityThroughput() catch |err| benchmarkFailure(
        "stage_entity_throughput",
        "Stage 2 entity masking throughput",
        "throughput_mb_per_sec",
        @errorName(err),
    );
    try results.append(allocator, entity);

    const fuzzy = benchmarkFuzzyThroughput() catch |err| benchmarkFailure(
        "stage_fuzzy_throughput",
        "Stage 3 fuzzy matching throughput",
        "throughput_mb_per_sec",
        @errorName(err),
    );
    try results.append(allocator, fuzzy);

    const pattern = benchmarkPatternThroughput() catch |err| benchmarkFailure(
        "stage_pattern_throughput",
        "Pattern scanner throughput",
        "throughput_mb_per_sec",
        @errorName(err),
    );
    try results.append(allocator, pattern);

    const mixed_json = benchmarkMixedJsonLatency() catch |err| benchmarkFailure(
        "e2e_mixed_json_latency",
        "E2E mixed JSON latency",
        "latency_ms",
        @errorName(err),
    );
    try results.append(allocator, mixed_json);

    const schema_hash = benchmarkSchemaHashLatency() catch |err| benchmarkFailure(
        "e2e_schema_hash_latency",
        "E2E schema HASH latency",
        "latency_ms",
        @errorName(err),
    );
    try results.append(allocator, schema_hash);

    const gateway_runtime_latency = benchmarkGatewayRuntimeLatency(allocator) catch |err| benchmarkFailure(
        "gateway_runtime_worker_pool_latency",
        "Gateway worker-pool latency",
        "latency_ms",
        @errorName(err),
    );
    try results.append(allocator, gateway_runtime_latency);

    const gateway_runtime_stack = benchmarkGatewayRuntimeStackReservation(allocator) catch |err| benchmarkFailure(
        "gateway_runtime_worker_pool_stack",
        "Gateway worker-pool stack reservation",
        "peak_working_set_bytes",
        @errorName(err),
    );
    try results.append(allocator, gateway_runtime_stack);

    const schema_streaming_latency = benchmarkSchemaStreamingLatency() catch |err| benchmarkFailure(
        "schema_streaming_latency",
        "Schema streaming latency",
        "latency_ms",
        @errorName(err),
    );
    try results.append(allocator, schema_streaming_latency);

    const schema_streaming_memory = benchmarkSchemaStreamingMemory() catch |err| benchmarkFailure(
        "schema_streaming_peak_memory",
        "Schema streaming peak memory",
        "peak_working_set_bytes",
        @errorName(err),
    );
    try results.append(allocator, schema_streaming_memory);

    const sse = benchmarkSseFirstChunk() catch |err| benchmarkFailure(
        "e2e_sse_first_chunk",
        "SSE first-chunk latency",
        "first_chunk_latency_ms",
        @errorName(err),
    );
    try results.append(allocator, sse);

    return try results.toOwnedSlice(allocator);
}

fn buildSummary(accuracy: []const AccuracyResult, benchmarks: []const BenchmarkResult) Summary {
    var accuracy_passed: usize = 0;
    var accuracy_failed: usize = 0;

    for (accuracy) |result| {
        switch (result.status) {
            .pass => accuracy_passed += 1,
            .fail => accuracy_failed += 1,
            .not_run => {},
        }
    }

    var benchmark_passed: usize = 0;
    var benchmark_failed: usize = 0;
    var benchmark_skipped: usize = 0;

    for (benchmarks) |result| {
        switch (result.status) {
            .pass => benchmark_passed += 1,
            .fail => benchmark_failed += 1,
            .not_run => benchmark_skipped += 1,
        }
    }

    return .{
        .accuracy_suites = accuracy.len,
        .accuracy_passed = accuracy_passed,
        .accuracy_failed = accuracy_failed,
        .benchmark_checks = benchmarks.len,
        .benchmark_passed = benchmark_passed,
        .benchmark_failed = benchmark_failed,
        .benchmark_skipped = benchmark_skipped,
        .hard_failures = accuracy_failed + benchmark_failed,
    };
}

pub fn runReport(allocator: std.mem.Allocator) !ProofReport {
    const accuracy = try runAccuracySuites(allocator);
    const benchmarks = try runBenchmarks(allocator);
    const summary = buildSummary(accuracy, benchmarks);

    return .{
        .suite = "nanomask_proof_harness",
        .generated_at_unix = std.time.timestamp(),
        .host_os = @tagName(builtin.os.tag),
        .accuracy = accuracy,
        .benchmarks = benchmarks,
        .summary = summary,
    };
}

pub fn hasHardFailures(report: ProofReport) bool {
    return report.summary.hard_failures > 0;
}

pub fn writeJson(writer: anytype, report: ProofReport) !void {
    try std.json.Stringify.value(report, .{}, writer);
}

fn writeAccuracyTableRow(writer: anytype, result: AccuracyResult) !void {
    try writer.print(
        "| {s} | {s} | {d:.3} | {d:.3} | {d:.3} | {}/{} |\n",
        .{
            result.label,
            statusString(result.status),
            result.precision,
            result.recall,
            result.false_positive_rate,
            result.true_positives + result.true_negatives,
            result.positives + result.negatives,
        },
    );
}

fn writeBenchmarkTableRow(writer: anytype, result: BenchmarkResult) !void {
    if (result.throughput_mb_per_sec) |throughput| {
        if (result.note) |note| {
            try writer.print(
                "| {s} | {s} | {d:.1} MB/s ({s}) | >= {d:.1} MB/s |\n",
                .{
                    result.label,
                    statusString(result.status),
                    throughput,
                    note,
                    result.min_throughput_mb_per_sec.?,
                },
            );
        } else {
            try writer.print(
                "| {s} | {s} | {d:.1} MB/s | >= {d:.1} MB/s |\n",
                .{
                    result.label,
                    statusString(result.status),
                    throughput,
                    result.min_throughput_mb_per_sec.?,
                },
            );
        }
        return;
    }

    if (result.observed_bytes) |observed_bytes| {
        if (result.note) |note| {
            try writer.print(
                "| {s} | {s} | {d} bytes ({s}) | <= {d} bytes |\n",
                .{
                    result.label,
                    statusString(result.status),
                    observed_bytes,
                    note,
                    result.max_bytes.?,
                },
            );
        } else {
            try writer.print(
                "| {s} | {s} | {d} bytes | <= {d} bytes |\n",
                .{
                    result.label,
                    statusString(result.status),
                    observed_bytes,
                    result.max_bytes.?,
                },
            );
        }
        return;
    }

    if (result.first_chunk_p95_ms) |first_chunk_p95| {
        if (result.note) |note| {
            try writer.print(
                "| {s} | {s} | first chunk p95 {d:.1} ms, total p95 {d:.1} ms ({s}) | <= {d:.1} ms |\n",
                .{
                    result.label,
                    statusString(result.status),
                    first_chunk_p95,
                    result.p95_ms.?,
                    note,
                    result.max_first_chunk_p95_ms.?,
                },
            );
        } else {
            try writer.print(
                "| {s} | {s} | first chunk p95 {d:.1} ms, total p95 {d:.1} ms | <= {d:.1} ms |\n",
                .{
                    result.label,
                    statusString(result.status),
                    first_chunk_p95,
                    result.p95_ms.?,
                    result.max_first_chunk_p95_ms.?,
                },
            );
        }
        return;
    }

    if (result.p95_ms) |p95| {
        if (result.note) |note| {
            try writer.print(
                "| {s} | {s} | p50 {d:.1} ms, p95 {d:.1} ms ({s}) | <= {d:.1} ms |\n",
                .{
                    result.label,
                    statusString(result.status),
                    result.p50_ms.?,
                    p95,
                    note,
                    result.max_p95_ms.?,
                },
            );
        } else {
            try writer.print(
                "| {s} | {s} | p50 {d:.1} ms, p95 {d:.1} ms | <= {d:.1} ms |\n",
                .{
                    result.label,
                    statusString(result.status),
                    result.p50_ms.?,
                    p95,
                    result.max_p95_ms.?,
                },
            );
        }
        return;
    }

    try writer.print(
        "| {s} | {s} | not run | {s} |\n",
        .{
            result.label,
            statusString(result.status),
            result.note orelse "",
        },
    );
}

pub fn writeMarkdown(writer: anytype, report: ProofReport) !void {
    try writer.writeAll("# NanoMask Proof Harness Report\n\n");
    try writer.print(
        "Generated at Unix time `{d}` on `{s}`.\n\n",
        .{ report.generated_at_unix, report.host_os },
    );

    try writer.writeAll("## Summary\n\n");
    try writer.print(
        "- Accuracy suites: {}/{} passed\n- Benchmark checks: {} passed, {} failed, {} skipped\n- Hard failures: {}\n\n",
        .{
            report.summary.accuracy_passed,
            report.summary.accuracy_suites,
            report.summary.benchmark_passed,
            report.summary.benchmark_failed,
            report.summary.benchmark_skipped,
            report.summary.hard_failures,
        },
    );

    try writer.writeAll("## Accuracy\n\n");
    try writer.writeAll("| Suite | Status | Precision | Recall | False Positive Rate | Passing Cases |\n");
    try writer.writeAll("| --- | --- | ---: | ---: | ---: | ---: |\n");
    for (report.accuracy) |result| {
        try writeAccuracyTableRow(writer, result);
    }
    try writer.writeAll("\n");

    for (report.accuracy) |result| {
        if (result.failures.len == 0) continue;
        try writer.print("### {s} Failures\n\n", .{result.label});
        for (result.failures) |failure| {
            try writer.print(
                "- `{s}`: {s}. Actual output preview: `{s}`\n",
                .{ failure.case_id, failure.reason, failure.actual_preview },
            );
        }
        try writer.writeAll("\n");
    }

    try writer.writeAll("## Benchmarks\n\n");
    try writer.writeAll("| Benchmark | Status | Observed | Target |\n");
    try writer.writeAll("| --- | --- | --- | --- |\n");
    for (report.benchmarks) |result| {
        try writeBenchmarkTableRow(writer, result);
    }
    try writer.writeAll("\n");
}

test "proof harness - all accuracy corpora meet thresholds" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const results = try runAccuracySuites(arena.allocator());
    try std.testing.expectEqual(@as(usize, suite_definitions.len), results.len);

    for (results) |result| {
        try std.testing.expectEqual(Status.pass, result.status);
    }
}

test "proof harness - healthcare corpus is present" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const results = try runAccuracySuites(arena.allocator());

    var found = false;
    for (results) |result| {
        if (std.mem.eql(u8, result.id, "healthcare")) {
            found = true;
            try std.testing.expectEqual(Status.pass, result.status);
        }
    }

    try std.testing.expect(found);
}
