const std = @import("std");
const redact = @import("../redaction/redact.zig");
const entity_mask = @import("../redaction/entity_mask.zig");
const pattern_scanner = @import("../patterns/scanner.zig");
const schema_mod = @import("../schema/schema.zig");
const json_redactor = @import("../schema/json_redactor.zig");
const hasher_mod = @import("../schema/hasher.zig");

const StarterCase = struct {
    name: []const u8,
    schema_path: []const u8,
    payload_path: []const u8,
    entity_path: []const u8,
    preset_path: []const u8,
    expected_schema_name: []const u8,
    expected_schema_version: []const u8,
    flags: pattern_scanner.PatternFlags,
    must_contain: []const []const u8,
    must_not_contain: []const []const u8,
    expected_listen_host: []const u8,
};

const starter_hash_key_path = "starters/healthcare/hash-key.example.txt";
const deployment_paths = [_][]const u8{
    "starters/healthcare/deployments/encounter-sidecar-pod.yaml",
    "starters/healthcare/deployments/claims-gateway.yaml",
    "starters/healthcare/README.md",
};

const starter_cases = [_]StarterCase{
    .{
        .name = "patient_demographics",
        .schema_path = "starters/healthcare/schemas/patient-demographics.nmschema",
        .payload_path = "starters/healthcare/payloads/patient-demographics.json",
        .entity_path = "starters/healthcare/entities/patient-demographics.txt",
        .preset_path = "starters/healthcare/presets/patient-demographics.env",
        .expected_schema_name = "patient_demographics",
        .expected_schema_version = "2026-03-09",
        .flags = .{
            .email = true,
            .phone = true,
            .healthcare = true,
        },
        .must_contain = &.{
            "\"full_name\":\"[REDACTED]\"",
            "\"subscriber_id\":\"PSEUDO_",
            "\"notes\":\"Entity_A confirmed SSN ***-**-**** and MRN: [MRN_REDACTED] during intake.\"",
        },
        .must_not_contain = &.{
            "Jane Smith",
            "123-45-6789",
            "1234567",
            "jane.smith@clinic.example",
            "SUB-778899",
        },
        .expected_listen_host = "127.0.0.1",
    },
    .{
        .name = "encounter_notes",
        .schema_path = "starters/healthcare/schemas/encounter-notes.nmschema",
        .payload_path = "starters/healthcare/payloads/encounter-note.json",
        .entity_path = "starters/healthcare/entities/encounter-notes.txt",
        .preset_path = "starters/healthcare/presets/encounter-notes.env",
        .expected_schema_name = "encounter_notes",
        .expected_schema_version = "2026-03-09",
        .flags = .{
            .email = true,
            .phone = true,
            .healthcare = true,
        },
        .must_contain = &.{
            "\"encounter_id\":\"PSEUDO_",
            "\"display_name\":\"[REDACTED]\"",
            "\"internal_id\":\"PSEUDO_",
            "\"summary\":\"Entity_A reported dizziness. Dr. Entity_B documented MRN: [MRN_REDACTED], diagnosis [ICD10_REDACTED], call back at [PHONE_REDACTED] or [EMAIL_REDACTED] for follow-up.\"",
        },
        .must_not_contain = &.{
            "John Doe",
            "Emily Carter",
            "7654321",
            "E11.65",
            "202-555-0110",
            "john.doe@hospital.org",
            "PT-99001",
        },
        .expected_listen_host = "127.0.0.1",
    },
    .{
        .name = "claims_processing",
        .schema_path = "starters/healthcare/schemas/claims-processing.nmschema",
        .payload_path = "starters/healthcare/payloads/claims-processing.json",
        .entity_path = "starters/healthcare/entities/claims-processing.txt",
        .preset_path = "starters/healthcare/presets/claims-gateway.env",
        .expected_schema_name = "claims_processing",
        .expected_schema_version = "2026-03-09",
        .flags = .{
            .ip = true,
            .healthcare = true,
        },
        .must_contain = &.{
            "\"claim_id\":\"PSEUDO_",
            "\"member_name\":\"[REDACTED]\"",
            "\"member_id\":\"PSEUDO_",
            "\"policy_number\":\"PSEUDO_",
            "\"service_note\":\"Entity_A called from [IPV4_REDACTED] about MRN: [MRN_REDACTED] and diagnosis [ICD10_REDACTED]. Member ID: [INSURANCE_REDACTED] verified.\"",
        },
        .must_not_contain = &.{
            "Marisol Vega",
            "203.0.113.10",
            "8899001",
            "Z87.891",
            "AB12345678",
            "POL99887766",
            "MBR-887766",
        },
        .expected_listen_host = "0.0.0.0",
    },
};

const ScanRuntime = struct {
    entity_map: ?*const entity_mask.EntityMap = null,
    flags: pattern_scanner.PatternFlags = .{},

    fn scan(input: []const u8, _: []const u8, ctx_ptr: *anyopaque, allocator: std.mem.Allocator) ![]u8 {
        const self: *ScanRuntime = @ptrCast(@alignCast(ctx_ptr));

        var current = try allocator.dupe(u8, input);
        redact.redactSsn(current);

        if (self.entity_map) |entity_map_ptr| {
            const masked = try entity_map_ptr.mask(current, allocator);
            allocator.free(current);
            current = masked;
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

fn readFile(allocator: std.mem.Allocator, path: []const u8, max_bytes: usize) ![]u8 {
    return std.fs.cwd().readFileAlloc(allocator, path, max_bytes);
}

fn loadEntityNames(arena: std.mem.Allocator, path: []const u8) ![]const []const u8 {
    const contents = try readFile(arena, path, 16 * 1024);

    var names = std.ArrayListUnmanaged([]const u8).empty;
    var lines = std.mem.splitScalar(u8, contents, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, std.mem.trimRight(u8, raw_line, "\r"), " \t");
        if (line.len == 0 or line[0] == '#') continue;
        try names.append(arena, try arena.dupe(u8, line));
    }

    return try names.toOwnedSlice(arena);
}

fn applyStarterCase(test_allocator: std.mem.Allocator, starter_case: StarterCase) ![]u8 {
    var arena = std.heap.ArenaAllocator.init(test_allocator);
    defer arena.deinit();
    const arena_allocator = arena.allocator();

    var schema = try schema_mod.Schema.loadFromFile(starter_case.schema_path, test_allocator);
    defer schema.deinit();

    var entity_map: ?entity_mask.EntityMap = null;
    defer if (entity_map) |*map| map.deinit();

    const entity_names = try loadEntityNames(arena_allocator, starter_case.entity_path);
    if (entity_names.len > 0) {
        entity_map = try entity_mask.EntityMap.init(test_allocator, entity_names);
    }

    var runtime = ScanRuntime{
        .entity_map = if (entity_map) |*map| map else null,
        .flags = starter_case.flags,
    };

    const scan_ctx = json_redactor.ScanContext{
        .scan_fn = &ScanRuntime.scan,
        .ctx_ptr = @ptrCast(&runtime),
    };

    var hasher = try hasher_mod.Hasher.initFromFile(starter_hash_key_path, test_allocator);
    defer hasher.deinit();

    const hasher_iface = json_redactor.HasherInterface{
        .hash_fn = &hashCallback,
        .ctx_ptr = @ptrCast(&hasher),
    };

    const payload = try readFile(arena_allocator, starter_case.payload_path, 32 * 1024);
    return json_redactor.redactJson(payload, &schema, hasher_iface, scan_ctx, test_allocator);
}

fn findEnvValue(contents: []const u8, key: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, contents, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, std.mem.trimRight(u8, raw_line, "\r"), " \t");
        if (line.len == 0 or line[0] == '#') continue;

        const eq_index = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const env_key = std.mem.trim(u8, line[0..eq_index], " \t");
        if (!std.mem.eql(u8, env_key, key)) continue;
        return std.mem.trim(u8, line[eq_index + 1 ..], " \t");
    }

    return null;
}

fn expectEnvValue(contents: []const u8, key: []const u8, expected: []const u8) !void {
    const actual = findEnvValue(contents, key) orelse return error.MissingEnvKey;
    try std.testing.expectEqualStrings(expected, actual);
}

test "healthcare starter pack schemas are versioned and parse from disk" {
    for (starter_cases) |starter_case| {
        var schema = try schema_mod.Schema.loadFromFile(starter_case.schema_path, std.testing.allocator);
        defer schema.deinit();

        try std.testing.expectEqualStrings(starter_case.expected_schema_name, schema.name);
        try std.testing.expectEqualStrings(starter_case.expected_schema_version, schema.version);
        try std.testing.expectEqual(schema_mod.SchemaAction.keep, schema.default_action);
        try std.testing.expect(schema.fieldCount() >= 4);
    }
}

test "healthcare starter pack payloads redact with checked-in starter assets" {
    for (starter_cases) |starter_case| {
        const redacted = try applyStarterCase(std.testing.allocator, starter_case);
        defer std.testing.allocator.free(redacted);

        for (starter_case.must_contain) |needle| {
            try std.testing.expect(std.mem.indexOf(u8, redacted, needle) != null);
        }
        for (starter_case.must_not_contain) |needle| {
            try std.testing.expect(std.mem.indexOf(u8, redacted, needle) == null);
        }
    }
}

test "healthcare starter pack presets reference checked-in assets" {
    for (starter_cases) |starter_case| {
        const preset = try readFile(std.testing.allocator, starter_case.preset_path, 8 * 1024);
        defer std.testing.allocator.free(preset);

        try expectEnvValue(preset, "NANOMASK_LISTEN_HOST", starter_case.expected_listen_host);
        try expectEnvValue(preset, "NANOMASK_ENTITY_FILE", starter_case.entity_path);
        try expectEnvValue(preset, "NANOMASK_SCHEMA_FILE", starter_case.schema_path);
        try expectEnvValue(preset, "NANOMASK_HASH_KEY_FILE", starter_hash_key_path);
        try expectEnvValue(preset, "NANOMASK_SCHEMA_DEFAULT", "KEEP");
        try expectEnvValue(preset, "NANOMASK_AUDIT_LOG", "true");
    }

    try std.fs.cwd().access(starter_hash_key_path, .{});
    for (deployment_paths) |path| {
        try std.fs.cwd().access(path, .{});
    }
}
