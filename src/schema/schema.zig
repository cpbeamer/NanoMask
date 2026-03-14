const std = @import("std");

/// Actions that can be applied to JSON fields based on the schema.
pub const SchemaAction = enum {
    redact, // Replace entire value without scanning
    keep, // Pass through untouched
    scan, // Run value through the 3-stage pipeline
    hash, // Deterministic pseudonymization via HMAC

    pub fn parse(s: []const u8) !SchemaAction {
        if (std.mem.eql(u8, s, "REDACT")) return .redact;
        if (std.mem.eql(u8, s, "KEEP")) return .keep;
        if (std.mem.eql(u8, s, "SCAN")) return .scan;
        if (std.mem.eql(u8, s, "HASH")) return .hash;
        return error.InvalidAction;
    }
};

/// Schema definition loaded from a config file.
/// Specifies per-field redaction actions for structured JSON payloads.
/// Uses a hash map for O(1) field lookups at runtime.
pub const Schema = struct {
    /// Owned schema name (empty slice when unset).
    name: []u8,
    /// Owned schema version (empty slice when unset).
    version: []u8,
    default_action: SchemaAction,
    /// Maps dotted key paths (e.g. "address.street") → action.
    /// Both keys and the map itself are owned by `allocator`.
    fields: std.StringHashMapUnmanaged(SchemaAction),
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) Schema {
        return .{
            .name = &.{},
            .version = &.{},
            .default_action = .scan,
            .fields = .empty,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *Schema) void {
        var it = self.fields.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
        }
        self.fields.deinit(self.allocator);
        if (self.name.len > 0) self.allocator.free(self.name);
        if (self.version.len > 0) self.allocator.free(self.version);
    }

    /// Look up the action for a dotted key path.
    /// Returns the field-specific action if found, otherwise the schema default.
    pub fn findAction(self: *const Schema, key_path: []const u8) SchemaAction {
        return self.fields.get(key_path) orelse self.default_action;
    }

    /// Returns true if any field rule uses the HASH action.
    /// Used to decide whether a Hasher needs to be created at startup.
    pub fn hasHashFields(self: *const Schema) bool {
        var it = self.fields.valueIterator();
        while (it.next()) |action| {
            if (action.* == .hash) return true;
        }
        return false;
    }

    /// Total number of field rules in the schema.
    pub fn fieldCount(self: *const Schema) usize {
        return self.fields.count();
    }

    /// Load and parse a schema from a file path.
    pub fn loadFromFile(path: []const u8, allocator: std.mem.Allocator) !Schema {
        const file = std.fs.cwd().openFile(path, .{}) catch |err| {
            std.debug.print("error: cannot open schema file '{s}': {s}\n", .{ path, @errorName(err) });
            return error.SchemaFileNotFound;
        };
        defer file.close();

        const content = file.readToEndAlloc(allocator, 1024 * 1024) catch {
            return error.SchemaFileReadError;
        };
        defer allocator.free(content);

        return parseContent(content, allocator);
    }

    /// Parse schema from a byte buffer (used by loadFromFile and tests).
    pub fn parseContent(content: []const u8, allocator: std.mem.Allocator) !Schema {
        var schema = Schema.init(allocator);
        errdefer schema.deinit();

        // First pass: count field rules to pre-size the hash map and avoid
        // repeated internal resizes for schemas with many rules.
        var field_count: u32 = 0;
        {
            var count_iter = std.mem.splitScalar(u8, content, '\n');
            while (count_iter.next()) |raw_line| {
                const line = std.mem.trimRight(u8, raw_line, "\r");
                const trimmed = std.mem.trim(u8, line, " \t");
                if (trimmed.len == 0 or trimmed[0] == '#') continue;
                // Skip metadata keys (schema.*)
                if (std.mem.startsWith(u8, trimmed, "schema.")) continue;
                if (std.mem.indexOfScalar(u8, trimmed, '=') != null) field_count += 1;
            }
        }
        if (field_count > 0) {
            try schema.fields.ensureTotalCapacity(allocator, field_count);
        }

        var line_iter = std.mem.splitScalar(u8, content, '\n');
        var line_num: usize = 0;
        while (line_iter.next()) |raw_line| {
            line_num += 1;
            // Strip \r for Windows line endings
            const line = std.mem.trimRight(u8, raw_line, "\r");
            const trimmed = std.mem.trim(u8, line, " \t");

            // Skip blank lines and comments
            if (trimmed.len == 0 or trimmed[0] == '#') continue;

            // Split on first '='
            const eq_pos = std.mem.indexOfScalar(u8, trimmed, '=') orelse {
                std.debug.print("error: schema line {d}: missing '=' separator\n", .{line_num});
                return error.InvalidSchemaFormat;
            };

            const key = std.mem.trim(u8, trimmed[0..eq_pos], " \t");
            const value = std.mem.trim(u8, trimmed[eq_pos + 1 ..], " \t");

            if (key.len == 0) {
                std.debug.print("error: schema line {d}: empty key\n", .{line_num});
                return error.InvalidSchemaFormat;
            }

            // Handle schema metadata keys
            if (std.mem.eql(u8, key, "schema.name")) {
                if (schema.name.len > 0) allocator.free(schema.name);
                schema.name = try allocator.dupe(u8, value);
            } else if (std.mem.eql(u8, key, "schema.version")) {
                if (schema.version.len > 0) allocator.free(schema.version);
                schema.version = try allocator.dupe(u8, value);
            } else if (std.mem.eql(u8, key, "schema.default")) {
                schema.default_action = SchemaAction.parse(value) catch {
                    std.debug.print("error: schema line {d}: invalid default action '{s}'\n", .{ line_num, value });
                    return error.InvalidAction;
                };
            } else {
                // Field rule: key_path = ACTION
                const action = SchemaAction.parse(value) catch {
                    std.debug.print("error: schema line {d}: invalid action '{s}' for key '{s}'\n", .{ line_num, value, key });
                    return error.InvalidAction;
                };

                const owned_key = try allocator.dupe(u8, key);
                const gop = try schema.fields.getOrPut(allocator, owned_key);
                if (gop.found_existing) {
                    // Key already exists in map — free the duplicate we just allocated
                    allocator.free(owned_key);
                }
                gop.value_ptr.* = action;
            }
        }

        return schema;
    }
};

// ===========================================================================
// Unit Tests
// ===========================================================================

test "schema - parse basic fields" {
    const content =
        \\# Test schema
        \\schema.name = test_form
        \\schema.version = 1.0
        \\
        \\patient_name = REDACT
        \\visit_date = KEEP
        \\notes = SCAN
        \\internal_id = HASH
    ;

    var schema = try Schema.parseContent(content, std.testing.allocator);
    defer schema.deinit();

    try std.testing.expectEqualStrings("test_form", schema.name);
    try std.testing.expectEqualStrings("1.0", schema.version);
    try std.testing.expectEqual(@as(usize, 4), schema.fieldCount());
    try std.testing.expectEqual(SchemaAction.redact, schema.findAction("patient_name"));
    try std.testing.expectEqual(SchemaAction.keep, schema.findAction("visit_date"));
    try std.testing.expectEqual(SchemaAction.scan, schema.findAction("notes"));
    try std.testing.expectEqual(SchemaAction.hash, schema.findAction("internal_id"));
}

test "schema - nested key paths" {
    const content =
        \\address.street = REDACT
        \\address.city = REDACT
        \\address.state = KEEP
        \\address.zip = REDACT
    ;

    var schema = try Schema.parseContent(content, std.testing.allocator);
    defer schema.deinit();

    try std.testing.expectEqual(SchemaAction.redact, schema.findAction("address.street"));
    try std.testing.expectEqual(SchemaAction.redact, schema.findAction("address.city"));
    try std.testing.expectEqual(SchemaAction.keep, schema.findAction("address.state"));
    try std.testing.expectEqual(SchemaAction.redact, schema.findAction("address.zip"));
}

test "schema - default action fallback" {
    const content =
        \\schema.default = KEEP
        \\patient_name = REDACT
    ;

    var schema = try Schema.parseContent(content, std.testing.allocator);
    defer schema.deinit();

    try std.testing.expectEqual(SchemaAction.redact, schema.findAction("patient_name"));
    // Unknown key falls back to schema default
    try std.testing.expectEqual(SchemaAction.keep, schema.findAction("unknown_field"));
}

test "schema - default is SCAN when unspecified" {
    const content =
        \\patient_name = REDACT
    ;

    var schema = try Schema.parseContent(content, std.testing.allocator);
    defer schema.deinit();

    try std.testing.expectEqual(SchemaAction.scan, schema.findAction("unknown_field"));
}

test "schema - comments and blank lines are skipped" {
    const content =
        \\# This is a comment
        \\
        \\# Another comment
        \\patient_name = REDACT
        \\
        \\# End-of-file comment
    ;

    var schema = try Schema.parseContent(content, std.testing.allocator);
    defer schema.deinit();

    try std.testing.expectEqual(@as(usize, 1), schema.fieldCount());
    try std.testing.expectEqual(SchemaAction.redact, schema.findAction("patient_name"));
}

test "schema - invalid action produces error" {
    const content =
        \\patient_name = DESTROY
    ;

    const result = Schema.parseContent(content, std.testing.allocator);
    try std.testing.expectError(error.InvalidAction, result);
}

test "schema - missing equals separator produces error" {
    const content =
        \\patient_name REDACT
    ;

    const result = Schema.parseContent(content, std.testing.allocator);
    try std.testing.expectError(error.InvalidSchemaFormat, result);
}

test "schema - empty key produces error" {
    const content =
        \\ = REDACT
    ;

    const result = Schema.parseContent(content, std.testing.allocator);
    try std.testing.expectError(error.InvalidSchemaFormat, result);
}

test "schema - empty content produces empty schema" {
    const content = "";

    var schema = try Schema.parseContent(content, std.testing.allocator);
    defer schema.deinit();

    try std.testing.expectEqual(@as(usize, 0), schema.fieldCount());
    try std.testing.expectEqualStrings("", schema.name);
}

test "schema - whitespace around keys and values is trimmed" {
    const content =
        \\  patient_name  =  REDACT  
        \\  visit_date=KEEP
    ;

    var schema = try Schema.parseContent(content, std.testing.allocator);
    defer schema.deinit();

    try std.testing.expectEqual(SchemaAction.redact, schema.findAction("patient_name"));
    try std.testing.expectEqual(SchemaAction.keep, schema.findAction("visit_date"));
}

test "schema - invalid default action produces error" {
    const content =
        \\schema.default = INVALID
    ;

    const result = Schema.parseContent(content, std.testing.allocator);
    try std.testing.expectError(error.InvalidAction, result);
}

test "schema - hasHashFields detects HASH rules" {
    const content =
        \\patient_name = REDACT
        \\internal_id = HASH
        \\notes = SCAN
    ;

    var schema = try Schema.parseContent(content, std.testing.allocator);
    defer schema.deinit();

    try std.testing.expect(schema.hasHashFields());
}

test "schema - hasHashFields returns false when no HASH rules" {
    const content =
        \\patient_name = REDACT
        \\visit_date = KEEP
    ;

    var schema = try Schema.parseContent(content, std.testing.allocator);
    defer schema.deinit();

    try std.testing.expect(!schema.hasHashFields());
}
