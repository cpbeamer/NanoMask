const std = @import("std");

// ---------------------------------------------------------------------------
// RBAC — Role-based access control and API key management
// ---------------------------------------------------------------------------
// Provides enterprise identity for the admin API without requiring a full
// SSO/OIDC stack. API keys carry a role and optional tenant scope. The store
// authenticates via constant-time SHA-256 digest comparison to prevent timing
// side-channels.
// ---------------------------------------------------------------------------

pub const Role = enum(u8) {
    viewer,
    operator,
    admin,

    pub fn label(self: Role) []const u8 {
        return switch (self) {
            .viewer => "viewer",
            .operator => "operator",
            .admin => "admin",
        };
    }

    pub fn parse(s: []const u8) ?Role {
        if (std.mem.eql(u8, s, "viewer")) return .viewer;
        if (std.mem.eql(u8, s, "operator")) return .operator;
        if (std.mem.eql(u8, s, "admin")) return .admin;
        return null;
    }

    /// Returns true if `self` has at least the privileges of `required`.
    /// Hierarchy: admin >= operator >= viewer.
    pub fn atLeast(self: Role, required: Role) bool {
        return @intFromEnum(self) >= @intFromEnum(required);
    }
};

/// SHA-256 digest used as the key identity. Raw keys are never stored.
pub const KeyDigest = [32]u8;

pub const ApiKey = struct {
    /// SHA-256 hash of the raw API key string.
    digest: KeyDigest,
    /// Assigned role controlling what endpoints this key can access.
    role: Role,
    /// Optional tenant namespace. When set, limits visibility to
    /// entities and audit events scoped to this tenant.
    tenant: ?[]const u8,
    /// Human-readable label for identification (e.g. "ci-bot", "ops-team").
    name: []const u8,
};

/// Thread-safe store of API keys indexed by their SHA-256 digest.
/// Designed for a small number of keys (< 1000) — linear scan is fine.
pub const ApiKeyStore = struct {
    keys: std.ArrayListUnmanaged(OwnedApiKey),
    allocator: std.mem.Allocator,
    mutex: std.Thread.Mutex,

    const OwnedApiKey = struct {
        digest: KeyDigest,
        role: Role,
        tenant: ?[]const u8,
        name: []const u8,
    };

    pub fn init(allocator: std.mem.Allocator) ApiKeyStore {
        return .{
            .keys = .empty,
            .allocator = allocator,
            .mutex = .{},
        };
    }

    pub fn deinit(self: *ApiKeyStore) void {
        for (self.keys.items) |key| {
            if (key.tenant) |t| self.allocator.free(t);
            self.allocator.free(key.name);
        }
        self.keys.deinit(self.allocator);
    }

    /// Authenticate a raw Bearer token. Returns the matching key's role and
    /// tenant if found, null otherwise. Uses constant-time digest comparison.
    pub fn authenticate(self: *ApiKeyStore, raw_token: []const u8) ?AuthResult {
        const digest = hashToken(raw_token);

        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.keys.items) |key| {
            if (constantTimeDigestEql(&key.digest, &digest)) {
                return .{
                    .role = key.role,
                    .tenant = key.tenant,
                    .name = key.name,
                };
            }
        }
        return null;
    }

    pub const AuthResult = struct {
        role: Role,
        tenant: ?[]const u8,
        name: []const u8,
    };

    /// Add a key to the store. Caller provides the raw token; only the
    /// SHA-256 digest is persisted. Returns error.DuplicateKey if a key
    /// with the same digest already exists, or error.DuplicateName if the
    /// name is already in use (names are the deletion handle; duplicates
    /// cause ambiguous removeByName behaviour).
    pub fn addKey(
        self: *ApiKeyStore,
        raw_token: []const u8,
        role: Role,
        tenant: ?[]const u8,
        name: []const u8,
    ) !void {
        const digest = hashToken(raw_token);

        self.mutex.lock();
        defer self.mutex.unlock();

        // Check for duplicate digest
        for (self.keys.items) |key| {
            if (constantTimeDigestEql(&key.digest, &digest)) {
                return error.DuplicateKey;
            }
        }

        // Check for duplicate name (names are the deletion key; duplicates cause ambiguity)
        for (self.keys.items) |key| {
            if (std.mem.eql(u8, key.name, name)) {
                return error.DuplicateName;
            }
        }

        const owned_tenant = if (tenant) |t| try self.allocator.dupe(u8, t) else null;
        errdefer if (owned_tenant) |t| self.allocator.free(t);

        const owned_name = try self.allocator.dupe(u8, name);
        errdefer self.allocator.free(owned_name);

        try self.keys.append(self.allocator, .{
            .digest = digest,
            .role = role,
            .tenant = owned_tenant,
            .name = owned_name,
        });
    }

    /// Remove a key by name. Returns true if found and removed.
    pub fn removeByName(self: *ApiKeyStore, name: []const u8) bool {
        self.mutex.lock();
        defer self.mutex.unlock();

        for (self.keys.items, 0..) |key, i| {
            if (std.mem.eql(u8, key.name, name)) {
                if (key.tenant) |t| self.allocator.free(t);
                self.allocator.free(key.name);
                _ = self.keys.swapRemove(i);
                return true;
            }
        }
        return false;
    }

    /// Return the number of registered keys.
    pub fn count(self: *ApiKeyStore) usize {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.keys.items.len;
    }

    /// Render a JSON array of key metadata (names, roles, tenants).
    /// Raw keys are never exposed.
    pub fn renderKeysJson(self: *ApiKeyStore, allocator: std.mem.Allocator) ![]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();

        var buf: std.ArrayListUnmanaged(u8) = .empty;
        errdefer buf.deinit(allocator);
        const writer = buf.writer(allocator);

        try writer.writeByte('[');
        for (self.keys.items, 0..) |key, i| {
            if (i > 0) try writer.writeByte(',');
            try writer.writeAll("{\"name\":\"");
            try writeJsonEscaped(writer, key.name);
            try writer.writeAll("\",\"role\":\"");
            try writer.writeAll(key.role.label());
            try writer.writeAll("\"");
            if (key.tenant) |t| {
                try writer.writeAll(",\"tenant\":\"");
                try writeJsonEscaped(writer, t);
                try writer.writeAll("\"");
            }
            try writer.writeByte('}');
        }
        try writer.writeByte(']');

        return try buf.toOwnedSlice(allocator);
    }

    /// Load API keys from a JSON file. File format:
    /// ```json
    /// [
    ///   {"key": "raw-secret-string", "role": "admin", "name": "bootstrap"},
    ///   {"key": "another-key", "role": "viewer", "name": "ro-bot", "tenant": "acme"}
    /// ]
    /// ```
    pub fn loadFromFile(path: []const u8, allocator: std.mem.Allocator) !ApiKeyStore {
        var store = ApiKeyStore.init(allocator);
        errdefer store.deinit();

        const file = std.fs.cwd().openFile(path, .{}) catch |err| {
            std.debug.print("error: cannot open API key file '{s}': {s}\n", .{ path, @errorName(err) });
            return error.FileNotFound;
        };
        defer file.close();

        const content = file.readToEndAlloc(allocator, 1 * 1024 * 1024) catch {
            return error.FileReadFailed;
        };
        defer allocator.free(content);

        try parseKeyArray(&store, content);
        return store;
    }
};

/// Compute the SHA-256 digest of a raw API key token.
pub fn hashToken(raw: []const u8) KeyDigest {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(raw);
    return hasher.finalResult();
}

/// Constant-time comparison of two 32-byte digests.
fn constantTimeDigestEql(a: *const KeyDigest, b: *const KeyDigest) bool {
    var diff: u8 = 0;
    for (a, b) |x, y| {
        diff |= x ^ y;
    }
    return diff == 0;
}

/// Escape a string for safe embedding in JSON. Matches the pattern used in
/// logger.zig to keep output consistent.
pub fn writeJsonEscaped(writer: anytype, s: []const u8) !void {
    for (s) |c| {
        switch (c) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            else => {
                if (c < 0x20) {
                    try std.fmt.format(writer, "\\u{x:0>4}", .{c});
                } else {
                    try writer.writeByte(c);
                }
            },
        }
    }
}

/// Minimal JSON array parser for the API key bootstrap file.
/// Expects: [{"key":"...","role":"...","name":"..."}, ...]
fn parseKeyArray(store: *ApiKeyStore, json: []const u8) !void {
    var i: usize = 0;

    // Skip to opening '['
    while (i < json.len and json[i] != '[') : (i += 1) {}
    if (i >= json.len) return error.InvalidJson;
    i += 1; // skip '['

    while (i < json.len) {
        skipWhitespace(json, &i);
        if (i >= json.len) break;
        if (json[i] == ']') break;
        if (json[i] == ',') {
            i += 1;
            continue;
        }

        if (json[i] != '{') return error.InvalidJson;
        i += 1;

        var key_val: ?[]const u8 = null;
        var role_val: ?[]const u8 = null;
        var name_val: ?[]const u8 = null;
        var tenant_val: ?[]const u8 = null;

        // Parse object fields
        while (i < json.len and json[i] != '}') {
            skipWhitespace(json, &i);
            if (i >= json.len) return error.InvalidJson;
            if (json[i] == ',') {
                i += 1;
                continue;
            }
            if (json[i] == '}') break;

            const field_name = try parseJsonString(json, &i);
            skipWhitespace(json, &i);
            if (i >= json.len or json[i] != ':') return error.InvalidJson;
            i += 1;
            skipWhitespace(json, &i);
            const field_value = try parseJsonString(json, &i);

            if (std.mem.eql(u8, field_name, "key")) {
                key_val = field_value;
            } else if (std.mem.eql(u8, field_name, "role")) {
                role_val = field_value;
            } else if (std.mem.eql(u8, field_name, "name")) {
                name_val = field_value;
            } else if (std.mem.eql(u8, field_name, "tenant")) {
                tenant_val = field_value;
            }
        }

        if (i < json.len and json[i] == '}') i += 1;

        const raw_key = key_val orelse return error.MissingKeyField;
        const role_str = role_val orelse return error.MissingRoleField;
        const name = name_val orelse return error.MissingNameField;

        const role = Role.parse(role_str) orelse return error.InvalidRole;

        store.addKey(raw_key, role, tenant_val, name) catch |err| switch (err) {
            error.DuplicateKey => {
                std.debug.print("warning: duplicate API key digest for '{s}', skipping\n", .{name});
            },
            error.DuplicateName => {
                std.debug.print("warning: duplicate API key name '{s}', skipping\n", .{name});
            },
            else => return err,
        };
    }
}

fn skipWhitespace(json: []const u8, i: *usize) void {
    while (i.* < json.len and (json[i.*] == ' ' or json[i.*] == '\t' or json[i.*] == '\n' or json[i.*] == '\r')) : (i.* += 1) {}
}

/// Parse a JSON string at position i, returning a slice into the json buffer.
/// Handles basic escaping but returns raw slices (no unescape needed for our use case).
fn parseJsonString(json: []const u8, i: *usize) ![]const u8 {
    if (i.* >= json.len or json[i.*] != '"') return error.InvalidJson;
    i.* += 1; // skip opening quote
    const start = i.*;
    while (i.* < json.len and json[i.*] != '"') {
        if (json[i.*] == '\\' and i.* + 1 < json.len) {
            i.* += 2;
        } else {
            i.* += 1;
        }
    }
    if (i.* >= json.len) return error.InvalidJson;
    const end = i.*;
    i.* += 1; // skip closing quote
    return json[start..end];
}

// ===========================================================================
// Unit Tests
// ===========================================================================

test "Role - atLeast hierarchy" {
    try std.testing.expect(Role.admin.atLeast(.admin));
    try std.testing.expect(Role.admin.atLeast(.operator));
    try std.testing.expect(Role.admin.atLeast(.viewer));
    try std.testing.expect(Role.operator.atLeast(.operator));
    try std.testing.expect(Role.operator.atLeast(.viewer));
    try std.testing.expect(!Role.operator.atLeast(.admin));
    try std.testing.expect(Role.viewer.atLeast(.viewer));
    try std.testing.expect(!Role.viewer.atLeast(.operator));
    try std.testing.expect(!Role.viewer.atLeast(.admin));
}

test "Role - parse and label round-trip" {
    const roles = [_]Role{ .viewer, .operator, .admin };
    for (roles) |role| {
        const parsed = Role.parse(role.label());
        try std.testing.expect(parsed != null);
        try std.testing.expectEqual(role, parsed.?);
    }
    try std.testing.expect(Role.parse("invalid") == null);
}

test "ApiKeyStore - add and authenticate" {
    var store = ApiKeyStore.init(std.testing.allocator);
    defer store.deinit();

    try store.addKey("my-secret-key", .admin, null, "test-admin");
    try store.addKey("viewer-key", .viewer, "acme", "test-viewer");

    try std.testing.expectEqual(@as(usize, 2), store.count());

    // Authenticate valid admin key
    const admin_result = store.authenticate("my-secret-key");
    try std.testing.expect(admin_result != null);
    try std.testing.expectEqual(Role.admin, admin_result.?.role);
    try std.testing.expect(admin_result.?.tenant == null);

    // Authenticate valid viewer key with tenant
    const viewer_result = store.authenticate("viewer-key");
    try std.testing.expect(viewer_result != null);
    try std.testing.expectEqual(Role.viewer, viewer_result.?.role);
    try std.testing.expect(viewer_result.?.tenant != null);
    try std.testing.expectEqualStrings("acme", viewer_result.?.tenant.?);

    // Invalid key returns null
    try std.testing.expect(store.authenticate("wrong-key") == null);
}

test "ApiKeyStore - duplicate key rejected" {
    var store = ApiKeyStore.init(std.testing.allocator);
    defer store.deinit();

    try store.addKey("same-key", .admin, null, "first");
    try std.testing.expectError(error.DuplicateKey, store.addKey("same-key", .viewer, null, "second"));
}

test "ApiKeyStore - duplicate name rejected" {
    var store = ApiKeyStore.init(std.testing.allocator);
    defer store.deinit();

    try store.addKey("key-alpha", .admin, null, "shared-name");
    try std.testing.expectError(error.DuplicateName, store.addKey("key-beta", .viewer, null, "shared-name"));
    // Both keys are different tokens — only the name collides.
    try std.testing.expectEqual(@as(usize, 1), store.count());
}

test "ApiKeyStore - removeByName" {
    var store = ApiKeyStore.init(std.testing.allocator);
    defer store.deinit();

    try store.addKey("key-a", .admin, null, "key-a-name");
    try store.addKey("key-b", .viewer, null, "key-b-name");

    try std.testing.expect(store.removeByName("key-a-name"));
    try std.testing.expectEqual(@as(usize, 1), store.count());
    try std.testing.expect(store.authenticate("key-a") == null);
    try std.testing.expect(store.authenticate("key-b") != null);

    // Remove non-existent
    try std.testing.expect(!store.removeByName("does-not-exist"));
}

test "ApiKeyStore - renderKeysJson" {
    var store = ApiKeyStore.init(std.testing.allocator);
    defer store.deinit();

    // Use long tokens that cannot appear as a substring of any key name/role/tenant
    try store.addKey("rawtoken_aaaaaaaaaaaaaaaaaaaaaaaaaaaa1", .admin, null, "admin-key");
    try store.addKey("rawtoken_bbbbbbbbbbbbbbbbbbbbbbbbbbbb2", .viewer, "acme", "viewer-key");

    const json = try store.renderKeysJson(std.testing.allocator);
    defer std.testing.allocator.free(json);

    // Verify it contains key metadata but not raw keys
    try std.testing.expect(std.mem.indexOf(u8, json, "\"admin-key\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"admin\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"viewer-key\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"acme\"") != null);
    // Raw tokens must NOT appear in output
    try std.testing.expect(std.mem.indexOf(u8, json, "rawtoken_aaaaaaaaaaaaaaaaaaaaaaaaaaaa1") == null);
    try std.testing.expect(std.mem.indexOf(u8, json, "rawtoken_bbbbbbbbbbbbbbbbbbbbbbbbbbbb2") == null);
}

test "hashToken - deterministic" {
    const d1 = hashToken("hello-world");
    const d2 = hashToken("hello-world");
    try std.testing.expectEqualSlices(u8, &d1, &d2);

    const d3 = hashToken("different");
    try std.testing.expect(!std.mem.eql(u8, &d1, &d3));
}

test "constantTimeDigestEql - matching and non-matching" {
    const a = hashToken("test");
    const b = hashToken("test");
    const c = hashToken("other");

    try std.testing.expect(constantTimeDigestEql(&a, &b));
    try std.testing.expect(!constantTimeDigestEql(&a, &c));
}
