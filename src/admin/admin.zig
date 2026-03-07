const std = @import("std");
const http = std.http;
const mem = std.mem;
const versioned_entity_set = @import("../entity/versioned_entity_set.zig");
const VersionedEntitySet = versioned_entity_set.VersionedEntitySet;
const EntitySnapshot = versioned_entity_set.EntitySnapshot;
const http_util = @import("../net/http_util.zig");

// ---------------------------------------------------------------------------
// Admin API — REST endpoints for runtime entity management
// ---------------------------------------------------------------------------
// Intercepts /_admin/entities requests before forwarding to upstream.
// Supports GET (list), POST (add), DELETE (remove), PUT (replace).
// All mutations trigger an RCU snapshot rebuild via VersionedEntitySet.swap().
// ---------------------------------------------------------------------------

/// Configuration for admin API behavior, passed from the main config.
pub const AdminConfig = struct {
    enabled: bool,
    token: ?[]const u8,
    entity_file_sync: bool,
    entity_file: ?[]const u8,
    fuzzy_threshold: f32,
};

/// Check if a request path is an admin route.
pub fn isAdminRoute(path: []const u8) bool {
    return std.mem.eql(u8, path, "/_admin/entities") or
        std.mem.startsWith(u8, path, "/_admin/entities?") or
        std.mem.startsWith(u8, path, "/_admin/entities/");
}

/// Handle an admin API request. Returns true if the request was handled
/// (caller should NOT forward to upstream). Returns false if admin API
/// is disabled and the request should be forwarded normally.
pub fn handleAdminRequest(
    request: *http.Server.Request,
    entity_set: ?*VersionedEntitySet,
    admin_config: AdminConfig,
    allocator: std.mem.Allocator,
) !bool {
    if (!admin_config.enabled) return false;
    if (!isAdminRoute(request.head.target)) return false;

    // Auth check: if token is configured, require Bearer token
    if (admin_config.token) |expected_token| {
        const auth_header = http_util.findHeader(request.head_buffer, "Authorization");
        if (auth_header == null or !validateBearerToken(auth_header.?, expected_token)) {
            try sendJsonResponse(request, .unauthorized, "{\"error\":\"unauthorized\"}");
            return true;
        }
    }

    const method = request.head.method;
    switch (method) {
        .GET => try handleGet(request, entity_set),
        .POST => try handlePost(request, entity_set, admin_config, allocator),
        .DELETE => try handleDelete(request, entity_set, admin_config, allocator),
        .PUT => try handlePut(request, entity_set, admin_config, allocator),
        else => try sendJsonResponse(request, .method_not_allowed, "{\"error\":\"method not allowed\"}"),
    }

    return true;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum request body size for admin API endpoints (1 MB).
/// Prevents memory exhaustion from malicious oversized payloads.
const max_body_size: usize = 1 * 1024 * 1024;

fn validateBearerToken(auth_value: []const u8, expected: []const u8) bool {
    const prefix = "Bearer ";
    if (auth_value.len < prefix.len) return false;
    // Check prefix in constant time to avoid leaking which part failed.
    // The prefix is not secret, but consistency prevents partial oracles.
    if (!mem.startsWith(u8, auth_value, prefix)) return false;
    return constantTimeEql(auth_value[prefix.len..], expected);
}

/// Constant-time byte comparison to prevent timing side-channel attacks.
/// Leaks only the length difference (standard practice — length is not secret
/// for Bearer tokens where the header format is known).
fn constantTimeEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var diff: u8 = 0;
    for (a, b) |x, y| {
        diff |= x ^ y;
    }
    return diff == 0;
}

// ---------------------------------------------------------------------------
// Response helper
// ---------------------------------------------------------------------------

fn sendJsonResponse(
    request: *http.Server.Request,
    status: http.Status,
    body: []const u8,
) !void {
    var buf: [2048]u8 = undefined;
    var response_writer = try request.respondStreaming(&buf, .{
        .respond_options = .{
            .status = status,
            .extra_headers = &.{
                .{ .name = "Content-Type", .value = "application/json" },
            },
        },
    });
    try response_writer.writer.writeAll(body);
    try response_writer.end();
}

// ---------------------------------------------------------------------------
// GET /_admin/entities
// ---------------------------------------------------------------------------

fn handleGet(
    request: *http.Server.Request,
    entity_set: ?*VersionedEntitySet,
) !void {
    if (entity_set == null) {
        try sendJsonResponse(request, .ok, "{\"version\":0,\"count\":0,\"entities\":[]}");
        return;
    }
    const es = entity_set.?;
    const snapshot = es.acquire();
    defer es.release(snapshot);

    // Build JSON response
    // Pre-calculate size: {"version":N,"count":N,"entities":["name","name",...]}
    var json_buf: std.ArrayListUnmanaged(u8) = .empty;
    defer json_buf.deinit(snapshot.allocator);

    try json_buf.appendSlice(snapshot.allocator, "{\"version\":");
    var version_buf: [16]u8 = undefined;
    const version_str = std.fmt.bufPrint(&version_buf, "{d}", .{snapshot.version}) catch unreachable;
    try json_buf.appendSlice(snapshot.allocator, version_str);

    try json_buf.appendSlice(snapshot.allocator, ",\"count\":");
    var count_buf: [16]u8 = undefined;
    const count_str = std.fmt.bufPrint(&count_buf, "{d}", .{snapshot.loaded_names.len}) catch unreachable;
    try json_buf.appendSlice(snapshot.allocator, count_str);

    try json_buf.appendSlice(snapshot.allocator, ",\"entities\":[");
    for (snapshot.loaded_names, 0..) |name, i| {
        if (i > 0) try json_buf.append(snapshot.allocator, ',');
        try json_buf.append(snapshot.allocator, '"');
        // Escape JSON string characters
        for (name) |c| {
            switch (c) {
                '"' => try json_buf.appendSlice(snapshot.allocator, "\\\""),
                '\\' => try json_buf.appendSlice(snapshot.allocator, "\\\\"),
                '\n' => try json_buf.appendSlice(snapshot.allocator, "\\n"),
                '\r' => try json_buf.appendSlice(snapshot.allocator, "\\r"),
                '\t' => try json_buf.appendSlice(snapshot.allocator, "\\t"),
                else => {
                    // Escape all C0 control characters per RFC 8259 §7
                    if (c < 0x20) {
                        var esc_buf: [6]u8 = undefined;
                        _ = std.fmt.bufPrint(&esc_buf, "\\u{X:0>4}", .{c}) catch unreachable;
                        try json_buf.appendSlice(snapshot.allocator, &esc_buf);
                    } else {
                        try json_buf.append(snapshot.allocator, c);
                    }
                },
            }
        }
        try json_buf.append(snapshot.allocator, '"');
    }
    try json_buf.appendSlice(snapshot.allocator, "]}");

    try sendJsonResponse(request, .ok, json_buf.items);
}

// ---------------------------------------------------------------------------
// POST /_admin/entities  (add entities)
// ---------------------------------------------------------------------------

fn handlePost(
    request: *http.Server.Request,
    entity_set: ?*VersionedEntitySet,
    admin_config: AdminConfig,
    allocator: std.mem.Allocator,
) !void {
    const body = try readRequestBody(request, allocator);
    defer allocator.free(body);

    const new_names = parseJsonStringArray(body, "add", allocator) catch {
        try sendJsonResponse(request, .bad_request, "{\"error\":\"invalid JSON, expected {\\\"add\\\":[...]}\"}");
        return;
    };
    defer {
        for (new_names) |n| allocator.free(n);
        allocator.free(new_names);
    }

    if (new_names.len == 0) {
        try sendJsonResponse(request, .bad_request, "{\"error\":\"empty add list\"}");
        return;
    }

    // Merge with existing names (deduplicate via HashMap for O(1) lookups)
    const es = entity_set orelse {
        try sendJsonResponse(request, .internal_server_error, "{\"error\":\"internal error\"}");
        return;
    };

    const current_snap = es.acquire();
    defer es.release(current_snap);

    // Build a set of lowercased existing names for O(1) dedup checks.
    // The hashmap owns all key allocations — freed in the defer below.
    var seen = std.StringHashMap(void).init(allocator);
    defer {
        var it = seen.iterator();
        while (it.next()) |entry| allocator.free(entry.key_ptr.*);
        seen.deinit();
    }

    var merged: std.ArrayListUnmanaged([]const u8) = .empty;
    defer merged.deinit(allocator);

    for (current_snap.loaded_names) |name| {
        const lower = try std.ascii.allocLowerString(allocator, name);
        try seen.put(lower, {}); // hashmap owns 'lower'
        try merged.append(allocator, name);
    }

    for (new_names) |new_name| {
        const lower = try std.ascii.allocLowerString(allocator, new_name);
        if (!seen.contains(lower)) {
            try seen.put(lower, {}); // hashmap owns 'lower'
            try merged.append(allocator, new_name);
        } else {
            allocator.free(lower); // not inserted — free immediately
        }
    }

    try rebuildAndSwap(es, merged.items, admin_config, allocator);
    try sendJsonResponse(request, .ok, "{\"status\":\"ok\"}");
}

// ---------------------------------------------------------------------------
// DELETE /_admin/entities  (remove entities)
// ---------------------------------------------------------------------------

fn handleDelete(
    request: *http.Server.Request,
    entity_set: ?*VersionedEntitySet,
    admin_config: AdminConfig,
    allocator: std.mem.Allocator,
) !void {
    const body = try readRequestBody(request, allocator);
    defer allocator.free(body);

    const remove_names = parseJsonStringArray(body, "remove", allocator) catch {
        try sendJsonResponse(request, .bad_request, "{\"error\":\"invalid JSON, expected {\\\"remove\\\":[...]}\"}");
        return;
    };
    defer {
        for (remove_names) |n| allocator.free(n);
        allocator.free(remove_names);
    }

    if (remove_names.len == 0) {
        try sendJsonResponse(request, .bad_request, "{\"error\":\"empty remove list\"}");
        return;
    }

    const es = entity_set orelse {
        try sendJsonResponse(request, .internal_server_error, "{\"error\":\"internal error\"}");
        return;
    };

    const current_snap = es.acquire();
    defer es.release(current_snap);

    // Build a set of names to remove for O(1) lookup
    var remove_set = std.StringHashMap(void).init(allocator);
    defer {
        var it = remove_set.iterator();
        while (it.next()) |entry| allocator.free(entry.key_ptr.*);
        remove_set.deinit();
    }
    for (remove_names) |remove| {
        const lower = try std.ascii.allocLowerString(allocator, remove);
        try remove_set.put(lower, {});
    }

    var kept: std.ArrayListUnmanaged([]const u8) = .empty;
    defer kept.deinit(allocator);

    for (current_snap.loaded_names) |name| {
        const lower = try std.ascii.allocLowerString(allocator, name);
        defer allocator.free(lower);
        if (!remove_set.contains(lower)) {
            try kept.append(allocator, name);
        }
    }

    try rebuildAndSwap(es, kept.items, admin_config, allocator);
    try sendJsonResponse(request, .ok, "{\"status\":\"ok\"}");
}

// ---------------------------------------------------------------------------
// PUT /_admin/entities  (replace all entities)
// ---------------------------------------------------------------------------

fn handlePut(
    request: *http.Server.Request,
    entity_set: ?*VersionedEntitySet,
    admin_config: AdminConfig,
    allocator: std.mem.Allocator,
) !void {
    const body = try readRequestBody(request, allocator);
    defer allocator.free(body);

    const new_names = parseJsonStringArray(body, "entities", allocator) catch {
        try sendJsonResponse(request, .bad_request, "{\"error\":\"invalid JSON, expected {\\\"entities\\\":[...]}\"}");
        return;
    };
    defer {
        for (new_names) |n| allocator.free(n);
        allocator.free(new_names);
    }

    const es = entity_set orelse {
        try sendJsonResponse(request, .internal_server_error, "{\"error\":\"internal error\"}");
        return;
    };

    try rebuildAndSwap(es, new_names, admin_config, allocator);
    try sendJsonResponse(request, .ok, "{\"status\":\"ok\"}");
}

// ---------------------------------------------------------------------------
// Shared: rebuild snapshot and atomically swap
// ---------------------------------------------------------------------------

fn rebuildAndSwap(
    entity_set: *VersionedEntitySet,
    names: []const []const u8,
    admin_config: AdminConfig,
    allocator: std.mem.Allocator,
) !void {
    // Atomically claim the next version to avoid races between
    // concurrent admin API mutations on different handler threads.
    const new_version = entity_set.nextVersion();
    const old_version = new_version - 1;

    std.debug.print("[ADMIN] Entity rebuild started (v{} → v{}, {} entities)\n", .{
        old_version,
        new_version,
        names.len,
    });

    const new_snapshot = try versioned_entity_set.loadSnapshotFromNames(
        names,
        admin_config.fuzzy_threshold,
        new_version,
        allocator,
    );

    entity_set.swap(new_snapshot);

    std.debug.print("[ADMIN] Entity rebuild complete (v{}, {} entities)\n", .{
        new_version,
        names.len,
    });

    // Optionally sync to entity file
    if (admin_config.entity_file_sync) {
        if (admin_config.entity_file) |path| {
            syncToFile(path, names, allocator) catch |err| {
                std.debug.print("[ADMIN] WARNING: Failed to sync entity file '{s}': {s}\n", .{
                    path,
                    @errorName(err),
                });
            };
        }
    }
}

/// Write the current entity list back to the entity file (one name per line).
/// Uses atomic write (temp file + rename) to prevent the file watcher from
/// reading a partially-written file during sync.
fn syncToFile(path: []const u8, names: []const []const u8, allocator: mem.Allocator) !void {
    // Build temp path: "{path}.tmp"
    const tmp_path = try allocator.alloc(u8, path.len + 4);
    defer allocator.free(tmp_path);
    @memcpy(tmp_path[0..path.len], path);
    @memcpy(tmp_path[path.len..], ".tmp");

    // Write to temp file
    var file = try std.fs.cwd().createFile(tmp_path, .{});
    errdefer {
        file.close();
        std.fs.cwd().deleteFile(tmp_path) catch {};
    }

    for (names) |name| {
        try file.writeAll(name);
        try file.writeAll("\n");
    }
    file.close();

    // Atomic rename over the real file
    try std.fs.cwd().rename(tmp_path, path);
}

// ---------------------------------------------------------------------------
// Request body reader
// ---------------------------------------------------------------------------

fn readRequestBody(
    request: *http.Server.Request,
    allocator: std.mem.Allocator,
) ![]u8 {
    var body: std.ArrayListUnmanaged(u8) = .empty;
    errdefer body.deinit(allocator);

    var body_read_buf: [8192]u8 = undefined;
    if (request.readerExpectContinue(&body_read_buf)) |body_reader| {
        var chunk_buf: [4096]u8 = undefined;
        while (true) {
            const bytes_read = try body_reader.readSliceShort(&chunk_buf);
            if (bytes_read == 0) break;
            if (body.items.len + bytes_read > max_body_size) {
                return error.PayloadTooLarge;
            }
            try body.appendSlice(allocator, chunk_buf[0..bytes_read]);
        }
    } else |err| {
        std.debug.print("[ADMIN] Failed to read request body: {s}\n", .{@errorName(err)});
        return err;
    }

    return try body.toOwnedSlice(allocator);
}

// ---------------------------------------------------------------------------
// Minimal JSON parser — extract a string array from a known key
// ---------------------------------------------------------------------------
// Handles: {"key": ["value1", "value2"]}
// No external dependencies. Handles escaped quotes within strings.

/// Parse a JSON object and extract a string array for the given key.
/// Returns owned copies of each string — caller must free.
pub fn parseJsonStringArray(
    json: []const u8,
    key: []const u8,
    allocator: std.mem.Allocator,
) ![][]const u8 {
    // Find the key in the JSON
    const array_start = findArrayForKey(json, key) orelse return error.KeyNotFound;

    // Parse the array contents
    var results: std.ArrayListUnmanaged([]const u8) = .empty;
    errdefer {
        for (results.items) |s| allocator.free(s);
        results.deinit(allocator);
    }

    var i = array_start;
    while (i < json.len) {
        // Skip whitespace and commas
        while (i < json.len and (json[i] == ' ' or json[i] == '\t' or json[i] == '\n' or json[i] == '\r' or json[i] == ',')) : (i += 1) {}

        if (i >= json.len) break;
        if (json[i] == ']') break;

        // Expect a quoted string
        if (json[i] != '"') return error.InvalidJson;
        i += 1; // skip opening quote

        const str_start = i;
        var str_end = i;
        while (str_end < json.len and json[str_end] != '"') {
            if (json[str_end] == '\\' and str_end + 1 < json.len) {
                str_end += 2; // skip escaped character
            } else {
                str_end += 1;
            }
        }
        if (str_end >= json.len) return error.InvalidJson;

        // Unescape the string value
        const raw = json[str_start..str_end];
        const unescaped = try unescapeJsonString(raw, allocator);
        try results.append(allocator, unescaped);

        i = str_end + 1; // skip closing quote
    }

    return try results.toOwnedSlice(allocator);
}

/// Find the position of the '[' that starts the array value for the given key.
fn findArrayForKey(json: []const u8, key: []const u8) ?usize {
    // Search for "key" then :, then [
    var i: usize = 0;
    while (i < json.len) {
        // Look for a quote
        if (json[i] == '"') {
            i += 1;
            const key_start = i;
            while (i < json.len and json[i] != '"') : (i += 1) {}
            if (i >= json.len) return null;
            const found_key = json[key_start..i];
            i += 1; // skip closing quote

            if (std.mem.eql(u8, found_key, key)) {
                // Skip whitespace and colon
                while (i < json.len and (json[i] == ' ' or json[i] == '\t' or json[i] == ':')) : (i += 1) {}
                if (i < json.len and json[i] == '[') {
                    return i + 1; // position after '['
                }
            }
        } else {
            i += 1;
        }
    }
    return null;
}

/// Unescape a JSON string value (handles \", \\, \n, \r, \t).
fn unescapeJsonString(raw: []const u8, allocator: std.mem.Allocator) ![]const u8 {
    var result: std.ArrayListUnmanaged(u8) = .empty;
    errdefer result.deinit(allocator);

    var i: usize = 0;
    while (i < raw.len) {
        if (raw[i] == '\\' and i + 1 < raw.len) {
            switch (raw[i + 1]) {
                '"' => try result.append(allocator, '"'),
                '\\' => try result.append(allocator, '\\'),
                'n' => try result.append(allocator, '\n'),
                'r' => try result.append(allocator, '\r'),
                't' => try result.append(allocator, '\t'),
                else => {
                    try result.append(allocator, raw[i]);
                    try result.append(allocator, raw[i + 1]);
                },
            }
            i += 2;
        } else {
            try result.append(allocator, raw[i]);
            i += 1;
        }
    }
    return try result.toOwnedSlice(allocator);
}

// ===========================================================================
// Unit Tests
// ===========================================================================

test "isAdminRoute - matching paths" {
    try std.testing.expect(isAdminRoute("/_admin/entities"));
    try std.testing.expect(isAdminRoute("/_admin/entities/"));
    try std.testing.expect(isAdminRoute("/_admin/entities?foo=bar"));
}

test "isAdminRoute - non-matching paths" {
    try std.testing.expect(!isAdminRoute("/admin/entities"));
    try std.testing.expect(!isAdminRoute("/_admin"));
    try std.testing.expect(!isAdminRoute("/post"));
    try std.testing.expect(!isAdminRoute("/"));
}

test "parseJsonStringArray - valid add array" {
    const allocator = std.testing.allocator;
    const json = "{\"add\": [\"Alice\", \"Bob\", \"Charlie\"]}";

    const result = try parseJsonStringArray(json, "add", allocator);
    defer {
        for (result) |s| allocator.free(s);
        allocator.free(result);
    }

    try std.testing.expectEqual(@as(usize, 3), result.len);
    try std.testing.expectEqualStrings("Alice", result[0]);
    try std.testing.expectEqualStrings("Bob", result[1]);
    try std.testing.expectEqualStrings("Charlie", result[2]);
}

test "parseJsonStringArray - valid entities array" {
    const allocator = std.testing.allocator;
    const json = "{\"entities\": [\"Jane Smith\", \"John Doe\"]}";

    const result = try parseJsonStringArray(json, "entities", allocator);
    defer {
        for (result) |s| allocator.free(s);
        allocator.free(result);
    }

    try std.testing.expectEqual(@as(usize, 2), result.len);
    try std.testing.expectEqualStrings("Jane Smith", result[0]);
    try std.testing.expectEqualStrings("John Doe", result[1]);
}

test "parseJsonStringArray - empty array" {
    const allocator = std.testing.allocator;
    const json = "{\"add\": []}";

    const result = try parseJsonStringArray(json, "add", allocator);
    defer allocator.free(result);

    try std.testing.expectEqual(@as(usize, 0), result.len);
}

test "parseJsonStringArray - escaped strings" {
    const allocator = std.testing.allocator;
    const json = "{\"add\": [\"O\\\"Brien\", \"back\\\\slash\"]}";

    const result = try parseJsonStringArray(json, "add", allocator);
    defer {
        for (result) |s| allocator.free(s);
        allocator.free(result);
    }

    try std.testing.expectEqual(@as(usize, 2), result.len);
    try std.testing.expectEqualStrings("O\"Brien", result[0]);
    try std.testing.expectEqualStrings("back\\slash", result[1]);
}

test "parseJsonStringArray - key not found" {
    const allocator = std.testing.allocator;
    const json = "{\"entities\": [\"Alice\"]}";

    const result = parseJsonStringArray(json, "add", allocator);
    try std.testing.expectError(error.KeyNotFound, result);
}

test "parseJsonStringArray - invalid json (no quotes)" {
    const allocator = std.testing.allocator;
    const json = "{\"add\": [hello]}";

    const result = parseJsonStringArray(json, "add", allocator);
    try std.testing.expectError(error.InvalidJson, result);
}

test "validateBearerToken - valid token" {
    try std.testing.expect(validateBearerToken("Bearer mysecret", "mysecret"));
}

test "validateBearerToken - wrong token" {
    try std.testing.expect(!validateBearerToken("Bearer wrong", "mysecret"));
}

test "validateBearerToken - missing Bearer prefix" {
    try std.testing.expect(!validateBearerToken("mysecret", "mysecret"));
}

test "validateBearerToken - empty auth value" {
    try std.testing.expect(!validateBearerToken("", "mysecret"));
}
