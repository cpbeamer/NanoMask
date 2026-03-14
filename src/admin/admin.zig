const std = @import("std");
const builtin = @import("builtin");
const http = std.http;
const mem = std.mem;
const versioned_entity_set = @import("../entity/versioned_entity_set.zig");
const VersionedEntitySet = versioned_entity_set.VersionedEntitySet;
const EntitySnapshot = versioned_entity_set.EntitySnapshot;
const http_util = @import("../net/http_util.zig");
const logger_mod = @import("../infra/logger.zig");
const Logger = logger_mod.Logger;

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
    allowlist: ?*const IpAllowlist = null,
    read_only: bool = false,
    mutation_rate_limit_per_minute: u32 = 60,
    state: ?*AdminState = null,
    logger: ?*Logger = null,
    entity_file_sync: bool,
    entity_file: ?[]const u8,
    fuzzy_threshold: f32,
};

pub const ListenerMode = enum {
    combined,
    proxy_only,
    admin_only,
};

pub const AdminState = struct {
    mutation_limiter: MutationRateLimiter = .{},
};

pub const MutationRateLimiter = struct {
    mutex: std.Thread.Mutex = .{},
    window_start_ms: i64 = 0,
    mutations_in_window: u32 = 0,

    pub fn allow(self: *MutationRateLimiter, limit_per_minute: u32) bool {
        if (limit_per_minute == 0) return true;

        const now_ms = std.time.milliTimestamp();
        self.mutex.lock();
        defer self.mutex.unlock();

        if (self.window_start_ms == 0 or now_ms - self.window_start_ms >= 60_000) {
            self.window_start_ms = now_ms;
            self.mutations_in_window = 0;
        }

        if (self.mutations_in_window >= limit_per_minute) return false;
        self.mutations_in_window += 1;
        return true;
    }
};

pub const IpAllowlist = struct {
    entries: []std.net.Address,
    allocator: std.mem.Allocator,

    pub fn initFromCsv(csv: []const u8, allocator: std.mem.Allocator) !IpAllowlist {
        var list: std.ArrayListUnmanaged(std.net.Address) = .empty;
        errdefer list.deinit(allocator);

        var it = std.mem.splitScalar(u8, csv, ',');
        while (it.next()) |entry| {
            const trimmed = std.mem.trim(u8, entry, " \t");
            if (trimmed.len == 0) continue;
            try list.append(allocator, try std.net.Address.parseIp(trimmed, 0));
        }

        if (list.items.len == 0) return error.InvalidAllowlist;

        return .{
            .entries = try list.toOwnedSlice(allocator),
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *IpAllowlist) void {
        self.allocator.free(self.entries);
        self.* = undefined;
    }

    pub fn allows(self: *const IpAllowlist, client_address: std.net.Address) bool {
        for (self.entries) |entry| {
            if (ipOnlyEqual(entry, client_address)) return true;
        }
        return false;
    }
};

/// Check if a request path is an admin route.
pub fn isAdminRoute(path: []const u8) bool {
    return std.mem.eql(u8, path, "/_admin/entities") or
        std.mem.startsWith(u8, path, "/_admin/entities?") or
        std.mem.startsWith(u8, path, "/_admin/entities/") or
        std.mem.eql(u8, path, "/_admin/evaluation-report") or
        std.mem.eql(u8, path, "/_admin/evaluation-report/reset");
}

/// Handle an admin API request. Returns true if the request was handled
/// (caller should NOT forward to upstream). Returns false if admin API
/// is disabled and the request should be forwarded normally.
pub fn handleAdminRequest(
    request: *http.Server.Request,
    entity_set: ?*VersionedEntitySet,
    admin_config: AdminConfig,
    client_address: std.net.Address,
    session_id: []const u8,
    allocator: std.mem.Allocator,
) !?http.Status {
    if (!admin_config.enabled) return null;
    if (!isAdminRoute(request.head.target)) return null;

    if (admin_config.allowlist) |allowlist| {
        if (!allowlist.allows(client_address)) {
            logAdminRequestDenied(admin_config, session_id, client_address, "allowlist_denied");
            try sendJsonResponse(request, .forbidden, "{\"error\":\"forbidden\"}");
            return .forbidden;
        }
    }

    // Auth check: if token is configured, require Bearer token
    if (admin_config.token) |expected_token| {
        const auth_header = http_util.findHeader(request.head_buffer, "Authorization");
        if (auth_header == null or !validateBearerToken(auth_header.?, expected_token)) {
            logAdminRequestDenied(admin_config, session_id, client_address, "unauthorized");
            try sendJsonResponse(request, .unauthorized, "{\"error\":\"unauthorized\"}");
            return .unauthorized;
        }
    }

    const method = request.head.method;
    if (isMutationMethod(method)) {
        if (admin_config.read_only) {
            logAdminRequestDenied(admin_config, session_id, client_address, "read_only");
            try sendJsonResponse(request, .forbidden, "{\"error\":\"admin API is read-only\"}");
            return .forbidden;
        }
        if (admin_config.state) |state| {
            if (!state.mutation_limiter.allow(admin_config.mutation_rate_limit_per_minute)) {
                logAdminRequestDenied(admin_config, session_id, client_address, "rate_limited");
                try sendJsonResponse(request, .too_many_requests, "{\"error\":\"admin mutation rate limit exceeded\"}");
                return .too_many_requests;
            }
        }
    }

    return switch (method) {
        .GET => try handleGet(request, entity_set),
        .POST => try handlePost(request, entity_set, admin_config, session_id, allocator),
        .DELETE => try handleDelete(request, entity_set, admin_config, session_id, allocator),
        .PUT => try handlePut(request, entity_set, admin_config, session_id, allocator),
        else => blk: {
            try sendJsonResponse(request, .method_not_allowed, "{\"error\":\"method not allowed\"}");
            break :blk .method_not_allowed;
        },
    };
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum request body size for admin API endpoints (1 MB).
/// Prevents memory exhaustion from malicious oversized payloads.
const max_body_size: usize = 1 * 1024 * 1024;

const RebuildResult = struct {
    version: u32,
    entity_count_after: usize,
};

pub fn validateBearerToken(auth_value: []const u8, expected: []const u8) bool {
    const prefix = "Bearer ";
    if (auth_value.len < prefix.len) return false;
    // Check prefix in constant time to avoid leaking which part failed.
    // The prefix is not secret, but consistency prevents partial oracles.
    if (!mem.startsWith(u8, auth_value, prefix)) return false;
    return constantTimeEql(auth_value[prefix.len..], expected);
}

fn ipOnlyEqual(a: std.net.Address, b: std.net.Address) bool {
    if (a.any.family != b.any.family) return false;
    return switch (a.any.family) {
        std.posix.AF.INET => {
            const a_bytes: *const [4]u8 = @ptrCast(&a.in.sa.addr);
            const b_bytes: *const [4]u8 = @ptrCast(&b.in.sa.addr);
            return std.mem.eql(u8, a_bytes, b_bytes);
        },
        std.posix.AF.INET6 => std.mem.eql(u8, a.in6.sa.addr[0..], b.in6.sa.addr[0..]),
        else => false,
    };
}

fn isMutationMethod(method: http.Method) bool {
    return method == .POST or method == .PUT or method == .DELETE;
}

fn logAdminRequestDenied(
    admin_config: AdminConfig,
    session_id: []const u8,
    client_address: std.net.Address,
    reason: []const u8,
) void {
    const logger = admin_config.logger orelse return;
    _ = client_address;
    logger.log(.warn, "admin_request_denied", session_id, &.{
        .{ .key = "reason", .value = .{ .string = reason } },
    });
}

fn emitAdminAudit(
    admin_config: AdminConfig,
    session_id: ?[]const u8,
    event: Logger.AdminAuditEvent,
) void {
    const logger = admin_config.logger orelse return;
    logger.auditAdmin(session_id, event);
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
) !http.Status {
    if (entity_set == null) {
        try sendJsonResponse(request, .ok, "{\"version\":0,\"count\":0,\"entities\":[]}");
        return .ok;
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
    return .ok;
}

// ---------------------------------------------------------------------------
// POST /_admin/entities  (add entities)
// ---------------------------------------------------------------------------

fn handlePost(
    request: *http.Server.Request,
    entity_set: ?*VersionedEntitySet,
    admin_config: AdminConfig,
    session_id: []const u8,
    allocator: std.mem.Allocator,
) !http.Status {
    const body = readRequestBody(request, allocator, admin_config.logger) catch |err| switch (err) {
        error.PayloadTooLarge => {
            try sendJsonResponse(request, .payload_too_large, "{\"error\":\"admin request body too large\"}");
            return .payload_too_large;
        },
        else => return err,
    };
    defer allocator.free(body);

    const new_names = parseJsonStringArray(body, "add", allocator) catch {
        try sendJsonResponse(request, .bad_request, "{\"error\":\"invalid JSON, expected {\\\"add\\\":[...]}\"}");
        return .bad_request;
    };
    defer {
        for (new_names) |n| allocator.free(n);
        allocator.free(new_names);
    }

    if (new_names.len == 0) {
        try sendJsonResponse(request, .bad_request, "{\"error\":\"empty add list\"}");
        return .bad_request;
    }

    // Merge with existing names (deduplicate via HashMap for O(1) lookups)
    const es = entity_set orelse {
        try sendJsonResponse(request, .internal_server_error, "{\"error\":\"internal error\"}");
        return .internal_server_error;
    };

    const current_snap = es.acquire();
    defer es.release(current_snap);
    const before_count = current_snap.loaded_names.len;

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

    const result = try rebuildAndSwap(es, merged.items, admin_config, allocator);
    emitAdminAudit(admin_config, session_id, .{
        .action = "entity_add",
        .source = "api",
        .result = "applied",
        .version = result.version,
        .entity_count_before = before_count,
        .entity_count_after = result.entity_count_after,
        .delta_count = @as(i64, @intCast(result.entity_count_after)) - @as(i64, @intCast(before_count)),
    });
    try sendJsonResponse(request, .ok, "{\"status\":\"ok\"}");
    return .ok;
}

// ---------------------------------------------------------------------------
// DELETE /_admin/entities  (remove entities)
// ---------------------------------------------------------------------------

fn handleDelete(
    request: *http.Server.Request,
    entity_set: ?*VersionedEntitySet,
    admin_config: AdminConfig,
    session_id: []const u8,
    allocator: std.mem.Allocator,
) !http.Status {
    const body = readRequestBody(request, allocator, admin_config.logger) catch |err| switch (err) {
        error.PayloadTooLarge => {
            try sendJsonResponse(request, .payload_too_large, "{\"error\":\"admin request body too large\"}");
            return .payload_too_large;
        },
        else => return err,
    };
    defer allocator.free(body);

    const remove_names = parseJsonStringArray(body, "remove", allocator) catch {
        try sendJsonResponse(request, .bad_request, "{\"error\":\"invalid JSON, expected {\\\"remove\\\":[...]}\"}");
        return .bad_request;
    };
    defer {
        for (remove_names) |n| allocator.free(n);
        allocator.free(remove_names);
    }

    if (remove_names.len == 0) {
        try sendJsonResponse(request, .bad_request, "{\"error\":\"empty remove list\"}");
        return .bad_request;
    }

    const es = entity_set orelse {
        try sendJsonResponse(request, .internal_server_error, "{\"error\":\"internal error\"}");
        return .internal_server_error;
    };

    const current_snap = es.acquire();
    defer es.release(current_snap);
    const before_count = current_snap.loaded_names.len;

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

    const result = try rebuildAndSwap(es, kept.items, admin_config, allocator);
    emitAdminAudit(admin_config, session_id, .{
        .action = "entity_remove",
        .source = "api",
        .result = "applied",
        .version = result.version,
        .entity_count_before = before_count,
        .entity_count_after = result.entity_count_after,
        .delta_count = @as(i64, @intCast(result.entity_count_after)) - @as(i64, @intCast(before_count)),
    });
    try sendJsonResponse(request, .ok, "{\"status\":\"ok\"}");
    return .ok;
}

// ---------------------------------------------------------------------------
// PUT /_admin/entities  (replace all entities)
// ---------------------------------------------------------------------------

fn handlePut(
    request: *http.Server.Request,
    entity_set: ?*VersionedEntitySet,
    admin_config: AdminConfig,
    session_id: []const u8,
    allocator: std.mem.Allocator,
) !http.Status {
    const body = readRequestBody(request, allocator, admin_config.logger) catch |err| switch (err) {
        error.PayloadTooLarge => {
            try sendJsonResponse(request, .payload_too_large, "{\"error\":\"admin request body too large\"}");
            return .payload_too_large;
        },
        else => return err,
    };
    defer allocator.free(body);

    const new_names = parseJsonStringArray(body, "entities", allocator) catch {
        try sendJsonResponse(request, .bad_request, "{\"error\":\"invalid JSON, expected {\\\"entities\\\":[...]}\"}");
        return .bad_request;
    };
    defer {
        for (new_names) |n| allocator.free(n);
        allocator.free(new_names);
    }

    const es = entity_set orelse {
        try sendJsonResponse(request, .internal_server_error, "{\"error\":\"internal error\"}");
        return .internal_server_error;
    };

    const current_snap = es.acquire();
    defer es.release(current_snap);
    const before_count = current_snap.loaded_names.len;

    const result = try rebuildAndSwap(es, new_names, admin_config, allocator);
    emitAdminAudit(admin_config, session_id, .{
        .action = "entity_replace",
        .source = "api",
        .result = "applied",
        .version = result.version,
        .entity_count_before = before_count,
        .entity_count_after = result.entity_count_after,
        .delta_count = @as(i64, @intCast(result.entity_count_after)) - @as(i64, @intCast(before_count)),
    });
    try sendJsonResponse(request, .ok, "{\"status\":\"ok\"}");
    return .ok;
}

// ---------------------------------------------------------------------------
// Shared: rebuild snapshot and atomically swap
// ---------------------------------------------------------------------------

fn rebuildAndSwap(
    entity_set: *VersionedEntitySet,
    names: []const []const u8,
    admin_config: AdminConfig,
    allocator: std.mem.Allocator,
) !RebuildResult {
    const logger = admin_config.logger;
    // Atomically claim the next version to avoid races between
    // concurrent admin API mutations on different handler threads.
    const new_version = entity_set.nextVersion();
    const old_version = new_version - 1;

    if (logger) |log| {
        log.log(.info, "entity_rebuild_started", null, &.{
            .{ .key = "old_version", .value = .{ .uint = old_version } },
            .{ .key = "new_version", .value = .{ .uint = new_version } },
            .{ .key = "entity_count", .value = .{ .uint = names.len } },
        });
    }

    const new_snapshot = try versioned_entity_set.loadSnapshotFromNames(
        names,
        admin_config.fuzzy_threshold,
        new_version,
        allocator,
    );

    entity_set.swap(new_snapshot);

    if (logger) |log| {
        log.log(.info, "entity_rebuild_complete", null, &.{
            .{ .key = "version", .value = .{ .uint = new_version } },
            .{ .key = "entity_count", .value = .{ .uint = names.len } },
        });
    }

    // Optionally sync to entity file
    if (admin_config.entity_file_sync) {
        if (admin_config.entity_file) |path| {
            syncToFile(path, names, allocator) catch |err| {
                if (logger) |log| {
                    log.log(.warn, "entity_file_sync_failed", null, &.{
                        .{ .key = "path", .value = .{ .string = path } },
                        .{ .key = "error", .value = .{ .string = @errorName(err) } },
                    });
                }
            };
        }
    }

    return .{
        .version = new_version,
        .entity_count_after = names.len,
    };
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

    // Atomic rename over the real file.
    // On Windows, rename can fail with AccessDenied if the file watcher
    // has the destination open for stat/read. Retry with short backoff.
    const max_rename_retries: u8 = if (builtin.os.tag == .windows) 3 else 0;
    var rename_attempt: u8 = 0;
    while (true) {
        std.fs.cwd().rename(tmp_path, path) catch |err| {
            if (err == error.AccessDenied and rename_attempt < max_rename_retries) {
                rename_attempt += 1;
                std.Thread.sleep(50 * std.time.ns_per_ms);
                continue;
            }
            return err;
        };
        break;
    }
}

// ---------------------------------------------------------------------------
// Request body reader
// ---------------------------------------------------------------------------

fn readRequestBody(
    request: *http.Server.Request,
    allocator: std.mem.Allocator,
    logger: ?*Logger,
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
        if (logger) |log| {
            log.log(.warn, "admin_body_read_failed", null, &.{
                .{ .key = "error", .value = .{ .string = @errorName(err) } },
            });
        }
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

test "IpAllowlist - exact IPv4 and IPv6 matches are allowed" {
    var allowlist = try IpAllowlist.initFromCsv("127.0.0.1,::1", std.testing.allocator);
    defer allowlist.deinit();

    try std.testing.expect(allowlist.allows(try std.net.Address.parseIp("127.0.0.1", 4321)));
    try std.testing.expect(allowlist.allows(try std.net.Address.parseIp("::1", 4321)));
    try std.testing.expect(!allowlist.allows(try std.net.Address.parseIp("10.0.0.5", 4321)));
}

test "MutationRateLimiter - enforces configured window cap" {
    var limiter = MutationRateLimiter{};

    try std.testing.expect(limiter.allow(2));
    try std.testing.expect(limiter.allow(2));
    try std.testing.expect(!limiter.allow(2));
    try std.testing.expect(limiter.allow(0));
}
