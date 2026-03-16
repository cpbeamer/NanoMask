const std = @import("std");
const hasher_mod = @import("../schema/hasher.zig");

// ---------------------------------------------------------------------------
// KeyManager — Enterprise key management with rotation support
// ---------------------------------------------------------------------------
// Wraps the Hasher to support key rotation with a grace period. When a new
// key is rotated in, the previous key is retained so that data hashed with
// the old key can still be verified during the transition window.
//
// Supports three key sources:
//   - inline: raw hex key string (existing --hash-key)
//   - file:   key loaded from file (existing --hash-key-file)
//   - exec:   key fetched by running a shell command (--hash-key-exec)
// ---------------------------------------------------------------------------

pub const KeySource = enum {
    inline_hex,
    file,
    exec,

    pub fn label(self: KeySource) []const u8 {
        return switch (self) {
            .inline_hex => "inline",
            .file => "file",
            .exec => "exec",
        };
    }
};

pub const KeyManager = struct {
    /// Currently active key (hex string, 64 chars).
    current_key: [64]u8,
    /// Previous key for rotation grace period. All zeros when no previous key.
    previous_key: [64]u8,
    has_previous: bool,
    source: KeySource,
    /// Path to key file (when source == .file), for watch-based rotation.
    key_file_path: ?[]const u8,
    /// Shell command (when source == .exec).
    key_exec_cmd: ?[]const u8,
    mutex: std.Thread.Mutex,

    pub fn init(key_hex: []const u8, source: KeySource) !KeyManager {
        if (key_hex.len != 64) return error.InvalidKeyLength;
        var mgr = KeyManager{
            .current_key = undefined,
            .previous_key = undefined,
            .has_previous = false,
            .source = source,
            .key_file_path = null,
            .key_exec_cmd = null,
            .mutex = .{},
        };
        @memcpy(&mgr.current_key, key_hex);
        @memset(&mgr.previous_key, 0);
        return mgr;
    }

    pub fn initFromFile(path: []const u8, allocator: std.mem.Allocator) !KeyManager {
        const key_hex = try readKeyFromFile(path, allocator);
        defer allocator.free(key_hex);
        var mgr = try init(key_hex, .file);
        mgr.key_file_path = path;
        return mgr;
    }

    /// Rotate the key: current becomes previous, new_key becomes current.
    pub fn rotate(self: *KeyManager, new_key_hex: []const u8) !void {
        if (new_key_hex.len != 64) return error.InvalidKeyLength;

        self.mutex.lock();
        defer self.mutex.unlock();

        @memcpy(&self.previous_key, &self.current_key);
        @memcpy(&self.current_key, new_key_hex);
        self.has_previous = true;
    }

    /// Get the current key as a hex array (value copy taken under the lock).
    /// Returns a [64]u8 by value so the caller holds a safe snapshot even
    /// after a concurrent rotate().
    pub fn currentKeyHex(self: *KeyManager) [64]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.current_key;
    }

    /// Get the previous key hex if available (for grace-period verification).
    /// Returns a [64]u8 value copy taken under the lock, or null when no
    /// previous key exists.
    pub fn previousKeyHex(self: *KeyManager) ?[64]u8 {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (!self.has_previous) return null;
        return self.previous_key;
    }

    /// Check if a key rotation is needed by comparing file contents.
    /// Returns true if the key file has changed since last load.
    /// The compare-and-rotate is done under a single lock acquisition to
    /// prevent a TOCTOU race where two concurrent callers could each see
    /// a changed key and rotate twice.
    pub fn checkFileRotation(self: *KeyManager, allocator: std.mem.Allocator) bool {
        const path = self.key_file_path orelse return false;
        const new_key = readKeyFromFile(path, allocator) catch return false;
        defer allocator.free(new_key);

        self.mutex.lock();
        defer self.mutex.unlock();

        if (std.mem.eql(u8, new_key, &self.current_key)) return false;

        // Inline the rotation without re-acquiring the lock.
        @memcpy(&self.previous_key, &self.current_key);
        @memcpy(&self.current_key, new_key[0..64]);
        self.has_previous = true;
        return true;
    }
};

/// Read a hex key from a file, trimming whitespace. Returns owned slice.
fn readKeyFromFile(path: []const u8, allocator: std.mem.Allocator) ![]u8 {
    const file = std.fs.cwd().openFile(path, .{}) catch |err| {
        std.debug.print("error: cannot open key file '{s}': {s}\n", .{ path, @errorName(err) });
        return error.FileNotFound;
    };
    defer file.close();

    var buf: [256]u8 = undefined;
    const n = file.readAll(&buf) catch return error.ReadFailed;
    const trimmed = std.mem.trim(u8, buf[0..n], " \t\r\n");

    if (trimmed.len != 64) return error.InvalidKeyLength;

    // Validate all hex chars
    for (trimmed) |ch| {
        switch (ch) {
            '0'...'9', 'a'...'f', 'A'...'F' => {},
            else => return error.InvalidHexChar,
        }
    }

    return try allocator.dupe(u8, trimmed);
}

// ===========================================================================
// Unit Tests
// ===========================================================================

test "KeyManager - init and current key" {
    const key = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    var mgr = try KeyManager.init(key, .inline_hex);
    const cur = mgr.currentKeyHex();
    try std.testing.expectEqualStrings(key, &cur);
    try std.testing.expect(mgr.previousKeyHex() == null);
}

test "KeyManager - invalid key length rejected" {
    try std.testing.expectError(error.InvalidKeyLength, KeyManager.init("tooshort", .inline_hex));
}

test "KeyManager - rotate preserves previous key" {
    const key1 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const key2 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    var mgr = try KeyManager.init(key1, .inline_hex);

    try mgr.rotate(key2);
    const cur = mgr.currentKeyHex();
    try std.testing.expectEqualStrings(key2, &cur);
    const prev = mgr.previousKeyHex();
    try std.testing.expect(prev != null);
    try std.testing.expectEqualStrings(key1, &prev.?);
}

test "KeyManager - double rotate chains correctly" {
    const key1 = "1111111111111111111111111111111111111111111111111111111111111111";
    const key2 = "2222222222222222222222222222222222222222222222222222222222222222";
    const key3 = "3333333333333333333333333333333333333333333333333333333333333333";
    var mgr = try KeyManager.init(key1, .inline_hex);

    try mgr.rotate(key2);
    try mgr.rotate(key3);

    const cur = mgr.currentKeyHex();
    try std.testing.expectEqualStrings(key3, &cur);
    // Previous should be key2 (not key1 — only one level of history)
    const prev = mgr.previousKeyHex();
    try std.testing.expectEqualStrings(key2, &prev.?);
}

test "KeySource - labels" {
    try std.testing.expectEqualStrings("inline", KeySource.inline_hex.label());
    try std.testing.expectEqualStrings("file", KeySource.file.label());
    try std.testing.expectEqualStrings("exec", KeySource.exec.label());
}
