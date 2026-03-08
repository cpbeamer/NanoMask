const std = @import("std");

/// Deterministic HMAC-SHA256 pseudonymization for HASH-mode fields.
/// Generates stable `PSEUDO_<16hex>` tokens from input values using a session key,
/// and maintains a reverse map for unhashing on the response path.
pub const Hasher = struct {
    session_key: [32]u8,
    /// Maps pseudonym (owned []u8) → original (owned []u8) for response-path reversal.
    /// Capped at `max_reverse_entries` to prevent unbounded memory growth.
    reverse_map: std.StringHashMapUnmanaged([]u8),
    allocator: std.mem.Allocator,

    /// Maximum number of reverse-map entries before eviction.
    /// At ~40 bytes per entry overhead, 100K entries ≈ 4 MB worst-case.
    const max_reverse_entries: usize = 100_000;

    /// Initialize with an explicit key or auto-generate a random one.
    pub fn init(key_hex: ?[]const u8, allocator: std.mem.Allocator) !Hasher {
        var key: [32]u8 = undefined;

        if (key_hex) |hex| {
            if (hex.len != 64) {
                std.debug.print("error: --hash-key must be exactly 64 hex characters (32 bytes)\n", .{});
                return error.InvalidHashKey;
            }
            // Decode hex to bytes
            for (0..32) |i| {
                key[i] = std.fmt.parseInt(u8, hex[i * 2 .. i * 2 + 2], 16) catch {
                    std.debug.print("error: --hash-key contains invalid hex at position {d}\n", .{i * 2});
                    return error.InvalidHashKey;
                };
            }
        } else {
            // Auto-generate cryptographically random key
            std.crypto.random.bytes(&key);
        }

        return .{
            .session_key = key,
            .reverse_map = .empty,
            .allocator = allocator,
        };
    }

    /// Load key from a file (reads first 64 hex chars).
    pub fn initFromFile(path: []const u8, allocator: std.mem.Allocator) !Hasher {
        const file = std.fs.cwd().openFile(path, .{}) catch |err| {
            std.debug.print("error: cannot open hash key file '{s}': {s}\n", .{ path, @errorName(err) });
            return error.HashKeyFileNotFound;
        };
        defer file.close();

        var buf: [128]u8 = undefined;
        const bytes_read = file.reader().readAll(&buf) catch {
            return error.HashKeyFileReadError;
        };
        if (bytes_read < 64) {
            std.debug.print("error: hash key file must contain at least 64 hex characters\n", .{});
            return error.InvalidHashKey;
        }

        const hex_str = std.mem.trim(u8, buf[0..bytes_read], " \t\n\r");
        if (hex_str.len < 64) {
            return error.InvalidHashKey;
        }

        return init(hex_str[0..64], allocator);
    }

    pub fn deinit(self: *Hasher) void {
        var it = self.reverse_map.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.reverse_map.deinit(self.allocator);
    }

    /// Produce a deterministic pseudonym for the given value.
    /// Returns a stable `PSEUDO_<16hex>` token. Same input + same session key
    /// always yields the same output. Stores the reverse mapping for later unhashing.
    pub fn hash(self: *Hasher, original: []const u8) ![]const u8 {
        // Compute HMAC-SHA256
        var mac: [32]u8 = undefined;
        const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
        HmacSha256.create(&mac, original, &self.session_key);

        // Truncate to 8 bytes (16 hex chars) for the pseudonym
        var hex_buf: [16]u8 = undefined;
        const hex_chars = "0123456789abcdef";
        for (0..8) |i| {
            hex_buf[i * 2] = hex_chars[mac[i] >> 4];
            hex_buf[i * 2 + 1] = hex_chars[mac[i] & 0x0f];
        }

        // Build "PSEUDO_<hex>" token (owned mutable slice)
        const token: []u8 = try std.fmt.allocPrint(self.allocator, "PSEUDO_{s}", .{hex_buf});
        errdefer self.allocator.free(token);

        // Store reverse mapping if not already present
        const gop = try self.reverse_map.getOrPut(self.allocator, token);
        if (!gop.found_existing) {
            gop.value_ptr.* = try self.allocator.dupe(u8, original);

            // Evict all entries when cap is reached to bound memory.
            // Full clear is simple and safe — deterministic hashing means
            // the same inputs will re-populate the map on next occurrence.
            if (self.reverse_map.count() > max_reverse_entries) {
                self.evictAll();
            }
        } else {
            // Token already mapped — free the duplicate token
            self.allocator.free(token);
        }

        return gop.key_ptr.*;
    }

    /// Look up the original value for a pseudonym token.
    pub fn unhash(self: *const Hasher, token: []const u8) ?[]const u8 {
        return if (self.reverse_map.get(token)) |v| v else null;
    }

    /// Evict all entries from the reverse map to reclaim memory.
    /// Called automatically when the map exceeds `max_reverse_entries`.
    fn evictAll(self: *Hasher) void {
        var it = self.reverse_map.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.reverse_map.clearRetainingCapacity();
    }

    /// Scan a JSON response for PSEUDO_ tokens and replace them with originals.
    /// Returns an owned slice with restored content.
    pub fn unhashJson(self: *const Hasher, input: []const u8, allocator: std.mem.Allocator) ![]u8 {
        const prefix = "PSEUDO_";
        const token_len = prefix.len + 16; // "PSEUDO_" + 16 hex chars

        if (input.len < token_len) {
            return try allocator.dupe(u8, input);
        }

        var result = std.ArrayListUnmanaged(u8).empty;
        errdefer result.deinit(allocator);

        var i: usize = 0;
        while (i < input.len) {
            // Look for PSEUDO_ prefix
            if (i + token_len <= input.len and std.mem.startsWith(u8, input[i..], prefix)) {
                const candidate = input[i .. i + token_len];
                // Verify it's a valid hex token
                if (isValidPseudoToken(candidate[prefix.len..])) {
                    if (self.unhash(candidate)) |original| {
                        try result.appendSlice(allocator, original);
                        i += token_len;
                        continue;
                    }
                }
            }
            try result.append(allocator, input[i]);
            i += 1;
        }

        return try result.toOwnedSlice(allocator);
    }

    fn isValidPseudoToken(hex: []const u8) bool {
        if (hex.len != 16) return false;
        for (hex) |c| {
            switch (c) {
                '0'...'9', 'a'...'f' => {},
                else => return false,
            }
        }
        return true;
    }

    /// Get the session key as a hex string (for logging at startup).
    pub fn keyHex(self: *const Hasher) [64]u8 {
        var buf: [64]u8 = undefined;
        const hex_chars = "0123456789abcdef";
        for (0..32) |i| {
            buf[i * 2] = hex_chars[self.session_key[i] >> 4];
            buf[i * 2 + 1] = hex_chars[self.session_key[i] & 0x0f];
        }
        return buf;
    }
};

// ===========================================================================
// Unit Tests
// ===========================================================================

test "hasher - deterministic output" {
    var h = try Hasher.init(null, std.testing.allocator);
    defer h.deinit();

    const t1 = try h.hash("John Doe");
    const t2 = try h.hash("John Doe");

    // Same input → same output
    try std.testing.expectEqualStrings(t1, t2);
    // Starts with PSEUDO_
    try std.testing.expect(std.mem.startsWith(u8, t1, "PSEUDO_"));
    // Token is 23 chars: "PSEUDO_" (7) + 16 hex
    try std.testing.expectEqual(@as(usize, 23), t1.len);
}

test "hasher - different inputs produce different tokens" {
    var h = try Hasher.init(null, std.testing.allocator);
    defer h.deinit();

    const t1 = try h.hash("John Doe");
    const t2 = try h.hash("Jane Smith");

    try std.testing.expect(!std.mem.eql(u8, t1, t2));
}

test "hasher - round-trip hash then unhash" {
    var h = try Hasher.init(null, std.testing.allocator);
    defer h.deinit();

    const original = "Patient Zero";
    const token = try h.hash(original);
    const restored = h.unhash(token);

    try std.testing.expect(restored != null);
    try std.testing.expectEqualStrings(original, restored.?);
}

test "hasher - unhash unknown token returns null" {
    var h = try Hasher.init(null, std.testing.allocator);
    defer h.deinit();

    try std.testing.expectEqual(@as(?[]const u8, null), h.unhash("PSEUDO_0000000000000000"));
}

test "hasher - explicit key produces consistent results" {
    const key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    var h1 = try Hasher.init(key_hex, std.testing.allocator);
    defer h1.deinit();

    var h2 = try Hasher.init(key_hex, std.testing.allocator);
    defer h2.deinit();

    const t1 = try h1.hash("test value");
    const t2 = try h2.hash("test value");

    try std.testing.expectEqualStrings(t1, t2);
}

test "hasher - unhashJson replaces tokens in response" {
    var h = try Hasher.init(null, std.testing.allocator);
    defer h.deinit();

    const token = try h.hash("John Doe");

    // Build a mock response containing the token
    const response = try std.fmt.allocPrint(std.testing.allocator, "Hello {s}, welcome back!", .{token});
    defer std.testing.allocator.free(response);

    const restored = try h.unhashJson(response, std.testing.allocator);
    defer std.testing.allocator.free(restored);

    try std.testing.expectEqualStrings("Hello John Doe, welcome back!", restored);
}

test "hasher - unhashJson with no tokens returns copy" {
    var h = try Hasher.init(null, std.testing.allocator);
    defer h.deinit();

    const input = "No pseudonyms here at all.";
    const output = try h.unhashJson(input, std.testing.allocator);
    defer std.testing.allocator.free(output);

    try std.testing.expectEqualStrings(input, output);
}

test "hasher - invalid key length" {
    const result = Hasher.init("tooshort", std.testing.allocator);
    try std.testing.expectError(error.InvalidHashKey, result);
}

test "hasher - keyHex returns correct representation" {
    const key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    var h = try Hasher.init(key_hex, std.testing.allocator);
    defer h.deinit();

    const hex = h.keyHex();
    try std.testing.expectEqualStrings(key_hex, &hex);
}

test "hasher - multiple unique values" {
    var h = try Hasher.init(null, std.testing.allocator);
    defer h.deinit();

    var tokens: [100][]const u8 = undefined;
    for (0..100) |i| {
        var name_buf: [32]u8 = undefined;
        const name = std.fmt.bufPrint(&name_buf, "Patient_{d}", .{i}) catch unreachable;
        tokens[i] = try h.hash(name);
    }

    // Verify all tokens are unique
    for (0..100) |i| {
        for (i + 1..100) |j| {
            try std.testing.expect(!std.mem.eql(u8, tokens[i], tokens[j]));
        }
    }
}
