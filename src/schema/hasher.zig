const std = @import("std");
const vault = @import("../vault/vault.zig");

/// Deterministic HMAC-SHA256 pseudonymization for HASH-mode fields.
/// Generates stable `PSEUDO_<16hex>` tokens from input values using a session key,
/// and uses a Vault to maintain a reverse map for unhashing on the response path.
pub const Hasher = struct {
    session_key: [32]u8,
    /// Backing store for token -> original mappings.
    vault_inst: vault.Vault,
    allocator: std.mem.Allocator,
    observability: ?*@import("../infra/observability.zig").Observability = null,

    /// Metrics for observability
    store_count: u64 = 0,
    lookup_count: u64 = 0,
    miss_count: u64 = 0,
    eviction_cycle_count: u64 = 0,

    /// Optional cap on vault size before forced eviction to protect memory.
    /// External vaults might handle mapping limits implicitly, but for MemoryVault
    /// we want to prevent unbounded growth.
    const max_reverse_entries: usize = 100_000;

    pub const HasherStats = struct {
        store_count: u64,
        lookup_count: u64,
        miss_count: u64,
        eviction_cycle_count: u64,
    };

    /// Return current operator-facing stats.
    pub fn stats(self: *const Hasher) HasherStats {
        return .{
            .store_count = self.store_count,
            .lookup_count = self.lookup_count,
            .miss_count = self.miss_count,
            .eviction_cycle_count = self.eviction_cycle_count,
        };
    }

    pub fn setObservability(self: *Hasher, obs: *@import("../infra/observability.zig").Observability) void {
        self.observability = obs;
    }

    /// Initialize with an explicit key or auto-generate a random one.
    pub fn init(key_hex: ?[]const u8, vault_inst: vault.Vault, allocator: std.mem.Allocator) !Hasher {
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
            .vault_inst = vault_inst,
            .allocator = allocator,
        };
    }

    /// Load key from a file (reads first 64 hex chars).
    pub fn initFromFile(path: []const u8, vault_inst: vault.Vault, allocator: std.mem.Allocator) !Hasher {
        const file = std.fs.cwd().openFile(path, .{}) catch |err| {
            std.debug.print("error: cannot open hash key file '{s}': {s}\n", .{ path, @errorName(err) });
            return error.HashKeyFileNotFound;
        };
        defer file.close();

        // Read entire key file (max 128 bytes — key is 64 hex chars)
        const contents = file.readToEndAlloc(allocator, 128) catch {
            return error.HashKeyFileReadError;
        };
        defer allocator.free(contents);

        if (contents.len < 64) {
            std.debug.print("error: hash key file must contain at least 64 hex characters\n", .{});
            return error.InvalidHashKey;
        }

        const hex_str = std.mem.trim(u8, contents, " \t\n\r");
        if (hex_str.len < 64) {
            return error.InvalidHashKey;
        }

        return init(hex_str[0..64], vault_inst, allocator);
    }

    // Hasher does NOT own the vault — the caller (main.zig) manages its lifetime.
    pub fn deinit(self: *Hasher) void {
        _ = self;
    }

    /// Produce a deterministic pseudonym for the given value.
    /// Returns a caller-owned `PSEUDO_<16hex>` token. Same input + same
    /// session key always yields the same output. Caller must free the
    /// returned slice. Stores the reverse mapping for later unhashing.
    pub fn hash(self: *Hasher, original: []const u8) ![]u8 {
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

        // Evict before inserting if we've exceeded the safety cap.
        // Deterministic hashing means the same inputs re-populate on next occurrence.
        if (self.store_count >= max_reverse_entries) {
            self.evictAll();
        }

        // Store in vault — count success, log failures via observability
        self.vault_inst.store(token, original) catch {
            // Surface the failure but don't crash the proxy
            self.miss_count += 1;
            return token;
        };
        self.store_count += 1;
        if (self.observability) |obs| obs.recordVaultStore();

        // Return the token (since store handles its own copies if needed,
        // and caller owns the returned token)
        return token;
    }

    /// Look up the original value for a pseudonym token.
    pub fn unhash(self: *Hasher, token: []const u8) ?[]const u8 {
        self.lookup_count += 1;
        if (self.vault_inst.lookup(token) catch null) |v| {
            if (self.observability) |obs| obs.recordVaultLookup(true);
            return v;
        } else {
            self.miss_count += 1;
            if (self.observability) |obs| obs.recordVaultLookup(false);
            return null;
        }
    }

    /// Evict all entries from the vault to reclaim memory or rotate keys.
    pub fn evictAll(self: *Hasher) void {
        self.eviction_cycle_count += 1;
        self.vault_inst.evictAll() catch {};
    }

    /// Scan a JSON response for PSEUDO_ tokens and replace them with originals.
    /// Returns an owned slice with restored content. Takes *Hasher (not *const)
    /// because miss tracking mutates the miss_count field.
    pub fn unhashJson(self: *Hasher, input: []const u8, allocator: std.mem.Allocator) ![]u8 {
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
                    // miss_count is now incremented inside unhash()
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
    const mem_vault = try @import("../vault/memory_vault.zig").MemoryVault.init(std.testing.allocator);
    defer mem_vault.vaultInterface().deinit();
    var h = try Hasher.init(null, mem_vault.vaultInterface(), std.testing.allocator);
    defer h.deinit();

    const t1 = try h.hash("John Doe");
    defer std.testing.allocator.free(t1);
    const t2 = try h.hash("John Doe");
    defer std.testing.allocator.free(t2);

    // Same input → same output
    try std.testing.expectEqualStrings(t1, t2);
    // Starts with PSEUDO_
    try std.testing.expect(std.mem.startsWith(u8, t1, "PSEUDO_"));
    // Token is 23 chars: "PSEUDO_" (7) + 16 hex
    try std.testing.expectEqual(@as(usize, 23), t1.len);
}

test "hasher - different inputs produce different tokens" {
    const mem_vault = try @import("../vault/memory_vault.zig").MemoryVault.init(std.testing.allocator);
    defer mem_vault.vaultInterface().deinit();
    var h = try Hasher.init(null, mem_vault.vaultInterface(), std.testing.allocator);
    defer h.deinit();

    const t1 = try h.hash("John Doe");
    defer std.testing.allocator.free(t1);
    const t2 = try h.hash("Jane Smith");
    defer std.testing.allocator.free(t2);

    try std.testing.expect(!std.mem.eql(u8, t1, t2));
}

test "hasher - round-trip hash then unhash" {
    const mem_vault = try @import("../vault/memory_vault.zig").MemoryVault.init(std.testing.allocator);
    defer mem_vault.vaultInterface().deinit();
    var h = try Hasher.init(null, mem_vault.vaultInterface(), std.testing.allocator);
    defer h.deinit();

    const original = "Patient Zero";
    const token = try h.hash(original);
    defer std.testing.allocator.free(token);
    const restored = h.unhash(token);

    try std.testing.expect(restored != null);
    try std.testing.expectEqualStrings(original, restored.?);
}

test "hasher - unhash unknown token returns null" {
    const mem_vault = try @import("../vault/memory_vault.zig").MemoryVault.init(std.testing.allocator);
    defer mem_vault.vaultInterface().deinit();
    var h = try Hasher.init(null, mem_vault.vaultInterface(), std.testing.allocator);
    defer h.deinit();

    try std.testing.expectEqual(@as(?[]const u8, null), h.unhash("PSEUDO_0000000000000000"));
}

test "hasher - explicit key produces consistent results" {
    const key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    const mem_vault1 = try @import("../vault/memory_vault.zig").MemoryVault.init(std.testing.allocator);
    defer mem_vault1.vaultInterface().deinit();
    var h1 = try Hasher.init(key_hex, mem_vault1.vaultInterface(), std.testing.allocator);
    defer h1.deinit();

    const mem_vault2 = try @import("../vault/memory_vault.zig").MemoryVault.init(std.testing.allocator);
    defer mem_vault2.vaultInterface().deinit();
    var h2 = try Hasher.init(key_hex, mem_vault2.vaultInterface(), std.testing.allocator);
    defer h2.deinit();

    const t1 = try h1.hash("test value");
    defer std.testing.allocator.free(t1);
    const t2 = try h2.hash("test value");
    defer std.testing.allocator.free(t2);

    try std.testing.expectEqualStrings(t1, t2);
}

test "hasher - unhashJson replaces tokens in response" {
    const mem_vault = try @import("../vault/memory_vault.zig").MemoryVault.init(std.testing.allocator);
    defer mem_vault.vaultInterface().deinit();
    var h = try Hasher.init(null, mem_vault.vaultInterface(), std.testing.allocator);
    defer h.deinit();

    const token = try h.hash("John Doe");
    defer std.testing.allocator.free(token);

    // Build a mock response containing the token
    const response = try std.fmt.allocPrint(std.testing.allocator, "Hello {s}, welcome back!", .{token});
    defer std.testing.allocator.free(response);

    const restored = try h.unhashJson(response, std.testing.allocator);
    defer std.testing.allocator.free(restored);

    try std.testing.expectEqualStrings("Hello John Doe, welcome back!", restored);
}

test "hasher - unhashJson with no tokens returns copy" {
    const mem_vault = try @import("../vault/memory_vault.zig").MemoryVault.init(std.testing.allocator);
    defer mem_vault.vaultInterface().deinit();
    var h = try Hasher.init(null, mem_vault.vaultInterface(), std.testing.allocator);
    defer h.deinit();

    const input = "No pseudonyms here at all.";
    const output = try h.unhashJson(input, std.testing.allocator);
    defer std.testing.allocator.free(output);

    try std.testing.expectEqualStrings(input, output);
}

test "hasher - invalid key length" {
    const mem_vault = try @import("../vault/memory_vault.zig").MemoryVault.init(std.testing.allocator);
    const result = Hasher.init("tooshort", mem_vault.vaultInterface(), std.testing.allocator);
    try std.testing.expectError(error.InvalidHashKey, result);
    mem_vault.vaultInterface().deinit();
}

test "hasher - keyHex returns correct representation" {
    const key_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const mem_vault = try @import("../vault/memory_vault.zig").MemoryVault.init(std.testing.allocator);
    defer mem_vault.vaultInterface().deinit();
    var h = try Hasher.init(key_hex, mem_vault.vaultInterface(), std.testing.allocator);
    defer h.deinit();

    const hex = h.keyHex();
    try std.testing.expectEqualStrings(key_hex, &hex);
}

test "hasher - eviction cycle increments counter and clears map" {
    const mem_vault = try @import("../vault/memory_vault.zig").MemoryVault.init(std.testing.allocator);
    defer mem_vault.vaultInterface().deinit();
    var h = try Hasher.init(null, mem_vault.vaultInterface(), std.testing.allocator);
    defer h.deinit();

    // Populate a few entries
    const t1 = try h.hash("Alice");
    defer std.testing.allocator.free(t1);
    const t2 = try h.hash("Bob");
    defer std.testing.allocator.free(t2);

    try std.testing.expectEqual(@as(u64, 2), h.stats().store_count);
    // h.stats() doesn't have reverse_map_size anymore, check store count instead
    try std.testing.expectEqual(@as(u64, 0), h.stats().eviction_cycle_count);

    // Trigger an eviction cycle directly (private, accessible from same file)
    h.evictAll();

    // Stats
    try std.testing.expectEqual(@as(u64, 1), h.stats().eviction_cycle_count);

    // After eviction, lookups for previously known tokens should miss
    try std.testing.expectEqual(@as(?[]const u8, null), h.unhash(t1));
}

test "hasher - miss_count increments on unknown token in unhashJson" {
    const mem_vault = try @import("../vault/memory_vault.zig").MemoryVault.init(std.testing.allocator);
    defer mem_vault.vaultInterface().deinit();
    var h = try Hasher.init(null, mem_vault.vaultInterface(), std.testing.allocator);
    defer h.deinit();

    try std.testing.expectEqual(@as(u64, 0), h.stats().miss_count);

    const response = "result is PSEUDO_deadbeef12345678 here";
    const out = try h.unhashJson(response, std.testing.allocator);
    defer std.testing.allocator.free(out);

    // The token was not in the map — miss_count should be 1
    try std.testing.expectEqual(@as(u64, 1), h.stats().miss_count);
    // The token should remain verbatim in the output (no substitution)
    try std.testing.expectEqualStrings(response, out);
}

test "hasher - multiple unique values" {
    const mem_vault = try @import("../vault/memory_vault.zig").MemoryVault.init(std.testing.allocator);
    defer mem_vault.vaultInterface().deinit();
    var h = try Hasher.init(null, mem_vault.vaultInterface(), std.testing.allocator);
    defer h.deinit();

    var tokens: [100][]u8 = undefined;
    for (0..100) |i| {
        var name_buf: [32]u8 = undefined;
        const name = std.fmt.bufPrint(&name_buf, "Patient_{d}", .{i}) catch unreachable;
        tokens[i] = try h.hash(name);
    }
    defer for (&tokens) |t| std.testing.allocator.free(t);

    // Verify all tokens are unique
    for (0..100) |i| {
        for (i + 1..100) |j| {
            try std.testing.expect(!std.mem.eql(u8, tokens[i], tokens[j]));
        }
    }
}
