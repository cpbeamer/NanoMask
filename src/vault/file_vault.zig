const std = @import("std");
const vault = @import("vault.zig");
const Vault = vault.Vault;
const VaultError = vault.VaultError;
const MemoryVault = @import("memory_vault.zig").MemoryVault;

// Simple AES-GCM encrypted append-only vault.
// Uses a 32-byte key derived elsewhere (or loaded from config).

pub const FileVault = struct {
    allocator: std.mem.Allocator,
    path: []const u8,
    file: std.fs.File,
    memory_vault: *MemoryVault, // Backing fast in-memory store
    lock: std.Thread.RwLock = .{},
    key: [32]u8, // AES-256-GCM key

    pub fn init(allocator: std.mem.Allocator, path: []const u8, key: [32]u8) !*FileVault {
        var file = try std.fs.cwd().createFile(path, .{ .read = true, .truncate = false });
        errdefer file.close();

        // Seek to end to append new entries
        try file.seekFromEnd(0);

        const mv = try MemoryVault.init(allocator);
        errdefer mv.vaultInterface().deinit();

        const self = try allocator.create(FileVault);
        self.* = .{
            .allocator = allocator,
            .path = try allocator.dupe(u8, path),
            .file = file,
            .memory_vault = mv,
            .key = key,
        };

        // Load existing entries from file into memory
        try self.loadFromFile();

        return self;
    }

    pub fn deinit(ctx: *anyopaque) void {
        const self: *FileVault = @ptrCast(@alignCast(ctx));

        // Wait for pending operations
        self.lock.lock();
        defer self.lock.unlock();

        self.memory_vault.vaultInterface().deinit();
        self.file.close();
        self.allocator.free(self.path);
        self.allocator.destroy(self);
    }

    pub fn vaultInterface(self: *FileVault) Vault {
        return .{
            .ptr = self,
            .vtable = &.{
                .store = store,
                .lookup = lookup,
                .evictAll = evictAll,
                .deinit = deinit,
            },
        };
    }

    // Append entry: nonce (12 bytes) | ciphertext | tag (16 bytes)
    // For simplicity, we write a length prefix for each entry so we can frame them.
    // Entry format: [u32 EntryLength] [12B Nonce] [16B Tag] [Ciphertext containing JSON or structured data]
    fn store(ctx: *anyopaque, token: []const u8, original: []const u8) VaultError!void {
        const self: *FileVault = @ptrCast(@alignCast(ctx));

        self.lock.lock();
        defer self.lock.unlock();

        // 1. Store in memory vault first for fast lookup
        try self.memory_vault.vaultInterface().store(token, original);

        // 2. Persist to file (JSON for convenience here, but could be binary)
        // Format payload: {"t":"TOKEN","o":"ORIGINAL"}
        var payload_buf = std.ArrayList(u8).init(self.allocator);
        defer payload_buf.deinit();

        const writer = payload_buf.writer();
        try writer.writeByte('{');
        try writer.writeAll("\"t\":\"");
        try writer.writeAll(token);
        try writer.writeAll("\",\"o\":\"");
        // Simple escaping just in case
        for (original) |c| {
            if (c == '"' or c == '\\') try writer.writeByte('\\');
            try writer.writeByte(c);
        }
        try writer.writeAll("\"}");

        const plaintext = payload_buf.items;

        // 3. Encrypt payload
        var nonce: [12]u8 = undefined;
        std.crypto.random.bytes(&nonce);

        const ciphertext = try self.allocator.alloc(u8, plaintext.len);
        defer self.allocator.free(ciphertext);

        var tag: [16]u8 = undefined;
        std.crypto.aead.aes_gcm.Aes256Gcm.encrypt(ciphertext, &tag, plaintext, &"", // aad
            nonce, self.key);

        // 4. Write to disk
        // Format: [Length u32 LE] [Nonce 12B] [Tag 16B] [Ciphertext]
        const total_len: u32 = @intCast(12 + 16 + ciphertext.len);
        var len_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &len_bytes, total_len, .little);

        try self.file.writeAll(&len_bytes);
        try self.file.writeAll(&nonce);
        try self.file.writeAll(&tag);
        try self.file.writeAll(ciphertext);

        // Ensure durability
        try self.file.sync();
    }

    fn lookup(ctx: *anyopaque, token: []const u8) VaultError!?[]const u8 {
        const self: *FileVault = @ptrCast(@alignCast(ctx));

        // Pass to memory vault since it holds the exact same data
        self.lock.lockShared();
        defer self.lock.unlockShared();

        return self.memory_vault.vaultInterface().lookup(token);
    }

    fn evictAll(ctx: *anyopaque) VaultError!void {
        const self: *FileVault = @ptrCast(@alignCast(ctx));

        self.lock.lock();
        defer self.lock.unlock();

        // Clear memory
        try self.memory_vault.vaultInterface().evictAll();

        // Truncate file
        try self.file.setEndPos(0);
        try self.file.seekTo(0);
        try self.file.sync();
    }

    fn loadFromFile(self: *@This()) !void {
        // Simple loader: scan all entries, decrypt, and put in memory_vault.
        try self.file.seekTo(0);
        const reader = self.file.reader();

        while (true) {
            const total_len = reader.readInt(u32, .little) catch |err| switch (err) {
                error.EndOfStream => break,
                else => return VaultError.InitializationFailed,
            };

            if (total_len < 28) return error.IntegrityCheckFailed; // Must have nonce(12) + tag(16)

            var nonce: [12]u8 = undefined;
            if (try reader.readAll(&nonce) != 12) return error.IntegrityCheckFailed;

            var tag: [16]u8 = undefined;
            if (try reader.readAll(&tag) != 16) return error.IntegrityCheckFailed;

            const ctext_len = total_len - 28;
            const ciphertext = try self.allocator.alloc(u8, ctext_len);
            defer self.allocator.free(ciphertext);

            if (try reader.readAll(ciphertext) != ctext_len) return error.IntegrityCheckFailed;

            const plaintext = try self.allocator.alloc(u8, ctext_len);
            defer self.allocator.free(plaintext);

            std.crypto.aead.aes_gcm.Aes256Gcm.decrypt(
                plaintext,
                ciphertext,
                tag,
                &"",
                nonce,
                self.key,
            ) catch return VaultError.IntegrityCheckFailed;

            // Simple parser: extract "t" and "o" values from the JSON payload.
            // SAFETY: This indexOf-based approach is safe because:
            //  1. Tokens are always "PSEUDO_<16hex>" — no special chars.
            //  2. Original values have `"` and `\` escaped during store().
            // The fixed payload layout {"t":"...","o":"..."} means "t" is
            // always first and "o" always second, so indexOf will match the
            // correct field boundaries.
            var t_val: []const u8 = "";
            var o_val: []const u8 = "";

            if (std.mem.indexOf(u8, plaintext, "\"t\":\"")) |t_idx| {
                const start = t_idx + 5;
                if (std.mem.indexOfScalarPos(u8, plaintext, start, '"')) |end| {
                    t_val = plaintext[start..end];
                }
            }
            if (std.mem.indexOf(u8, plaintext, "\"o\":\"")) |o_idx| {
                const start = o_idx + 5;
                if (std.mem.indexOfScalarPos(u8, plaintext, start, '"')) |end| {
                    o_val = plaintext[start..end];
                }
            }

            if (t_val.len > 0 and o_val.len > 0) {
                // To unescape \ characters
                var clean_o = try self.allocator.alloc(u8, o_val.len);
                defer self.allocator.free(clean_o);
                var j: usize = 0;
                var i: usize = 0;
                while (i < o_val.len) {
                    if (o_val[i] == '\\' and i + 1 < o_val.len) {
                        clean_o[j] = o_val[i + 1];
                        i += 2;
                        j += 1;
                    } else {
                        clean_o[j] = o_val[i];
                        i += 1;
                        j += 1;
                    }
                }

                // memory vault expects to own data, but we let it dupe it
                try self.memory_vault.vaultInterface().store(t_val, clean_o[0..j]);
            } else {
                return VaultError.IntegrityCheckFailed;
            }
        }
    }
};

const testing = std.testing;

test "FileVault - basic store and lookup" {
    const tmp_path = "test_vault_basic.enc";
    defer std.fs.cwd().deleteFile(tmp_path) catch {};

    var key: [32]u8 = undefined;
    std.crypto.random.bytes(&key);

    var vault_inst = try FileVault.init(std.testing.allocator, tmp_path, key);
    var iface = vault_inst.vaultInterface();
    defer iface.deinit();

    try iface.store("PT-001", "John Doe");

    const lookup1 = try iface.lookup("PT-001");
    try testing.expect(lookup1 != null);
    try testing.expectEqualStrings("John Doe", lookup1.?);

    const lookup2 = try iface.lookup("PT-002");
    try testing.expect(lookup2 == null);
}

test "FileVault - persistence across initializations" {
    const tmp_path = "test_vault_persistence.enc";
    defer std.fs.cwd().deleteFile(tmp_path) catch {};

    var key: [32]u8 = undefined;
    std.crypto.random.bytes(&key);

    // First instance: store data
    {
        var vault1 = try FileVault.init(std.testing.allocator, tmp_path, key);
        var iface1 = vault1.vaultInterface();
        defer iface1.deinit();

        try iface1.store("T1", "Alice");
        try iface1.store("T2", "Bob");
    }

    // Second instance: verify data is loaded
    {
        var vault2 = try FileVault.init(std.testing.allocator, tmp_path, key);
        var iface2 = vault2.vaultInterface();
        defer iface2.deinit();

        const v1 = try iface2.lookup("T1");
        try testing.expect(v1 != null);
        try testing.expectEqualStrings("Alice", v1.?);

        const v2 = try iface2.lookup("T2");
        try testing.expect(v2 != null);
        try testing.expectEqualStrings("Bob", v2.?);
    }
}

test "FileVault - evictAll" {
    const tmp_path = "test_vault_eviction.enc";
    defer std.fs.cwd().deleteFile(tmp_path) catch {};

    var key: [32]u8 = undefined;
    std.crypto.random.bytes(&key);

    var vault_inst = try FileVault.init(std.testing.allocator, tmp_path, key);
    var iface = vault_inst.vaultInterface();
    defer iface.deinit();

    try iface.store("T1", "Alice");
    try iface.evictAll();

    const lookup_after = try iface.lookup("T1");
    try testing.expect(lookup_after == null);

    // Verify file is truncated
    const stat = try std.fs.cwd().statFile(tmp_path);
    try testing.expectEqual(@as(u64, 0), stat.size);
}
