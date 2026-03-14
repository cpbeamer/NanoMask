const std = @import("std");

/// Common error set for vault operations.
pub const VaultError = error{
    StoreFailed,
    LookupFailed,
    EvictFailed,
    InvalidToken,
    InitializationFailed,
    EncryptionFailed,
    DecryptionFailed,
    IntegrityCheckFailed,
} || std.mem.Allocator.Error || std.fs.File.OpenError || std.fs.File.WriteError || std.fs.File.ReadError;

/// The Vault abstraction provides a durable or in-memory key-value store 
/// for mapping pseudonymized HASH tokens back to their original values 
/// for the reverse unmasking process.
pub const Vault = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        /// Store a new token mapping. The vault implementation takes ownership 
        /// of copying the strings if it needs to retain them in memory.
        store: *const fn (ctx: *anyopaque, token: []const u8, original: []const u8) VaultError!void,

        /// Look up an original value by its token. Returns null if not found.
        /// The returned slice is owned by the vault and valid until `evictAll()` 
        /// is called or the vault is destroyed.
        lookup: *const fn (ctx: *anyopaque, token: []const u8) VaultError!?[]const u8,

        /// Evict all items from the vault (e.g., when keys rotate).
        evictAll: *const fn (ctx: *anyopaque) VaultError!void,
        
        /// Free all resources associated with the vault.
        deinit: *const fn (ctx: *anyopaque) void,
    };

    pub fn store(self: Vault, token: []const u8, original: []const u8) VaultError!void {
        return self.vtable.store(self.ptr, token, original);
    }

    pub fn lookup(self: Vault, token: []const u8) VaultError!?[]const u8 {
        return self.vtable.lookup(self.ptr, token);
    }

    pub fn evictAll(self: Vault) VaultError!void {
        return self.vtable.evictAll(self.ptr);
    }

    pub fn deinit(self: Vault) void {
        self.vtable.deinit(self.ptr);
    }
};

const MemoryVault = @import("memory_vault.zig").MemoryVault;
const FileVault = @import("file_vault.zig").FileVault;
const ExternalVault = @import("external_vault.zig").ExternalVault;

/// Tagged union used by main.zig to hold the concrete vault backend so it
/// can be properly cleaned up on shutdown.
pub const VaultBackend = union(enum) {
    memory: *MemoryVault,
    file: *FileVault,
    external: *ExternalVault,
};
