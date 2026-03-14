const std = @import("std");
const vault = @import("vault.zig");
const Vault = vault.Vault;
const VaultError = vault.VaultError;

/// MemoryVault is an in-memory implementation of the Vault interface.
/// It uses an ArrayHashMap to store the original values associated with tokens.
pub const MemoryVault = struct {
    allocator: std.mem.Allocator,
    
    /// Map from string token (e.g. "PSEUDO_ABCD") to string original.
    /// MemoryVault owns the memory for both keys and values.
    map: std.StringArrayHashMap([]const u8),
    lock: std.Thread.RwLock,

    pub fn init(allocator: std.mem.Allocator) !*MemoryVault {
        const self = try allocator.create(MemoryVault);
        self.* = .{
            .allocator = allocator,
            .map = std.StringArrayHashMap([]const u8).init(allocator),
            .lock = .{},
        };
        return self;
    }

    pub fn deinit(ctx: *anyopaque) void {
        const self: *MemoryVault = @ptrCast(@alignCast(ctx));
        self.lock.lock();
        var it = self.map.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.map.deinit();
        self.lock.unlock();
        self.allocator.destroy(self);
    }

    pub fn vaultInterface(self: *MemoryVault) Vault {
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

    fn store(ctx: *anyopaque, token: []const u8, original: []const u8) VaultError!void {
        const self: *MemoryVault = @ptrCast(@alignCast(ctx));
        
        const token_dupe = self.allocator.dupe(u8, token) catch return VaultError.StoreFailed;
        errdefer self.allocator.free(token_dupe);
        
        const original_dupe = self.allocator.dupe(u8, original) catch return VaultError.StoreFailed;
        errdefer self.allocator.free(original_dupe);

        self.lock.lock();
        defer self.lock.unlock();
        
        // If it already exists, free the old dupes and the new dupes we just made.
        // ArrayHashMap.put() overwrites the value but not the key ptr if it exists,
        // so it's safer to check first.
        if (self.map.getPtr(token)) |existing_value_ptr| {
            self.allocator.free(existing_value_ptr.*);
            existing_value_ptr.* = original_dupe;
            self.allocator.free(token_dupe); // not needed, key already exists
        } else {
            self.map.put(token_dupe, original_dupe) catch return VaultError.StoreFailed;
        }
    }

    fn lookup(ctx: *anyopaque, token: []const u8) VaultError!?[]const u8 {
        const self: *MemoryVault = @ptrCast(@alignCast(ctx));
        self.lock.lockShared();
        defer self.lock.unlockShared();
        return self.map.get(token);
    }

    fn evictAll(ctx: *anyopaque) VaultError!void {
        const self: *MemoryVault = @ptrCast(@alignCast(ctx));
        self.lock.lock();
        defer self.lock.unlock();
        
        var it = self.map.iterator();
        while (it.next()) |entry| {
            self.allocator.free(entry.key_ptr.*);
            self.allocator.free(entry.value_ptr.*);
        }
        self.map.clearRetainingCapacity();
    }
};
