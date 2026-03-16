const std = @import("std");
const vault = @import("vault.zig");
const Vault = vault.Vault;
const VaultError = vault.VaultError;

/// ExternalVault is a stub for an external token vault backend
/// (e.g., HashiCorp Vault, AWS KMS, or a dedicated tokenization service).
/// This implementation just returns errors indicating it's not yet implemented.
pub const ExternalVault = struct {
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator) !*ExternalVault {
        const self = try allocator.create(ExternalVault);
        self.* = .{
            .allocator = allocator,
        };
        return self;
    }

    pub fn deinit(ctx: *anyopaque) void {
        const self: *ExternalVault = @ptrCast(@alignCast(ctx));
        self.allocator.destroy(self);
    }

    pub fn vaultInterface(self: *ExternalVault) Vault {
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
        _ = ctx;
        _ = token;
        _ = original;
        return VaultError.StoreFailed; // Not implemented
    }

    fn lookup(ctx: *anyopaque, token: []const u8) VaultError!?[]const u8 {
        _ = ctx;
        _ = token;
        return VaultError.LookupFailed; // Not implemented
    }

    fn evictAll(ctx: *anyopaque) VaultError!void {
        _ = ctx;
        return VaultError.EvictFailed; // Not implemented
    }
};
