//! By convention, root.zig is the root source file when making a library.
//! Re-exports the core NanoMask modules for consumers.
pub const redact = @import("redact.zig");
pub const entity_mask = @import("entity_mask.zig");
pub const fuzzy_match = @import("fuzzy_match.zig");
pub const versioned_entity_set = @import("versioned_entity_set.zig");
pub const config = @import("config.zig");
pub const file_watcher = @import("file_watcher.zig");
pub const admin = @import("admin.zig");

test {
    // Ensure all tests in re-exported modules are discovered by `zig build test`.
    _ = redact;
    _ = entity_mask;
    _ = fuzzy_match;
    _ = versioned_entity_set;
    _ = config;
    _ = file_watcher;
    _ = admin;
    _ = @import("http_util.zig");
}
