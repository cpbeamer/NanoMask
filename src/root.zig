//! By convention, root.zig is the root source file when making a library.
//! Re-exports the core NanoMask modules for consumers.
pub const redact = @import("redaction/redact.zig");
pub const entity_mask = @import("redaction/entity_mask.zig");
pub const fuzzy_match = @import("redaction/fuzzy_match.zig");
pub const versioned_entity_set = @import("entity/versioned_entity_set.zig");
pub const config = @import("infra/config.zig");
pub const file_watcher = @import("entity/file_watcher.zig");
pub const admin = @import("admin/admin.zig");
pub const tls_server = @import("crypto/tls.zig");
pub const logger = @import("infra/logger.zig");

// Pattern library (Phase 5 / Epic 7)
pub const email = @import("patterns/email.zig");
pub const phone = @import("patterns/phone.zig");
pub const credit_card = @import("patterns/credit_card.zig");
pub const ip_address = @import("patterns/ip_address.zig");
pub const healthcare = @import("patterns/healthcare.zig");
pub const pattern_scanner = @import("patterns/scanner.zig");

// Schema-aware redaction (Phase 5 / Epic 8)
pub const schema = @import("schema/schema.zig");
pub const json_redactor = @import("schema/json_redactor.zig");
pub const hasher = @import("schema/hasher.zig");

test {
    // Ensure all tests in re-exported modules are discovered by `zig build test`.
    _ = redact;
    _ = entity_mask;
    _ = fuzzy_match;
    _ = versioned_entity_set;
    _ = config;
    _ = file_watcher;
    _ = admin;
    _ = tls_server;
    _ = logger;
    _ = @import("net/http_util.zig");
    // Pattern library
    _ = email;
    _ = phone;
    _ = credit_card;
    _ = ip_address;
    _ = healthcare;
    _ = pattern_scanner;
    // Schema-aware redaction
    _ = schema;
    _ = json_redactor;
    _ = hasher;
}
