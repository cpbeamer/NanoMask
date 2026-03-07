//! By convention, root.zig is the root source file when making a library.
//! Re-exports the core NanoMask modules for consumers.
pub const redact = @import("redact.zig");

test {
    // Ensure all tests in re-exported modules are discovered by `zig build test`.
    _ = redact;
}
