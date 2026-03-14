const std = @import("std");
const entity_mask = @import("../redaction/entity_mask.zig");
const hasher_mod = @import("../schema/hasher.zig");

// ===========================================================================
// NMV3-015: Entity & Tokenization Scaling Tests
//
// Validates that the entity masking engine works correctly with entity sets
// much larger than the previous 702-entity cap, and that hasher stats
// accumulate correctly under high cardinality.
// ===========================================================================

// ---------------------------------------------------------------------------
// Alias generation: unbounded numeric scheme
// ---------------------------------------------------------------------------

test "scaling - alias generation produces Entity_<N> format" {
    const allocator = std.testing.allocator;

    // Verify through the public EntityMap API that aliases use numeric format
    var em = try entity_mask.EntityMap.init(allocator, &.{ "Alice", "Bob", "Charlie" });
    defer em.deinit();

    try std.testing.expectEqualStrings("Entity_1", em.aliases[0]);
    try std.testing.expectEqualStrings("Entity_2", em.aliases[1]);
    try std.testing.expectEqualStrings("Entity_3", em.aliases[2]);
}

// ---------------------------------------------------------------------------
// Large entity set: 1000 entities
// ---------------------------------------------------------------------------

test "scaling - 1000 entity EntityMap builds and masks" {
    const allocator = std.testing.allocator;

    var names_buf: [1000][]const u8 = undefined;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const arena_alloc = arena.allocator();

    for (0..1000) |i| {
        names_buf[i] = try std.fmt.allocPrint(arena_alloc, "TestPerson{d:0>4}", .{i});
    }

    var em = try entity_mask.EntityMap.init(allocator, names_buf[0..1000]);
    defer em.deinit();

    // Mask a string containing the first and last entity
    const input = try std.fmt.allocPrint(allocator, "Patient {s} was referred to {s}.", .{
        names_buf[0],
        names_buf[999],
    });
    defer allocator.free(input);

    const masked = try em.mask(input, allocator);
    defer allocator.free(masked);

    // Should not contain the original names
    try std.testing.expect(std.mem.indexOf(u8, masked, "TestPerson0000") == null);
    try std.testing.expect(std.mem.indexOf(u8, masked, "TestPerson0999") == null);

    // Should contain the numeric aliases
    try std.testing.expect(std.mem.indexOf(u8, masked, "Entity_1") != null);
    try std.testing.expect(std.mem.indexOf(u8, masked, "Entity_1000") != null);
}

// ---------------------------------------------------------------------------
// Large entity set: 5000 entities
// ---------------------------------------------------------------------------

test "scaling - 5000 entity EntityMap builds successfully" {
    const allocator = std.testing.allocator;

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const arena_alloc = arena.allocator();

    var names = std.ArrayListUnmanaged([]const u8).empty;
    defer names.deinit(allocator);

    for (0..5000) |i| {
        const name = try std.fmt.allocPrint(arena_alloc, "Person{d:0>5}", .{i});
        try names.append(allocator, name);
    }

    var em = try entity_mask.EntityMap.init(allocator, names.items);
    defer em.deinit();

    // Verify entity count
    try std.testing.expectEqual(@as(usize, 5000), em.names.len);
    try std.testing.expectEqual(@as(usize, 5000), em.aliases.len);
}

// ---------------------------------------------------------------------------
// Hasher stats: miss and eviction tracking
// ---------------------------------------------------------------------------

test "scaling - hasher stats track misses" {
    const allocator = std.testing.allocator;

    var hasher = try hasher_mod.Hasher.init(null, allocator);
    defer hasher.deinit();

    // Hash a value to populate the reverse map
    const token = try hasher.hash("original_value");
    defer allocator.free(token);

    // Stats should show 1 entry, 0 misses
    const s1 = hasher.stats();
    try std.testing.expectEqual(@as(usize, 1), s1.reverse_map_size);
    try std.testing.expectEqual(@as(u64, 0), s1.miss_count);

    // Unhash with a valid-looking but unknown PSEUDO_ token — should miss
    const unknown_response = "value is PSEUDO_deadbeef12345678 here";
    const restored = try hasher.unhashJson(unknown_response, allocator);
    defer allocator.free(restored);

    const s2 = hasher.stats();
    try std.testing.expectEqual(@as(u64, 1), s2.miss_count);
}

test "scaling - hasher eviction_cycle_count starts at zero" {
    // Full eviction-cycle testing (triggering evictAll directly) lives in
    // hasher.zig where the private method is accessible. This test verifies
    // the stats surface via the public API under normal operating conditions.
    const allocator = std.testing.allocator;

    var hasher = try hasher_mod.Hasher.init(null, allocator);
    defer hasher.deinit();

    // Before any hashing, all stats should be zero
    const s0 = hasher.stats();
    try std.testing.expectEqual(@as(usize, 0), s0.reverse_map_size);
    try std.testing.expectEqual(@as(u64, 0), s0.miss_count);
    try std.testing.expectEqual(@as(u64, 0), s0.eviction_cycle_count);

    // After hashing, reverse_map_size grows and cycle counter stays at 0
    const tok = try hasher.hash("SomePatient");
    defer allocator.free(tok);
    const s1 = hasher.stats();
    try std.testing.expectEqual(@as(usize, 1), s1.reverse_map_size);
    try std.testing.expectEqual(@as(u64, 0), s1.eviction_cycle_count);
}

// ---------------------------------------------------------------------------
// Hasher high-cardinality: many unique tokens
// ---------------------------------------------------------------------------

test "scaling - hasher handles 1000 unique tokens" {
    const allocator = std.testing.allocator;

    var hasher = try hasher_mod.Hasher.init(null, allocator);
    defer hasher.deinit();

    var tokens = std.ArrayListUnmanaged([]u8).empty;
    defer {
        for (tokens.items) |t| allocator.free(t);
        tokens.deinit(allocator);
    }

    for (0..1000) |i| {
        var buf: [32]u8 = undefined;
        const original = try std.fmt.bufPrint(&buf, "value_{d}", .{i});
        const token = try hasher.hash(original);
        try tokens.append(allocator, token);
    }

    // Should have 1000 entries (no collisions expected with HMAC-SHA256)
    try std.testing.expectEqual(@as(usize, 1000), hasher.stats().reverse_map_size);

    // Unhash the first and last — should restore correctly
    const first_original = hasher.unhash(tokens.items[0]);
    try std.testing.expect(first_original != null);
    try std.testing.expectEqualStrings("value_0", first_original.?);

    const last_original = hasher.unhash(tokens.items[999]);
    try std.testing.expect(last_original != null);
    try std.testing.expectEqualStrings("value_999", last_original.?);
}
