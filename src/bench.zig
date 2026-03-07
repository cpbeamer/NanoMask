const std = @import("std");
const redact = @import("redact.zig");
const entity_mask = @import("entity_mask.zig");
const fuzzy_match = @import("fuzzy_match.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("\n=== NanoMask Pipeline Benchmarks ===\n\n", .{});

    // --- Stage 1: SIMD SSN Redaction ---
    {
        const payload_size = 1024 * 1024;
        var buf: [payload_size]u8 = undefined;
        @memset(&buf, 'a');
        var pos: usize = 0;
        while (pos + 11 <= payload_size) : (pos += 100) {
            const ssn = "123-45-6789";
            @memcpy(buf[pos..][0..ssn.len], ssn);
        }

        var timer = std.time.Timer.start() catch return;
        const iterations = 100;
        var run: usize = 0;
        while (run < iterations) : (run += 1) {
            // Reset SSNs for each iteration (redactSsn mutates in-place)
            pos = 0;
            while (pos + 11 <= payload_size) : (pos += 100) {
                const ssn = "123-45-6789";
                @memcpy(buf[pos..][0..ssn.len], ssn);
            }
            redact.redactSsn(&buf);
        }
        const elapsed_ns = timer.read();
        const total_bytes = payload_size * iterations;
        const mb_per_sec = (@as(f64, @floatFromInt(total_bytes)) /
            @as(f64, @floatFromInt(elapsed_ns))) * 1_000_000_000.0 / (1024.0 * 1024.0);
        std.debug.print("Stage 1 | SIMD SSN Redaction  | {d:>8.1} MB/s | {d:>4} iterations x {d} bytes\n", .{
            mb_per_sec, iterations, payload_size,
        });
    }

    // --- Stage 2: Aho-Corasick Entity Mask ---
    {
        const names = [_][]const u8{
            "John Doe", "Jane Smith", "Dr. Johnson", "Mary Williams", "Robert Brown",
        };
        var em = try entity_mask.EntityMap.init(allocator, &names);
        defer em.deinit();

        const payload_size = 1024 * 1024;
        const payload = try allocator.alloc(u8, payload_size);
        defer allocator.free(payload);
        @memset(payload, 'a');

        const name_str = " John Doe ";
        var pos: usize = 100;
        while (pos + name_str.len <= payload_size) {
            @memcpy(payload[pos..][0..name_str.len], name_str);
            pos += 200;
        }

        var timer = std.time.Timer.start() catch return;
        const iterations = 50;
        var run: usize = 0;
        while (run < iterations) : (run += 1) {
            const result = try em.mask(payload, allocator);
            allocator.free(result);
        }
        const elapsed_ns = timer.read();
        const total_bytes = payload_size * iterations;
        const mb_per_sec = (@as(f64, @floatFromInt(total_bytes)) /
            @as(f64, @floatFromInt(elapsed_ns))) * 1_000_000_000.0 / (1024.0 * 1024.0);
        std.debug.print("Stage 2 | Aho-Corasick Mask   | {d:>8.1} MB/s | {d:>4} iterations x {d} bytes\n", .{
            mb_per_sec, iterations, payload_size,
        });
    }

    // --- Stage 3: Myers' Fuzzy Match ---
    {
        const names = [_][]const u8{
            "John Doe", "Jane Smith", "Dr. Johnson", "Mary Williams", "Robert Brown",
        };
        const aliases = [_][]const u8{
            "Entity_A", "Entity_B", "Entity_C", "Entity_D", "Entity_E",
        };
        var fm = try fuzzy_match.FuzzyMatcher.init(allocator, &names, &aliases, 0.80);
        defer fm.deinit();

        const payload_size = 256 * 1024;
        const payload = try allocator.alloc(u8, payload_size);
        defer allocator.free(payload);
        @memset(payload, 'a');

        const corrupted = " J0hn Doe ";
        var pos: usize = 100;
        while (pos + corrupted.len <= payload_size) {
            @memcpy(payload[pos..][0..corrupted.len], corrupted);
            pos += 200;
        }

        var timer = std.time.Timer.start() catch return;
        const iterations = 10;
        var run: usize = 0;
        while (run < iterations) : (run += 1) {
            const result = try fm.fuzzyRedact(payload, &aliases, &.{}, allocator);
            allocator.free(result);
        }
        const elapsed_ns = timer.read();
        const total_bytes = payload_size * iterations;
        const mb_per_sec = (@as(f64, @floatFromInt(total_bytes)) /
            @as(f64, @floatFromInt(elapsed_ns))) * 1_000_000_000.0 / (1024.0 * 1024.0);
        std.debug.print("Stage 3 | Myers' Fuzzy Match  | {d:>8.1} MB/s | {d:>4} iterations x {d} bytes\n", .{
            mb_per_sec, iterations, payload_size,
        });
    }

    std.debug.print("\n===================================\n", .{});
}
