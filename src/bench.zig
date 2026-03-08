const std = @import("std");
const redact = @import("redaction/redact.zig");
const entity_mask = @import("redaction/entity_mask.zig");
const fuzzy_match = @import("redaction/fuzzy_match.zig");
const email_pattern = @import("patterns/email.zig");
const phone_pattern = @import("patterns/phone.zig");
const credit_card_pattern = @import("patterns/credit_card.zig");
const ip_address_pattern = @import("patterns/ip_address.zig");
const healthcare_pattern = @import("patterns/healthcare.zig");

/// Write a formatted string to stderr via std.debug.print for reliable output.
fn println(comptime fmt: []const u8, args: anytype) void {
    std.debug.print(fmt ++ "\n", args);
}

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    println("", .{});
    println("=== NanoMask Pipeline Benchmarks ===", .{});
    println("", .{});

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
        println("Stage 1 | SIMD SSN Redaction  | {d:>8.1} MB/s | {d:>4} iter x {d} bytes", .{
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
        println("Stage 2 | Aho-Corasick Mask   | {d:>8.1} MB/s | {d:>4} iter x {d} bytes", .{
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
        println("Stage 3 | Myers' Fuzzy Match  | {d:>8.1} MB/s | {d:>4} iter x {d} bytes", .{
            mb_per_sec, iterations, payload_size,
        });
    }

    // --- Stage 2C: Chunked Aho-Corasick Mask ---
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

        const chunk_size: usize = 4096;
        var timer = std.time.Timer.start() catch return;
        const iterations = 50;
        var run: usize = 0;
        while (run < iterations) : (run += 1) {
            var state = em.initChunkState();
            defer state.deinit(allocator);
            var offset: usize = 0;
            while (offset < payload_size) {
                const end = @min(offset + chunk_size, payload_size);
                const result = try em.maskChunked(payload[offset..end], &state, allocator);
                allocator.free(result);
                offset = end;
            }
            const flushed = try state.flush(&em, allocator);
            allocator.free(flushed);
        }
        const elapsed_ns = timer.read();
        const total_bytes = payload_size * iterations;
        const mb_per_sec = (@as(f64, @floatFromInt(total_bytes)) /
            @as(f64, @floatFromInt(elapsed_ns))) * 1_000_000_000.0 / (1024.0 * 1024.0);
        println("Stage2C | Chunked AC Mask     | {d:>8.1} MB/s | {d:>4} iter x {d} bytes ({}B chunks)", .{
            mb_per_sec, iterations, payload_size, chunk_size,
        });
    }

    // --- Stage 3C: Chunked Fuzzy Match ---
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

        const chunk_size: usize = 4096;
        var timer = std.time.Timer.start() catch return;
        const iterations = 10;
        var run: usize = 0;
        while (run < iterations) : (run += 1) {
            var state = fm.initChunkState();
            defer state.deinit(allocator);
            var offset: usize = 0;
            while (offset < payload_size) {
                const end = @min(offset + chunk_size, payload_size);
                const result = try fm.fuzzyRedactChunked(payload[offset..end], &state, &aliases, &.{}, allocator);
                allocator.free(result);
                offset = end;
            }
            const flushed = try state.flush(&fm, &aliases, &.{}, allocator);
            allocator.free(flushed);
        }
        const elapsed_ns = timer.read();
        const total_bytes = payload_size * iterations;
        const mb_per_sec = (@as(f64, @floatFromInt(total_bytes)) /
            @as(f64, @floatFromInt(elapsed_ns))) * 1_000_000_000.0 / (1024.0 * 1024.0);
        println("Stage3C | Chunked Fuzzy Match | {d:>8.1} MB/s | {d:>4} iter x {d} bytes ({}B chunks)", .{
            mb_per_sec, iterations, payload_size, chunk_size,
        });
    }

    println("", .{});
    println("--- Pattern Library ---", .{});
    println("", .{});

    // --- Stage 4: Email Redaction ---
    {
        const payload_size = 1024 * 1024;
        const payload = try allocator.alloc(u8, payload_size);
        defer allocator.free(payload);
        @memset(payload, 'a');

        const sample = " user@example.com ";
        var pos: usize = 100;
        while (pos + sample.len <= payload_size) {
            @memcpy(payload[pos..][0..sample.len], sample);
            pos += 200;
        }

        var timer = std.time.Timer.start() catch return;
        const iterations = 100;
        var run: usize = 0;
        while (run < iterations) : (run += 1) {
            const result = try email_pattern.redactEmails(payload, allocator);
            allocator.free(result);
        }
        const elapsed_ns = timer.read();
        const total_bytes = payload_size * iterations;
        const mb_per_sec = (@as(f64, @floatFromInt(total_bytes)) /
            @as(f64, @floatFromInt(elapsed_ns))) * 1_000_000_000.0 / (1024.0 * 1024.0);
        println("Stage 4 | Email Redaction     | {d:>8.1} MB/s | {d:>4} iter x {d} bytes", .{
            mb_per_sec, iterations, payload_size,
        });
    }

    // --- Stage 5: Phone Redaction ---
    {
        const payload_size = 1024 * 1024;
        const payload = try allocator.alloc(u8, payload_size);
        defer allocator.free(payload);
        @memset(payload, 'a');

        const sample = " (555) 234-5678 ";
        var pos: usize = 100;
        while (pos + sample.len <= payload_size) {
            @memcpy(payload[pos..][0..sample.len], sample);
            pos += 200;
        }

        var timer = std.time.Timer.start() catch return;
        const iterations = 100;
        var run: usize = 0;
        while (run < iterations) : (run += 1) {
            const result = try phone_pattern.redactPhones(payload, allocator);
            allocator.free(result);
        }
        const elapsed_ns = timer.read();
        const total_bytes = payload_size * iterations;
        const mb_per_sec = (@as(f64, @floatFromInt(total_bytes)) /
            @as(f64, @floatFromInt(elapsed_ns))) * 1_000_000_000.0 / (1024.0 * 1024.0);
        println("Stage 5 | Phone Redaction     | {d:>8.1} MB/s | {d:>4} iter x {d} bytes", .{
            mb_per_sec, iterations, payload_size,
        });
    }

    // --- Stage 6: Credit Card Redaction ---
    {
        const payload_size = 1024 * 1024;
        const payload = try allocator.alloc(u8, payload_size);
        defer allocator.free(payload);
        @memset(payload, 'a');

        const sample = " 4111-1111-1111-1111 ";
        var pos: usize = 100;
        while (pos + sample.len <= payload_size) {
            @memcpy(payload[pos..][0..sample.len], sample);
            pos += 200;
        }

        var timer = std.time.Timer.start() catch return;
        const iterations = 100;
        var run: usize = 0;
        while (run < iterations) : (run += 1) {
            const result = try credit_card_pattern.redactCreditCards(payload, allocator);
            allocator.free(result);
        }
        const elapsed_ns = timer.read();
        const total_bytes = payload_size * iterations;
        const mb_per_sec = (@as(f64, @floatFromInt(total_bytes)) /
            @as(f64, @floatFromInt(elapsed_ns))) * 1_000_000_000.0 / (1024.0 * 1024.0);
        println("Stage 6 | Credit Card Redact  | {d:>8.1} MB/s | {d:>4} iter x {d} bytes", .{
            mb_per_sec, iterations, payload_size,
        });
    }

    // --- Stage 7: IP Address Redaction ---
    {
        const payload_size = 1024 * 1024;
        const payload = try allocator.alloc(u8, payload_size);
        defer allocator.free(payload);
        @memset(payload, 'a');

        const sample = " 192.168.1.42 ";
        var pos: usize = 100;
        while (pos + sample.len <= payload_size) {
            @memcpy(payload[pos..][0..sample.len], sample);
            pos += 200;
        }

        var timer = std.time.Timer.start() catch return;
        const iterations = 100;
        var run: usize = 0;
        while (run < iterations) : (run += 1) {
            const result = try ip_address_pattern.redactIpAddresses(payload, allocator);
            allocator.free(result);
        }
        const elapsed_ns = timer.read();
        const total_bytes = payload_size * iterations;
        const mb_per_sec = (@as(f64, @floatFromInt(total_bytes)) /
            @as(f64, @floatFromInt(elapsed_ns))) * 1_000_000_000.0 / (1024.0 * 1024.0);
        println("Stage 7 | IP Address Redact   | {d:>8.1} MB/s | {d:>4} iter x {d} bytes", .{
            mb_per_sec, iterations, payload_size,
        });
    }

    // --- Stage 8: Healthcare ID Redaction ---
    {
        const payload_size = 1024 * 1024;
        const payload = try allocator.alloc(u8, payload_size);
        defer allocator.free(payload);
        @memset(payload, 'a');

        const sample = " MRN: 12345678 ";
        var pos: usize = 100;
        while (pos + sample.len <= payload_size) {
            @memcpy(payload[pos..][0..sample.len], sample);
            pos += 200;
        }

        var timer = std.time.Timer.start() catch return;
        const iterations = 100;
        var run: usize = 0;
        while (run < iterations) : (run += 1) {
            const result = try healthcare_pattern.redactHealthcare(payload, allocator);
            allocator.free(result);
        }
        const elapsed_ns = timer.read();
        const total_bytes = payload_size * iterations;
        const mb_per_sec = (@as(f64, @floatFromInt(total_bytes)) /
            @as(f64, @floatFromInt(elapsed_ns))) * 1_000_000_000.0 / (1024.0 * 1024.0);
        println("Stage 8 | Healthcare Redact   | {d:>8.1} MB/s | {d:>4} iter x {d} bytes", .{
            mb_per_sec, iterations, payload_size,
        });
    }

    println("", .{});
    println("===================================", .{});
}
