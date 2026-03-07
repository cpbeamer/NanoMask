const std = @import("std");

// ---------------------------------------------------------------------------
// SIMD-accelerated SSN redaction engine
// ---------------------------------------------------------------------------
// Strategy: scan for '-' characters first (rare in typical payloads) using
// @Vector(16, u8) SIMD loads, then validate the full XXX-XX-XXXX digit
// pattern only at candidate positions. This avoids touching most bytes.
// ---------------------------------------------------------------------------

const vector_len = 16;
const Vector = @Vector(vector_len, u8);

/// Produce a bitmask where bit `i` is set if `vec[i] == needle`.
inline fn dashMask(vec: Vector) u16 {
    const dashes: Vector = @splat('-');
    const match_result: @Vector(vector_len, u1) = @bitCast(vec == dashes);
    return @bitCast(match_result);
}

/// Validate and redact a full SSN at `buf[start .. start+11]`.
/// Returns true (and mutates in-place) if the pattern matches XXX-XX-XXXX.
inline fn tryRedactAt(buf: []u8, start: usize) bool {
    if (start + 11 > buf.len) return false;

    const b = buf[start..][0..11];

    // Dashes at fixed offsets
    if (b[3] != '-' or b[6] != '-') return false;

    // All other positions must be ASCII digits
    inline for ([_]usize{ 0, 1, 2, 4, 5, 7, 8, 9, 10 }) |off| {
        if (!std.ascii.isDigit(b[off])) return false;
    }

    // Pattern confirmed — redact digits in-place
    inline for ([_]usize{ 0, 1, 2, 4, 5, 7, 8, 9, 10 }) |off| {
        b[off] = '*';
    }
    return true;
}

/// High-performance SSN redactor using SIMD dash scanning.
/// Falls back to scalar tail processing for the last < 16 bytes.
pub fn redactSsn(buffer: []u8) void {
    if (buffer.len < 11) return;

    var i: usize = 0;

    // --- SIMD pass: scan 16 bytes at a time for '-' candidates -----------
    while (i + vector_len + 10 <= buffer.len) {
        // We need dashes at relative offsets +3 and +6 from any SSN start.
        // A dash found at absolute position `d` could be offset +3 of an SSN
        // starting at `d - 3`, OR offset +6 of one starting at `d - 6`.
        const chunk: Vector = buffer[i..][0..vector_len].*;
        var mask = dashMask(chunk);

        if (mask == 0) {
            // No dashes in this 16-byte window — skip entirely.
            i += vector_len;
            continue;
        }

        // Process each dash position in the mask
        while (mask != 0) {
            const bit_pos: u4 = @truncate(@ctz(mask));
            const dash_abs = i + bit_pos;

            // This dash could be at SSN offset +3 → start = dash_abs - 3
            if (dash_abs >= 3) {
                const start = dash_abs - 3;
                if (tryRedactAt(buffer, start)) {
                    // Successfully redacted — jump past this SSN entirely.
                    // Set i to end of SSN so outer loop re-scans from there.
                    i = start + 11;
                    // Re-enter outer loop (mask is now stale).
                    break;
                }
            }

            // Clear this bit and move to next dash
            mask &= mask - 1;
        } else {
            // Exhausted all dashes in this chunk with no redaction — advance.
            i += 1;
        }
    }

    // --- Scalar tail: handle remaining bytes that don't fill a vector -----
    // The SIMD loop advances by vector_len when no dashes are found. An SSN's
    // first dash is at offset +3, so an SSN starting 3 bytes before the
    // current `i` could have its first dash just past the last SIMD window.
    // Rewind by 3 to catch this edge case.
    i = if (i >= 3) i - 3 else 0;
    while (i + 11 <= buffer.len) {
        if (tryRedactAt(buffer, i)) {
            i += 11;
        } else {
            i += 1;
        }
    }
}

/// Scalar-only reference implementation (kept for benchmarking comparisons).
pub fn redactSsnScalar(buffer: []u8) void {
    var i: usize = 0;
    while (i + 11 <= buffer.len) {
        if (std.ascii.isDigit(buffer[i]) and std.ascii.isDigit(buffer[i + 1]) and std.ascii.isDigit(buffer[i + 2]) and
            buffer[i + 3] == '-' and
            std.ascii.isDigit(buffer[i + 4]) and std.ascii.isDigit(buffer[i + 5]) and
            buffer[i + 6] == '-' and
            std.ascii.isDigit(buffer[i + 7]) and std.ascii.isDigit(buffer[i + 8]) and std.ascii.isDigit(buffer[i + 9]) and std.ascii.isDigit(buffer[i + 10]))
        {
            buffer[i] = '*';
            buffer[i + 1] = '*';
            buffer[i + 2] = '*';
            buffer[i + 4] = '*';
            buffer[i + 5] = '*';
            buffer[i + 7] = '*';
            buffer[i + 8] = '*';
            buffer[i + 9] = '*';
            buffer[i + 10] = '*';
            i += 11;
        } else {
            i += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Chunked SSN Redaction — streaming-compatible interface
// ---------------------------------------------------------------------------
// An SSN is exactly 11 bytes (XXX-XX-XXXX). When processing data in chunks,
// up to 10 bytes of a pattern can spill from one chunk to the next.
//
// Strategy: withhold the last 10 bytes of each chunk as "pending". When the
// next chunk arrives, combine pending + chunk prefix, scan for boundary SSNs,
// then finalize the old pending bytes and keep a new pending tail. This ensures
// boundary-spanning SSNs are always caught before bytes are committed.
//
// Callers own the state and pass it into each successive call. After all
// chunks are processed, call `flush()` to emit the final pending bytes.
// ---------------------------------------------------------------------------

/// Maximum overlap: SSN is 11 bytes, so at most 10 bytes can span a boundary.
const ssn_overlap = 10;

/// Result of a single `redactSsnChunked` call.
pub const SsnChunkResult = struct {
    /// Finalized bytes from the previous chunk's tail (boundary-scanned).
    /// Valid until the next `redactSsnChunked` or `flush` call.
    finalized: []u8,
    /// Safe-to-emit sub-slice of the current chunk (may be empty for small chunks).
    emitted: []u8,
};

/// Persistent state for chunked SSN redaction.
/// Caller initializes once, passes to each `redactSsnChunked` / `flush` call.
pub const SsnChunkState = struct {
    /// Bytes withheld from the previous chunk, not yet committed.
    pending: [ssn_overlap]u8 = undefined,
    /// Finalized pending bytes (output buffer for the caller).
    finalized: [ssn_overlap]u8 = undefined,
    /// How many bytes in `pending` are valid (0 on first call).
    len: u8 = 0,

    /// Emit any remaining pending bytes (call after the last chunk).
    /// Returns a slice into `self.finalized` — valid until the next call.
    pub fn flush(self: *SsnChunkState) []u8 {
        if (self.len == 0) return self.finalized[0..0];
        // Redact any SSN patterns within the remaining pending bytes.
        redactSsn(self.pending[0..self.len]);
        @memcpy(self.finalized[0..self.len], self.pending[0..self.len]);
        const out_len = self.len;
        self.len = 0;
        return self.finalized[0..out_len];
    }
};

/// Process a single chunk for SSN redaction in streaming mode.
///
/// Returns finalized bytes from the previous chunk's tail (after boundary
/// scanning) and the safe-to-emit sub-slice of the current chunk.
///
/// The caller should emit `result.finalized` then `result.emitted`.
/// After all chunks, call `state.flush()` for the remaining tail.
pub fn redactSsnChunked(chunk: []u8, state: *SsnChunkState) SsnChunkResult {
    if (chunk.len == 0) {
        return .{ .finalized = state.finalized[0..0], .emitted = chunk[0..0] };
    }

    const old_pending_len: usize = state.len;
    const total = old_pending_len + chunk.len;

    // If the combined pending + chunk is too small to contain an SSN,
    // just accumulate into pending without emitting anything.
    if (total <= ssn_overlap) {
        @memcpy(state.pending[old_pending_len..][0..chunk.len], chunk);
        state.len = @intCast(total);
        return .{ .finalized = state.finalized[0..0], .emitted = chunk[0..0] };
    }

    // --- Phase 1: scan for SSNs spanning the pending/chunk boundary ---
    if (old_pending_len > 0) {
        var boundary: [ssn_overlap + 11]u8 = undefined;
        @memcpy(boundary[0..old_pending_len], state.pending[0..old_pending_len]);
        const take: usize = @min(11, chunk.len);
        @memcpy(boundary[old_pending_len..][0..take], chunk[0..take]);
        const boundary_len = old_pending_len + take;

        var i: usize = 0;
        while (i + 11 <= boundary_len) {
            if (i >= old_pending_len) break;
            if (tryRedactAt(&boundary, i)) {
                const pending_end = @min(i + 11, old_pending_len);
                @memcpy(state.pending[i..pending_end], boundary[i..pending_end]);
                if (i + 11 > old_pending_len) {
                    const chunk_end: usize = i + 11 - old_pending_len;
                    @memcpy(chunk[0..chunk_end], boundary[old_pending_len..][0..chunk_end]);
                }
                i += 11;
            } else {
                i += 1;
            }
        }
    }

    // --- Phase 2: redact SSNs fully within the chunk ---
    redactSsn(chunk);

    // --- Phase 3: finalize old pending, withhold new tail ---
    @memcpy(state.finalized[0..old_pending_len], state.pending[0..old_pending_len]);

    // Withhold the last ssn_overlap bytes of chunk as new pending.
    const new_pending_len: u8 = @intCast(@min(ssn_overlap, chunk.len));
    const emit_len = chunk.len - new_pending_len;

    state.len = new_pending_len;
    @memcpy(state.pending[0..new_pending_len], chunk[chunk.len - new_pending_len ..]);

    return .{
        .finalized = state.finalized[0..old_pending_len],
        .emitted = chunk[0..emit_len],
    };
}

// ---------------------------------------------------------------------------
// Unit Tests
// ---------------------------------------------------------------------------

test "redactSsn - basic multi-SSN redaction" {
    var buf = "Hello my SSN is 123-45-6789 and my friend is 987-65-4321!".*;
    redactSsn(&buf);
    try std.testing.expectEqualStrings("Hello my SSN is ***-**-**** and my friend is ***-**-****!", &buf);
}

test "redactSsn - no SSNs present" {
    var buf = "This string has no sensitive data at all.".*;
    const expected = "This string has no sensitive data at all.";
    redactSsn(&buf);
    try std.testing.expectEqualStrings(expected, &buf);
}

test "redactSsn - SSN at start of buffer" {
    var buf = "123-45-6789 is at the start".*;
    redactSsn(&buf);
    try std.testing.expectEqualStrings("***-**-**** is at the start", &buf);
}

test "redactSsn - SSN at end of buffer" {
    var buf = "SSN at end: 123-45-6789".*;
    redactSsn(&buf);
    try std.testing.expectEqualStrings("SSN at end: ***-**-****", &buf);
}

test "redactSsn - adjacent SSNs no separator" {
    var buf = "111-22-3333444-55-6666".*;
    redactSsn(&buf);
    try std.testing.expectEqualStrings("***-**-*******-**-****", &buf);
}

test "redactSsn - partial pattern is not redacted" {
    var buf = "12-34-5678 is not an SSN".*;
    const expected = "12-34-5678 is not an SSN";
    redactSsn(&buf);
    try std.testing.expectEqualStrings(expected, &buf);
}

test "redactSsn - empty buffer" {
    var buf: [0]u8 = .{};
    redactSsn(&buf);
    try std.testing.expectEqual(@as(usize, 0), buf.len);
}

test "redactSsn - SSN with surrounding digits" {
    var buf = "9123-45-67890".*;
    redactSsn(&buf);
    try std.testing.expectEqualStrings("9***-**-****0", &buf);
}

test "redactSsn - scalar fallback matches SIMD" {
    const input = "prefix 111-22-3333 mid 444-55-6666 end 777-88-9999 tail".*;
    var simd_buf = input;
    var scalar_buf = input;
    redactSsn(&simd_buf);
    redactSsnScalar(&scalar_buf);
    try std.testing.expectEqualStrings(&scalar_buf, &simd_buf);
}

test "redactSsn - large buffer with scattered SSNs" {
    var buf = "aaaaaaaaaa123-45-6789bbbbbbbbbb987-65-4321cccccccccc555-12-9876ddddddddddeeeeee".*;
    redactSsn(&buf);
    try std.testing.expectEqualStrings("aaaaaaaaaa***-**-****bbbbbbbbbb***-**-****cccccccccc***-**-****ddddddddddeeeeee", &buf);
}

// ---------------------------------------------------------------------------
// Chunked SSN Redaction Tests
// ---------------------------------------------------------------------------

/// Test helper: run chunked SSN redaction on `input` using the given chunk size,
/// collecting all output (finalized + emitted + flush) into one contiguous buffer.
fn runChunkedSsn(input: []const u8, chunk_size: usize, allocator: std.mem.Allocator) ![]u8 {
    const buf = try allocator.dupe(u8, input);
    defer allocator.free(buf);

    var output: std.ArrayListUnmanaged(u8) = .empty;
    errdefer output.deinit(allocator);

    var state = SsnChunkState{};
    var offset: usize = 0;

    while (offset < buf.len) {
        const end = @min(offset + chunk_size, buf.len);
        const result = redactSsnChunked(buf[offset..end], &state);
        try output.appendSlice(allocator, result.finalized);
        try output.appendSlice(allocator, result.emitted);
        offset = end;
    }

    // Flush remaining pending bytes.
    const flushed = state.flush();
    try output.appendSlice(allocator, flushed);

    return try output.toOwnedSlice(allocator);
}

test "redactSsnChunked - SSN fully within one chunk" {
    const allocator = std.testing.allocator;
    const result = try runChunkedSsn("Hello 123-45-6789 world", 64, allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Hello ***-**-**** world", result);
}

test "redactSsnChunked - SSN split across two chunks at every boundary" {
    const allocator = std.testing.allocator;
    const ssn = "123-45-6789";

    // Reference: single-pass redaction
    var reference = "123-45-6789".*;
    redactSsn(&reference);

    // Split at every possible byte boundary (chunk size = split offset)
    for (1..11) |split| {
        const result = try runChunkedSsn(ssn, split, allocator);
        defer allocator.free(result);
        try std.testing.expectEqualStrings(&reference, result);
    }
}

test "redactSsnChunked - no SSNs across multiple chunks" {
    const allocator = std.testing.allocator;
    const result = try runChunkedSsn("Hello world, this has no sensitive data.", 13, allocator);
    defer allocator.free(result);
    try std.testing.expectEqualStrings("Hello world, this has no sensitive data.", result);
}

test "redactSsnChunked - equivalence vs single-pass on 1 MB payload" {
    const allocator = std.testing.allocator;
    const payload_size = 1024 * 1024;

    // Build reference payload — SSNs planted every 100 bytes.
    const reference = try allocator.alloc(u8, payload_size);
    defer allocator.free(reference);
    @memset(reference, 'a');
    {
        var pos: usize = 50;
        while (pos + 11 <= payload_size) {
            @memcpy(reference[pos..][0..11], "123-45-6789");
            pos += 100;
        }
    }

    // Single-pass result
    const single_buf = try allocator.dupe(u8, reference);
    defer allocator.free(single_buf);
    redactSsn(single_buf);

    // Chunked result — process in 64-byte chunks
    const chunked_result = try runChunkedSsn(reference, 64, allocator);
    defer allocator.free(chunked_result);

    try std.testing.expectEqualStrings(single_buf, chunked_result);
}

// ---------------------------------------------------------------------------
// Benchmark
// ---------------------------------------------------------------------------

test "bench - redactSsn throughput" {
    // 1 MB payload with SSNs every ~100 bytes.
    const payload_size = 1024 * 1024;
    var buf: [payload_size]u8 = undefined;

    // Fill with 'a' and plant SSNs every 100 bytes
    @memset(&buf, 'a');
    var pos: usize = 50;
    while (pos + 11 <= payload_size) {
        @memcpy(buf[pos..][0..11], "123-45-6789");
        pos += 100;
    }

    var timer = std.time.Timer.start() catch {
        // Timer not available on all platforms — skip silently.
        return;
    };

    const iterations = 100;
    var run: usize = 0;
    while (run < iterations) : (run += 1) {
        // Re-plant SSNs (they get masked each iteration)
        pos = 50;
        while (pos + 11 <= payload_size) {
            @memcpy(buf[pos..][0..11], "123-45-6789");
            pos += 100;
        }
        redactSsn(&buf);
    }

    const elapsed_ns = timer.read();
    const total_bytes = payload_size * iterations;
    const ns_per_byte = elapsed_ns / total_bytes;
    const mb_per_sec = (@as(f64, @floatFromInt(total_bytes)) / @as(f64, @floatFromInt(elapsed_ns))) * 1_000_000_000.0 / (1024.0 * 1024.0);

    std.debug.print("\n\n\n[BENCH] SIMD redactSsn: {d} ns/byte, {d:.1} MB/s ({} iterations x {} bytes)\n", .{
        ns_per_byte,
        mb_per_sec,
        iterations,
        payload_size,
    });
}
