const std = @import("std");
const config = @import("config.zig");

/// Thread-safe structured JSON logger for compliance-grade audit logging.
/// Outputs newline-delimited JSON (NDJSON) to stderr or a file.
pub const Logger = struct {
    mutex: std.Thread.Mutex,
    min_level: config.LogLevel,
    audit_enabled: bool,
    /// The output file handle (stderr or a log file). Used for production writes.
    output_file: ?std.fs.File,
    /// Optional type-erased writer for test injection. When non-null, writes go
    /// here instead of output_file, allowing tests to capture output into a buffer.
    test_writer: ?std.io.AnyWriter,
    /// When true, the logger owns output_file and closes it on deinit.
    owns_file: bool,
    /// Counts log lines that could not be written due to I/O errors.
    /// Surfaced via /healthz so operators can detect silent log loss.
    dropped_lines: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    pub const OutputWriter = std.io.AnyWriter;

    /// Initialise a Logger writing to stderr (default) or a file.
    /// `log_file_path`: if non-null, open in append mode and write there instead of stderr.
    pub fn init(
        min_level: config.LogLevel,
        audit_enabled: bool,
        log_file_path: ?[]const u8,
    ) !Logger {
        if (log_file_path) |path| {
            const file = try std.fs.cwd().createFile(path, .{
                .truncate = false,
            });
            // Seek to end for append behaviour.
            file.seekFromEnd(0) catch {};
            return .{
                .mutex = .{},
                .min_level = min_level,
                .audit_enabled = audit_enabled,
                .output_file = file,
                .test_writer = null,
                .owns_file = true,
            };
        }
        return .{
            .mutex = .{},
            .min_level = min_level,
            .audit_enabled = audit_enabled,
            .output_file = null,
            .test_writer = null,
            .owns_file = false,
        };
    }

    pub fn deinit(self: *Logger) void {
        if (self.owns_file) {
            if (self.output_file) |fh| {
                fh.close();
                self.output_file = null;
            }
        }
    }

    /// Write bytes to the configured output. Priority:
    ///   1. test_writer (injected buffer for unit tests)
    ///   2. output_file (log file opened in init)
    ///   3. stderr via std.debug.print (default when no file configured)
    fn writeOutput(self: *Logger, data: []const u8) void {
        if (self.test_writer) |tw| {
            tw.writeAll(data) catch {};
        } else if (self.output_file) |fh| {
            fh.writeAll(data) catch {
                // Fallback to stderr so operators see the failure, and track
                // the drop count for /healthz compliance monitoring.
                _ = self.dropped_lines.fetchAdd(1, .monotonic);
                std.debug.print("[LOG_WRITE_FAILED] {s}", .{data});
            };
        } else {
            std.debug.print("{s}", .{data});
        }
    }

    // -----------------------------------------------------------------------
    // Convenience leveled helpers
    // -----------------------------------------------------------------------

    pub fn debug(self: *Logger, msg: []const u8, session_id: ?[]const u8) void {
        self.log(.debug, msg, session_id, &.{});
    }

    pub fn info(self: *Logger, msg: []const u8, session_id: ?[]const u8) void {
        self.log(.info, msg, session_id, &.{});
    }

    pub fn warn(self: *Logger, msg: []const u8, session_id: ?[]const u8) void {
        self.log(.warn, msg, session_id, &.{});
    }

    pub fn err(self: *Logger, msg: []const u8, session_id: ?[]const u8) void {
        self.log(.error_, msg, session_id, &.{});
    }

    // -----------------------------------------------------------------------
    // Generic log with extra key-value pairs
    // -----------------------------------------------------------------------

    pub const KV = struct {
        key: []const u8,
        value: KVValue,
    };

    pub const KVValue = union(enum) {
        string: []const u8,
        int: i64,
        uint: u64,
        float: f64,
        boolean: bool,
    };

    pub const AuditEvent = struct {
        stage: []const u8,
        match_type: []const u8,
        offset: ?u64 = null,
        field_path: ?[]const u8 = null,
        original_length: u64,
        replacement_type: []const u8,
        confidence: ?f64 = null,
    };

    /// Emit a structured JSON log line. Thread-safe — acquires mutex for the
    /// duration of the write so that lines are never interleaved.
    pub fn log(
        self: *Logger,
        level: config.LogLevel,
        msg: []const u8,
        session_id: ?[]const u8,
        extra: []const KV,
    ) void {
        if (@intFromEnum(level) < @intFromEnum(self.min_level)) return;

        // Build the full JSON line into a stack buffer, then write atomically.
        var buf: [8192]u8 = undefined;
        const line = formatLine(&buf, level, msg, session_id, extra) catch {
            // Overflow or formatting failure — emit a minimal fallback so
            // operators know something was dropped rather than silent loss.
            var fallback: [128]u8 = undefined;
            const fb = std.fmt.bufPrint(&fallback, "{{\"level\":\"ERROR\",\"msg\":\"log_format_overflow\",\"dropped_msg\":\"{s}\"}}\n", .{msg[0..@min(msg.len, 64)]}) catch return;
            self.mutex.lock();
            defer self.mutex.unlock();
            self.writeOutput(fb);
            return;
        };

        self.mutex.lock();
        defer self.mutex.unlock();
        self.writeOutput(line);
    }

    /// Emit a redaction audit event. No-op when audit logging is disabled.
    pub fn auditRedaction(
        self: *Logger,
        session_id: []const u8,
        audit_event: AuditEvent,
    ) void {
        if (!self.audit_enabled) return;

        var buf: [8192]u8 = undefined;
        var fbs = std.io.fixedBufferStream(&buf);
        const w = fbs.writer();

        w.writeAll("{\"ts\":\"") catch return;
        writeTimestamp(w) catch return;
        w.writeAll("\",\"level\":\"") catch return;
        w.writeAll(levelStr(.info)) catch return;
        w.writeAll("\",\"event\":\"redaction_audit\",\"session_id\":\"") catch return;
        w.writeAll(session_id) catch return;
        w.writeAll("\",\"stage\":\"") catch return;
        writeJsonEscaped(w, audit_event.stage) catch return;
        w.writeAll("\",\"match_type\":\"") catch return;
        writeJsonEscaped(w, audit_event.match_type) catch return;
        w.writeAll("\"") catch return;
        if (audit_event.offset) |offset| {
            w.writeAll(",\"offset\":") catch return;
            std.fmt.format(w, "{d}", .{offset}) catch return;
        }
        if (audit_event.field_path) |field_path| {
            w.writeAll(",\"field_path\":\"") catch return;
            writeJsonEscaped(w, field_path) catch return;
            w.writeAll("\"") catch return;
        }
        w.writeAll(",\"original_length\":") catch return;
        std.fmt.format(w, "{d}", .{audit_event.original_length}) catch return;
        w.writeAll(",\"replacement_type\":\"") catch return;
        writeJsonEscaped(w, audit_event.replacement_type) catch return;
        w.writeAll("\"") catch return;
        if (audit_event.confidence) |c| {
            w.writeAll(",\"confidence\":") catch return;
            std.fmt.format(w, "{d:.2}", .{c}) catch return;
        }
        w.writeAll("}\n") catch return;

        const line = fbs.getWritten();
        self.mutex.lock();
        defer self.mutex.unlock();
        self.writeOutput(line);
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn formatLine(
        buf: []u8,
        level: config.LogLevel,
        msg: []const u8,
        session_id: ?[]const u8,
        extra: []const KV,
    ) ![]const u8 {
        var fbs = std.io.fixedBufferStream(buf);
        const w = fbs.writer();

        try w.writeAll("{\"ts\":\"");
        try writeTimestamp(w);
        try w.writeAll("\",\"level\":\"");
        try w.writeAll(levelStr(level));
        try w.writeAll("\",\"session_id\":\"");
        if (session_id) |sid| {
            try w.writeAll(sid);
        } else {
            try w.writeAll("-");
        }
        try w.writeAll("\",\"msg\":\"");
        try writeJsonEscaped(w, msg);
        try w.writeAll("\"");

        for (extra) |kv| {
            try w.writeAll(",\"");
            try w.writeAll(kv.key);
            try w.writeAll("\":");
            switch (kv.value) {
                .string => |s| {
                    try w.writeAll("\"");
                    try writeJsonEscaped(w, s);
                    try w.writeAll("\"");
                },
                .int => |v| try std.fmt.format(w, "{d}", .{v}),
                .uint => |v| try std.fmt.format(w, "{d}", .{v}),
                .float => |v| try std.fmt.format(w, "{d:.2}", .{v}),
                .boolean => |v| try w.writeAll(if (v) "true" else "false"),
            }
        }

        try w.writeAll("}\n");
        return fbs.getWritten();
    }

    fn levelStr(level: config.LogLevel) []const u8 {
        return switch (level) {
            .debug => "DEBUG",
            .info => "INFO",
            .warn => "WARN",
            .error_ => "ERROR",
        };
    }

    fn writeTimestamp(writer: anytype) !void {
        // Single clock source avoids TOCTOU race between seconds and
        // sub-second components that could skew timestamps by ~1 s.
        const nanos = std.time.nanoTimestamp();
        // Clamp to zero if the system clock is before epoch (NTP slew, VM
        // snapshot restore, etc.) to avoid @intCast panic on negative values.
        const nanos_u: u64 = if (nanos < 0) 0 else @intCast(@as(u128, @intCast(nanos)));
        const epoch_secs: u64 = nanos_u / std.time.ns_per_s;
        const millis = (nanos_u % std.time.ns_per_s) / std.time.ns_per_ms;

        const es: std.time.epoch.EpochSeconds = .{ .secs = @intCast(epoch_secs) };
        const day_secs = es.getDaySeconds();
        const year_day = es.getEpochDay().calculateYearDay();
        const month_day = year_day.calculateMonthDay();

        try std.fmt.format(writer, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}.{d:0>3}Z", .{
            year_day.year,
            month_day.month.numeric(),
            month_day.day_index + 1,
            day_secs.getHoursIntoDay(),
            day_secs.getMinutesIntoHour(),
            day_secs.getSecondsIntoMinute(),
            millis,
        });
    }

    /// Escape a string for safe embedding in a JSON value.
    /// Processes byte-by-byte; valid multi-byte UTF-8 sequences pass through
    /// unchanged (bytes >= 0x80 are written verbatim). Non-UTF-8 binary input
    /// could produce invalid JSON — callers should ensure text-only payloads.
    fn writeJsonEscaped(writer: anytype, s: []const u8) !void {
        for (s) |c| {
            switch (c) {
                '"' => try writer.writeAll("\\\""),
                '\\' => try writer.writeAll("\\\\"),
                '\n' => try writer.writeAll("\\n"),
                '\r' => try writer.writeAll("\\r"),
                '\t' => try writer.writeAll("\\t"),
                else => {
                    if (c < 0x20) {
                        try std.fmt.format(writer, "\\u{x:0>4}", .{c});
                    } else {
                        try writer.writeByte(c);
                    }
                },
            }
        }
    }
};

/// Generate a random 8-hex-character session ID for request correlation.
pub fn generateSessionId(buf: *[8]u8) []const u8 {
    var random_bytes: [4]u8 = undefined;
    std.crypto.random.bytes(&random_bytes);
    const hex_chars = "0123456789abcdef";
    for (random_bytes, 0..) |byte, i| {
        buf[i * 2] = hex_chars[byte >> 4];
        buf[i * 2 + 1] = hex_chars[byte & 0x0f];
    }
    return buf[0..8];
}

// ===========================================================================
// Unit Tests
// ===========================================================================

test "Logger - level filtering suppresses lower levels" {
    var output_buf: [4096]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&output_buf);

    var logger = Logger{
        .mutex = .{},
        .test_writer = fbs.writer().any(),
        .min_level = .info,
        .audit_enabled = false,
        .output_file = null,
        .owns_file = false,
    };

    logger.debug("should_not_appear", null);
    try std.testing.expectEqual(@as(usize, 0), fbs.getWritten().len);

    logger.info("should_appear", null);
    try std.testing.expect(fbs.getWritten().len > 0);
}

test "Logger - JSON output contains required fields" {
    var output_buf: [4096]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&output_buf);

    var logger = Logger{
        .mutex = .{},
        .test_writer = fbs.writer().any(),
        .min_level = .debug,
        .audit_enabled = false,
        .output_file = null,
        .owns_file = false,
    };

    logger.info("test_event", "abcd1234");

    const output = fbs.getWritten();
    // Verify it's a complete line ending with \n
    try std.testing.expect(output.len > 0);
    try std.testing.expectEqual(@as(u8, '\n'), output[output.len - 1]);

    // Verify required JSON fields are present
    try std.testing.expect(std.mem.indexOf(u8, output, "\"ts\":\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"level\":\"INFO\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"session_id\":\"abcd1234\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"msg\":\"test_event\"") != null);
}

test "Logger - extra key-value pairs in output" {
    var output_buf: [4096]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&output_buf);

    var logger = Logger{
        .mutex = .{},
        .test_writer = fbs.writer().any(),
        .min_level = .debug,
        .audit_enabled = false,
        .output_file = null,
        .owns_file = false,
    };

    logger.log(.info, "request_received", "sess1234", &.{
        .{ .key = "method", .value = .{ .string = "POST" } },
        .{ .key = "path", .value = .{ .string = "/api/v1" } },
        .{ .key = "bytes_in", .value = .{ .uint = 1024 } },
    });

    const output = fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, output, "\"method\":\"POST\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"path\":\"/api/v1\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"bytes_in\":1024") != null);
}

test "Logger - session ID is null-safe" {
    var output_buf: [4096]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&output_buf);

    var logger = Logger{
        .mutex = .{},
        .test_writer = fbs.writer().any(),
        .min_level = .debug,
        .audit_enabled = false,
        .output_file = null,
        .owns_file = false,
    };

    logger.info("startup", null);
    const output = fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, output, "\"session_id\":\"-\"") != null);
}

test "Logger - JSON escaping special characters" {
    var output_buf: [4096]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&output_buf);

    var logger = Logger{
        .mutex = .{},
        .test_writer = fbs.writer().any(),
        .min_level = .debug,
        .audit_enabled = false,
        .output_file = null,
        .owns_file = false,
    };

    logger.info("msg with \"quotes\" and \\backslash", null);
    const output = fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, output, "\\\"quotes\\\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\\\\backslash") != null);
}

test "Logger - audit redaction event emitted when enabled" {
    var output_buf: [4096]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&output_buf);

    var logger = Logger{
        .mutex = .{},
        .test_writer = fbs.writer().any(),
        .min_level = .debug,
        .audit_enabled = true,
        .output_file = null,
        .owns_file = false,
    };

    logger.auditRedaction("sess1234", .{
        .stage = "ssn",
        .match_type = "ssn",
        .offset = 42,
        .original_length = 11,
        .replacement_type = "mask",
    });

    const output = fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, output, "\"event\":\"redaction_audit\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"stage\":\"ssn\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"match_type\":\"ssn\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"offset\":42") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"original_length\":11") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"replacement_type\":\"mask\"") != null);
}

test "Logger - audit redaction event with confidence" {
    var output_buf: [4096]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&output_buf);

    var logger = Logger{
        .mutex = .{},
        .test_writer = fbs.writer().any(),
        .min_level = .debug,
        .audit_enabled = true,
        .output_file = null,
        .owns_file = false,
    };

    logger.auditRedaction("sess1234", .{
        .stage = "fuzzy_match",
        .match_type = "entity_variant",
        .field_path = "notes.patient_name",
        .original_length = 9,
        .replacement_type = "entity_alias",
        .confidence = 0.87,
    });

    const output = fbs.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, output, "\"stage\":\"fuzzy_match\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"field_path\":\"notes.patient_name\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, output, "\"confidence\":0.87") != null);
}

test "Logger - audit disabled produces zero output" {
    var output_buf: [4096]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&output_buf);

    var logger = Logger{
        .mutex = .{},
        .test_writer = fbs.writer().any(),
        .min_level = .debug,
        .audit_enabled = false,
        .output_file = null,
        .owns_file = false,
    };

    logger.auditRedaction("sess1234", .{
        .stage = "ssn",
        .match_type = "ssn",
        .offset = 42,
        .original_length = 11,
        .replacement_type = "mask",
    });
    try std.testing.expectEqual(@as(usize, 0), fbs.getWritten().len);
}

test "generateSessionId - 8 hex characters" {
    var buf: [8]u8 = undefined;
    const sid = generateSessionId(&buf);
    try std.testing.expectEqual(@as(usize, 8), sid.len);

    // Verify all characters are valid hex
    for (sid) |c| {
        const is_hex = (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f');
        try std.testing.expect(is_hex);
    }
}

test "generateSessionId - unique across calls" {
    var buf1: [8]u8 = undefined;
    var buf2: [8]u8 = undefined;
    const sid1 = generateSessionId(&buf1);
    const sid2 = generateSessionId(&buf2);
    // Statistically should never collide (32 bits of entropy)
    try std.testing.expect(!std.mem.eql(u8, sid1, sid2));
}

test "Logger - thread safety stress test" {
    const thread_count = 4;
    const msgs_per_thread = 50;
    const expected_lines = thread_count * msgs_per_thread;
    // Each JSON line is ~140 bytes; pad generously to avoid silent truncation.
    const buf_size = expected_lines * 256;
    var output_buf: [buf_size]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&output_buf);

    var logger = Logger{
        .mutex = .{},
        .test_writer = fbs.writer().any(),
        .min_level = .debug,
        .audit_enabled = false,
        .output_file = null,
        .owns_file = false,
    };

    const Worker = struct {
        fn run(log: *Logger, thread_id: u8) void {
            var id_buf: [8]u8 = undefined;
            const sid = generateSessionId(&id_buf);
            for (0..msgs_per_thread) |_| {
                log.log(.info, "stress_test", sid, &.{
                    .{ .key = "thread", .value = .{ .uint = thread_id } },
                });
            }
        }
    };

    var threads: [thread_count]std.Thread = undefined;
    for (&threads, 0..) |*t, i| {
        t.* = try std.Thread.spawn(.{}, Worker.run, .{ &logger, @as(u8, @intCast(i)) });
    }
    for (&threads) |*t| {
        t.join();
    }

    // Count newlines — should be exactly thread_count × msgs_per_thread
    const written = fbs.getWritten();
    var newline_count: usize = 0;
    for (written) |c| {
        if (c == '\n') newline_count += 1;
    }
    try std.testing.expectEqual(@as(usize, expected_lines), newline_count);
}
