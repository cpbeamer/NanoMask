const std = @import("std");

pub const LogLevel = enum {
    debug,
    info,
    warn,
    error_,

    pub fn parse(s: []const u8) !LogLevel {
        if (std.mem.eql(u8, s, "debug")) return .debug;
        if (std.mem.eql(u8, s, "info")) return .info;
        if (std.mem.eql(u8, s, "warn")) return .warn;
        if (std.mem.eql(u8, s, "error")) return .error_;
        return error.InvalidLogLevel;
    }
};

pub const Config = struct {
    listen_port: u16 = 8081,
    target_host: []const u8 = "httpbin.org",
    target_port: u16 = 80,
    entity_file: ?[]const u8 = null,
    fuzzy_threshold: f32 = 0.80,
    max_connections: u32 = 128,
    log_level: LogLevel = .info,

    pub const ParseError = error{
        HelpRequested,
        MissingValue,
        InvalidPort,
        InvalidThreshold,
        InvalidLogLevel,
        InvalidMaxConnections,
        EntityFileNotFound,
        UnknownFlag,
    };

    pub fn printHelp(writer: anytype) !void {
        try writer.print(
            \\Usage: nanomask [options]
            \\
            \\Options:
            \\  --listen-port <u16>        Port to listen on (default: 8081)
            \\  --target-host <string>     Upstream target host (default: httpbin.org)
            \\  --target-port <u16>        Upstream target port (default: 80)
            \\  --entity-file <path>       Path to file containing entity aliases (default: none)
            \\  --fuzzy-threshold <f32>    Threshold for fuzzy matching (0.0 - 1.0) (default: 0.8)
            \\  --max-connections <u32>    Maximum concurrent connections (default: 128)
            \\  --log-level <level>        Logging level: debug, info, warn, error (default: info)
            \\  --help                     Print this help message and exit
            \\
        , .{});
    }

    /// Parses configuration from a slice of argument strings. Errors out via writer if not headless.
    pub fn parse(args: []const []const u8, err_writer: anytype) !Config {
        var config = Config{};
        var i: usize = 1; // skip executable (args[0])

        while (i < args.len) : (i += 1) {
            const arg = args[i];

            if (std.mem.eql(u8, arg, "--help")) {
                try printHelp(err_writer);
                return error.HelpRequested;
            } else if (std.mem.eql(u8, arg, "--listen-port")) {
                i += 1;
                if (i >= args.len) {
                    try err_writer.print("error: expected value for --listen-port\n", .{});
                    return error.MissingValue;
                }
                config.listen_port = std.fmt.parseInt(u16, args[i], 10) catch {
                    try err_writer.print("error: --listen-port must be 1-65535, got '{s}'\n", .{args[i]});
                    return error.InvalidPort;
                };
                if (config.listen_port == 0) {
                    try err_writer.print("error: --listen-port must be 1-65535, got '{s}'\n", .{args[i]});
                    return error.InvalidPort;
                }
            } else if (std.mem.eql(u8, arg, "--target-host")) {
                i += 1;
                if (i >= args.len) {
                    try err_writer.print("error: expected value for --target-host\n", .{});
                    return error.MissingValue;
                }
                config.target_host = args[i];
            } else if (std.mem.eql(u8, arg, "--target-port")) {
                i += 1;
                if (i >= args.len) {
                    try err_writer.print("error: expected value for --target-port\n", .{});
                    return error.MissingValue;
                }
                config.target_port = std.fmt.parseInt(u16, args[i], 10) catch {
                    try err_writer.print("error: --target-port must be 1-65535, got '{s}'\n", .{args[i]});
                    return error.InvalidPort;
                };
                if (config.target_port == 0) {
                    try err_writer.print("error: --target-port must be 1-65535, got '{s}'\n", .{args[i]});
                    return error.InvalidPort;
                }
            } else if (std.mem.eql(u8, arg, "--entity-file")) {
                i += 1;
                if (i >= args.len) {
                    try err_writer.print("error: expected value for --entity-file\n", .{});
                    return error.MissingValue;
                }
                config.entity_file = args[i];
                _ = std.fs.cwd().statFile(args[i]) catch |err| {
                    try err_writer.print("error: cannot stat entity file '{s}': {s}\n", .{ args[i], @errorName(err) });
                    return error.EntityFileNotFound;
                };
            } else if (std.mem.eql(u8, arg, "--fuzzy-threshold")) {
                i += 1;
                if (i >= args.len) {
                    try err_writer.print("error: expected value for --fuzzy-threshold\n", .{});
                    return error.MissingValue;
                }
                config.fuzzy_threshold = std.fmt.parseFloat(f32, args[i]) catch {
                    try err_writer.print("error: --fuzzy-threshold must be a float between 0.0 and 1.0, got '{s}'\n", .{args[i]});
                    return error.InvalidThreshold;
                };
                if (config.fuzzy_threshold < 0.0 or config.fuzzy_threshold > 1.0) {
                    try err_writer.print("error: --fuzzy-threshold must be between 0.0 and 1.0, got '{s}'\n", .{args[i]});
                    return error.InvalidThreshold;
                }
            } else if (std.mem.eql(u8, arg, "--max-connections")) {
                i += 1;
                if (i >= args.len) {
                    try err_writer.print("error: expected value for --max-connections\n", .{});
                    return error.MissingValue;
                }
                config.max_connections = std.fmt.parseInt(u32, args[i], 10) catch {
                    try err_writer.print("error: --max-connections must be an integer, got '{s}'\n", .{args[i]});
                    return error.InvalidMaxConnections;
                };
                if (config.max_connections == 0) {
                    try err_writer.print("error: --max-connections must be > 0\n", .{});
                    return error.InvalidMaxConnections;
                }
            } else if (std.mem.eql(u8, arg, "--log-level")) {
                i += 1;
                if (i >= args.len) {
                    try err_writer.print("error: expected value for --log-level\n", .{});
                    return error.MissingValue;
                }
                config.log_level = LogLevel.parse(args[i]) catch {
                    try err_writer.print("error: --log-level must be debug, info, warn, error, got '{s}'\n", .{args[i]});
                    return error.InvalidLogLevel;
                };
            } else {
                try err_writer.print("error: unknown flag '{s}'\n", .{arg});
                try printHelp(err_writer);
                return error.UnknownFlag;
            }
        }

        return config;
    }
};

const testing = std.testing;

test "Config - parse valid arguments" {
    const args = [_][]const u8{
        "nanomask",
        "--listen-port", "9090",
        "--target-host", "api.example.com",
        "--target-port", "443",
        "--fuzzy-threshold", "0.9",
        "--max-connections", "1000",
        "--log-level", "debug",
    };

    var out_buf: [1024]u8 = undefined;
    var fba = std.io.fixedBufferStream(&out_buf);

    const config = try Config.parse(&args, fba.writer());

    try testing.expectEqual(@as(u16, 9090), config.listen_port);
    try testing.expectEqualStrings("api.example.com", config.target_host);
    try testing.expectEqual(@as(u16, 443), config.target_port);
    try testing.expectEqual(@as(f32, 0.9), config.fuzzy_threshold);
    try testing.expectEqual(@as(u32, 1000), config.max_connections);
    try testing.expectEqual(LogLevel.debug, config.log_level);
    try testing.expectEqual(@as(?[]const u8, null), config.entity_file);
}

test "Config - missing value" {
    const args = [_][]const u8{
        "nanomask",
        "--listen-port",
    };

    var out_buf: [1024]u8 = undefined;
    var fba = std.io.fixedBufferStream(&out_buf);

    const res = Config.parse(&args, fba.writer());
    try testing.expectError(error.MissingValue, res);
    try testing.expectEqualStrings("error: expected value for --listen-port\n", fba.getWritten());
}

test "Config - invalid port" {
    const args = [_][]const u8{
        "nanomask",
        "--listen-port", "99999",
    };

    var out_buf: [1024]u8 = undefined;
    var fba = std.io.fixedBufferStream(&out_buf);

    const res = Config.parse(&args, fba.writer());
    try testing.expectError(error.InvalidPort, res);
    try testing.expectEqualStrings("error: --listen-port must be 1-65535, got '99999'\n", fba.getWritten());
}

test "Config - out of range fuzzy threshold" {
    const args = [_][]const u8{
        "nanomask",
        "--fuzzy-threshold", "1.5",
    };

    var out_buf: [1024]u8 = undefined;
    var fba = std.io.fixedBufferStream(&out_buf);

    const res = Config.parse(&args, fba.writer());
    try testing.expectError(error.InvalidThreshold, res);
    try testing.expectEqualStrings("error: --fuzzy-threshold must be between 0.0 and 1.0, got '1.5'\n", fba.getWritten());
}

test "Config - unknown flag" {
    const args = [_][]const u8{
        "nanomask",
        "--unknown-flag",
    };

    var out_buf: [1024]u8 = undefined;
    var fba = std.io.fixedBufferStream(&out_buf);

    const res = Config.parse(&args, fba.writer());
    try testing.expectError(error.UnknownFlag, res);
    const written = fba.getWritten();
    try testing.expect(std.mem.startsWith(u8, written, "error: unknown flag '--unknown-flag'\nUsage: nanomask"));
}

test "Config - help flag" {
    const args = [_][]const u8{
        "nanomask",
        "--help",
    };

    var out_buf: [1024]u8 = undefined;
    var fba = std.io.fixedBufferStream(&out_buf);

    const res = Config.parse(&args, fba.writer());
    try testing.expectError(error.HelpRequested, res);
    const written = fba.getWritten();
    try testing.expect(std.mem.startsWith(u8, written, "Usage: nanomask"));
}

test "Config - invalid max connections zero" {
    const args = [_][]const u8{
        "nanomask",
        "--max-connections", "0",
    };

    var out_buf: [1024]u8 = undefined;
    var fba = std.io.fixedBufferStream(&out_buf);

    const res = Config.parse(&args, fba.writer());
    try testing.expectError(error.InvalidMaxConnections, res);
    try testing.expectEqualStrings("error: --max-connections must be > 0\n", fba.getWritten());
}
