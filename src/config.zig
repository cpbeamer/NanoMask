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

pub const ConfigSource = enum {
    default,
    env_var,
    cli_flag,

    pub fn asStr(self: ConfigSource) []const u8 {
        return switch (self) {
            .default => "default",
            .env_var => "env var",
            .cli_flag => "CLI flag",
        };
    }
};

pub const Config = struct {
    listen_port: u16 = 8081,
    listen_port_src: ConfigSource = .default,
    target_host: []const u8 = "httpbin.org",
    target_host_src: ConfigSource = .default,
    target_port: u16 = 80,
    target_port_src: ConfigSource = .default,
    entity_file: ?[]const u8 = null,
    entity_file_src: ConfigSource = .default,
    fuzzy_threshold: f32 = 0.80,
    fuzzy_threshold_src: ConfigSource = .default,
    max_connections: u32 = 128,
    max_connections_src: ConfigSource = .default,
    log_level: LogLevel = .info,
    log_level_src: ConfigSource = .default,

    allocator: std.mem.Allocator,

    pub const ParseError = error{
        HelpRequested,
        MissingValue,
        InvalidPort,
        InvalidThreshold,
        InvalidLogLevel,
        InvalidMaxConnections,
        EntityFileNotFound,
        UnknownFlag,
        OutOfMemory,
    };

    pub fn deinit(self: *Config) void {
        if (self.target_host_src == .env_var) {
            self.allocator.free(self.target_host);
        }
        if (self.entity_file != null and self.entity_file_src == .env_var) {
            self.allocator.free(self.entity_file.?);
        }
    }

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

    fn applyEnvVar(config: *Config, name: []const u8, value: []const u8, allocator: std.mem.Allocator) !void {
        if (std.mem.eql(u8, name, "NANOMASK_LISTEN_PORT")) {
            config.listen_port = std.fmt.parseInt(u16, value, 10) catch {
                std.debug.print("error: NANOMASK_LISTEN_PORT must be 1-65535, got '{s}'\n", .{value});
                return error.InvalidPort;
            };
            if (config.listen_port == 0) return error.InvalidPort;
            config.listen_port_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_TARGET_HOST")) {
            config.target_host = try allocator.dupe(u8, value);
            config.target_host_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_TARGET_PORT")) {
            config.target_port = std.fmt.parseInt(u16, value, 10) catch {
                std.debug.print("error: NANOMASK_TARGET_PORT must be 1-65535, got '{s}'\n", .{value});
                return error.InvalidPort;
            };
            if (config.target_port == 0) return error.InvalidPort;
            config.target_port_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_ENTITY_FILE")) {
            config.entity_file = try allocator.dupe(u8, value);
            config.entity_file_src = .env_var;
            if (std.fs.cwd().openFile(value, .{})) |*f| {
                f.close();
            } else |err| {
                std.debug.print("error: cannot open entity file '{s}': {s}\n", .{ value, @errorName(err) });
                return error.EntityFileNotFound;
            }
        } else if (std.mem.eql(u8, name, "NANOMASK_FUZZY_THRESHOLD")) {
            config.fuzzy_threshold = std.fmt.parseFloat(f32, value) catch {
                std.debug.print("error: NANOMASK_FUZZY_THRESHOLD must be a float between 0.0 and 1.0, got '{s}'\n", .{value});
                return error.InvalidThreshold;
            };
            if (config.fuzzy_threshold < 0.0 or config.fuzzy_threshold > 1.0) return error.InvalidThreshold;
            config.fuzzy_threshold_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_MAX_CONNECTIONS")) {
            config.max_connections = std.fmt.parseInt(u32, value, 10) catch {
                std.debug.print("error: NANOMASK_MAX_CONNECTIONS must be an integer, got '{s}'\n", .{value});
                return error.InvalidMaxConnections;
            };
            if (config.max_connections == 0) return error.InvalidMaxConnections;
            config.max_connections_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_LOG_LEVEL")) {
            config.log_level = LogLevel.parse(value) catch {
                std.debug.print("error: NANOMASK_LOG_LEVEL must be debug, info, warn, error, got '{s}'\n", .{value});
                return error.InvalidLogLevel;
            };
            config.log_level_src = .env_var;
        }
    }

    /// Parses configuration from a slice of argument strings. Errors out via writer if not headless.
    pub fn parse(allocator: std.mem.Allocator, args: []const []const u8) !Config {
        var config = Config{ .allocator = allocator };

        var env = try std.process.getEnvMap(allocator);
        defer env.deinit();

        const env_keys = [_][]const u8{
            "NANOMASK_LISTEN_PORT",
            "NANOMASK_TARGET_HOST",
            "NANOMASK_TARGET_PORT",
            "NANOMASK_ENTITY_FILE",
            "NANOMASK_FUZZY_THRESHOLD",
            "NANOMASK_MAX_CONNECTIONS",
            "NANOMASK_LOG_LEVEL",
        };

        for (env_keys) |key| {
            if (env.get(key)) |val| {
                try applyEnvVar(&config, key, val, allocator);
            }
        }

        var i: usize = 1; // skip executable (args[0])

        while (i < args.len) : (i += 1) {
            const arg = args[i];

            if (std.mem.eql(u8, arg, "--help")) {
                std.debug.print("Usage: nanomask [options]\n", .{});
                return error.HelpRequested;
            } else if (std.mem.eql(u8, arg, "--listen-port")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --listen-port\n", .{});
                    return error.MissingValue;
                }
                config.listen_port = std.fmt.parseInt(u16, args[i], 10) catch {
                    std.debug.print("error: --listen-port must be 1-65535, got '{s}'\n", .{args[i]});
                    return error.InvalidPort;
                };
                if (config.listen_port == 0) {
                    std.debug.print("error: --listen-port must be 1-65535, got '{s}'\n", .{args[i]});
                    return error.InvalidPort;
                }
                config.listen_port_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--target-host")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --target-host\n", .{});
                    return error.MissingValue;
                }
                if (config.target_host_src == .env_var) allocator.free(config.target_host);
                config.target_host = args[i];
                config.target_host_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--target-port")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --target-port\n", .{});
                    return error.MissingValue;
                }
                config.target_port = std.fmt.parseInt(u16, args[i], 10) catch {
                    std.debug.print("error: --target-port must be 1-65535, got '{s}'\n", .{args[i]});
                    return error.InvalidPort;
                };
                if (config.target_port == 0) {
                    std.debug.print("error: --target-port must be 1-65535, got '{s}'\n", .{args[i]});
                    return error.InvalidPort;
                }
                config.target_port_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--entity-file")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --entity-file\n", .{});
                    return error.MissingValue;
                }
                if (config.entity_file != null and config.entity_file_src == .env_var) {
                    allocator.free(config.entity_file.?);
                }
                config.entity_file = args[i];
                config.entity_file_src = .cli_flag;
                if (std.fs.cwd().openFile(args[i], .{})) |*f| {
                    f.close();
                } else |err| {
                    std.debug.print("error: cannot open entity file '{s}': {s}\n", .{ args[i], @errorName(err) });
                    return error.EntityFileNotFound;
                }
            } else if (std.mem.eql(u8, arg, "--fuzzy-threshold")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --fuzzy-threshold\n", .{});
                    return error.MissingValue;
                }
                config.fuzzy_threshold = std.fmt.parseFloat(f32, args[i]) catch {
                    std.debug.print("error: --fuzzy-threshold must be a float between 0.0 and 1.0, got '{s}'\n", .{args[i]});
                    return error.InvalidThreshold;
                };
                if (config.fuzzy_threshold < 0.0 or config.fuzzy_threshold > 1.0) {
                    std.debug.print("error: --fuzzy-threshold must be between 0.0 and 1.0, got '{s}'\n", .{args[i]});
                    return error.InvalidThreshold;
                }
                config.fuzzy_threshold_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--max-connections")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --max-connections\n", .{});
                    return error.MissingValue;
                }
                config.max_connections = std.fmt.parseInt(u32, args[i], 10) catch {
                    std.debug.print("error: --max-connections must be an integer, got '{s}'\n", .{args[i]});
                    return error.InvalidMaxConnections;
                };
                if (config.max_connections == 0) {
                    std.debug.print("error: --max-connections must be > 0\n", .{});
                    return error.InvalidMaxConnections;
                }
                config.max_connections_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--log-level")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --log-level\n", .{});
                    return error.MissingValue;
                }
                config.log_level = LogLevel.parse(args[i]) catch {
                    std.debug.print("error: --log-level must be debug, info, warn, error, got '{s}'\n", .{args[i]});
                    return error.InvalidLogLevel;
                };
                config.log_level_src = .cli_flag;
            } else {
                std.debug.print("error: unknown flag '{s}'\n", .{arg});
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

    var config = try Config.parse(std.testing.allocator, &args, fba.writer());
    defer config.deinit();

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

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.MissingValue, res);
}

test "Config - invalid port" {
    const args = [_][]const u8{
        "nanomask",
        "--listen-port", "99999",
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.InvalidPort, res);
}

test "Config - out of range fuzzy threshold" {
    const args = [_][]const u8{
        "nanomask",
        "--fuzzy-threshold", "1.5",
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.InvalidThreshold, res);
}

test "Config - unknown flag" {
    const args = [_][]const u8{
        "nanomask",
        "--unknown-flag",
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.UnknownFlag, res);
}

test "Config - help flag" {
    const args = [_][]const u8{
        "nanomask",
        "--help",
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.HelpRequested, res);
}

test "Config - invalid max connections zero" {
    const args = [_][]const u8{
        "nanomask",
        "--max-connections", "0",
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.InvalidMaxConnections, res);
}

