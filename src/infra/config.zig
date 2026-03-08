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
    /// Centralised version string — referenced by /healthz and future endpoints.
    pub const version = "0.1.0";
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
    watch_interval_ms: u64 = 1000,
    watch_interval_ms_src: ConfigSource = .default,
    admin_api: bool = false,
    admin_api_src: ConfigSource = .default,
    admin_token: ?[]const u8 = null,
    admin_token_src: ConfigSource = .default,
    entity_file_sync: bool = false,
    entity_file_sync_src: ConfigSource = .default,
    tls_cert: ?[]const u8 = null,
    tls_cert_src: ConfigSource = .default,
    tls_key: ?[]const u8 = null,
    tls_key_src: ConfigSource = .default,
    target_tls: bool = false,
    target_tls_src: ConfigSource = .default,
    ca_file: ?[]const u8 = null,
    ca_file_src: ConfigSource = .default,
    tls_no_system_ca: bool = false,
    tls_no_system_ca_src: ConfigSource = .default,
    max_body_size: usize = 10 * 1024 * 1024,
    max_body_size_src: ConfigSource = .default,
    log_file: ?[]const u8 = null,
    log_file_src: ConfigSource = .default,
    audit_log: bool = false,
    audit_log_src: ConfigSource = .default,
    // --- Pattern library flags (Phase 5 / Epic 7) ---
    enable_email: bool = false,
    enable_email_src: ConfigSource = .default,
    enable_phone: bool = false,
    enable_phone_src: ConfigSource = .default,
    enable_credit_card: bool = false,
    enable_credit_card_src: ConfigSource = .default,
    enable_ip: bool = false,
    enable_ip_src: ConfigSource = .default,
    enable_healthcare: bool = false,
    enable_healthcare_src: ConfigSource = .default,
    // --- Schema-aware redaction flags (Phase 5 / Epic 8) ---
    schema_file: ?[]const u8 = null,
    schema_file_src: ConfigSource = .default,
    schema_default: []const u8 = "SCAN",
    schema_default_src: ConfigSource = .default,
    hash_key: ?[]const u8 = null,
    hash_key_src: ConfigSource = .default,
    hash_key_file: ?[]const u8 = null,
    hash_key_file_src: ConfigSource = .default,

    /// When true, perform a health check probe against localhost and exit.
    /// Used by Docker HEALTHCHECK in scratch containers with no curl/wget.
    healthcheck: bool = false,

    allocator: std.mem.Allocator,

    pub const ParseError = error{
        HelpRequested,
        MissingValue,
        InvalidPort,
        InvalidThreshold,
        InvalidLogLevel,
        InvalidMaxConnections,
        InvalidWatchInterval,
        EntityFileNotFound,
        InvalidAdminFlag,
        MissingTlsPair,
        TlsCertNotFound,
        TlsKeyNotFound,
        CaFileNotFound,
        InvalidTargetTlsFlag,
        InvalidNoSystemCaFlag,
        InvalidMaxBodySize,
        MissingAdminToken,
        InvalidAuditLogFlag,
        InvalidPatternFlag,
        InvalidSchemaDefault,
        SchemaFileNotFound,
        InvalidHashKey,
        HashKeyFileNotFound,
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
        if (self.admin_token != null and self.admin_token_src == .env_var) {
            self.allocator.free(self.admin_token.?);
        }
        if (self.tls_cert != null and self.tls_cert_src == .env_var) {
            self.allocator.free(self.tls_cert.?);
        }
        if (self.tls_key != null and self.tls_key_src == .env_var) {
            self.allocator.free(self.tls_key.?);
        }
        if (self.ca_file != null and self.ca_file_src == .env_var) {
            self.allocator.free(self.ca_file.?);
        }
        if (self.log_file != null and self.log_file_src == .env_var) {
            self.allocator.free(self.log_file.?);
        }
        if (self.schema_file != null and self.schema_file_src == .env_var) {
            self.allocator.free(self.schema_file.?);
        }
        if (self.hash_key != null and self.hash_key_src == .env_var) {
            self.allocator.free(self.hash_key.?);
        }
        if (self.hash_key_file != null and self.hash_key_file_src == .env_var) {
            self.allocator.free(self.hash_key_file.?);
        }
        // schema_default is a borrowed static literal ("SCAN") by default.
        // Only free when overridden from an env var or CLI flag (duped in both paths).
        if (self.schema_default_src == .env_var or self.schema_default_src == .cli_flag) {
            self.allocator.free(@constCast(self.schema_default));
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
            \\  --watch-interval <ms>      Entity file poll interval in ms (default: 1000)
            \\  --admin-api                 Enable /_admin/entities REST endpoints (default: disabled)
            \\  --admin-token <secret>      Require Bearer token for admin endpoints
            \\  --entity-file-sync          Write API entity changes back to entity file
            \\  --tls-cert <path>           PEM certificate file for TLS (requires --tls-key)
            \\  --tls-key <path>            PEM private key file for TLS (requires --tls-cert)
            \\  --target-tls                Enable TLS for upstream connections (default: disabled)
            \\  --ca-file <path>            Custom CA bundle PEM for upstream TLS verification
            \\  --tls-no-system-ca          Suppress system CA bundle loading (use with --ca-file for self-signed certs)
            \\  --max-body-size <bytes>      Maximum request body size in bytes (default: 10485760 = 10 MB)
            \\  --log-file <path>            Write structured JSON logs to file (default: stderr)
            \\  --audit-log                  Enable per-redaction audit events in log output
            \\  --enable-email               Redact email addresses (default: disabled)
            \\  --enable-phone               Redact US phone numbers (default: disabled)
            \\  --enable-credit-card          Redact credit card numbers with Luhn validation (default: disabled)
            \\  --enable-ip                  Redact IPv4/IPv6 addresses (default: disabled)
            \\  --enable-healthcare           Redact healthcare IDs: MRN, ICD-10, Insurance (default: disabled)
            \\  --schema-file <path>          JSON schema file for field-level redaction (Epic 8)
            \\  --schema-default <action>     Default action for unlisted keys: REDACT, KEEP, SCAN (default: SCAN)
            \\  --hash-key <hex>              64-char hex HMAC key for HASH-mode pseudonymization
            \\  --hash-key-file <path>        File containing 64-char hex HMAC key
            \\  --healthcheck                Probe /healthz on localhost and exit (for Docker HEALTHCHECK)
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
        } else if (std.mem.eql(u8, name, "NANOMASK_WATCH_INTERVAL")) {
            config.watch_interval_ms = std.fmt.parseInt(u64, value, 10) catch {
                std.debug.print("error: NANOMASK_WATCH_INTERVAL must be a positive integer (ms), got '{s}'\n", .{value});
                return error.InvalidWatchInterval;
            };
            if (config.watch_interval_ms == 0) return error.InvalidWatchInterval;
            config.watch_interval_ms_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_ADMIN_API")) {
            if (std.mem.eql(u8, value, "true") or std.mem.eql(u8, value, "1")) {
                config.admin_api = true;
            } else if (std.mem.eql(u8, value, "false") or std.mem.eql(u8, value, "0")) {
                config.admin_api = false;
            } else {
                std.debug.print("error: NANOMASK_ADMIN_API must be true/false or 1/0, got '{s}'\n", .{value});
                return error.InvalidAdminFlag;
            }
            config.admin_api_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_ADMIN_TOKEN")) {
            config.admin_token = try allocator.dupe(u8, value);
            config.admin_token_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_ENTITY_FILE_SYNC")) {
            if (std.mem.eql(u8, value, "true") or std.mem.eql(u8, value, "1")) {
                config.entity_file_sync = true;
            } else if (std.mem.eql(u8, value, "false") or std.mem.eql(u8, value, "0")) {
                config.entity_file_sync = false;
            } else {
                std.debug.print("error: NANOMASK_ENTITY_FILE_SYNC must be true/false or 1/0, got '{s}'\n", .{value});
                return error.InvalidAdminFlag;
            }
            config.entity_file_sync_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_TLS_CERT")) {
            config.tls_cert = try allocator.dupe(u8, value);
            config.tls_cert_src = .env_var;
            if (std.fs.cwd().openFile(value, .{})) |*f| {
                f.close();
            } else |err| {
                std.debug.print("error: cannot open TLS cert file '{s}': {s}\n", .{ value, @errorName(err) });
                return error.TlsCertNotFound;
            }
        } else if (std.mem.eql(u8, name, "NANOMASK_TLS_KEY")) {
            config.tls_key = try allocator.dupe(u8, value);
            config.tls_key_src = .env_var;
            if (std.fs.cwd().openFile(value, .{})) |*f| {
                f.close();
            } else |err| {
                std.debug.print("error: cannot open TLS key file '{s}': {s}\n", .{ value, @errorName(err) });
                return error.TlsKeyNotFound;
            }
        } else if (std.mem.eql(u8, name, "NANOMASK_TARGET_TLS")) {
            if (std.mem.eql(u8, value, "true") or std.mem.eql(u8, value, "1")) {
                config.target_tls = true;
            } else if (std.mem.eql(u8, value, "false") or std.mem.eql(u8, value, "0")) {
                config.target_tls = false;
            } else {
                std.debug.print("error: NANOMASK_TARGET_TLS must be true/false or 1/0, got '{s}'\n", .{value});
                return error.InvalidTargetTlsFlag;
            }
            config.target_tls_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_CA_FILE")) {
            config.ca_file = try allocator.dupe(u8, value);
            config.ca_file_src = .env_var;
            if (std.fs.cwd().openFile(value, .{})) |*f| {
                f.close();
            } else |err| {
                std.debug.print("error: cannot open CA file '{s}': {s}\n", .{ value, @errorName(err) });
                return error.CaFileNotFound;
            }
        } else if (std.mem.eql(u8, name, "NANOMASK_TLS_NO_SYSTEM_CA")) {
            if (std.mem.eql(u8, value, "true") or std.mem.eql(u8, value, "1")) {
                config.tls_no_system_ca = true;
            } else if (std.mem.eql(u8, value, "false") or std.mem.eql(u8, value, "0")) {
                config.tls_no_system_ca = false;
            } else {
                std.debug.print("error: NANOMASK_TLS_NO_SYSTEM_CA must be true/false or 1/0, got '{s}'\n", .{value});
                return error.InvalidNoSystemCaFlag;
            }
            config.tls_no_system_ca_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_MAX_BODY_SIZE")) {
            config.max_body_size = std.fmt.parseInt(usize, value, 10) catch {
                std.debug.print("error: NANOMASK_MAX_BODY_SIZE must be a positive integer, got '{s}'\n", .{value});
                return error.InvalidMaxBodySize;
            };
            if (config.max_body_size == 0) return error.InvalidMaxBodySize;
            config.max_body_size_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_LOG_FILE")) {
            config.log_file = try allocator.dupe(u8, value);
            config.log_file_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_AUDIT_LOG")) {
            if (std.mem.eql(u8, value, "true") or std.mem.eql(u8, value, "1")) {
                config.audit_log = true;
            } else if (std.mem.eql(u8, value, "false") or std.mem.eql(u8, value, "0")) {
                config.audit_log = false;
            } else {
                std.debug.print("error: NANOMASK_AUDIT_LOG must be true/false or 1/0, got '{s}'\n", .{value});
                return error.InvalidAuditLogFlag;
            }
            config.audit_log_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_ENABLE_EMAIL")) {
            config.enable_email = parseBoolEnv(value) orelse return error.InvalidPatternFlag;
            config.enable_email_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_ENABLE_PHONE")) {
            config.enable_phone = parseBoolEnv(value) orelse return error.InvalidPatternFlag;
            config.enable_phone_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_ENABLE_CREDIT_CARD")) {
            config.enable_credit_card = parseBoolEnv(value) orelse return error.InvalidPatternFlag;
            config.enable_credit_card_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_ENABLE_IP")) {
            config.enable_ip = parseBoolEnv(value) orelse return error.InvalidPatternFlag;
            config.enable_ip_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_ENABLE_HEALTHCARE")) {
            config.enable_healthcare = parseBoolEnv(value) orelse return error.InvalidPatternFlag;
            config.enable_healthcare_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_SCHEMA_FILE")) {
            config.schema_file = try allocator.dupe(u8, value);
            config.schema_file_src = .env_var;
            if (std.fs.cwd().openFile(value, .{})) |*f| {
                f.close();
            } else |err| {
                std.debug.print("error: cannot open schema file '{s}': {s}\n", .{ value, @errorName(err) });
                return error.SchemaFileNotFound;
            }
        } else if (std.mem.eql(u8, name, "NANOMASK_SCHEMA_DEFAULT")) {
            if (std.mem.eql(u8, value, "REDACT") or std.mem.eql(u8, value, "KEEP") or std.mem.eql(u8, value, "SCAN")) {
                config.schema_default = try allocator.dupe(u8, value);
                config.schema_default_src = .env_var;
            } else {
                std.debug.print("error: NANOMASK_SCHEMA_DEFAULT must be REDACT, KEEP, or SCAN, got '{s}'\n", .{value});
                return error.InvalidSchemaDefault;
            }
        } else if (std.mem.eql(u8, name, "NANOMASK_HASH_KEY")) {
            config.hash_key = try allocator.dupe(u8, value);
            config.hash_key_src = .env_var;
        } else if (std.mem.eql(u8, name, "NANOMASK_HASH_KEY_FILE")) {
            config.hash_key_file = try allocator.dupe(u8, value);
            config.hash_key_file_src = .env_var;
            if (std.fs.cwd().openFile(value, .{})) |*f| {
                f.close();
            } else |err| {
                std.debug.print("error: cannot open hash key file '{s}': {s}\n", .{ value, @errorName(err) });
                return error.HashKeyFileNotFound;
            }
        }
    }

    fn parseBoolEnv(value: []const u8) ?bool {
        if (std.mem.eql(u8, value, "true") or std.mem.eql(u8, value, "1")) return true;
        if (std.mem.eql(u8, value, "false") or std.mem.eql(u8, value, "0")) return false;
        return null;
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
            "NANOMASK_WATCH_INTERVAL",
            "NANOMASK_ADMIN_API",
            "NANOMASK_ADMIN_TOKEN",
            "NANOMASK_ENTITY_FILE_SYNC",
            "NANOMASK_TLS_CERT",
            "NANOMASK_TLS_KEY",
            "NANOMASK_TARGET_TLS",
            "NANOMASK_CA_FILE",
            "NANOMASK_TLS_NO_SYSTEM_CA",
            "NANOMASK_MAX_BODY_SIZE",
            "NANOMASK_LOG_FILE",
            "NANOMASK_AUDIT_LOG",
            "NANOMASK_ENABLE_EMAIL",
            "NANOMASK_ENABLE_PHONE",
            "NANOMASK_ENABLE_CREDIT_CARD",
            "NANOMASK_ENABLE_IP",
            "NANOMASK_ENABLE_HEALTHCARE",
            "NANOMASK_SCHEMA_FILE",
            "NANOMASK_SCHEMA_DEFAULT",
            "NANOMASK_HASH_KEY",
            "NANOMASK_HASH_KEY_FILE",
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
            } else if (std.mem.eql(u8, arg, "--watch-interval")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --watch-interval\n", .{});
                    return error.MissingValue;
                }
                config.watch_interval_ms = std.fmt.parseInt(u64, args[i], 10) catch {
                    std.debug.print("error: --watch-interval must be a positive integer (ms), got '{s}'\n", .{args[i]});
                    return error.InvalidWatchInterval;
                };
                if (config.watch_interval_ms == 0) {
                    std.debug.print("error: --watch-interval must be > 0\n", .{});
                    return error.InvalidWatchInterval;
                }
                config.watch_interval_ms_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--admin-api")) {
                config.admin_api = true;
                config.admin_api_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--admin-token")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --admin-token\n", .{});
                    return error.MissingValue;
                }
                if (config.admin_token != null and config.admin_token_src == .env_var) {
                    allocator.free(config.admin_token.?);
                }
                config.admin_token = args[i];
                config.admin_token_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--entity-file-sync")) {
                config.entity_file_sync = true;
                config.entity_file_sync_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--tls-cert")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --tls-cert\n", .{});
                    return error.MissingValue;
                }
                if (config.tls_cert != null and config.tls_cert_src == .env_var) {
                    allocator.free(config.tls_cert.?);
                }
                config.tls_cert = args[i];
                config.tls_cert_src = .cli_flag;
                if (std.fs.cwd().openFile(args[i], .{})) |*f| {
                    f.close();
                } else |err| {
                    std.debug.print("error: cannot open TLS cert file '{s}': {s}\n", .{ args[i], @errorName(err) });
                    return error.TlsCertNotFound;
                }
            } else if (std.mem.eql(u8, arg, "--tls-key")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --tls-key\n", .{});
                    return error.MissingValue;
                }
                if (config.tls_key != null and config.tls_key_src == .env_var) {
                    allocator.free(config.tls_key.?);
                }
                config.tls_key = args[i];
                config.tls_key_src = .cli_flag;
                if (std.fs.cwd().openFile(args[i], .{})) |*f| {
                    f.close();
                } else |err| {
                    std.debug.print("error: cannot open TLS key file '{s}': {s}\n", .{ args[i], @errorName(err) });
                    return error.TlsKeyNotFound;
                }
            } else if (std.mem.eql(u8, arg, "--target-tls")) {
                config.target_tls = true;
                config.target_tls_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--ca-file")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --ca-file\n", .{});
                    return error.MissingValue;
                }
                if (config.ca_file != null and config.ca_file_src == .env_var) {
                    allocator.free(config.ca_file.?);
                }
                config.ca_file = args[i];
                config.ca_file_src = .cli_flag;
                if (std.fs.cwd().openFile(args[i], .{})) |*f| {
                    f.close();
                } else |err| {
                    std.debug.print("error: cannot open CA file '{s}': {s}\n", .{ args[i], @errorName(err) });
                    return error.CaFileNotFound;
                }
            } else if (std.mem.eql(u8, arg, "--tls-no-system-ca")) {
                config.tls_no_system_ca = true;
                config.tls_no_system_ca_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--max-body-size")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --max-body-size\n", .{});
                    return error.MissingValue;
                }
                config.max_body_size = std.fmt.parseInt(usize, args[i], 10) catch {
                    std.debug.print("error: --max-body-size must be a positive integer, got '{s}'\n", .{args[i]});
                    return error.InvalidMaxBodySize;
                };
                if (config.max_body_size == 0) {
                    std.debug.print("error: --max-body-size must be > 0\n", .{});
                    return error.InvalidMaxBodySize;
                }
                config.max_body_size_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--log-file")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --log-file\n", .{});
                    return error.MissingValue;
                }
                if (config.log_file != null and config.log_file_src == .env_var) {
                    allocator.free(config.log_file.?);
                }
                config.log_file = args[i];
                config.log_file_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--audit-log")) {
                config.audit_log = true;
                config.audit_log_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--enable-email")) {
                config.enable_email = true;
                config.enable_email_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--enable-phone")) {
                config.enable_phone = true;
                config.enable_phone_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--enable-credit-card")) {
                config.enable_credit_card = true;
                config.enable_credit_card_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--enable-ip")) {
                config.enable_ip = true;
                config.enable_ip_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--enable-healthcare")) {
                config.enable_healthcare = true;
                config.enable_healthcare_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--schema-file")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --schema-file\n", .{});
                    return error.MissingValue;
                }
                if (config.schema_file != null and config.schema_file_src == .env_var) {
                    allocator.free(config.schema_file.?);
                }
                config.schema_file = args[i];
                config.schema_file_src = .cli_flag;
                if (std.fs.cwd().openFile(args[i], .{})) |*f| {
                    f.close();
                } else |err| {
                    std.debug.print("error: cannot open schema file '{s}': {s}\n", .{ args[i], @errorName(err) });
                    return error.SchemaFileNotFound;
                }
            } else if (std.mem.eql(u8, arg, "--schema-default")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --schema-default\n", .{});
                    return error.MissingValue;
                }
                if (std.mem.eql(u8, args[i], "REDACT") or std.mem.eql(u8, args[i], "KEEP") or std.mem.eql(u8, args[i], "SCAN")) {
                    // Free previous env-var-duped value if being overridden
                    if (config.schema_default_src == .env_var) {
                        allocator.free(@constCast(config.schema_default));
                    }
                    config.schema_default = try allocator.dupe(u8, args[i]);
                    config.schema_default_src = .cli_flag;
                } else {
                    std.debug.print("error: --schema-default must be REDACT, KEEP, or SCAN, got '{s}'\n", .{args[i]});
                    return error.InvalidSchemaDefault;
                }
            } else if (std.mem.eql(u8, arg, "--hash-key")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --hash-key\n", .{});
                    return error.MissingValue;
                }
                // Validate 64 hex chars at parse time for fail-fast behavior
                if (args[i].len != 64) {
                    std.debug.print("error: --hash-key must be exactly 64 hex characters (32 bytes), got {d} chars\n", .{args[i].len});
                    return error.InvalidHashKey;
                }
                for (args[i]) |ch| {
                    switch (ch) {
                        '0'...'9', 'a'...'f', 'A'...'F' => {},
                        else => {
                            std.debug.print("error: --hash-key contains non-hex character '{c}'\n", .{ch});
                            return error.InvalidHashKey;
                        },
                    }
                }
                if (config.hash_key != null and config.hash_key_src == .env_var) {
                    allocator.free(config.hash_key.?);
                }
                config.hash_key = args[i];
                config.hash_key_src = .cli_flag;
            } else if (std.mem.eql(u8, arg, "--hash-key-file")) {
                i += 1;
                if (i >= args.len) {
                    std.debug.print("error: expected value for --hash-key-file\n", .{});
                    return error.MissingValue;
                }
                if (config.hash_key_file != null and config.hash_key_file_src == .env_var) {
                    allocator.free(config.hash_key_file.?);
                }
                config.hash_key_file = args[i];
                config.hash_key_file_src = .cli_flag;
                if (std.fs.cwd().openFile(args[i], .{})) |*f| {
                    f.close();
                } else |err| {
                    std.debug.print("error: cannot open hash key file '{s}': {s}\n", .{ args[i], @errorName(err) });
                    return error.HashKeyFileNotFound;
                }
            } else if (std.mem.eql(u8, arg, "--healthcheck")) {
                config.healthcheck = true;
            } else {
                std.debug.print("error: unknown flag '{s}'\n", .{arg});
                return error.UnknownFlag;
            }
        }

        // Validate TLS cert/key pairing — both must be provided together
        if (config.tls_cert != null and config.tls_key == null) {
            std.debug.print("error: --tls-cert requires --tls-key\n", .{});
            return error.MissingTlsPair;
        }
        if (config.tls_key != null and config.tls_cert == null) {
            std.debug.print("error: --tls-key requires --tls-cert\n", .{});
            return error.MissingTlsPair;
        }

        // Warn if --ca-file or --tls-no-system-ca given without --target-tls
        if (!config.target_tls and config.ca_file != null) {
            std.debug.print("WARNING: --ca-file has no effect without --target-tls\n", .{});
        }
        if (!config.target_tls and config.tls_no_system_ca) {
            std.debug.print("WARNING: --tls-no-system-ca has no effect without --target-tls\n", .{});
        }

        // When --tls-no-system-ca is set without --ca-file, no CAs will be
        // trusted at all — every upstream HTTPS handshake will fail. Warn
        // the user to pair it with --ca-file.
        if (config.tls_no_system_ca and config.ca_file == null and config.target_tls) {
            std.debug.print("WARNING: --tls-no-system-ca without --ca-file means NO certificates are trusted — upstream HTTPS will fail\n", .{});
            std.debug.print("  hint: use --ca-file <path> to provide your self-signed CA bundle\n", .{});
        }

        // Require --admin-token when --admin-api is enabled to prevent
        // unauthenticated access to entity management endpoints.
        if (config.admin_api and config.admin_token == null) {
            std.debug.print("error: --admin-api requires --admin-token <secret> for authentication\n", .{});
            return error.MissingAdminToken;
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

    var config = try Config.parse(std.testing.allocator, &args);
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

test "Config - valid watch interval" {
    const args = [_][]const u8{
        "nanomask",
        "--watch-interval", "5000",
    };

    var config = try Config.parse(std.testing.allocator, &args);
    defer config.deinit();

    try testing.expectEqual(@as(u64, 5000), config.watch_interval_ms);
    try testing.expectEqual(ConfigSource.cli_flag, config.watch_interval_ms_src);
}

test "Config - invalid watch interval zero" {
    const args = [_][]const u8{
        "nanomask",
        "--watch-interval", "0",
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.InvalidWatchInterval, res);
}

test "Config - invalid watch interval non-numeric" {
    const args = [_][]const u8{
        "nanomask",
        "--watch-interval", "abc",
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.InvalidWatchInterval, res);
}

test "Config - admin-api flag" {
    const args = [_][]const u8{
        "nanomask",
        "--admin-api",
        "--admin-token", "test-secret",
    };

    var cfg = try Config.parse(std.testing.allocator, &args);
    defer cfg.deinit();

    try testing.expect(cfg.admin_api);
    try testing.expectEqual(ConfigSource.cli_flag, cfg.admin_api_src);
}

test "Config - admin-api without token fails" {
    const args = [_][]const u8{
        "nanomask",
        "--admin-api",
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.MissingAdminToken, res);
}

test "Config - admin-token flag" {
    const args = [_][]const u8{
        "nanomask",
        "--admin-token", "mysecret",
    };

    var cfg = try Config.parse(std.testing.allocator, &args);
    defer cfg.deinit();

    try testing.expectEqualStrings("mysecret", cfg.admin_token.?);
    try testing.expectEqual(ConfigSource.cli_flag, cfg.admin_token_src);
}

test "Config - admin-token missing value" {
    const args = [_][]const u8{
        "nanomask",
        "--admin-token",
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.MissingValue, res);
}

test "Config - entity-file-sync flag" {
    const args = [_][]const u8{
        "nanomask",
        "--entity-file-sync",
    };

    var cfg = try Config.parse(std.testing.allocator, &args);
    defer cfg.deinit();

    try testing.expect(cfg.entity_file_sync);
    try testing.expectEqual(ConfigSource.cli_flag, cfg.entity_file_sync_src);
}

test "Config - tls-cert without tls-key" {
    // Create a temporary cert file for the test
    const tmp_cert = "test_tls_cert.pem";
    {
        var f = try std.fs.cwd().createFile(tmp_cert, .{});
        defer f.close();
        try f.writeAll("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n");
    }
    defer std.fs.cwd().deleteFile(tmp_cert) catch {};

    const args = [_][]const u8{
        "nanomask",
        "--tls-cert", tmp_cert,
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.MissingTlsPair, res);
}

test "Config - tls-key without tls-cert" {
    const tmp_key = "test_tls_key.pem";
    {
        var f = try std.fs.cwd().createFile(tmp_key, .{});
        defer f.close();
        try f.writeAll("-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n");
    }
    defer std.fs.cwd().deleteFile(tmp_key) catch {};

    const args = [_][]const u8{
        "nanomask",
        "--tls-key", tmp_key,
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.MissingTlsPair, res);
}

test "Config - tls-cert and tls-key valid pair" {
    const tmp_cert = "test_tls_cert2.pem";
    const tmp_key = "test_tls_key2.pem";
    {
        var f = try std.fs.cwd().createFile(tmp_cert, .{});
        defer f.close();
        try f.writeAll("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n");
    }
    defer std.fs.cwd().deleteFile(tmp_cert) catch {};
    {
        var f = try std.fs.cwd().createFile(tmp_key, .{});
        defer f.close();
        try f.writeAll("-----BEGIN PRIVATE KEY-----\ntest\n-----END PRIVATE KEY-----\n");
    }
    defer std.fs.cwd().deleteFile(tmp_key) catch {};

    const args = [_][]const u8{
        "nanomask",
        "--tls-cert", tmp_cert,
        "--tls-key", tmp_key,
    };

    var cfg = try Config.parse(std.testing.allocator, &args);
    defer cfg.deinit();

    try testing.expectEqualStrings(tmp_cert, cfg.tls_cert.?);
    try testing.expectEqualStrings(tmp_key, cfg.tls_key.?);
    try testing.expectEqual(ConfigSource.cli_flag, cfg.tls_cert_src);
    try testing.expectEqual(ConfigSource.cli_flag, cfg.tls_key_src);
}

test "Config - tls-cert file not found" {
    const args = [_][]const u8{
        "nanomask",
        "--tls-cert", "nonexistent_tls_cert_12345.pem",
        "--tls-key", "nonexistent_tls_key_12345.pem",
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.TlsCertNotFound, res);
}

test "Config - tls-key file not found" {
    const tmp_cert = "test_tls_cert3.pem";
    {
        var f = try std.fs.cwd().createFile(tmp_cert, .{});
        defer f.close();
        try f.writeAll("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n");
    }
    defer std.fs.cwd().deleteFile(tmp_cert) catch {};

    const args = [_][]const u8{
        "nanomask",
        "--tls-cert", tmp_cert,
        "--tls-key", "nonexistent_tls_key_12345.pem",
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.TlsKeyNotFound, res);
}

test "Config - target-tls flag" {
    const args = [_][]const u8{
        "nanomask",
        "--target-tls",
    };

    var cfg = try Config.parse(std.testing.allocator, &args);
    defer cfg.deinit();

    try testing.expect(cfg.target_tls);
    try testing.expectEqual(ConfigSource.cli_flag, cfg.target_tls_src);
}

test "Config - tls-no-system-ca flag" {
    const args = [_][]const u8{
        "nanomask",
        "--tls-no-system-ca",
    };

    var cfg = try Config.parse(std.testing.allocator, &args);
    defer cfg.deinit();

    try testing.expect(cfg.tls_no_system_ca);
    try testing.expectEqual(ConfigSource.cli_flag, cfg.tls_no_system_ca_src);
}

test "Config - ca-file with valid file" {
    const tmp_ca = "test_ca_bundle.pem";
    {
        var f = try std.fs.cwd().createFile(tmp_ca, .{});
        defer f.close();
        try f.writeAll("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n");
    }
    defer std.fs.cwd().deleteFile(tmp_ca) catch {};

    const args = [_][]const u8{
        "nanomask",
        "--ca-file", tmp_ca,
    };

    var cfg = try Config.parse(std.testing.allocator, &args);
    defer cfg.deinit();

    try testing.expectEqualStrings(tmp_ca, cfg.ca_file.?);
    try testing.expectEqual(ConfigSource.cli_flag, cfg.ca_file_src);
}

test "Config - ca-file not found" {
    const args = [_][]const u8{
        "nanomask",
        "--ca-file", "nonexistent_ca_12345.pem",
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.CaFileNotFound, res);
}

test "Config - target-tls + tls-no-system-ca combo" {
    const args = [_][]const u8{
        "nanomask",
        "--target-tls",
        "--tls-no-system-ca",
    };

    var cfg = try Config.parse(std.testing.allocator, &args);
    defer cfg.deinit();

    try testing.expect(cfg.target_tls);
    try testing.expect(cfg.tls_no_system_ca);
    try testing.expectEqual(ConfigSource.cli_flag, cfg.target_tls_src);
    try testing.expectEqual(ConfigSource.cli_flag, cfg.tls_no_system_ca_src);
}

test "Config - tls-no-system-ca + ca-file is valid (complementary)" {
    const tmp_ca = "test_ca_combo.pem";
    {
        var f = try std.fs.cwd().createFile(tmp_ca, .{});
        defer f.close();
        try f.writeAll("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n");
    }
    defer std.fs.cwd().deleteFile(tmp_ca) catch {};

    const args = [_][]const u8{
        "nanomask",
        "--target-tls",
        "--tls-no-system-ca",
        "--ca-file", tmp_ca,
    };

    var cfg = try Config.parse(std.testing.allocator, &args);
    defer cfg.deinit();

    try testing.expect(cfg.tls_no_system_ca);
    try testing.expectEqualStrings(tmp_ca, cfg.ca_file.?);
}

test "Config - healthcheck flag" {
    const args = [_][]const u8{
        "nanomask",
        "--healthcheck",
    };

    var cfg = try Config.parse(std.testing.allocator, &args);
    defer cfg.deinit();

    try testing.expect(cfg.healthcheck);
}

// --- Epic 8: Schema-aware redaction flag tests ---

test "Config - schema-default flag valid values" {
    const args = [_][]const u8{
        "nanomask",
        "--schema-default", "REDACT",
    };

    var cfg = try Config.parse(std.testing.allocator, &args);
    defer cfg.deinit();

    try testing.expectEqualStrings("REDACT", cfg.schema_default);
    try testing.expectEqual(ConfigSource.cli_flag, cfg.schema_default_src);
}

test "Config - schema-default invalid value" {
    const args = [_][]const u8{
        "nanomask",
        "--schema-default", "DELETE",
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.InvalidSchemaDefault, res);
}

test "Config - schema-default missing value" {
    const args = [_][]const u8{
        "nanomask",
        "--schema-default",
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.MissingValue, res);
}

test "Config - hash-key valid 64 hex chars" {
    const valid_key = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const args = [_][]const u8{
        "nanomask",
        "--hash-key", valid_key,
    };

    var cfg = try Config.parse(std.testing.allocator, &args);
    defer cfg.deinit();

    try testing.expectEqualStrings(valid_key, cfg.hash_key.?);
    try testing.expectEqual(ConfigSource.cli_flag, cfg.hash_key_src);
}

test "Config - hash-key invalid length" {
    const args = [_][]const u8{
        "nanomask",
        "--hash-key", "tooshort",
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.InvalidHashKey, res);
}

test "Config - hash-key invalid hex chars" {
    // 64 chars but contains 'g' which is not valid hex
    const args = [_][]const u8{
        "nanomask",
        "--hash-key", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdeg",
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.InvalidHashKey, res);
}

test "Config - hash-key missing value" {
    const args = [_][]const u8{
        "nanomask",
        "--hash-key",
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.MissingValue, res);
}

test "Config - hash-key-file not found" {
    const args = [_][]const u8{
        "nanomask",
        "--hash-key-file", "nonexistent_hash_key_12345.txt",
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.HashKeyFileNotFound, res);
}

test "Config - schema-file not found" {
    const args = [_][]const u8{
        "nanomask",
        "--schema-file", "nonexistent_schema_12345.txt",
    };

    const res = Config.parse(std.testing.allocator, &args);
    try testing.expectError(error.SchemaFileNotFound, res);
}
