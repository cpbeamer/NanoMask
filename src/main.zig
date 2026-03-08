const std = @import("std");
const proxy = @import("net/proxy.zig");
const entity_mask = @import("redaction/entity_mask.zig");
const fuzzy_match = @import("redaction/fuzzy_match.zig");
const config = @import("infra/config.zig");
const Config = config.Config;
const versioned_entity_set = @import("entity/versioned_entity_set.zig");
const VersionedEntitySet = versioned_entity_set.VersionedEntitySet;
const EntitySnapshot = versioned_entity_set.EntitySnapshot;
const file_watcher = @import("entity/file_watcher.zig");
const FileWatcher = file_watcher.FileWatcher;
const admin = @import("admin/admin.zig");
const tls_mod = @import("crypto/tls.zig");
const logger_mod = @import("infra/logger.zig");
const Logger = logger_mod.Logger;
const schema_mod = @import("schema/schema.zig");
const hasher_mod = @import("schema/hasher.zig");
const body_policy = @import("net/body_policy.zig");

const ThreadContext = struct {
    allocator: std.mem.Allocator,
    target_host: []const u8,
    target_port: u16,
    /// RCU-managed entity set — `null` when running in SSN-only mode.
    /// Handler threads call acquire() at request start and release() when done.
    entity_set: ?*VersionedEntitySet,
    /// Shared HTTP client with built-in thread-safe connection pool.
    /// The stdlib ConnectionPool uses std.Thread.Mutex internally,
    /// so concurrent acquire/release from handler threads is safe.
    /// Individual Request objects are per-handler (not thread-safe).
    http_client: *std.http.Client,
    active_connections: *std.atomic.Value(u32),
    admin_config: admin.AdminConfig,
    /// Optional TLS context — when present, each accepted connection performs
    /// a TLS 1.3 handshake before HTTP processing.
    tls_context: ?*tls_mod.TlsContext,
    /// When true, the proxy uses HTTPS to connect to the upstream target.
    target_tls: bool,
    /// Maximum request body size in bytes for the proxy pipeline.
    max_body_size: usize,
    /// Structured JSON logger — thread-safe, shared across all handlers.
    logger: *Logger,
    /// Lifetime connection counter for /healthz endpoint.
    connections_total: *std.atomic.Value(u64),
    /// Server start timestamp (epoch seconds) for uptime calculation.
    start_time: i64,
    unsupported_request_body_behavior: body_policy.UnsupportedBodyBehavior,
    unsupported_response_body_behavior: body_policy.UnsupportedBodyBehavior,
    // Pattern library enable flags (Phase 5 / Epic 7)
    enable_email: bool,
    enable_phone: bool,
    enable_credit_card: bool,
    enable_ip: bool,
    enable_healthcare: bool,
    // Schema-aware redaction (Epic 8)
    schema: ?*const schema_mod.Schema,
    hasher: ?*hasher_mod.Hasher,
};

fn handleConnection(connection: std.net.Server.Connection, ctx: ThreadContext) void {
    defer {
        connection.stream.close();
        _ = ctx.active_connections.fetchSub(1, .release);
    }

    // Generate a unique session ID for request correlation in structured logs.
    var sid_buf: [8]u8 = undefined;
    const session_id = logger_mod.generateSessionId(&sid_buf);

    // Acquire a snapshot at the start of the request. This is lock-free —
    // just an atomic load + fetchAdd. The snapshot stays valid for the
    // entire request even if a hot-reload swaps the active version.
    const snapshot: ?*EntitySnapshot = if (ctx.entity_set) |es| es.acquire() else null;
    defer if (snapshot) |snap| {
        if (ctx.entity_set) |es| es.release(snap);
    };

    var read_buf: [16 * 1024]u8 = undefined;
    var write_buf: [16 * 1024]u8 = undefined;

    var stream_reader = connection.stream.reader(&read_buf);
    var stream_writer = connection.stream.writer(&write_buf);

    // TLS handshake: wrap the raw stream with encrypted reader/writer
    var tls_stream_buf: [32 * 1024]u8 = undefined;
    var tls_stream: ?tls_mod.TlsServerStream = null;
    const raw_reader_iface = stream_reader.interface();
    if (ctx.tls_context) |tls_ctx| {
        tls_stream = tls_mod.accept(tls_ctx, raw_reader_iface, &stream_writer.interface, &tls_stream_buf) catch |err| {
            ctx.logger.log(.error_, "tls_handshake_failed", session_id, &.{
                .{ .key = "error", .value = .{ .string = @errorName(err) } },
            });
            return;
        };
    }

    // Use TLS stream reader/writer if handshake succeeded, otherwise raw stream
    var final_reader: std.Io.Reader = if (tls_stream) |*ts| ts.reader().* else raw_reader_iface.*;
    var final_writer: std.Io.Writer = if (tls_stream) |*ts| ts.writer().* else stream_writer.interface;
    var server = std.http.Server.init(&final_reader, &final_writer);

    var request = server.receiveHead() catch |err| {
        ctx.logger.log(.error_, "receive_head_failed", session_id, &.{
            .{ .key = "error", .value = .{ .string = @errorName(err) } },
        });
        return;
    };

    // Extract entity_map and fuzzy_matcher from the snapshot for the proxy
    const em: ?*const entity_mask.EntityMap = if (snapshot) |s| &s.entity_map else null;
    const fm: ?*const fuzzy_match.FuzzyMatcher = if (snapshot) |s| &s.fuzzy_matcher else null;

    proxy.handleRequest(
        &request,
        .{
            .allocator = ctx.allocator,
            .client = ctx.http_client,
            .target_host = ctx.target_host,
            .target_port = ctx.target_port,
            .target_tls = ctx.target_tls,
            .session_entity_map = em,
            .session_fuzzy_matcher = fm,
            .entity_set = ctx.entity_set,
            .admin_config = ctx.admin_config,
            .max_body_size = ctx.max_body_size,
            .log = ctx.logger,
            .session_id = session_id,
            .active_connections = ctx.active_connections,
            .connections_total = ctx.connections_total,
            .start_time = ctx.start_time,
            .unsupported_request_body_behavior = ctx.unsupported_request_body_behavior,
            .unsupported_response_body_behavior = ctx.unsupported_response_body_behavior,
            .enable_email = ctx.enable_email,
            .enable_phone = ctx.enable_phone,
            .enable_credit_card = ctx.enable_credit_card,
            .enable_ip = ctx.enable_ip,
            .enable_healthcare = ctx.enable_healthcare,
            .schema = ctx.schema,
            .hasher = ctx.hasher,
        },
    ) catch |err| {
        ctx.logger.log(.error_, "proxy_request_failed", session_id, &.{
            .{ .key = "error", .value = .{ .string = @errorName(err) } },
        });
    };
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    // SAFETY: main() runs an infinite accept loop and never returns under normal
    // operation, so gpa.deinit() is unreachable. Detached handler threads
    // continue to use this allocator for the program's entire lifetime.
    // If graceful shutdown is added later, drain active_connections to zero
    // before calling gpa.deinit().
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);

    var cfg = Config.parse(allocator, args) catch |err| {
        if (err == error.HelpRequested) {
            std.process.exit(0);
        } else {
            std.process.exit(1);
        }
    };
    defer cfg.deinit();

    // --- Healthcheck probe mode ---
    // When --healthcheck is set, act as a client: probe /healthz on the
    // configured listener and exit 0 (healthy) or 1 (unhealthy). Wildcard
    // listeners map to loopback so container probes still work.
    if (cfg.healthcheck) {
        var client = std.http.Client{ .allocator = allocator };
        defer client.deinit();

        var url_buf: [160]u8 = undefined;
        const url = cfg.formatHealthcheckUrl(&url_buf) catch {
            std.process.exit(1);
        };

        const result = client.fetch(.{
            .location = .{ .url = url },
        }) catch {
            std.process.exit(1);
        };

        if (result.status == .ok) {
            std.process.exit(0);
        }
        std.process.exit(1);
    }

    // --- Structured Logger ---
    var log = Logger.init(cfg.log_level, cfg.audit_log, cfg.log_file) catch |err| {
        std.debug.print("error: failed to initialise logger: {}\n", .{err});
        std.process.exit(1);
    };
    defer log.deinit();

    var listen_address_buf: [128]u8 = undefined;
    const listen_address = cfg.formatListenAddress(&listen_address_buf) catch {
        std.debug.print("error: failed to format listen address\n", .{});
        std.process.exit(1);
    };

    log.log(.info, "config_resolved", null, &.{
        .{ .key = "listen_host", .value = .{ .string = cfg.listen_host } },
        .{ .key = "listen_port", .value = .{ .uint = cfg.listen_port } },
        .{ .key = "listen_address", .value = .{ .string = listen_address } },
        .{ .key = "target_host", .value = .{ .string = cfg.target_host } },
        .{ .key = "target_port", .value = .{ .uint = cfg.target_port } },
        .{ .key = "log_level", .value = .{ .string = @tagName(cfg.log_level) } },
        .{ .key = "unsupported_request_body_behavior", .value = .{ .string = @tagName(cfg.unsupported_request_body_behavior) } },
        .{ .key = "unsupported_response_body_behavior", .value = .{ .string = @tagName(cfg.unsupported_response_body_behavior) } },
    });

    // --- Entity Masking Setup (RCU) ---
    // Heap-allocate so the pointer is stable for the FileWatcher's background
    // thread — avoids dangling pointer risk from stack-local optionals.
    var entity_set: ?*VersionedEntitySet = null;
    var watcher: ?FileWatcher = null;

    defer {
        // Join the watcher thread before freeing the entity set it references.
        if (watcher) |*w| w.join();
        if (entity_set) |es| {
            es.deinit();
            allocator.destroy(es);
        }
    }

    if (cfg.entity_file) |ef| {
        const initial_snapshot = versioned_entity_set.loadSnapshotFromFile(
            ef,
            cfg.fuzzy_threshold,
            1,
            allocator,
        ) catch {
            std.process.exit(1);
        };

        log.log(.info, "entities_loaded", null, &.{
            .{ .key = "count", .value = .{ .uint = initial_snapshot.loaded_names.len } },
            .{ .key = "file", .value = .{ .string = ef } },
        });

        const es = try allocator.create(VersionedEntitySet);
        es.* = VersionedEntitySet.init(initial_snapshot);
        entity_set = es;

        // Start watching the entity file for changes (hot-reload via RCU)
        watcher = FileWatcher.init(
            ef,
            cfg.watch_interval_ms,
            es,
            cfg.fuzzy_threshold,
            allocator,
        );
        watcher.?.start() catch {
            log.warn("file_watcher_start_failed", null);
            watcher = null;
        };
    } else if (cfg.admin_api) {
        const empty_names = [_][]const u8{};
        const initial_snapshot = versioned_entity_set.loadSnapshotFromNames(
            &empty_names,
            cfg.fuzzy_threshold,
            1,
            allocator,
        ) catch {
            log.err("empty_entity_set_failed", null);
            std.process.exit(1);
        };
        log.info("admin_api_enabled", null);
        const es = try allocator.create(VersionedEntitySet);
        es.* = VersionedEntitySet.init(initial_snapshot);
        entity_set = es;
    } else {
        log.warn("ssn_only_mode", null);
    }

    // --- Schema-aware redaction setup (Epic 8) ---
    var schema_instance: ?schema_mod.Schema = null;
    defer if (schema_instance) |*s| s.deinit();

    if (cfg.schema_file) |sf| {
        schema_instance = schema_mod.Schema.loadFromFile(sf, allocator) catch |err| {
            std.debug.print("error: failed to load schema file: {}\n", .{err});
            std.process.exit(1);
        };
        // Override default action from CLI/env if provided
        if (cfg.schema_default) |sd| {
            schema_instance.?.default_action = schema_mod.SchemaAction.parse(sd) catch .scan;
        }
        log.log(.info, "schema_loaded", null, &.{
            .{ .key = "file", .value = .{ .string = sf } },
            .{ .key = "fields", .value = .{ .uint = schema_instance.?.fieldCount() } },
        });
    }

    var hasher_instance: ?hasher_mod.Hasher = null;
    defer if (hasher_instance) |*h| h.deinit();

    // Only create a hasher when an explicit key is provided or the schema
    // actually contains HASH-action fields. This avoids unnecessary
    // crypto-random key generation for schemas with no HASH rules.
    const needs_hasher = cfg.hash_key != null or cfg.hash_key_file != null or
        (if (schema_instance) |*s| s.hasHashFields() else false);

    if (needs_hasher) {
        if (cfg.hash_key_file) |kf| {
            hasher_instance = hasher_mod.Hasher.initFromFile(kf, allocator) catch |err| {
                std.debug.print("error: failed to load hash key file: {}\n", .{err});
                std.process.exit(1);
            };
        } else {
            hasher_instance = hasher_mod.Hasher.init(cfg.hash_key, allocator) catch |err| {
                std.debug.print("error: failed to initialise hasher: {}\n", .{err});
                std.process.exit(1);
            };
        }
        const hex = hasher_instance.?.keyHex();
        log.log(.info, "hasher_initialized", null, &.{
            .{ .key = "key_source", .value = .{ .string = if (cfg.hash_key != null) "cli" else if (cfg.hash_key_file != null) "file" else "auto" } },
            .{ .key = "key_prefix", .value = .{ .string = hex[0..8] } },
        });
    }

    // --- TLS setup ---
    var tls_context: ?tls_mod.TlsContext = null;
    defer if (tls_context) |*tc| tc.deinit();

    if (cfg.tls_cert) |cert_path| {
        if (cfg.tls_key) |key_path| {
            tls_context = tls_mod.TlsContext.init(cert_path, key_path, allocator) catch |err| {
                std.debug.print("error: failed to load TLS certificate/key: {}\n", .{err});
                std.process.exit(1);
            };
            log.log(.info, "tls_loaded", null, &.{
                .{ .key = "cert", .value = .{ .string = cert_path } },
            });
        }
    }

    const tls_enabled = tls_context != null;
    const protocol = if (tls_enabled) "https" else "http";
    const upstream_protocol = if (cfg.target_tls) "https" else "http";
    log.log(.info, "server_starting", null, &.{
        .{ .key = "protocol", .value = .{ .string = protocol } },
        .{ .key = "listen_host", .value = .{ .string = cfg.listen_host } },
        .{ .key = "listen_port", .value = .{ .uint = cfg.listen_port } },
        .{ .key = "listen_address", .value = .{ .string = listen_address } },
        .{ .key = "upstream_protocol", .value = .{ .string = upstream_protocol } },
        .{ .key = "target_host", .value = .{ .string = cfg.target_host } },
        .{ .key = "target_port", .value = .{ .uint = cfg.target_port } },
        .{ .key = "max_connections", .value = .{ .uint = cfg.max_connections } },
        .{ .key = "tls_enabled", .value = .{ .boolean = tls_enabled } },
    });

    if (!tls_enabled) {
        log.warn("no_tls_warning", null);
    }

    // --- Upstream TLS status ---
    if (cfg.target_tls) {
        if (cfg.ca_file) |ca| {
            log.log(.info, "upstream_tls_ca", null, &.{
                .{ .key = "ca_file", .value = .{ .string = ca } },
            });
        }
        if (cfg.tls_no_system_ca) {
            log.warn("system_ca_suppressed", null);
        }
    }

    const bind_address = std.net.Address.parseIp(cfg.listen_host, cfg.listen_port) catch {
        std.debug.print("error: invalid listen address '{s}'\n", .{cfg.listen_host});
        std.process.exit(1);
    };

    var net_server = try std.net.Address.listen(bind_address, .{
        .reuse_address = true,
    });
    defer net_server.deinit();

    log.log(.info, "server_listening", null, &.{
        .{ .key = "listen_host", .value = .{ .string = cfg.listen_host } },
        .{ .key = "listen_port", .value = .{ .uint = cfg.listen_port } },
        .{ .key = "listen_address", .value = .{ .string = listen_address } },
    });

    // Shared HTTP client: the stdlib ConnectionPool is thread-safe (uses Mutex).
    // All handler threads share this client, enabling TCP connection reuse with
    // keep-alive. Eliminates per-request TCP handshake overhead (5-10ms savings).
    var http_client = std.http.Client{ .allocator = allocator };
    defer http_client.deinit();

    // Configure upstream TLS CA bundle.
    //
    // By default, std.http.Client rescans system CAs on the first HTTPS
    // request (next_https_rescan_certs = true). We override this only when
    // the user requests a custom CA file or suppresses system CAs.
    //
    // --tls-no-system-ca prevents system CA loading. On its own this means
    // the CA bundle stays empty and ALL upstream HTTPS will fail (the TLS
    // client requires at least one trusted root). Pair it with --ca-file
    // to provide the self-signed CA that should be trusted instead.
    if (cfg.target_tls) {
        if (cfg.ca_file) |ca_path| {
            // Load a custom CA bundle PEM file for internal PKI / GovCloud.
            http_client.ca_bundle.addCertsFromFilePath(allocator, std.fs.cwd(), ca_path) catch |err| {
                std.debug.print("error: failed to load CA file '{s}': {}\n", .{ ca_path, err });
                std.process.exit(1);
            };
        }
        if (cfg.tls_no_system_ca) {
            // Prevent the default system CA rescan — only explicitly loaded
            // CAs (from --ca-file) will be trusted.
            http_client.next_https_rescan_certs = false;
        } else if (cfg.ca_file != null) {
            // When a custom CA is provided without --tls-no-system-ca, we
            // still suppress the system rescan. This is intentional: mixing
            // a custom internal CA with the system bundle risks trusting
            // unexpected public CAs in a compliance-sensitive proxy. Use
            // --ca-file as the sole trust anchor for deterministic behavior.
            http_client.next_https_rescan_certs = false;
        }
        // When neither flag is set, the default system CA scan applies.
    }

    // NOTE: Upstream request timeouts are not yet configurable via std.http.Client.
    // Long-running upstream calls will block the handler thread until completion.
    // This is a known limitation to address when the stdlib exposes timeout options.

    var active_connections = std.atomic.Value(u32).init(0);
    var connections_total = std.atomic.Value(u64).init(0);
    const start_time = std.time.timestamp();

    const admin_config = admin.AdminConfig{
        .enabled = cfg.admin_api,
        .token = cfg.admin_token,
        .entity_file_sync = cfg.entity_file_sync,
        .entity_file = cfg.entity_file,
        .fuzzy_threshold = cfg.fuzzy_threshold,
    };

    const ctx = ThreadContext{
        .allocator = allocator,
        .target_host = cfg.target_host,
        .target_port = cfg.target_port,
        .entity_set = entity_set,
        .http_client = &http_client,
        .active_connections = &active_connections,
        .admin_config = admin_config,
        .tls_context = if (tls_context) |*tc| tc else null,
        .target_tls = cfg.target_tls,
        .max_body_size = cfg.max_body_size,
        .logger = &log,
        .connections_total = &connections_total,
        .start_time = start_time,
        .unsupported_request_body_behavior = cfg.unsupported_request_body_behavior,
        .unsupported_response_body_behavior = cfg.unsupported_response_body_behavior,
        .enable_email = cfg.enable_email,
        .enable_phone = cfg.enable_phone,
        .enable_credit_card = cfg.enable_credit_card,
        .enable_ip = cfg.enable_ip,
        .enable_healthcare = cfg.enable_healthcare,
        .schema = if (schema_instance) |*s| s else null,
        .hasher = if (hasher_instance) |*h| h else null,
    };

    while (true) {
        const connection = net_server.accept() catch {
            log.err("accept_failed", null);
            continue;
        };

        _ = connections_total.fetchAdd(1, .monotonic);

        // Enforce connection limit to prevent thread exhaustion under load.
        const current = active_connections.fetchAdd(1, .acquire);
        if (current >= cfg.max_connections) {
            log.warn("connection_limit_reached", null);
            _ = active_connections.fetchSub(1, .release);
            connection.stream.close();
            continue;
        }

        // Spawn a thread per connection for concurrent request handling.
        const thread = std.Thread.spawn(.{}, handleConnection, .{ connection, ctx }) catch {
            log.err("thread_spawn_failed", null);
            _ = active_connections.fetchSub(1, .release);
            connection.stream.close();
            continue;
        };
        thread.detach();
    }
}
