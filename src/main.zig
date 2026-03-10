const std = @import("std");
const builtin = @import("builtin");
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
const observability_mod = @import("infra/observability.zig");
const Observability = observability_mod.Observability;
const schema_mod = @import("schema/schema.zig");
const hasher_mod = @import("schema/hasher.zig");
const body_policy = @import("net/body_policy.zig");
const shutdown_mod = @import("infra/shutdown.zig");
const proxy_server_mod = @import("net/proxy_server.zig");
const runtime_model_mod = @import("net/runtime_model.zig");
const upstream_client = @import("net/upstream_client.zig");

var termination_signal_requested = std.atomic.Value(bool).init(false);

fn handleTerminationSignal(sig: i32) callconv(.c) void {
    _ = sig;
    termination_signal_requested.store(true, .release);
}

fn installTerminationSignalHandlers() void {
    if (builtin.os.tag == .windows) return;

    const action = std.posix.Sigaction{
        .handler = .{ .handler = handleTerminationSignal },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(std.posix.SIG.INT, &action, null);
    std.posix.sigaction(std.posix.SIG.TERM, &action, null);
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

    var active_connections = std.atomic.Value(u32).init(0);
    var connections_total = std.atomic.Value(u64).init(0);
    const start_time = std.time.timestamp();
    var observability = Observability.init(&log, &active_connections);

    var listen_address_buf: [128]u8 = undefined;
    const listen_address = cfg.formatListenAddress(&listen_address_buf) catch {
        std.debug.print("error: failed to format listen address\n", .{});
        std.process.exit(1);
    };
    const proxy_runtime_worker_threads = runtime_model_mod.resolveWorkerThreads(
        cfg.runtime_model,
        cfg.runtime_worker_threads,
        cfg.max_connections,
    );

    log.log(.info, "config_resolved", null, &.{
        .{ .key = "listen_host", .value = .{ .string = cfg.listen_host } },
        .{ .key = "listen_port", .value = .{ .uint = cfg.listen_port } },
        .{ .key = "listen_address", .value = .{ .string = listen_address } },
        .{ .key = "target_host", .value = .{ .string = cfg.target_host } },
        .{ .key = "target_port", .value = .{ .uint = cfg.target_port } },
        .{ .key = "admin_api", .value = .{ .boolean = cfg.admin_api } },
        .{ .key = "admin_listen_address", .value = .{ .string = cfg.admin_listen_address orelse "-" } },
        .{ .key = "admin_allowlist_configured", .value = .{ .boolean = cfg.admin_allowlist != null } },
        .{ .key = "admin_read_only", .value = .{ .boolean = cfg.admin_read_only } },
        .{ .key = "admin_mutation_rate_limit_per_minute", .value = .{ .uint = cfg.admin_mutation_rate_limit_per_minute } },
        .{ .key = "upstream_connect_timeout_ms", .value = .{ .uint = cfg.upstream_connect_timeout_ms } },
        .{ .key = "upstream_read_timeout_ms", .value = .{ .uint = cfg.upstream_read_timeout_ms } },
        .{ .key = "upstream_request_timeout_ms", .value = .{ .uint = cfg.upstream_request_timeout_ms } },
        .{ .key = "shutdown_drain_timeout_ms", .value = .{ .uint = cfg.shutdown_drain_timeout_ms } },
        .{ .key = "runtime_model", .value = .{ .string = cfg.runtime_model.label() } },
        .{ .key = "runtime_worker_threads", .value = .{ .uint = proxy_runtime_worker_threads } },
        .{ .key = "log_level", .value = .{ .string = @tagName(cfg.log_level) } },
        .{ .key = "unsupported_request_body_behavior", .value = .{ .string = @tagName(cfg.unsupported_request_body_behavior) } },
        .{ .key = "unsupported_response_body_behavior", .value = .{ .string = @tagName(cfg.unsupported_response_body_behavior) } },
    });

    var admin_state = admin.AdminState{};
    var admin_allowlist: ?admin.IpAllowlist = null;
    defer if (admin_allowlist) |*allowlist| allowlist.deinit();

    if (cfg.admin_allowlist) |allowlist_csv| {
        admin_allowlist = admin.IpAllowlist.initFromCsv(allowlist_csv, allocator) catch |err| {
            std.debug.print("error: failed to parse admin allowlist: {}\n", .{err});
            std.process.exit(1);
        };
    }

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
            &observability,
            &log,
        );
        watcher.?.start() catch {
            log.warn("file_watcher_start_failed", null);
            observability.markEntityReloadFailure();
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
        .{ .key = "admin_listen_address", .value = .{ .string = cfg.admin_listen_address orelse "-" } },
        .{ .key = "upstream_protocol", .value = .{ .string = upstream_protocol } },
        .{ .key = "target_host", .value = .{ .string = cfg.target_host } },
        .{ .key = "target_port", .value = .{ .uint = cfg.target_port } },
        .{ .key = "max_connections", .value = .{ .uint = cfg.max_connections } },
        .{ .key = "runtime_model", .value = .{ .string = cfg.runtime_model.label() } },
        .{ .key = "runtime_worker_threads", .value = .{ .uint = proxy_runtime_worker_threads } },
        .{ .key = "shutdown_drain_timeout_ms", .value = .{ .uint = cfg.shutdown_drain_timeout_ms } },
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
    const dedicated_admin_listener = cfg.admin_api and cfg.admin_listen_address != null;
    const admin_runtime_model = if (dedicated_admin_listener)
        proxy_server_mod.RuntimeModel.thread_per_connection
    else
        cfg.runtime_model;

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

    const admin_config = admin.AdminConfig{
        .enabled = cfg.admin_api,
        .token = cfg.admin_token,
        .allowlist = if (admin_allowlist) |*allowlist| allowlist else null,
        .read_only = cfg.admin_read_only,
        .mutation_rate_limit_per_minute = cfg.admin_mutation_rate_limit_per_minute,
        .state = &admin_state,
        .logger = &log,
        .entity_file_sync = cfg.entity_file_sync,
        .entity_file = cfg.entity_file,
        .fuzzy_threshold = cfg.fuzzy_threshold,
    };

    var shutdown_state = shutdown_mod.ShutdownState{};

    observability.markStartupReady();

    const net_server = try std.net.Address.listen(bind_address, .{
        .reuse_address = true,
    });
    var admin_net_server: ?std.net.Server = null;
    if (dedicated_admin_listener) {
        const admin_bind_address = std.net.Address.parseIpAndPort(cfg.admin_listen_address.?) catch {
            std.debug.print("error: invalid admin listen address '{s}'\n", .{cfg.admin_listen_address.?});
            std.process.exit(1);
        };
        admin_net_server = std.net.Address.listen(admin_bind_address, .{
            .reuse_address = true,
        }) catch |err| {
            std.debug.print("error: failed to bind admin listener '{s}': {s}\n", .{
                cfg.admin_listen_address.?,
                @errorName(err),
            });
            std.process.exit(1);
        };
    }

    log.log(.info, "server_listening", null, &.{
        .{ .key = "listen_host", .value = .{ .string = cfg.listen_host } },
        .{ .key = "listen_port", .value = .{ .uint = cfg.listen_port } },
        .{ .key = "listen_address", .value = .{ .string = listen_address } },
    });
    if (dedicated_admin_listener) {
        log.log(.info, "admin_server_listening", null, &.{
            .{ .key = "listen_address", .value = .{ .string = cfg.admin_listen_address.? } },
            .{ .key = "read_only", .value = .{ .boolean = cfg.admin_read_only } },
            .{ .key = "allowlist_configured", .value = .{ .boolean = cfg.admin_allowlist != null } },
            .{ .key = "mutation_rate_limit_per_minute", .value = .{ .uint = cfg.admin_mutation_rate_limit_per_minute } },
        });
    }

    var server = proxy_server_mod.ProxyServer{
        .net_server = net_server,
        .handler = .{
            .ctx = .{
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
                .observability = &observability,
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
                .shutdown_state = &shutdown_state,
                .listener_mode = if (dedicated_admin_listener) .proxy_only else .combined,
                .upstream_timeouts = .{
                    .connect_timeout_ms = cfg.upstream_connect_timeout_ms,
                    .read_timeout_ms = cfg.upstream_read_timeout_ms,
                    .request_timeout_ms = cfg.upstream_request_timeout_ms,
                },
            },
        },
        .max_connections = cfg.max_connections,
        .drain_timeout_ms = cfg.shutdown_drain_timeout_ms,
        .active_connections = &active_connections,
        .logger = &log,
        .observability = &observability,
        .shutdown_state = &shutdown_state,
        .runtime_model = cfg.runtime_model,
        .runtime_worker_threads = proxy_runtime_worker_threads,
    };
    defer server.deinit();

    var admin_server: ?proxy_server_mod.ProxyServer = null;
    if (admin_net_server) |ns| {
        admin_server = .{
            .net_server = ns,
            .handler = .{
                .ctx = .{
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
                    .observability = &observability,
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
                    .shutdown_state = &shutdown_state,
                    .listener_mode = .admin_only,
                    .upstream_timeouts = .{
                        .connect_timeout_ms = cfg.upstream_connect_timeout_ms,
                        .read_timeout_ms = cfg.upstream_read_timeout_ms,
                        .request_timeout_ms = cfg.upstream_request_timeout_ms,
                    },
                },
            },
            .max_connections = cfg.max_connections,
            .drain_timeout_ms = cfg.shutdown_drain_timeout_ms,
            .active_connections = &active_connections,
            .logger = &log,
            .observability = &observability,
            .shutdown_state = &shutdown_state,
            .runtime_model = admin_runtime_model,
        };
    }
    defer if (admin_server) |*server_ptr| server_ptr.deinit();

    termination_signal_requested.store(false, .release);
    installTerminationSignalHandlers();

    const ListenerRunner = struct {
        fn run(ps: *proxy_server_mod.ProxyServer) void {
            ps.serve();
        }
    };

    const ShutdownWatcher = struct {
        fn run(ps: *proxy_server_mod.ProxyServer, admin_ps: ?*proxy_server_mod.ProxyServer) void {
            if (builtin.os.tag == .windows) return;

            while (!ps.shutdown_state.isRequested()) {
                if (termination_signal_requested.load(.acquire)) {
                    ps.initiateShutdown("signal");
                    if (admin_ps) |server_ptr| {
                        server_ptr.initiateShutdown("signal");
                    }
                    return;
                }
                std.Thread.sleep(50 * std.time.ns_per_ms);
            }
        }
    };

    const maybe_admin_thread = if (admin_server) |*server_ptr|
        try std.Thread.spawn(.{}, ListenerRunner.run, .{server_ptr})
    else
        null;
    defer if (maybe_admin_thread) |admin_thread| admin_thread.join();

    const maybe_shutdown_watcher = if (builtin.os.tag == .windows)
        null
    else
        try std.Thread.spawn(.{}, ShutdownWatcher.run, .{
            &server,
            if (admin_server) |*server_ptr| server_ptr else null,
        });
    defer if (maybe_shutdown_watcher) |signal_watcher| signal_watcher.join();

    server.serve();
}
