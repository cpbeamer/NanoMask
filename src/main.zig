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
const evaluation_report_mod = @import("infra/evaluation_report.zig");
const EvaluationReport = evaluation_report_mod.EvaluationReport;
const rbac = @import("admin/rbac.zig");
const ApiKeyStore = rbac.ApiKeyStore;
const audit_store_mod = @import("infra/audit_store.zig");
const AuditStore = audit_store_mod.AuditStore;
const semantic_cache_mod = @import("infra/semantic_cache.zig");
const vault_mod = @import("vault/vault.zig");
const memory_vault_mod = @import("vault/memory_vault.zig");
const file_vault_mod = @import("vault/file_vault.zig");
const external_vault_mod = @import("vault/external_vault.zig");

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

fn appendFeature(
    features: *std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,
    label: []const u8,
) !void {
    if (features.items.len > 0) {
        try features.appendSlice(allocator, ", ");
    }
    try features.appendSlice(allocator, label);
}

fn buildFeatureSummary(
    allocator: std.mem.Allocator,
    cfg: Config,
    entity_count: usize,
    schema_field_count: usize,
) ![]u8 {
    var features: std.ArrayListUnmanaged(u8) = .empty;
    errdefer features.deinit(allocator);

    try appendFeature(&features, allocator, "ssn");
    if (entity_count > 0 or cfg.admin_api) try appendFeature(&features, allocator, "entity-mask");
    if (cfg.enable_email) try appendFeature(&features, allocator, "email");
    if (cfg.enable_phone) try appendFeature(&features, allocator, "phone");
    if (cfg.enable_credit_card) try appendFeature(&features, allocator, "credit-card");
    if (cfg.enable_ip) try appendFeature(&features, allocator, "ip");
    if (cfg.enable_healthcare) try appendFeature(&features, allocator, "healthcare");
    if (cfg.enable_iban) try appendFeature(&features, allocator, "iban");
    if (cfg.enable_uk_nino) try appendFeature(&features, allocator, "uk-nino");
    if (cfg.enable_passport) try appendFeature(&features, allocator, "passport");
    if (cfg.enable_intl_phone) try appendFeature(&features, allocator, "intl-phone");
    if (cfg.enable_dates) try appendFeature(&features, allocator, "dates");
    if (cfg.enable_addresses) try appendFeature(&features, allocator, "addresses");
    if (cfg.enable_fax) try appendFeature(&features, allocator, "fax");
    if (cfg.enable_accounts) try appendFeature(&features, allocator, "accounts");
    if (cfg.enable_licenses) try appendFeature(&features, allocator, "licenses");
    if (cfg.enable_urls) try appendFeature(&features, allocator, "urls");
    if (cfg.enable_vehicle_ids) try appendFeature(&features, allocator, "vehicle-ids");

    if (schema_field_count > 0) try appendFeature(&features, allocator, "schema");
    if (cfg.target_tls) try appendFeature(&features, allocator, "upstream-tls");
    if (cfg.report_only) try appendFeature(&features, allocator, "report-only");

    if (cfg.enable_guardrails) {
        var guardrail_buf: [48]u8 = undefined;
        const label = try std.fmt.bufPrint(&guardrail_buf, "guardrails({s})", .{cfg.guardrail_mode.label()});
        try appendFeature(&features, allocator, label);
    }

    if (cfg.enable_semantic_cache) {
        try appendFeature(&features, allocator, "semantic-cache");
    }

    if (cfg.admin_api) {
        try appendFeature(&features, allocator, "admin-api");
    }

    return try features.toOwnedSlice(allocator);
}

fn printStartupBanner(
    allocator: std.mem.Allocator,
    cfg: Config,
    entity_count: usize,
    schema_field_count: usize,
) !void {
    const feature_summary = try buildFeatureSummary(allocator, cfg, entity_count, schema_field_count);
    defer allocator.free(feature_summary);

    var schema_buf: [32]u8 = undefined;
    const schema_summary = if (schema_field_count > 0)
        try std.fmt.bufPrint(&schema_buf, "{d} fields", .{schema_field_count})
    else
        "disabled";

    std.debug.print(
        "\n" ++
            "NanoMask {s}\n" ++
            "  Listener  {s}:{d}\n" ++
            "  Upstream  {s}://{s}:{d}\n" ++
            "  Entities  {d}\n" ++
            "  Schema    {s}\n" ++
            "  Features  {s}\n" ++
            "\n",
        .{
            Config.version,
            cfg.listen_host,
            cfg.listen_port,
            if (cfg.target_tls) "https" else "http",
            cfg.target_host,
            cfg.target_port,
            entity_count,
            schema_summary,
            feature_summary,
        },
    );
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

    // --- Validate-config mode ---
    // When --validate-config is set, print the resolved configuration
    // summary and exit 0. All file existence, flag pairing, and
    // consistency checks already ran during Config.parse().
    if (cfg.validate_config) {
        std.debug.print(
            "NanoMask configuration valid.\n" ++
                "\n" ++
                "  Network\n" ++
                "    listen        {s}:{d}\n" ++
                "    target        {s}:{d}\n" ++
                "    target_tls    {s}\n" ++
                "    listener_tls  {s}\n" ++
                "    max_conns     {d}\n" ++
                "    runtime       {s}\n" ++
                "\n" ++
                "  Redaction\n" ++
                "    entity_file   {s}\n" ++
                "    schema_file   {s}\n" ++
                "    email         {s}\n" ++
                "    phone         {s}\n" ++
                "    credit_card   {s}\n" ++
                "    ip            {s}\n" ++
                "    healthcare    {s}\n" ++
                "    iban          {s}\n" ++
                "    uk_nino       {s}\n" ++
                "    passport      {s}\n" ++
                "    intl_phone    {s}\n" ++
                "    dates         {s}\n" ++
                "    addresses     {s}\n" ++
                "    accounts      {s}\n" ++
                "    licenses      {s}\n" ++
                "    urls          {s}\n" ++
                "    vehicle_ids   {s}\n" ++
                "    report_only   {s}\n" ++
                "    guardrails    {s} ({s})\n" ++
                "    sem_cache     {s} ttl={d}ms entries={d}\n" ++
                "\n" ++
                "  Admin\n" ++
                "    admin_api     {s}\n" ++
                "    audit_log     {s}\n" ++
                "    log_level     {s}\n" ++
                "\n" ++
                "  Not Yet Implemented (flags accepted, no effect)\n" ++
                "    syslog        accepted (UDP syslog forwarding not yet implemented)\n" ++
                "    mtls          accepted (mTLS enforcement not yet implemented)\n",
            .{
                cfg.listen_host,
                cfg.listen_port,
                cfg.target_host,
                cfg.target_port,
                if (cfg.target_tls) "enabled" else "disabled",
                if (cfg.tls_cert != null) "enabled" else "disabled",
                cfg.max_connections,
                cfg.runtime_model.label(),
                cfg.entity_file orelse "none",
                cfg.schema_file orelse "none",
                if (cfg.enable_email) "enabled" else "disabled",
                if (cfg.enable_phone) "enabled" else "disabled",
                if (cfg.enable_credit_card) "enabled" else "disabled",
                if (cfg.enable_ip) "enabled" else "disabled",
                if (cfg.enable_healthcare) "enabled" else "disabled",
                if (cfg.enable_iban) "enabled" else "disabled",
                if (cfg.enable_uk_nino) "enabled" else "disabled",
                if (cfg.enable_passport) "enabled" else "disabled",
                if (cfg.enable_intl_phone) "enabled" else "disabled",
                if (cfg.enable_dates) "enabled" else "disabled",
                if (cfg.enable_addresses) "enabled" else "disabled",
                if (cfg.enable_accounts) "enabled" else "disabled",
                if (cfg.enable_licenses) "enabled" else "disabled",
                if (cfg.enable_urls) "enabled" else "disabled",
                if (cfg.enable_vehicle_ids) "enabled" else "disabled",
                if (cfg.report_only) "enabled" else "disabled",
                if (cfg.enable_guardrails) "enabled" else "disabled",
                cfg.guardrail_mode.label(),
                if (cfg.enable_semantic_cache) "enabled" else "disabled",
                cfg.semantic_cache_ttl_ms,
                cfg.semantic_cache_max_entries,
                if (cfg.admin_api) "enabled" else "disabled",
                if (cfg.audit_log) "enabled" else "disabled",
                @tagName(cfg.log_level),
            },
        );
        std.process.exit(0);
    }

    // --- Structured Logger ---
    var log = Logger.init(cfg.log_level, cfg.audit_log, cfg.log_file) catch |err| {
        std.debug.print("error: failed to initialise logger: {}\n", .{err});
        std.process.exit(1);
    };
    defer log.deinit();

    // --- OTel service name (Phase 3 / NMV3-013) ---
    if (cfg.otel_service_name) |svc| {
        log.service_name = svc;
    }

    // --- Syslog forwarding (Phase 3 / NMV3-013) ---
    // UDP syslog output is not yet implemented. Warn the operator rather than
    // silently ignoring the flag so they know it has no effect.
    if (cfg.syslog_address != null) {
        log.log(.warn, "syslog_not_implemented", null, &.{
            .{ .key = "note", .value = .{ .string = "--syslog-address is accepted but UDP syslog forwarding is not yet implemented in this build" } },
        });
    }

    // --- mTLS (Phase 3 / NMV3-011) ---
    // PEM files are validated at startup (see config.zig checkPemFile) but
    // mTLS enforcement is not yet wired into the TLS stack. Warn the operator.
    if (cfg.mtls_ca != null or cfg.mtls_cert != null or cfg.mtls_key != null) {
        log.log(.warn, "mtls_not_implemented", null, &.{
            .{ .key = "note", .value = .{ .string = "--mtls-* flags are accepted but mTLS enforcement is not yet implemented in this build" } },
        });
    }

    // --- Audit ring buffer (Phase 3 / NMV3-012) ---
    var audit_store_instance = AuditStore.init(cfg.audit_buffer_size, allocator) catch |err| {
        std.debug.print("error: failed to initialise audit store: {}\n", .{err});
        std.process.exit(1);
    };
    defer audit_store_instance.deinit();
    // Wire audit events from the logger into the ring buffer.
    log.audit_store = &audit_store_instance;

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
        .{ .key = "report_only", .value = .{ .boolean = cfg.report_only } },
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
    var entity_count: usize = 0;

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
            &log,
            allocator,
        ) catch {
            std.process.exit(1);
        };

        log.log(.info, "entities_loaded", null, &.{
            .{ .key = "count", .value = .{ .uint = initial_snapshot.loaded_names.len } },
            .{ .key = "file", .value = .{ .string = ef } },
        });
        entity_count = initial_snapshot.loaded_names.len;

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
            &log,
            allocator,
        ) catch {
            log.err("empty_entity_set_failed", null);
            std.process.exit(1);
        };
        log.info("admin_api_enabled", null);
        entity_count = initial_snapshot.loaded_names.len;
        const es = try allocator.create(VersionedEntitySet);
        es.* = VersionedEntitySet.init(initial_snapshot);
        entity_set = es;
    } else {
        log.warn("ssn_only_mode", null);
    }

    // --- Schema-aware redaction setup (Epic 8) ---
    var schema_instance: ?schema_mod.Schema = null;
    var schema_field_count: usize = 0;
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
        schema_field_count = schema_instance.?.fieldCount();
        log.log(.info, "schema_loaded", null, &.{
            .{ .key = "file", .value = .{ .string = sf } },
            .{ .key = "fields", .value = .{ .uint = schema_field_count } },
        });
    }

    var vault_instance: ?vault_mod.VaultBackend = null;
    var hasher_instance: ?hasher_mod.Hasher = null;
    defer {
        // Hasher does NOT own the vault — deinit only frees hasher-internal state.
        if (hasher_instance) |*h| h.deinit();
        // Vault is owned by main and freed here.
        if (vault_instance) |*v| {
            switch (v.*) {
                .memory => |m| m.vaultInterface().deinit(),
                .file => |f| f.vaultInterface().deinit(),
                .external => |e| e.vaultInterface().deinit(),
            }
        }
    }

    // Only create a hasher when an explicit key is provided or the schema
    // actually contains HASH-action fields. This avoids unnecessary
    // crypto-random key generation for schemas with no HASH rules.
    const needs_hasher = cfg.hash_key != null or cfg.hash_key_file != null or
        cfg.hash_key_exec != null or
        (if (schema_instance) |*s| s.hasHashFields() else false);

    if (needs_hasher) {
        // 1. Resolve the HMAC key bytes first — FileVault needs them for encryption.
        var resolved_key_hex: ?[]const u8 = null;
        var exec_output_owned: ?[]u8 = null;
        defer if (exec_output_owned) |eo| allocator.free(eo);
        // Holds file contents when --hash-key-file is used; freed after hasher init.
        var file_key_contents_owned: ?[]u8 = null;
        defer if (file_key_contents_owned) |fkc| allocator.free(fkc);

        if (cfg.hash_key_exec) |cmd| {
            const argv = if (builtin.os.tag == .windows)
                &[_][]const u8{ "cmd.exe", "/c", cmd }
            else
                &[_][]const u8{ "/bin/sh", "-c", cmd };

            var child = std.process.Child.init(argv, allocator);
            child.stdout_behavior = .Pipe;
            child.stderr_behavior = .Inherit;
            child.spawn() catch |err| {
                std.debug.print("error: failed to spawn hash-key-exec command '{s}': {}\n", .{ cmd, err });
                std.process.exit(1);
            };
            exec_output_owned = child.stdout.?.readToEndAlloc(allocator, 256) catch |err| {
                std.debug.print("error: failed to read hash-key-exec output: {}\n", .{err});
                std.process.exit(1);
            };
            _ = child.wait() catch {};
            resolved_key_hex = std.mem.trim(u8, exec_output_owned.?, " \t\r\n");
        } else if (cfg.hash_key_file) |kf| {
            // Read the key file now so the same hex is used for both FileVault
            // encryption key derivation and Hasher initialization. Without this,
            // the FileVault would be encrypted with a random key that is lost on
            // restart, breaking pseudonymization reversibility.
            const kf_file = std.fs.cwd().openFile(kf, .{}) catch |err| {
                std.debug.print("error: cannot open hash key file '{s}': {s}\n", .{ kf, @errorName(err) });
                std.process.exit(1);
            };
            defer kf_file.close();
            file_key_contents_owned = kf_file.readToEndAlloc(allocator, 128) catch {
                std.debug.print("error: failed to read hash key file '{s}'\n", .{kf});
                std.process.exit(1);
            };
            const trimmed = std.mem.trim(u8, file_key_contents_owned.?, " \t\n\r");
            if (trimmed.len < 64) {
                std.debug.print("error: hash key file must contain at least 64 hex characters\n", .{});
                std.process.exit(1);
            }
            resolved_key_hex = trimmed[0..64];
        } else {
            resolved_key_hex = cfg.hash_key; // may be null → auto-generated
        }

        // Parse or auto-generate the 32-byte key for vault encryption.
        var vault_key: [32]u8 = undefined;
        var vault_key_from_hex = false;

        if (resolved_key_hex) |hex| {
            if (hex.len >= 64) {
                if (std.fmt.hexToBytes(&vault_key, hex[0..64])) |_| {
                    vault_key_from_hex = true;
                } else |_| {
                    // Invalid hex chars — Hasher.init will also reject this
                }
            }
        }

        if (!vault_key_from_hex) {
            // Auto-generate — no hex key provided or hex decode failed.
            std.crypto.random.bytes(&vault_key);
        }

        // 2. Initialize the correct Vault backend
        switch (cfg.vault_backend) {
            .memory => {
                vault_instance = .{ .memory = memory_vault_mod.MemoryVault.init(allocator) catch |err| {
                    std.debug.print("error: failed to initialize memory vault: {}\n", .{err});
                    std.process.exit(1);
                } };
            },
            .file => {
                vault_instance = .{ .file = file_vault_mod.FileVault.init(allocator, cfg.vault_file_path.?, vault_key) catch |err| {
                    std.debug.print("error: failed to initialize file vault: {}\n", .{err});
                    std.process.exit(1);
                } };
            },
            .external => {
                std.debug.print("error: the 'external' vault backend is not yet implemented. Use --vault-backend memory or --vault-backend file.\n", .{});
                std.process.exit(1);
            },
        }

        const vault_iface = switch (vault_instance.?) {
            .memory => |m| m.vaultInterface(),
            .file => |f| f.vaultInterface(),
            .external => |e| e.vaultInterface(),
        };

        // 3. Initialize the Hasher with the resolved key and vault interface.
        // All key sources now have resolved_key_hex set (or null for auto-generated),
        // so we use Hasher.init uniformly instead of branching on the key source.
        const key_source: []const u8 = if (cfg.hash_key_exec != null) "exec" else if (cfg.hash_key_file != null) "file" else if (cfg.hash_key != null) "cli" else "auto";

        hasher_instance = hasher_mod.Hasher.init(resolved_key_hex, vault_iface, allocator) catch |err| {
            std.debug.print("error: failed to initialise hasher ({s}): {}\n", .{ key_source, err });
            std.process.exit(1);
        };

        log.log(.info, "hasher_initialized", null, &.{
            .{ .key = "key_source", .value = .{ .string = key_source } },
            .{ .key = "key_prefix", .value = .{ .string = hasher_instance.?.keyHex()[0..8] } },
            .{ .key = "vault_backend", .value = .{ .string = cfg.vault_backend.asStr() } },
        });
    }

    if (hasher_instance) |*h| {
        h.setObservability(&observability);
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

    // --- TLS posture summary ---
    // Emit a structured log summarizing the listener and upstream TLS
    // configuration so operators can verify the deployment matches their
    // intended security posture at a glance.
    const listener_cipher = if (tls_enabled) "TLS_AES_128_GCM_SHA256" else "none";
    const listener_cert = if (cfg.tls_cert) |cert| cert else "none";
    const upstream_ca_source: []const u8 = if (cfg.ca_file != null and cfg.tls_no_system_ca)
        "custom_only"
    else if (cfg.ca_file != null)
        "custom"
    else if (cfg.tls_no_system_ca)
        "none"
    else
        "system";
    log.log(.info, "tls_posture", null, &.{
        .{ .key = "listener_tls", .value = .{ .boolean = tls_enabled } },
        .{ .key = "listener_cipher", .value = .{ .string = listener_cipher } },
        .{ .key = "listener_cert", .value = .{ .string = listener_cert } },
        .{ .key = "upstream_tls", .value = .{ .boolean = cfg.target_tls } },
        .{ .key = "upstream_ca_source", .value = .{ .string = upstream_ca_source } },
    });
    // Hint: built-in TLS works but a hardened ingress tier is recommended
    // for production deployments (see docs/tls_strategy.md).
    if (tls_enabled) {
        log.log(.info, "production_tls_hint", null, &.{
            .{ .key = "recommendation", .value = .{ .string = "use a hardened ingress tier (NGINX, Envoy, ALB) for production TLS termination" } },
            .{ .key = "docs", .value = .{ .string = "docs/tls_strategy.md" } },
        });
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

    // --- RBAC API key store (Phase 3 / NMV3-011) ---
    var api_key_store: ?ApiKeyStore = if (cfg.admin_api_key_file) |key_file| blk: {
        var store = ApiKeyStore.loadFromFile(key_file, allocator) catch |err| {
            std.debug.print("error: failed to load API key file '{s}': {}\n", .{ key_file, err });
            std.process.exit(1);
        };
        // Suppress "unused variable" warning; store is read below via .count().
        _ = &store;
        log.log(.info, "api_key_store_loaded", null, &.{
            .{ .key = "file", .value = .{ .string = key_file } },
            .{ .key = "key_count", .value = .{ .uint = store.count() } },
        });
        break :blk store;
    } else null;
    defer if (api_key_store) |*aks| aks.deinit();

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
        .api_key_store = if (api_key_store) |*aks| aks else null,
        .audit_store = &audit_store_instance,
    };

    var shutdown_state = shutdown_mod.ShutdownState{};

    // --- Report-only mode evaluation report (Phase 2 / NMV3-007) ---
    var evaluation_report: ?EvaluationReport = if (cfg.report_only) .{} else null;
    if (cfg.report_only) {
        log.log(.info, "report_only_mode_enabled", null, &.{
            .{ .key = "mode", .value = .{ .string = "report_only" } },
            .{ .key = "description", .value = .{ .string = "PII detection active, payload modification disabled" } },
        });
    }

    var semantic_cache: ?semantic_cache_mod.SemanticCache = if (cfg.enable_semantic_cache)
        semantic_cache_mod.SemanticCache.init(allocator, cfg.semantic_cache_max_entries, cfg.semantic_cache_ttl_ms)
    else
        null;
    // Wire the logger so OOM warnings in SemanticCache.lookup() reach the
    // structured log rather than silently disappearing (F2).
    if (semantic_cache) |*cache| cache.log = &log;
    defer if (semantic_cache) |*cache| cache.deinit();

    if (cfg.enable_guardrails) {
        log.log(.info, "guardrails_enabled", null, &.{
            .{ .key = "mode", .value = .{ .string = cfg.guardrail_mode.label() } },
        });
    }
    if (cfg.enable_semantic_cache) {
        log.log(.info, "semantic_cache_enabled", null, &.{
            .{ .key = "ttl_ms", .value = .{ .uint = cfg.semantic_cache_ttl_ms } },
            .{ .key = "max_entries", .value = .{ .uint = cfg.semantic_cache_max_entries } },
            .{ .key = "tenant_header", .value = .{ .string = cfg.semantic_cache_tenant_header } },
        });
    }

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
    printStartupBanner(allocator, cfg, entity_count, schema_field_count) catch |err| {
        std.debug.print("warning: failed to print startup summary: {s}\n", .{@errorName(err)});
    };

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
                .enable_iban = cfg.enable_iban,
                .enable_uk_nino = cfg.enable_uk_nino,
                .enable_passport = cfg.enable_passport,
                .enable_intl_phone = cfg.enable_intl_phone,
                .enable_dates = cfg.enable_dates,
                .enable_addresses = cfg.enable_addresses,
                .enable_accounts = cfg.enable_accounts,
                .enable_licenses = cfg.enable_licenses,
                .enable_urls = cfg.enable_urls,
                .enable_vehicle_ids = cfg.enable_vehicle_ids,
                .guardrail_settings = .{
                    .enabled = cfg.enable_guardrails,
                    .mode = cfg.guardrail_mode,
                },
                .semantic_cache = if (semantic_cache) |*cache| cache else null,
                .semantic_cache_tenant_header = cfg.semantic_cache_tenant_header,
                .schema = if (schema_instance) |*s| s else null,
                .hasher = if (hasher_instance) |*h| h else null,
                .shutdown_state = &shutdown_state,
                .listener_mode = if (dedicated_admin_listener) .proxy_only else .combined,
                .upstream_timeouts = .{
                    .connect_timeout_ms = cfg.upstream_connect_timeout_ms,
                    .read_timeout_ms = cfg.upstream_read_timeout_ms,
                    .request_timeout_ms = cfg.upstream_request_timeout_ms,
                },
                .report_only = cfg.report_only,
                .evaluation_report = if (evaluation_report) |*er| er else null,
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
                    .enable_iban = cfg.enable_iban,
                    .enable_uk_nino = cfg.enable_uk_nino,
                    .enable_passport = cfg.enable_passport,
                    .enable_intl_phone = cfg.enable_intl_phone,
                    .enable_dates = cfg.enable_dates,
                    .enable_addresses = cfg.enable_addresses,
                    .enable_accounts = cfg.enable_accounts,
                    .enable_licenses = cfg.enable_licenses,
                    .enable_urls = cfg.enable_urls,
                    .enable_vehicle_ids = cfg.enable_vehicle_ids,
                    .guardrail_settings = .{
                        .enabled = cfg.enable_guardrails,
                        .mode = cfg.guardrail_mode,
                    },
                    .semantic_cache = if (semantic_cache) |*cache| cache else null,
                    .semantic_cache_tenant_header = cfg.semantic_cache_tenant_header,
                    .schema = if (schema_instance) |*s| s else null,
                    .hasher = if (hasher_instance) |*h| h else null,
                    .shutdown_state = &shutdown_state,
                    .listener_mode = .admin_only,
                    .upstream_timeouts = .{
                        .connect_timeout_ms = cfg.upstream_connect_timeout_ms,
                        .read_timeout_ms = cfg.upstream_read_timeout_ms,
                        .request_timeout_ms = cfg.upstream_request_timeout_ms,
                    },
                    .report_only = cfg.report_only,
                    .evaluation_report = if (evaluation_report) |*er| er else null,
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

    const maybe_shutdown_watcher: ?std.Thread = if (builtin.os.tag == .windows)
        null
    else
        try std.Thread.spawn(.{}, ShutdownWatcher.run, .{
            &server,
            if (admin_server) |*server_ptr| server_ptr else null,
        });
    defer if (maybe_shutdown_watcher) |signal_watcher| signal_watcher.join();

    server.serve();
}
