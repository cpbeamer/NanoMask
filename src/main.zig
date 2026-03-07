const std = @import("std");
const proxy = @import("proxy.zig");
const entity_mask = @import("entity_mask.zig");
const fuzzy_match = @import("fuzzy_match.zig");
const config = @import("config.zig");
const Config = config.Config;
const versioned_entity_set = @import("versioned_entity_set.zig");
const VersionedEntitySet = versioned_entity_set.VersionedEntitySet;
const EntitySnapshot = versioned_entity_set.EntitySnapshot;
const file_watcher = @import("file_watcher.zig");
const FileWatcher = file_watcher.FileWatcher;
const admin = @import("admin.zig");
const tls_mod = @import("tls.zig");

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
};

fn handleConnection(connection: std.net.Server.Connection, ctx: ThreadContext) void {
    defer {
        connection.stream.close();
        _ = ctx.active_connections.fetchSub(1, .release);
    }

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
            std.debug.print("[ERR] TLS handshake failed: {}\n", .{err});
            return;
        };
    }

    // Use TLS stream reader/writer if handshake succeeded, otherwise raw stream
    var final_reader: std.Io.Reader = if (tls_stream) |*ts| ts.reader().* else raw_reader_iface.*;
    var final_writer: std.Io.Writer = if (tls_stream) |*ts| ts.writer().* else stream_writer.interface;
    var server = std.http.Server.init(&final_reader, &final_writer);

    var request = server.receiveHead() catch |err| {
        std.debug.print("[ERR] Receiving head: {}\n", .{err});
        return;
    };

    // Extract entity_map and fuzzy_matcher from the snapshot for the proxy
    const em: ?*const entity_mask.EntityMap = if (snapshot) |s| &s.entity_map else null;
    const fm: ?*const fuzzy_match.FuzzyMatcher = if (snapshot) |s| &s.fuzzy_matcher else null;

    proxy.handleRequest(
        ctx.allocator,
        &request,
        ctx.http_client,
        ctx.target_host,
        ctx.target_port,
        em,
        fm,
        ctx.entity_set,
        ctx.admin_config,
    ) catch |err| {
        std.debug.print("[ERR] Proxy request failed: {}\n", .{err});
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

    std.debug.print("Config resolved:\n", .{});
    std.debug.print("  listen_port={d} (from {s})\n", .{ cfg.listen_port, cfg.listen_port_src.asStr() });
    std.debug.print("  target_host={s} (from {s})\n", .{ cfg.target_host, cfg.target_host_src.asStr() });
    std.debug.print("  target_port={d} (from {s})\n", .{ cfg.target_port, cfg.target_port_src.asStr() });
    if (cfg.entity_file) |ef| {
        std.debug.print("  entity_file={s} (from {s})\n", .{ ef, cfg.entity_file_src.asStr() });
    } else {
        std.debug.print("  entity_file=null (from {s})\n", .{cfg.entity_file_src.asStr()});
    }
    std.debug.print("  fuzzy_threshold={d:.2} (from {s})\n", .{ cfg.fuzzy_threshold, cfg.fuzzy_threshold_src.asStr() });
    std.debug.print("  max_connections={d} (from {s})\n", .{ cfg.max_connections, cfg.max_connections_src.asStr() });
    std.debug.print("  log_level={s} (from {s})\n", .{ @tagName(cfg.log_level), cfg.log_level_src.asStr() });
    std.debug.print("  watch_interval_ms={d} (from {s})\n", .{ cfg.watch_interval_ms, cfg.watch_interval_ms_src.asStr() });
    if (cfg.tls_cert) |tc| {
        std.debug.print("  tls_cert={s} (from {s})\n", .{ tc, cfg.tls_cert_src.asStr() });
    } else {
        std.debug.print("  tls_cert=null (from {s})\n", .{cfg.tls_cert_src.asStr()});
    }
    if (cfg.tls_key) |tk| {
        std.debug.print("  tls_key={s} (from {s})\n", .{ tk, cfg.tls_key_src.asStr() });
    } else {
        std.debug.print("  tls_key=null (from {s})\n", .{cfg.tls_key_src.asStr()});
    }
    std.debug.print("\n", .{});

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

        std.debug.print("loaded {} entities from {s}\n", .{ initial_snapshot.loaded_names.len, ef });

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
        watcher.?.start() catch |err| {
            std.debug.print("[WARN] Failed to start file watcher: {} — hot-reload disabled\n", .{err});
            watcher = null;
        };
    } else if (cfg.admin_api) {
        // Admin API is enabled but no entity file — create an empty entity set
        // so the admin API can populate it from scratch via POST/PUT.
        const empty_names = [_][]const u8{};
        const initial_snapshot = versioned_entity_set.loadSnapshotFromNames(
            &empty_names,
            cfg.fuzzy_threshold,
            1,
            allocator,
        ) catch {
            std.debug.print("error: failed to create empty entity set for admin API\n", .{});
            std.process.exit(1);
        };
        std.debug.print("Admin API enabled with empty entity set (populate via POST /_admin/entities)\n", .{});
        const es = try allocator.create(VersionedEntitySet);
        es.* = VersionedEntitySet.init(initial_snapshot);
        entity_set = es;
    } else {
        std.debug.print("WARNING: No entity file provided. Running in SSN-only mode unless X-ZPG-Entities header is present on requests.\n", .{});
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
            std.debug.print("TLS: loaded certificate from {s}\n", .{cert_path});
        }
    }

    const tls_enabled = tls_context != null;
    const protocol = if (tls_enabled) "https" else "http";
    std.debug.print("Listening on {s}://127.0.0.1:{}\n", .{ protocol, cfg.listen_port });
    std.debug.print("Forwarding to http://{s}:{}\n", .{ cfg.target_host, cfg.target_port });

    if (entity_set) |es| {
        const snap = es.acquire();
        defer es.release(snap);
        std.debug.print("Entity masking: {} session names loaded (v{})\n", .{ snap.loaded_names.len, snap.version });
        std.debug.print("Fuzzy matching: {} variants at {d:.0}% threshold\n", .{ snap.fuzzy_matcher.variants.len, cfg.fuzzy_threshold * 100.0 });
        if (watcher != null) {
            std.debug.print("Hot-reload: enabled (polling every {}ms)\n", .{cfg.watch_interval_ms});
        } else {
            std.debug.print("Hot-reload: disabled (admin-only, no file watcher)\n", .{});
        }
    } else {
        std.debug.print("Entity masking: disabled (SSN-only mode)\n", .{});
        std.debug.print("Fuzzy matching: disabled (SSN-only mode)\n", .{});
        std.debug.print("Hot-reload: disabled (no entity file)\n", .{});
    }

    std.debug.print("Connection pool: shared client with keep-alive (up to 32 upstream connections)\n", .{});
    std.debug.print("Bidirectional pipeline: mask request -> unmask response\n", .{});
    std.debug.print("Multi-threaded: up to {} concurrent connections\n", .{cfg.max_connections});
    if (cfg.admin_api) {
        std.debug.print("Admin API: enabled at /_admin/entities", .{});
        if (cfg.admin_token != null) {
            std.debug.print(" (auth required)", .{});
        } else {
            std.debug.print(" (WARNING: no auth token set)", .{});
        }
        if (cfg.entity_file_sync) {
            std.debug.print(" [file-sync on]", .{});
        }
        std.debug.print("\n", .{});
    } else {
        std.debug.print("Admin API: disabled\n", .{});
    }
    if (tls_enabled) {
        std.debug.print("TLS: enabled (TLS 1.3, AES-128-GCM-SHA256)\n", .{});
    } else {
        std.debug.print("WARNING: running without TLS -- not suitable for production\n", .{});
    }
    std.debug.print("\n", .{});

    var net_server = try std.net.Address.listen(try std.net.Address.parseIp("127.0.0.1", cfg.listen_port), .{
        .reuse_address = true,
    });
    defer net_server.deinit();

    // Shared HTTP client: the stdlib ConnectionPool is thread-safe (uses Mutex).
    // All handler threads share this client, enabling TCP connection reuse with
    // keep-alive. Eliminates per-request TCP handshake overhead (5-10ms savings).
    var http_client = std.http.Client{ .allocator = allocator };
    defer http_client.deinit();

    // NOTE: Upstream request timeouts are not yet configurable via std.http.Client.
    // Long-running upstream calls will block the handler thread until completion.
    // This is a known limitation to address when the stdlib exposes timeout options.

    var active_connections = std.atomic.Value(u32).init(0);

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
    };

    while (true) {
        const connection = net_server.accept() catch |err| {
            std.debug.print("[ERR] Accepting connection: {}\n", .{err});
            continue;
        };

        // Enforce connection limit to prevent thread exhaustion under load.
        const current = active_connections.fetchAdd(1, .acquire);
        if (current >= cfg.max_connections) {
            std.debug.print("[WARN] Connection limit reached ({}/{}), rejecting\n", .{ current + 1, cfg.max_connections });
            _ = active_connections.fetchSub(1, .release);
            connection.stream.close();
            continue;
        }

        // Spawn a thread per connection for concurrent request handling.
        const thread = std.Thread.spawn(.{}, handleConnection, .{ connection, ctx }) catch |err| {
            std.debug.print("[ERR] Spawning thread: {}\n", .{err});
            _ = active_connections.fetchSub(1, .release);
            connection.stream.close();
            continue;
        };
        thread.detach();
    }
}
