const std = @import("std");
const proxy = @import("proxy.zig");
const entity_mask = @import("entity_mask.zig");
const fuzzy_match = @import("fuzzy_match.zig");
const config = @import("config.zig");
const Config = config.Config;

const ThreadContext = struct {
    allocator: std.mem.Allocator,
    target_host: []const u8,
    target_port: u16,
    entity_map: ?*const entity_mask.EntityMap,
    fuzzy_matcher: ?*const fuzzy_match.FuzzyMatcher,
    /// Shared HTTP client with built-in thread-safe connection pool.
    /// The stdlib ConnectionPool uses std.Thread.Mutex internally,
    /// so concurrent acquire/release from handler threads is safe.
    /// Individual Request objects are per-handler (not thread-safe).
    http_client: *std.http.Client,
    active_connections: *std.atomic.Value(u32),
};

fn handleConnection(connection: std.net.Server.Connection, ctx: ThreadContext) void {
    defer {
        connection.stream.close();
        _ = ctx.active_connections.fetchSub(1, .release);
    }

    var read_buf: [16 * 1024]u8 = undefined;
    var write_buf: [16 * 1024]u8 = undefined;

    var stream_reader = connection.stream.reader(&read_buf);
    var stream_writer = connection.stream.writer(&write_buf);

    var server = std.http.Server.init(stream_reader.interface(), &stream_writer.interface);

    var request = server.receiveHead() catch |err| {
        std.debug.print("[ERR] Receiving head: {}\n", .{err});
        return;
    };

    proxy.handleRequest(
        ctx.allocator,
        &request,
        ctx.http_client,
        ctx.target_host,
        ctx.target_port,
        ctx.entity_map,
        ctx.fuzzy_matcher,
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
    std.debug.print("\n", .{});

    // --- Entity Masking Setup ---
    var loaded_names: ?[][]const u8 = null;
    var entity_map_alloc: ?entity_mask.EntityMap = null;
    var fuzzy_matcher_alloc: ?fuzzy_match.FuzzyMatcher = null;

    defer {
        if (fuzzy_matcher_alloc) |*fm| fm.deinit();
        if (entity_map_alloc) |*em| em.deinit();
        if (loaded_names) |names| {
            for (names) |name| allocator.free(name);
            allocator.free(names);
        }
    }

    if (cfg.entity_file) |ef| {
        var file = std.fs.cwd().openFile(ef, .{}) catch |err| {
            std.debug.print("error: cannot open entity file '{s}': {s}\n", .{ ef, @errorName(err) });
            std.process.exit(1);
        };
        defer file.close();
        
        const content = try file.readToEndAlloc(allocator, 10 * 1024 * 1024);
        defer allocator.free(content);

        var names_list: std.ArrayListUnmanaged([]const u8) = .empty;
        defer names_list.deinit(allocator);

        var line_it = std.mem.splitScalar(u8, content, '\n');
        while (line_it.next()) |line| {
            const trimmed = std.mem.trimRight(u8, std.mem.trimLeft(u8, line, " \t\r"), " \t\r");
            if (trimmed.len == 0 or trimmed[0] == '#') continue;
            try names_list.append(allocator, try allocator.dupe(u8, trimmed));
        }

        loaded_names = try names_list.toOwnedSlice(allocator);
        entity_map_alloc = try entity_mask.EntityMap.init(allocator, loaded_names.?);
        
        fuzzy_matcher_alloc = try fuzzy_match.FuzzyMatcher.init(
            allocator,
            entity_map_alloc.?.getRawNames(),
            entity_map_alloc.?.getAliases(),
            cfg.fuzzy_threshold,
        );
        std.debug.print("loaded {} entities from {s}\n", .{ loaded_names.?.len, ef });
    } else {
        std.debug.print("WARNING: No entity file provided. Running in SSN-only mode unless X-ZPG-Entities header is present on requests.\n", .{});
    }

    std.debug.print("Listening on http://127.0.0.1:{}\n", .{cfg.listen_port});
    std.debug.print("Forwarding to http://{s}:{}\n", .{ cfg.target_host, cfg.target_port });
    
    if (loaded_names) |names| {
        std.debug.print("Entity masking: {} session names loaded\n", .{ names.len });
        std.debug.print("Fuzzy matching: {} variants at {d:.0}% threshold\n", .{ fuzzy_matcher_alloc.?.variants.len, cfg.fuzzy_threshold * 100.0 });
    } else {
        std.debug.print("Entity masking: disabled (SSN-only mode)\n", .{});
        std.debug.print("Fuzzy matching: disabled (SSN-only mode)\n", .{});
    }

    std.debug.print("Connection pool: shared client with keep-alive (up to 32 upstream connections)\n", .{});
    std.debug.print("Bidirectional pipeline: mask request -> unmask response\n", .{});
    std.debug.print("Multi-threaded: up to {} concurrent connections\n\n", .{cfg.max_connections});

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

    const ctx = ThreadContext{
        .allocator = allocator,
        .target_host = cfg.target_host,
        .target_port = cfg.target_port,
        .entity_map = if (entity_map_alloc) |*em| em else null,
        .fuzzy_matcher = if (fuzzy_matcher_alloc) |*fm| fm else null,
        .http_client = &http_client,
        .active_connections = &active_connections,
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
