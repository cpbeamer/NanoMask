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
        std.debug.print("[ERR] {s} {s}: {}\n", .{ @tagName(request.head.method), request.head.target, err });
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
    // SAFETY: We don't free args to prevent dangling target_host pointers since main operates effectively as program lifetime
    // and args slices point into this pool if passed by user.
    // However, if process terminates, OS reclaims memory.

    const cfg = Config.parse(args, std.io.getStdErr().writer()) catch |err| {
        if (err == error.HelpRequested) {
            std.process.exit(0);
        } else {
            std.process.exit(1);
        }
    };

    // --- Entity Masking Setup ---
    // Demo name set. In production, these come from case metadata,
    // API headers (X-ZPG-Entities), or a per-session config file.
    const demo_names = [_][]const u8{ "John Doe", "Jane Smith", "Dr. Johnson" };
    var entity_map = try entity_mask.EntityMap.init(allocator, &demo_names);
    defer entity_map.deinit();

    // --- Fuzzy Matcher Setup (Stage 3: OCR-resilient name matching) ---
    // Threshold 0.80 = 80% similarity required. Tunable per deployment.
    var fuzzy_matcher = try fuzzy_match.FuzzyMatcher.init(
        allocator,
        entity_map.getRawNames(),
        entity_map.getAliases(),
        cfg.fuzzy_threshold,
    );
    defer fuzzy_matcher.deinit();

    std.debug.print("Listening on http://127.0.0.1:{}\n", .{cfg.listen_port});
    std.debug.print("Forwarding to http://{s}:{}\n", .{ cfg.target_host, cfg.target_port });
    std.debug.print("Entity masking: {} session names loaded\n", .{demo_names.len});
    std.debug.print("Fuzzy matching: {} variants at {d:.0}% threshold\n", .{ fuzzy_matcher.variants.len, cfg.fuzzy_threshold * 100.0 });
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
        .entity_map = &entity_map,
        .fuzzy_matcher = &fuzzy_matcher,
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
