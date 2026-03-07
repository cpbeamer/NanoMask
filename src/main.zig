const std = @import("std");
const proxy = @import("proxy.zig");
const entity_mask = @import("entity_mask.zig");

/// Maximum number of concurrent connections. Incoming connections beyond this
/// limit are closed immediately with a log warning.
const max_concurrent_connections = 128;

const ThreadContext = struct {
    allocator: std.mem.Allocator,
    target_host: []const u8,
    target_port: u16,
    entity_map: ?*const entity_mask.EntityMap,
    active_connections: *std.atomic.Value(u32),
};

fn handleConnection(connection: std.net.Server.Connection, ctx: ThreadContext) void {
    defer {
        connection.stream.close();
        _ = ctx.active_connections.fetchSub(1, .release);
    }

    // Per-thread HTTP client — avoids data races from sharing mutable client state.
    var client = std.http.Client{ .allocator = ctx.allocator };
    defer client.deinit();

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
        &client,
        ctx.target_host,
        ctx.target_port,
        ctx.entity_map,
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

    const listen_port: u16 = 8081;
    // SAFETY: target_host is a comptime string literal — the slice pointer is
    // valid for the program's entire lifetime. If this is ever loaded from a
    // config file or CLI arg (heap-allocated), it must be duped or pinned.
    const target_host = "httpbin.org";
    const target_port: u16 = 80;

    // --- Entity Masking Setup ---
    // Demo name set. In production, these come from case metadata,
    // API headers (X-ZPG-Entities), or a per-session config file.
    const demo_names = [_][]const u8{ "John Doe", "Jane Smith", "Dr. Johnson" };
    var entity_map = try entity_mask.EntityMap.init(allocator, &demo_names);
    defer entity_map.deinit();

    std.debug.print("Starting ZPG Proxy - Phase 2\n", .{});
    std.debug.print("Listening on http://127.0.0.1:{}\n", .{listen_port});
    std.debug.print("Forwarding to http://{s}:{}\n", .{ target_host, target_port });
    std.debug.print("Entity masking: {} session names loaded\n", .{demo_names.len});
    std.debug.print("Bidirectional pipeline: mask request -> unmask response\n", .{});
    std.debug.print("Multi-threaded: up to {} concurrent connections\n\n", .{max_concurrent_connections});

    var net_server = try std.net.Address.listen(try std.net.Address.parseIp("127.0.0.1", listen_port), .{
        .reuse_address = true,
    });
    defer net_server.deinit();

    // NOTE: Upstream request timeouts are not yet configurable via std.http.Client.
    // Long-running upstream calls will block the handler thread until completion.
    // This is a known limitation to address when the stdlib exposes timeout options.

    var active_connections = std.atomic.Value(u32).init(0);

    const ctx = ThreadContext{
        .allocator = allocator,
        .target_host = target_host,
        .target_port = target_port,
        .entity_map = &entity_map,
        .active_connections = &active_connections,
    };

    while (true) {
        const connection = net_server.accept() catch |err| {
            std.debug.print("[ERR] Accepting connection: {}\n", .{err});
            continue;
        };

        // Enforce connection limit to prevent thread exhaustion under load.
        const current = active_connections.fetchAdd(1, .acquire);
        if (current >= max_concurrent_connections) {
            std.debug.print("[WARN] Connection limit reached ({}/{}), rejecting\n", .{ current + 1, max_concurrent_connections });
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
