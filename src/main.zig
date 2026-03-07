const std = @import("std");
const proxy = @import("proxy.zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const listen_port: u16 = 8081;
    const target_host = "httpbin.org";
    const target_port: u16 = 80;

    std.debug.print("Starting ZPG Proxy MVP\n", .{});
    std.debug.print("Listening on http://127.0.0.1:{}\n", .{listen_port});
    std.debug.print("Forwarding to http://{s}:{}\n", .{ target_host, target_port });

    var net_server = try std.net.Address.listen(try std.net.Address.parseIp("127.0.0.1", listen_port), .{
        .reuse_address = true,
    });
    defer net_server.deinit();

    while (true) {
        var connection = net_server.accept() catch |err| {
            std.debug.print("Error accepting connection: {}\n", .{err});
            continue;
        };
        // Explicitly handle sequentially for MVP
        defer connection.stream.close();

        var read_buf: [16 * 1024]u8 = undefined;
        var write_buf: [16 * 1024]u8 = undefined;

        var stream_reader = connection.stream.reader(&read_buf);
        var stream_writer = connection.stream.writer(&write_buf);

        var server = std.http.Server.init(stream_reader.interface(), &stream_writer.interface);

        var request = server.receiveHead() catch |err| {
            std.debug.print("Error receiving head: {}\n", .{err});
            continue;
        };

        proxy.handleRequest(allocator, &request, target_host, target_port) catch |err| {
            std.debug.print("Error handling request: {}\n", .{err});
        };
    }
}
