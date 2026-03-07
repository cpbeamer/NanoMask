const std = @import("std");

pub fn main() !void {
    var server = try std.net.Address.listen(try std.net.Address.parseIp("127.0.0.1", 8080), .{
        .reuse_address = true,
        .reuse_port = true,
    });
    defer server.deinit();

    var connection = try server.accept();
    defer connection.stream.close();

    var reader = connection.stream.reader();
    var writer = connection.stream.writer();

    // Test if we can init the server
    var http_server = std.http.Server.init(&reader, &writer);
    _ = http_server;
}
