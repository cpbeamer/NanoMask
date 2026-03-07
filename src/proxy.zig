const std = @import("std");
const http = std.http;

pub fn handleRequest(allocator: std.mem.Allocator, request: *http.Server.Request, target_host: []const u8, target_port: u16) !void {
    const method = request.head.method;
    const uri_str = request.head.target;

    std.debug.print("[PRX] {s} {s}\n", .{ @tagName(method), uri_str });

    var client = std.http.Client{ .allocator = allocator };
    defer client.deinit();

    const target_url_str = try std.fmt.allocPrint(allocator, "http://{s}:{d}{s}", .{ target_host, target_port, uri_str });
    defer allocator.free(target_url_str);

    const target_uri = try std.Uri.parse(target_url_str);

    var client_req = try client.request(method, target_uri, .{});
    defer client_req.deinit();

    if (method.requestHasBody()) {
        try client_req.sendBodilessUnflushed(); // Not sending body yet for MVP
    } else {
        try client_req.sendBodilessUnflushed();
    }
    try client_req.connection.?.flush();

    var redirect_buffer: [4096]u8 = undefined;
    var downstream_res = try client_req.receiveHead(&redirect_buffer);

    var transfer_buf: [8192]u8 = undefined;
    var downstream_reader = downstream_res.reader(&transfer_buf);

    var body_alloc: std.ArrayListUnmanaged(u8) = .empty;
    defer body_alloc.deinit(allocator);

    try downstream_reader.appendRemainingUnlimited(allocator, &body_alloc);

    // Apply ZPG Rules immediately to the buffered body
    const redact = @import("redact.zig");
    redact.redactSsn(body_alloc.items);

    try request.respond(body_alloc.items, .{
        .status = downstream_res.head.status,
    });
}
