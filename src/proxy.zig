const std = @import("std");
const http = std.http;
const redact = @import("redact.zig");

/// Maximum length for the constructed target URL (stack-allocated).
const max_url_len = 512;

pub fn handleRequest(allocator: std.mem.Allocator, request: *http.Server.Request, client: *std.http.Client, target_host: []const u8, target_port: u16) !void {
    const method = request.head.method;
    const uri_str = request.head.target;

    std.debug.print("[PRX] {s} {s}\n", .{ @tagName(method), uri_str });

    // Stack-allocated URL construction — zero heap allocs per request.
    var url_buf: [max_url_len]u8 = undefined;
    const target_url_str = try std.fmt.bufPrint(&url_buf, "http://{s}:{d}{s}", .{ target_host, target_port, uri_str });

    const target_uri = try std.Uri.parse(target_url_str);

    var client_req = try client.request(method, target_uri, .{});
    defer client_req.deinit();

    // MVP: always send bodiless regardless of method — body forwarding is Phase 2.
    try client_req.sendBodilessUnflushed();
    try client_req.connection.?.flush();

    var redirect_buffer: [4096]u8 = undefined;
    var downstream_res = try client_req.receiveHead(&redirect_buffer);

    var transfer_buf: [8192]u8 = undefined;
    var downstream_reader = downstream_res.reader(&transfer_buf);

    var body_alloc: std.ArrayListUnmanaged(u8) = .empty;
    defer body_alloc.deinit(allocator);

    try downstream_reader.appendRemainingUnlimited(allocator, &body_alloc);

    // Apply ZPG redaction rules to the buffered body
    redact.redactSsn(body_alloc.items);

    try request.respond(body_alloc.items, .{
        .status = downstream_res.head.status,
    });
}
