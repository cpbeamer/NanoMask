const std = @import("std");
const proxy = @import("proxy.zig");
const entity_mask = @import("../redaction/entity_mask.zig");
const fuzzy_match = @import("../redaction/fuzzy_match.zig");
const versioned_entity_set = @import("../entity/versioned_entity_set.zig");
const VersionedEntitySet = versioned_entity_set.VersionedEntitySet;
const EntitySnapshot = versioned_entity_set.EntitySnapshot;
const admin = @import("../admin/admin.zig");
const tls_mod = @import("../crypto/tls.zig");
const logger_mod = @import("../infra/logger.zig");
const Logger = logger_mod.Logger;
const observability_mod = @import("../infra/observability.zig");
const Observability = observability_mod.Observability;
const schema_mod = @import("../schema/schema.zig");
const hasher_mod = @import("../schema/hasher.zig");
const body_policy = @import("body_policy.zig");
const shutdown_mod = @import("../infra/shutdown.zig");
const upstream_client = @import("upstream_client.zig");

pub const ThreadContext = struct {
    allocator: std.mem.Allocator,
    target_host: []const u8,
    target_port: u16,
    entity_set: ?*VersionedEntitySet,
    http_client: *std.http.Client,
    active_connections: *std.atomic.Value(u32),
    admin_config: admin.AdminConfig,
    tls_context: ?*tls_mod.TlsContext,
    target_tls: bool,
    max_body_size: usize,
    logger: *Logger,
    observability: *Observability,
    connections_total: *std.atomic.Value(u64),
    start_time: i64,
    unsupported_request_body_behavior: body_policy.UnsupportedBodyBehavior,
    unsupported_response_body_behavior: body_policy.UnsupportedBodyBehavior,
    enable_email: bool,
    enable_phone: bool,
    enable_credit_card: bool,
    enable_ip: bool,
    enable_healthcare: bool,
    schema: ?*const schema_mod.Schema,
    hasher: ?*hasher_mod.Hasher,
    shutdown_state: *shutdown_mod.ShutdownState,
    upstream_timeouts: upstream_client.UpstreamTimeouts,
};

pub const ProxyServer = struct {
    net_server: std.net.Server,
    ctx: ThreadContext,
    max_connections: u32,
    drain_timeout_ms: u64,
    active_connections: *std.atomic.Value(u32),
    logger: *Logger,
    observability: *Observability,
    shutdown_state: *shutdown_mod.ShutdownState,
    listener_mutex: std.Thread.Mutex = .{},
    listener_closed: bool = false,

    pub fn serve(self: *ProxyServer) void {
        while (true) {
            const connection = self.net_server.accept() catch |err| {
                if (self.shutdown_state.isRequested() or self.shutdown_state.isDraining()) {
                    self.finishShutdown();
                    return;
                }

                self.logger.log(.error_, "accept_failed", null, &.{
                    .{ .key = "error", .value = .{ .string = @errorName(err) } },
                });
                continue;
            };

            if (self.shutdown_state.isRequested() or self.shutdown_state.isDraining()) {
                connection.stream.close();
                self.finishShutdown();
                return;
            }

            _ = self.ctx.connections_total.fetchAdd(1, .monotonic);

            const current = self.active_connections.fetchAdd(1, .acquire);
            if (current >= self.max_connections) {
                self.logger.warn("connection_limit_reached", null);
                _ = self.active_connections.fetchSub(1, .release);
                connection.stream.close();
                continue;
            }

            const thread = std.Thread.spawn(.{}, handleConnection, .{ connection, self.ctx }) catch |err| {
                self.logger.log(.error_, "thread_spawn_failed", null, &.{
                    .{ .key = "error", .value = .{ .string = @errorName(err) } },
                });
                _ = self.active_connections.fetchSub(1, .release);
                connection.stream.close();
                continue;
            };
            thread.detach();
        }
    }

    pub fn initiateShutdown(self: *ProxyServer, reason: []const u8) void {
        const first_request = self.shutdown_state.request();
        const first_drain = self.shutdown_state.beginDraining();

        if (first_request or first_drain) {
            self.observability.markShutdownDraining();
            self.logger.log(.info, "shutdown_requested", null, &.{
                .{ .key = "reason", .value = .{ .string = reason } },
                .{ .key = "drain_timeout_ms", .value = .{ .uint = self.drain_timeout_ms } },
                .{ .key = "active_connections", .value = .{ .uint = self.active_connections.load(.acquire) } },
            });
        }

        self.closeListener();
    }

    pub fn deinit(self: *ProxyServer) void {
        self.closeListener();
    }

    fn finishShutdown(self: *ProxyServer) void {
        if (self.shutdown_state.beginDraining()) {
            self.observability.markShutdownDraining();
            self.logger.log(.info, "shutdown_draining", null, &.{
                .{ .key = "drain_timeout_ms", .value = .{ .uint = self.drain_timeout_ms } },
            });
        }

        const drain_result = shutdown_mod.waitForDrain(self.active_connections, self.drain_timeout_ms);
        if (drain_result.completed) {
            self.logger.log(.info, "shutdown_complete", null, &.{
                .{ .key = "remaining_connections", .value = .{ .uint = drain_result.remaining_connections } },
            });
        } else {
            self.logger.log(.warn, "shutdown_timeout", null, &.{
                .{ .key = "remaining_connections", .value = .{ .uint = drain_result.remaining_connections } },
                .{ .key = "drain_timeout_ms", .value = .{ .uint = self.drain_timeout_ms } },
            });
        }
    }

    fn closeListener(self: *ProxyServer) void {
        self.listener_mutex.lock();
        defer self.listener_mutex.unlock();

        if (self.listener_closed) return;
        self.net_server.deinit();
        self.listener_closed = true;
    }
};

fn handleConnection(connection: std.net.Server.Connection, ctx: ThreadContext) void {
    defer {
        connection.stream.close();
        _ = ctx.active_connections.fetchSub(1, .release);
    }

    var sid_buf: [8]u8 = undefined;
    const session_id = logger_mod.generateSessionId(&sid_buf);

    const snapshot: ?*EntitySnapshot = if (ctx.entity_set) |es| es.acquire() else null;
    defer if (snapshot) |snap| {
        if (ctx.entity_set) |es| es.release(snap);
    };

    var read_buf: [16 * 1024]u8 = undefined;
    var write_buf: [16 * 1024]u8 = undefined;

    var stream_reader = connection.stream.reader(&read_buf);
    var stream_writer = connection.stream.writer(&write_buf);

    var tls_stream_buf: [32 * 1024]u8 = undefined;
    var tls_stream: ?tls_mod.TlsServerStream = null;
    const raw_reader_iface = stream_reader.interface();
    const raw_writer_iface = &stream_writer.interface;
    if (ctx.tls_context) |tls_ctx| {
        tls_stream = tls_mod.accept(tls_ctx, raw_reader_iface, raw_writer_iface, &tls_stream_buf) catch |err| {
            ctx.logger.log(.error_, "tls_handshake_failed", session_id, &.{
                .{ .key = "error", .value = .{ .string = @errorName(err) } },
            });
            return;
        };
    }

    const final_reader = if (tls_stream) |*ts| ts.reader() else raw_reader_iface;
    const final_writer = if (tls_stream) |*ts| ts.writer() else raw_writer_iface;
    var server = std.http.Server.init(final_reader, final_writer);

    var request = server.receiveHead() catch |err| {
        ctx.logger.log(.error_, "receive_head_failed", session_id, &.{
            .{ .key = "error", .value = .{ .string = @errorName(err) } },
        });
        return;
    };

    const em: ?*const entity_mask.EntityMap = if (snapshot) |s| &s.entity_map else null;
    const fm: ?*const fuzzy_match.FuzzyMatcher = if (snapshot) |s| &s.fuzzy_matcher else null;

    proxy.handleRequest(
        &request,
        .{
            .allocator = ctx.allocator,
            .client = ctx.http_client,
            .target_host = ctx.target_host,
            .target_port = ctx.target_port,
            .target_tls = ctx.target_tls,
            .session_entity_map = em,
            .session_fuzzy_matcher = fm,
            .entity_set = ctx.entity_set,
            .admin_config = ctx.admin_config,
            .max_body_size = ctx.max_body_size,
            .log = ctx.logger,
            .observability = ctx.observability,
            .session_id = session_id,
            .active_connections = ctx.active_connections,
            .connections_total = ctx.connections_total,
            .start_time = ctx.start_time,
            .unsupported_request_body_behavior = ctx.unsupported_request_body_behavior,
            .unsupported_response_body_behavior = ctx.unsupported_response_body_behavior,
            .enable_email = ctx.enable_email,
            .enable_phone = ctx.enable_phone,
            .enable_credit_card = ctx.enable_credit_card,
            .enable_ip = ctx.enable_ip,
            .enable_healthcare = ctx.enable_healthcare,
            .schema = ctx.schema,
            .hasher = ctx.hasher,
            .shutdown_state = ctx.shutdown_state,
            .upstream_timeouts = ctx.upstream_timeouts,
        },
    ) catch |err| {
        ctx.logger.log(.error_, "proxy_request_failed", session_id, &.{
            .{ .key = "error", .value = .{ .string = @errorName(err) } },
        });
    };
}
