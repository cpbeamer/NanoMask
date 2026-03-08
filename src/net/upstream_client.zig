const std = @import("std");
const builtin = @import("builtin");
const http = std.http;
const net = std.net;
const posix = std.posix;

pub const UpstreamTimeouts = struct {
    connect_timeout_ms: u64 = 5_000,
    read_timeout_ms: u64 = 30_000,
    request_timeout_ms: u64 = 60_000,
};

pub const TimeoutPhase = enum {
    connect,
    read,
    request,
};

pub const DeadlineError = error{
    UpstreamRequestTimedOut,
};

pub const RequestDeadline = struct {
    timeouts: UpstreamTimeouts,
    start_ns: i128,
    last_read_phase: TimeoutPhase = .read,
    last_read_timeout_ms: ?u32 = null,

    pub fn init(timeouts: UpstreamTimeouts) RequestDeadline {
        return .{
            .timeouts = timeouts,
            .start_ns = std.time.nanoTimestamp(),
        };
    }

    pub fn ensureWithinOverall(self: *RequestDeadline) DeadlineError!void {
        if (self.remainingRequestMs() == null) return;
        if (self.remainingRequestMs().? == 0) return error.UpstreamRequestTimedOut;
    }

    pub fn remainingRequestMs(self: *const RequestDeadline) ?u64 {
        if (self.timeouts.request_timeout_ms == 0) return null;

        const elapsed_ns = std.time.nanoTimestamp() - self.start_ns;
        if (elapsed_ns <= 0) return self.timeouts.request_timeout_ms;

        const elapsed_ms: u64 = @intCast(@divTrunc(elapsed_ns, std.time.ns_per_ms));
        if (elapsed_ms >= self.timeouts.request_timeout_ms) return 0;
        return self.timeouts.request_timeout_ms - elapsed_ms;
    }

    pub fn connectTimeoutMs(self: *RequestDeadline) DeadlineError!?u32 {
        return chooseOperationTimeout(
            self.timeouts.connect_timeout_ms,
            self.remainingRequestMs(),
        );
    }

    pub fn armReadOperation(
        self: *RequestDeadline,
        connection: *http.Client.Connection,
    ) (DeadlineError || posix.SetSockOptError)!void {
        const remaining_request_ms = self.remainingRequestMs();
        const timeout_ms = try chooseOperationTimeout(
            self.timeouts.read_timeout_ms,
            remaining_request_ms,
        ) orelse return;

        self.last_read_phase = if (remaining_request_ms) |remaining|
            if (self.timeouts.read_timeout_ms == 0 or remaining <= self.timeouts.read_timeout_ms) .request else .read
        else
            .read;

        if (self.last_read_timeout_ms == null or self.last_read_timeout_ms.? != timeout_ms) {
            try setReceiveTimeout(connection.stream_reader.getStream().handle, timeout_ms);
            self.last_read_timeout_ms = timeout_ms;
        }
    }

    pub fn readTimeoutPhase(self: *const RequestDeadline) TimeoutPhase {
        return self.last_read_phase;
    }
};

fn chooseOperationTimeout(
    operation_timeout_ms: u64,
    remaining_request_ms: ?u64,
) DeadlineError!?u32 {
    if (remaining_request_ms) |remaining| {
        if (remaining == 0) return error.UpstreamRequestTimedOut;
        if (operation_timeout_ms == 0) return castTimeout(remaining);
        return castTimeout(@min(operation_timeout_ms, remaining));
    }

    if (operation_timeout_ms == 0) return null;
    return castTimeout(operation_timeout_ms);
}

fn castTimeout(value_ms: u64) u32 {
    return @intCast(@min(value_ms, std.math.maxInt(u32)));
}

fn setReceiveTimeout(
    socket: net.Stream.Handle,
    timeout_ms: u32,
) posix.SetSockOptError!void {
    if (builtin.os.tag == .windows) {
        var timeout = timeout_ms;
        try posix.setsockopt(socket, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout));
        return;
    }

    var timeout = posix.timeval{
        .tv_sec = @intCast(@divTrunc(timeout_ms, 1_000)),
        .tv_usec = @intCast((timeout_ms % 1_000) * 1_000),
    };
    try posix.setsockopt(socket, posix.SOL.SOCKET, posix.SO.RCVTIMEO, std.mem.asBytes(&timeout));
}

fn setSocketBlocking(
    socket: net.Stream.Handle,
    blocking: bool,
) !void {
    if (builtin.os.tag == .windows) {
        const ws2_32 = std.os.windows.ws2_32;
        var mode: u32 = if (blocking) 0 else 1;
        if (ws2_32.ioctlsocket(socket, ws2_32.FIONBIO, &mode) == ws2_32.SOCKET_ERROR) {
            return error.UnexpectedConnectFailure;
        }
        return;
    }

    const flags = try posix.fcntl(socket, posix.F.GETFL, 0);
    const nonblock_bit = @as(usize, 1) << @bitOffsetOf(posix.O, "NONBLOCK");
    const next_flags = if (blocking)
        flags & ~nonblock_bit
    else
        flags | nonblock_bit;
    _ = try posix.fcntl(socket, posix.F.SETFL, next_flags);
}

fn connectAddressWithTimeout(
    address: net.Address,
    timeout_ms: ?u32,
) (posix.SocketError || posix.ConnectError || posix.PollError || error{UnexpectedConnectFailure})!net.Stream {
    if (timeout_ms == null) {
        return net.tcpConnectToAddress(address);
    }

    const sock_flags = posix.SOCK.STREAM |
        (if (builtin.os.tag == .windows) 0 else posix.SOCK.CLOEXEC);
    const socket = try posix.socket(address.any.family, sock_flags, posix.IPPROTO.TCP);
    errdefer net.Stream.close(.{ .handle = socket });

    try setSocketBlocking(socket, false);

    posix.connect(socket, &address.any, address.getOsSockLen()) catch |err| switch (err) {
        error.WouldBlock, error.ConnectionPending => {},
        else => return err,
    };

    var poll_fds = [_]posix.pollfd{
        .{
            .fd = socket,
            .events = posix.POLL.OUT,
            .revents = 0,
        },
    };

    const poll_result = try posix.poll(&poll_fds, @intCast(timeout_ms.?));
    if (poll_result == 0) return error.ConnectionTimedOut;

    try checkPendingConnectResult(socket);
    try setSocketBlocking(socket, true);

    return .{ .handle = socket };
}

fn checkPendingConnectResult(
    socket: net.Stream.Handle,
) (posix.ConnectError || error{UnexpectedConnectFailure})!void {
    if (builtin.os.tag == .windows) {
        const ws2_32 = std.os.windows.ws2_32;
        var err_code: i32 = 0;
        var err_len: i32 = @sizeOf(i32);
        if (ws2_32.getsockopt(
            socket,
            posix.SOL.SOCKET,
            @intCast(posix.SO.ERROR),
            @ptrCast(&err_code),
            &err_len,
        ) == ws2_32.SOCKET_ERROR) {
            return error.UnexpectedConnectFailure;
        }

        if (err_code == 0) return;

        switch (@as(ws2_32.WinsockError, @enumFromInt(@as(u16, @intCast(err_code))))) {
            .WSAECONNREFUSED => return error.ConnectionRefused,
            .WSAECONNRESET => return error.ConnectionResetByPeer,
            .WSAETIMEDOUT => return error.ConnectionTimedOut,
            .WSAEHOSTUNREACH, .WSAENETUNREACH => return error.NetworkUnreachable,
            else => return error.UnexpectedConnectFailure,
        }
    }

    try posix.getsockoptError(socket);
}

fn createPlainConnection(
    client: *http.Client,
    remote_host: []const u8,
    port: u16,
    stream: net.Stream,
) error{OutOfMemory}!*http.Client.Connection {
    const alloc_len = @sizeOf(PlainConnection) + remote_host.len + client.read_buffer_size + client.write_buffer_size;
    const base = try client.allocator.alignedAlloc(u8, .of(PlainConnection), alloc_len);
    errdefer client.allocator.free(base);

    const host_buffer = base[@sizeOf(PlainConnection)..][0..remote_host.len];
    const socket_read_buffer = host_buffer.ptr[host_buffer.len..][0..client.read_buffer_size];
    const socket_write_buffer = socket_read_buffer.ptr[socket_read_buffer.len..][0..client.write_buffer_size];
    @memcpy(host_buffer, remote_host);

    const plain: *PlainConnection = @ptrCast(base);
    plain.* = .{
        .connection = .{
            .client = client,
            .stream_writer = stream.writer(socket_write_buffer),
            .stream_reader = stream.reader(socket_read_buffer),
            .pool_node = .{},
            .port = port,
            .host_len = @intCast(remote_host.len),
            .proxied = false,
            .closing = false,
            .protocol = .plain,
        },
    };
    client.connection_pool.addUsed(&plain.connection);
    return &plain.connection;
}

fn createTlsConnection(
    client: *http.Client,
    remote_host: []const u8,
    port: u16,
    stream: net.Stream,
) error{ OutOfMemory, TlsInitializationFailed }!*http.Client.Connection {
    const tls_read_buffer_len = client.tls_buffer_size + client.read_buffer_size;
    const alloc_len = @sizeOf(TlsConnection) + remote_host.len + tls_read_buffer_len +
        client.tls_buffer_size + client.write_buffer_size + client.tls_buffer_size;
    const base = try client.allocator.alignedAlloc(u8, .of(TlsConnection), alloc_len);
    errdefer client.allocator.free(base);

    const host_buffer = base[@sizeOf(TlsConnection)..][0..remote_host.len];
    const tls_read_buffer = host_buffer.ptr[host_buffer.len..][0..tls_read_buffer_len];
    const tls_write_buffer = tls_read_buffer.ptr[tls_read_buffer.len..][0..client.tls_buffer_size];
    const socket_write_buffer = tls_write_buffer.ptr[tls_write_buffer.len..][0..client.write_buffer_size];
    const socket_read_buffer = socket_write_buffer.ptr[socket_write_buffer.len..][0..client.tls_buffer_size];
    @memcpy(host_buffer, remote_host);

    const tls_connection: *TlsConnection = @ptrCast(base);
    tls_connection.* = .{
        .connection = .{
            .client = client,
            .stream_writer = stream.writer(tls_write_buffer),
            .stream_reader = stream.reader(socket_read_buffer),
            .pool_node = .{},
            .port = port,
            .host_len = @intCast(remote_host.len),
            .proxied = false,
            .closing = false,
            .protocol = .tls,
        },
        .client = std.crypto.tls.Client.init(
            tls_connection.connection.stream_reader.interface(),
            &tls_connection.connection.stream_writer.interface,
            .{
                .host = .{ .explicit = remote_host },
                .ca = .{ .bundle = client.ca_bundle },
                .ssl_key_log = client.ssl_key_log,
                .read_buffer = tls_read_buffer,
                .write_buffer = socket_write_buffer,
                .allow_truncation_attacks = true,
            },
        ) catch return error.TlsInitializationFailed,
    };
    client.connection_pool.addUsed(&tls_connection.connection);
    return &tls_connection.connection;
}

fn createConnection(
    client: *http.Client,
    host: []const u8,
    port: u16,
    protocol: http.Client.Protocol,
    stream: net.Stream,
) http.Client.ConnectTcpError!*http.Client.Connection {
    return switch (protocol) {
        .plain => createPlainConnection(client, host, port, stream) catch return error.UnexpectedConnectFailure,
        .tls => createTlsConnection(client, host, port, stream) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.TlsInitializationFailed => return error.TlsInitializationFailed,
        },
    };
}

fn connectDirectWithTimeout(
    client: *http.Client,
    host: []const u8,
    port: u16,
    protocol: http.Client.Protocol,
    timeout_ms: ?u32,
) http.Client.ConnectTcpError!*http.Client.Connection {
    if (client.connection_pool.findConnection(.{
        .host = host,
        .port = port,
        .protocol = protocol,
    })) |conn| return conn;

    const address_list = net.getAddressList(client.allocator, host, port) catch |err| switch (err) {
        error.TemporaryNameServerFailure => return error.TemporaryNameServerFailure,
        error.NameServerFailure => return error.NameServerFailure,
        error.UnknownHostName => return error.UnknownHostName,
        error.HostLacksNetworkAddresses => return error.HostLacksNetworkAddresses,
        else => return error.UnexpectedConnectFailure,
    };
    defer address_list.deinit();

    if (address_list.addrs.len == 0) return error.UnknownHostName;

    for (address_list.addrs) |address| {
        const stream = connectAddressWithTimeout(address, timeout_ms) catch |err| switch (err) {
            error.ConnectionRefused => continue,
            error.ConnectionTimedOut => return error.ConnectionTimedOut,
            error.NetworkUnreachable => return error.NetworkUnreachable,
            error.ConnectionResetByPeer => return error.ConnectionResetByPeer,
            else => return error.UnexpectedConnectFailure,
        };
        errdefer stream.close();

        return createConnection(client, host, port, protocol, stream);
    }

    return error.ConnectionRefused;
}

fn ensureTlsRootsReady(client: *http.Client) http.Client.RequestError!void {
    if (@atomicLoad(bool, &client.next_https_rescan_certs, .acquire)) {
        client.ca_bundle_mutex.lock();
        defer client.ca_bundle_mutex.unlock();

        if (client.next_https_rescan_certs) {
            client.ca_bundle.rescan(client.allocator) catch return error.CertificateBundleLoadFailure;
            @atomicStore(bool, &client.next_https_rescan_certs, false, .release);
        }
    }
}

pub fn requestWithTimeouts(
    client: *http.Client,
    method: http.Method,
    uri: std.Uri,
    options: http.Client.RequestOptions,
    deadline: *RequestDeadline,
) (DeadlineError || http.Client.RequestError)!http.Client.Request {
    if (options.connection != null) {
        return client.request(method, uri, options);
    }

    const protocol = http.Client.Protocol.fromUri(uri) orelse return error.UnsupportedUriScheme;
    if (protocol == .tls) {
        try ensureTlsRootsReady(client);
    }

    if ((protocol == .plain and client.http_proxy != null) or
        (protocol == .tls and client.https_proxy != null))
    {
        return client.request(method, uri, options);
    }

    var host_name_buffer: [std.Uri.host_name_max]u8 = undefined;
    const host_name = try uri.getHost(&host_name_buffer);
    const port: u16 = uri.port orelse switch (protocol) {
        .plain => @as(u16, 80),
        .tls => @as(u16, 443),
    };
    const connect_timeout_ms = try deadline.connectTimeoutMs();
    const connection = try connectDirectWithTimeout(client, host_name, port, protocol, connect_timeout_ms);
    errdefer {
        connection.closing = true;
        client.connection_pool.release(connection);
    }

    return client.request(method, uri, .{
        .version = options.version,
        .handle_continue = options.handle_continue,
        .keep_alive = options.keep_alive,
        .redirect_behavior = options.redirect_behavior,
        .connection = connection,
        .headers = options.headers,
        .extra_headers = options.extra_headers,
        .privileged_headers = options.privileged_headers,
    });
}

const PlainConnection = struct {
    connection: http.Client.Connection,
};

const TlsConnection = struct {
    client: std.crypto.tls.Client,
    connection: http.Client.Connection,
};

test "RequestDeadline prefers overall timeout when it is smaller" {
    var deadline = RequestDeadline.init(.{
        .connect_timeout_ms = 5_000,
        .read_timeout_ms = 2_000,
        .request_timeout_ms = 1_000,
    });

    try std.testing.expectEqual(@as(?u64, 1_000), deadline.remainingRequestMs());
    try std.testing.expectEqual(@as(?u32, 1_000), try deadline.connectTimeoutMs());
}
