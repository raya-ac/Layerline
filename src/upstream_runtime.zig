const std = @import("std");
const php_version = @import("php_version.zig");
const config_mod = @import("config.zig");
const config_store = @import("config_store.zig");
const http_headers = @import("http_headers.zig");
const metrics_mod = @import("metrics.zig");
const proxy_utils = @import("proxy_utils.zig");
const request_mod = @import("request.zig");
const upstream_mod = @import("upstream.zig");
const upstream_idle = @import("upstream_idle.zig");
const read_deadline = @import("read_deadline.zig");
const write_deadline = @import("write_deadline.zig");
const backend_deadline = @import("backend_deadline.zig");
const upstream_reader = @import("upstream_reader.zig");

const HttpRequest = request_mod.HttpRequest;
const ServerConfig = config_mod.ServerConfig;
const UpstreamConfig = config_mod.UpstreamConfig;
const UpstreamIdleConnection = config_mod.UpstreamIdleConnection;
const UpstreamPoolConfig = config_mod.UpstreamPoolConfig;
const UpstreamPoolPolicy = config_mod.UpstreamPoolPolicy;
const UpstreamRuntimePolicy = config_mod.UpstreamRuntimePolicy;
const UpstreamResponseForwardResult = proxy_utils.UpstreamResponseForwardResult;

pub const Callbacks = struct {
    send_response_no_body_headers: *const fn (std.Io.net.Stream, u16, []const u8, []const u8, usize, bool, ?[]const u8) anyerror!void,
    access_log_set_upstream: *const fn ([]const u8) void,
    active_io: *const fn () std.Io,
    bind_thread_io: *const fn (std.Io) void,
    connect_tcp_host: *const fn (std.mem.Allocator, []const u8, u16) anyerror!std.Io.net.Stream,
    current_request_id: *const fn () []const u8,
    metrics: *metrics_mod.ServerMetrics,
    proxy_raw_bidirectional: *const fn (std.Io.net.Stream, std.Io.net.Stream, []const u8) anyerror!void,
    send_cool_error: *const fn (std.Io.net.Stream, std.mem.Allocator, u16, []const u8, []const u8, bool, bool, ?[]const u8) anyerror!void,
    set_stream_timeouts: *const fn (std.Io.net.Stream, u32, u32) anyerror!void,
    shutdown_requested: *std.atomic.Value(bool),
    stream_close: *const fn (std.Io.net.Stream) void,
    stream_read: *const fn (std.Io.net.Stream, []u8) anyerror!usize,
    stream_write_all: *const fn (std.Io.net.Stream, []const u8) anyerror!void,
    upstream_now_ms: *const fn () i64,
    write_response_headers: *const fn (std.Io.net.Stream) anyerror!void,
};

pub const HealthTransition = enum {
    unchanged,
    ejected,
    recovered,
};

pub const HealthCheckContext = struct {
    io: std.Io,
    acquire_config: *const fn () config_store.Lease,
    callbacks: Callbacks,
};

const UpstreamConnectionLease = struct {
    stream: std.Io.net.Stream,
    requests_served: usize,
};

fn keepaliveConfigured(cfg: *const ServerConfig) bool {
    return cfg.upstream_keepalive_enabled and cfg.upstream_keepalive_max_idle > 0;
}

fn closeIdleConnection(conn: UpstreamIdleConnection, callbacks: Callbacks) void {
    callbacks.stream_close(conn.stream);
    callbacks.metrics.upstreamConnectionDiscarded();
}

pub fn deinitConfigPools(io: std.Io, cfg: *ServerConfig, metrics: *metrics_mod.ServerMetrics, close: *const fn (std.Io.net.Stream) void) void {
    const Cleanup = struct {
        fn target(context: std.Io, upstream: *UpstreamConfig, counters: *metrics_mod.ServerMetrics, close_stream: *const fn (std.Io.net.Stream) void) void {
            upstream.keepalive_pool.mutex.lockUncancelable(context);
            defer upstream.keepalive_pool.mutex.unlock(context);
            while (upstream.keepalive_pool.idle.pop()) |conn| {
                close_stream(conn.stream);
                counters.upstreamConnectionDiscarded();
            }
            upstream.keepalive_pool.idle.deinit(std.heap.page_allocator);
            upstream.keepalive_pool.idle = .empty;
        }
        fn pool(context: std.Io, targets: *UpstreamPoolConfig, counters: *metrics_mod.ServerMetrics, close_stream: *const fn (std.Io.net.Stream) void) void {
            for (targets.targets.items) |*upstream| target(context, upstream, counters, close_stream);
        }
    };
    if (cfg.h2_upstream) |*upstream| Cleanup.target(io, upstream, metrics, close);
    if (cfg.upstream) |*pool| Cleanup.pool(io, pool, metrics, close);
    for (cfg.routes.items) |*route| if (route.upstream) |*pool| Cleanup.pool(io, pool, metrics, close);
    for (cfg.domains.items) |*domain| {
        if (domain.upstream) |*pool| Cleanup.pool(io, pool, metrics, close);
        for (domain.routes.items) |*route| if (route.upstream) |*pool| Cleanup.pool(io, pool, metrics, close);
    }
}

test "retired global route domain and domain-route pools close all idle descriptors" {
    const Fake = struct {
        var closed: usize = 0;
        fn close(_: std.Io.net.Stream) void {
            closed += 1;
        }
    };
    Fake.closed = 0;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var cfg = config_mod.defaultServerConfig();
    var metrics = metrics_mod.ServerMetrics.init();
    defer deinitConfigPools(std.testing.io, &cfg, &metrics, Fake.close);
    for ([_][2][]const u8{
        .{ "h2_upstream", "http://127.0.0.1:8999" },
        .{ "proxy", "http://127.0.0.1:9000" },
        .{ "route", "app /app/* proxy" },
        .{ "route_proxy.app", "http://127.0.0.1:9001" },
        .{ "server", "site" },
        .{ "server_name.site", "example.test" },
        .{ "server_proxy.site", "http://127.0.0.1:9002" },
        .{ "server_route.site", "app /app/* proxy" },
        .{ "server_route_proxy.site.app", "http://127.0.0.1:9003" },
    }) |entry| try config_mod.applyConfigLine(&cfg, allocator, entry[0], entry[1]);
    const pools = [_]*UpstreamPoolConfig{ &cfg.upstream.?, &cfg.routes.items[0].upstream.?, &cfg.domains.items[0].upstream.?, &cfg.domains.items[0].routes.items[0].upstream.? };
    try cfg.h2_upstream.?.keepalive_pool.idle.append(std.heap.page_allocator, .{ .stream = .{ .socket = .{ .handle = 122, .address = undefined } }, .expires_at_ms = 1000, .requests_served = 1 });
    for (pools, 0..) |pool, index| try pool.targets.items[0].keepalive_pool.idle.append(std.heap.page_allocator, .{ .stream = .{ .socket = .{ .handle = @intCast(123 + index), .address = undefined } }, .expires_at_ms = 1000, .requests_served = 1 });
    deinitConfigPools(std.testing.io, &cfg, &metrics, Fake.close);
    try std.testing.expectEqual(5, Fake.closed);
    try std.testing.expectEqual(0, cfg.h2_upstream.?.keepalive_pool.idle.capacity);
    for (pools) |pool| try std.testing.expectEqual(0, pool.targets.items[0].keepalive_pool.idle.capacity);
}

fn acquireConnection(allocator: std.mem.Allocator, upstream: *UpstreamConfig, cfg: *const ServerConfig, now_ms: i64, callbacks: Callbacks) !UpstreamConnectionLease {
    if (keepaliveConfigured(cfg) and !upstream.https) {
        const io = callbacks.active_io();
        upstream.keepalive_pool.mutex.lockUncancelable(io);
        defer upstream.keepalive_pool.mutex.unlock(io);

        while (upstream.keepalive_pool.idle.pop()) |conn| {
            if (conn.expires_at_ms <= now_ms or conn.requests_served >= cfg.upstream_keepalive_max_requests or !upstream_idle.reusable(conn.stream)) {
                closeIdleConnection(conn, callbacks);
                continue;
            }

            callbacks.metrics.upstreamConnectionReused();
            return .{
                .stream = conn.stream,
                .requests_served = conn.requests_served,
            };
        }
    }

    const upstream_conn = try callbacks.connect_tcp_host(allocator, upstream.host, upstream.port);
    errdefer callbacks.stream_close(upstream_conn);
    try callbacks.set_stream_timeouts(upstream_conn, cfg.upstream_timeout_ms, cfg.upstream_timeout_ms);
    callbacks.metrics.upstreamConnectionOpened();
    return .{
        .stream = upstream_conn,
        .requests_served = 0,
    };
}

fn releaseConnection(upstream: *UpstreamConfig, cfg: *const ServerConfig, lease: UpstreamConnectionLease, reusable: bool, now_ms: i64, callbacks: Callbacks) void {
    if (!reusable or !keepaliveConfigured(cfg) or upstream.https) {
        callbacks.stream_close(lease.stream);
        callbacks.metrics.upstreamConnectionDiscarded();
        return;
    }

    const served = lease.requests_served + 1;
    if (served >= cfg.upstream_keepalive_max_requests) {
        callbacks.stream_close(lease.stream);
        callbacks.metrics.upstreamConnectionDiscarded();
        return;
    }

    const idle_conn = UpstreamIdleConnection{
        .stream = lease.stream,
        .expires_at_ms = now_ms + @as(i64, @intCast(cfg.upstream_keepalive_idle_timeout_ms)),
        .requests_served = served,
    };

    const io = callbacks.active_io();
    upstream.keepalive_pool.mutex.lockUncancelable(io);
    defer upstream.keepalive_pool.mutex.unlock(io);

    while (upstream.keepalive_pool.idle.items.len >= cfg.upstream_keepalive_max_idle) {
        closeIdleConnection(upstream.keepalive_pool.idle.orderedRemove(0), callbacks);
    }

    upstream.keepalive_pool.idle.append(std.heap.page_allocator, idle_conn) catch {
        callbacks.stream_close(idle_conn.stream);
        callbacks.metrics.upstreamConnectionDiscarded();
        return;
    };
    callbacks.metrics.upstreamConnectionPooled();
}

fn forwardFields(stream: std.Io.net.Stream, fields: []const u8, connection_fields: []const u8, callbacks: Callbacks) !void {
    var lines = std.mem.splitSequence(u8, fields, "\r\n");
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse return error.BadGateway;
        if (proxy_utils.skipResponseField(connection_fields, line[0..colon])) continue;
        callbacks.stream_write_all(stream, http_headers.trimValue(line)) catch return error.DownstreamClosed;
        callbacks.stream_write_all(stream, "\r\n") catch return error.DownstreamClosed;
    }
}

fn forwardInterim(stream: std.Io.net.Stream, head: upstream_reader.Head, callbacks: Callbacks) !void {
    if (head.framing.status_code.? == 100) return;
    callbacks.stream_write_all(stream, head.status_line) catch return error.DownstreamClosed;
    callbacks.stream_write_all(stream, "\r\n") catch return error.DownstreamClosed;
    try forwardFields(stream, head.fields, head.fields, callbacks);
    callbacks.stream_write_all(stream, "\r\n") catch return error.DownstreamClosed;
    // A complete interim reply is not the start of the final response.
    write_deadline.restart(stream);
}

fn forwardResponse(stream: std.Io.net.Stream, allocator: std.mem.Allocator, upstream_conn: std.Io.net.Stream, req: HttpRequest, sticky_cookie_header: ?[]const u8, timeout_ms: u32, callbacks: Callbacks) !UpstreamResponseForwardResult {
    const reader = try upstream_reader.Reader.create(allocator, upstream_conn, callbacks.stream_read);
    defer allocator.destroy(reader);
    const head = final: while (true) {
        const head = try reader.nextHead();
        if (php_version.exposedHeaders(head.fields)) |version| {
            php_version.log(version);
            const message = try php_version.updateMessage(std.heap.page_allocator, version);
            defer std.heap.page_allocator.free(message);
            try callbacks.send_response_no_body_headers(stream, 503, "Service Unavailable", "text/plain; charset=utf-8", message.len, true, "Cache-Control: no-store\r\n");
            if (!std.mem.eql(u8, req.method, "HEAD")) try callbacks.stream_write_all(stream, message);
            return .{ .reusable = false };
        }
        const status = head.framing.status_code.?;
        if (status == 101) return error.BadGateway;
        if (status >= 200) break :final head;
        try forwardInterim(stream, head, callbacks);
    };
    const framing = head.framing;
    try reader.beginBody(req.method, framing, null);
    callbacks.stream_write_all(stream, head.status_line) catch return error.DownstreamClosed;
    callbacks.stream_write_all(stream, "\r\n") catch return error.DownstreamClosed;
    try forwardFields(stream, head.fields, head.fields, callbacks);
    if (framing.status_code.? != 204) {
        // Regenerate message framing even if the origin nominated those fields
        // as hop-by-hop. The bytes sent below must match our own framing.
        if (framing.transfer_chunked) {
            try callbacks.stream_write_all(stream, "Transfer-Encoding: chunked\r\n");
        } else if (framing.content_length) |length| {
            var buffer: [64]u8 = undefined;
            try callbacks.stream_write_all(stream, try std.fmt.bufPrint(&buffer, "Content-Length: {d}\r\n", .{length}));
        }
    }

    if (sticky_cookie_header) |header| try callbacks.stream_write_all(stream, header);
    try callbacks.write_response_headers(stream);
    callbacks.stream_write_all(stream, "Connection: close\r\n\r\n") catch return error.DownstreamClosed;

    // Once headers are visible, backend body waits spend the same transfer
    // budget as writes. No retry or second status line is safe after this point.
    const budget = write_deadline.forStream(stream);
    const previous_read = if (budget) |state| read_deadline.push(.{
        .io = callbacks.active_io(),
        .handle = upstream_conn.socket.handle,
        .deadline = state.deadline,
        .restore_timeout_ms = timeout_ms,
    }) else null;
    defer if (budget != null) read_deadline.restore(previous_read);

    const chunked = framing.transfer_chunked and !proxy_utils.responseHasNoBody(req.method, framing.status_code);
    while (try reader.nextData()) |data| {
        if (chunked) {
            var buffer: [32]u8 = undefined;
            callbacks.stream_write_all(stream, try std.fmt.bufPrint(&buffer, "{x}\r\n", .{data.len})) catch return error.DownstreamClosed;
        }
        callbacks.stream_write_all(stream, data) catch return error.DownstreamClosed;
        if (chunked) callbacks.stream_write_all(stream, "\r\n") catch return error.DownstreamClosed;
    }
    if (chunked) {
        callbacks.stream_write_all(stream, "0\r\n") catch return error.DownstreamClosed;
        try forwardFields(stream, reader.trailers(), head.fields, callbacks);
        callbacks.stream_write_all(stream, "\r\n") catch return error.DownstreamClosed;
    }
    return .{ .reusable = reader.reusable(framing) };
}

fn forwardUpgradeResponse(stream: std.Io.net.Stream, allocator: std.mem.Allocator, upstream_conn: std.Io.net.Stream, req: HttpRequest, callbacks: Callbacks) !void {
    const reader = try upstream_reader.Reader.create(allocator, upstream_conn, callbacks.stream_read);
    defer allocator.destroy(reader);
    const head = final: while (true) {
        const head = try reader.nextHead();
        if (php_version.exposedHeaders(head.fields)) |version| {
            php_version.log(version);
            const message = try php_version.updateMessage(std.heap.page_allocator, version);
            defer std.heap.page_allocator.free(message);
            try callbacks.send_response_no_body_headers(stream, 503, "Service Unavailable", "text/plain; charset=utf-8", message.len, true, "Cache-Control: no-store\r\n");
            if (!std.mem.eql(u8, req.method, "HEAD")) try callbacks.stream_write_all(stream, message);
            return;
        }
        const status = head.framing.status_code.?;
        if (status == 101) break :final head;
        if (status >= 200) return error.BadGateway;
        try forwardInterim(stream, head, callbacks);
    };
    if (!proxy_utils.isHttpUpgradeHeaders(head.fields)) return error.BadGateway;
    const protocol = http_headers.findHeaderValue(head.fields, "Upgrade").?;
    if (!http_headers.hasConnectionToken(http_headers.findHeaderValue(req.headers, "Upgrade").?, protocol)) return error.BadGateway;
    callbacks.stream_write_all(stream, head.status_line) catch return error.DownstreamClosed;
    callbacks.stream_write_all(stream, "\r\n") catch return error.DownstreamClosed;
    try forwardFields(stream, head.fields, head.fields, callbacks);
    callbacks.stream_write_all(stream, "Connection: Upgrade\r\nUpgrade: ") catch return error.DownstreamClosed;
    callbacks.stream_write_all(stream, protocol) catch return error.DownstreamClosed;
    callbacks.stream_write_all(stream, "\r\n\r\n") catch return error.DownstreamClosed;
    write_deadline.clear(stream);
    backend_deadline.clear(upstream_conn);
    callbacks.proxy_raw_bidirectional(upstream_conn, stream, reader.pending) catch return error.DownstreamClosed;
}

fn responseDeadlineOwnsTimeout(response: read_deadline.Deadline, attempt: read_deadline.Deadline) bool {
    const limit = response.at orelse return false;
    return if (attempt.at) |other| limit.nanoseconds <= other.nanoseconds else true;
}

fn responseFailure(stream: std.Io.net.Stream, upstream_conn: std.Io.net.Stream, err: anyerror, callbacks: Callbacks) anyerror {
    if (err == error.DownstreamClosed or err == error.WriteTimeout) return error.DownstreamClosed;
    if (write_deadline.forStream(stream)) |budget| {
        if (write_deadline.started(stream)) {
            const attempt = if (backend_deadline.forStream(upstream_conn)) |state| state.deadline else read_deadline.Deadline{};
            // Socket timers can fire before a second clock sample crosses the
            // exact boundary. Attribute the timeout to the controlling budget.
            if (budget.deadline.expired(.now(callbacks.active_io(), .awake)) or
                (err == error.RequestTimeout and responseDeadlineOwnsTimeout(budget.deadline, attempt)))
            {
                budget.logTimeoutPhase("upstream");
                return error.DownstreamClosed;
            }
            // A total attempt budget also elapses while forwarding to a slow
            // client. After output starts, it is not reliable backend health evidence.
            if (err == error.RequestTimeout) return error.DownstreamClosed;
            return error.ResponseAborted;
        }
    }
    return err;
}

fn forwardToUpstream(stream: std.Io.net.Stream, allocator: std.mem.Allocator, upstream: *UpstreamConfig, req: HttpRequest, cfg: *const ServerConfig, timeout_ms: u32, sticky_cookie_header: ?[]const u8, callbacks: Callbacks) !void {
    if (upstream.https) {
        return error.UnsupportedUpstreamScheme;
    }

    const upgrade_request = proxy_utils.isHttpUpgradeHeaders(req.headers);
    const keepalive_enabled = keepaliveConfigured(cfg) and !upgrade_request;
    const previous_backend = backend_deadline.push(callbacks.active_io(), timeout_ms);
    defer backend_deadline.restore(previous_backend);
    const lease = try acquireConnection(allocator, upstream, cfg, callbacks.upstream_now_ms(), callbacks);
    var lease_released = false;
    defer if (!lease_released) {
        callbacks.stream_close(lease.stream);
        callbacks.metrics.upstreamConnectionDiscarded();
    };
    try callbacks.set_stream_timeouts(lease.stream, timeout_ms, timeout_ms);
    try backend_deadline.attach(lease.stream);

    const proxy_path = try proxy_utils.buildProxyPath(allocator, upstream.base_path, req.path, req.query);
    defer allocator.free(proxy_path);

    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);

    const forwarded_host = if (http_headers.findHeaderValue(req.headers, "Host")) |host|
        http_headers.trimValue(host)
    else
        upstream.host;
    const client_proto = if (proxy_utils.isConnectionField(req.headers, "X-Forwarded-Proto")) null else http_headers.findHeaderValue(req.headers, "X-Forwarded-Proto");
    const forwarded_proto = if (client_proto) |proto|
        http_headers.trimValue(proto)
    else if (cfg.tls_enabled)
        "https"
    else
        "http";

    try out.print(
        allocator,
        "{s} {s} HTTP/1.1\r\nHost: {s}\r\nConnection: {s}\r\n",
        .{
            req.method,
            proxy_path,
            forwarded_host,
            if (upgrade_request) "Upgrade" else if (keepalive_enabled) "keep-alive" else "close",
        },
    );
    if (upgrade_request) {
        try out.print(allocator, "Upgrade: {s}\r\n", .{http_headers.trimValue(http_headers.findHeaderValue(req.headers, "Upgrade").?)});
    }

    var saw_forwarded_host = false;
    var saw_forwarded_proto = false;
    var headers = std.mem.splitSequence(u8, req.headers, "\r\n");
    while (headers.next()) |line| {
        const trimmed = http_headers.trimValue(line);
        if (trimmed.len == 0) continue;
        if (std.mem.indexOfScalar(u8, trimmed, ':')) |colon| {
            const name = http_headers.trimValue(trimmed[0..colon]);
            if (proxy_utils.skipRequestField(req.headers, name)) continue;
            const value = http_headers.trimValue(trimmed[colon + 1 ..]);
            if (std.ascii.eqlIgnoreCase(name, "X-Forwarded-Host")) saw_forwarded_host = true;
            if (std.ascii.eqlIgnoreCase(name, "X-Forwarded-Proto")) saw_forwarded_proto = true;
            try out.print(allocator, "{s}: {s}\r\n", .{ name, value });
        }
    }

    if (!saw_forwarded_host) try out.print(allocator, "X-Forwarded-Host: {s}\r\n", .{forwarded_host});
    if (!saw_forwarded_proto) try out.print(allocator, "X-Forwarded-Proto: {s}\r\n", .{forwarded_proto});
    if (callbacks.current_request_id().len > 0) try out.print(allocator, "X-Request-Id: {s}\r\n", .{callbacks.current_request_id()});

    if (upgrade_request and req.body.len == 0) {
        try out.appendSlice(allocator, "\r\n");
    } else {
        try out.print(allocator, "Content-Length: {d}\r\n\r\n", .{req.body.len});
    }
    const request_line = try out.toOwnedSlice(allocator);
    defer allocator.free(request_line);

    callbacks.stream_write_all(lease.stream, request_line) catch |err| switch (err) {
        error.RequestTimeout => return err,
        else => |e| return e,
    };
    if (req.body.len > 0) {
        callbacks.stream_write_all(lease.stream, req.body) catch |err| switch (err) {
            error.RequestTimeout => return err,
            else => |e| return e,
        };
    }

    if (upgrade_request) {
        forwardUpgradeResponse(stream, allocator, lease.stream, req, callbacks) catch |err| return responseFailure(stream, lease.stream, err, callbacks);
        return error.CloseConnection;
    }

    const result = forwardResponse(stream, allocator, lease.stream, req, sticky_cookie_header, timeout_ms, callbacks) catch |err| {
        return responseFailure(stream, lease.stream, err, callbacks);
    };
    releaseConnection(upstream, cfg, lease, result.reusable, callbacks.upstream_now_ms(), callbacks);
    lease_released = true;

    return error.CloseConnection;
}

fn readHealthStatus(upstream_conn: std.Io.net.Stream, callbacks: Callbacks) !u16 {
    var buffer: [2048]u8 = undefined;
    var used: usize = 0;
    while (used < buffer.len) {
        const n = callbacks.stream_read(upstream_conn, buffer[used..]) catch |err| switch (err) {
            error.RequestTimeout => return err,
            else => |e| return e,
        };
        if (n == 0) break;
        used += n;
        if (std.mem.indexOf(u8, buffer[0..used], "\r\n\r\n") != null) break;
    }

    if (used == 0) return error.InvalidUpstream;
    return proxy_utils.parseHttpStatusCode(buffer[0..used]) orelse error.InvalidUpstream;
}

fn checkHealth(allocator: std.mem.Allocator, upstream: *const UpstreamConfig, health_path: []const u8, timeout_ms: u32, callbacks: Callbacks) !bool {
    if (upstream.https) return error.UnsupportedUpstreamScheme;

    const previous_backend = backend_deadline.push(callbacks.active_io(), timeout_ms);
    defer backend_deadline.restore(previous_backend);
    const upstream_conn = try callbacks.connect_tcp_host(allocator, upstream.host, upstream.port);
    defer callbacks.stream_close(upstream_conn);
    try backend_deadline.attach(upstream_conn);
    try callbacks.set_stream_timeouts(upstream_conn, timeout_ms, timeout_ms);

    const probe_path = try proxy_utils.buildProxyPath(allocator, upstream.base_path, health_path, "");
    defer allocator.free(probe_path);

    var request_buffer: [1024]u8 = undefined;
    const request = try std.fmt.bufPrint(
        &request_buffer,
        "GET {s} HTTP/1.1\r\nHost: {s}\r\nUser-Agent: Layerline-healthcheck\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
        .{ probe_path, upstream.host },
    );
    try callbacks.stream_write_all(upstream_conn, request);

    const status_code = try readHealthStatus(upstream_conn, callbacks);
    return status_code >= 200 and status_code < 400;
}

pub fn recordActiveHealthResult(upstream: *UpstreamConfig, healthy: bool, now_ms: i64, cooldown_ms: u32, slow_start_ms: u32) HealthTransition {
    if (healthy) {
        const was_unavailable = upstream.ejected_until_ms.load(.monotonic) != 0 or upstream.passive_failures.load(.monotonic) != 0;
        upstream_mod.upstreamRecordSuccess(upstream, now_ms, slow_start_ms);
        return if (was_unavailable) .recovered else .unchanged;
    }

    const was_available = !upstream_mod.upstreamIsEjected(upstream, now_ms);
    upstream.passive_failures.store(1, .monotonic);
    upstream.ejected_until_ms.store(now_ms + @as(i64, @intCast(cooldown_ms)), .monotonic);
    return if (was_available) .ejected else .unchanged;
}

fn activeHealthCooldownMs(policy: UpstreamRuntimePolicy) u32 {
    const doubled_interval = policy.health_check_interval_ms *| 2;
    return @max(doubled_interval, policy.health_check_timeout_ms);
}

fn recordActiveHealthMetrics(transition: HealthTransition, healthy: bool, callbacks: Callbacks) void {
    callbacks.metrics.upstreamHealthCheckRan();
    if (!healthy) callbacks.metrics.upstreamHealthCheckFailed();
    switch (transition) {
        .ejected => callbacks.metrics.upstreamEjected(),
        .recovered => callbacks.metrics.upstreamHealthCheckRecovered(),
        .unchanged => {},
    }
}

fn runHealthCheckForPool(allocator: std.mem.Allocator, pool: *UpstreamPoolConfig, policy: UpstreamRuntimePolicy, callbacks: Callbacks) void {
    if (!policy.health_check_enabled) return;
    const cooldown_ms = activeHealthCooldownMs(policy);
    for (pool.targets.items) |*upstream| {
        if (callbacks.shutdown_requested.load(.acquire)) return;

        const healthy = checkHealth(allocator, upstream, policy.health_check_path, policy.health_check_timeout_ms, callbacks) catch |err| switch (err) {
            error.Canceled => return,
            error.OutOfMemory, error.BackendCapacity => continue,
            else => false,
        };
        const transition = recordActiveHealthResult(upstream, healthy, callbacks.upstream_now_ms(), cooldown_ms, policy.slow_start_ms);
        recordActiveHealthMetrics(transition, healthy, callbacks);
    }
}

const HealthSchedule = struct {
    generation: u64 = 0,
    cursor: usize = 0,
    deadlines: std.ArrayList(i64) = .empty,

    fn begin(self: *HealthSchedule, generation: u64) void {
        if (self.generation != generation) {
            self.deadlines.clearRetainingCapacity();
            self.generation = generation;
        }
        self.cursor = 0;
    }

    fn due(self: *HealthSchedule, allocator: std.mem.Allocator, now_ms: i64, interval_ms: u32) !bool {
        const index = self.cursor;
        self.cursor += 1;
        if (index == self.deadlines.items.len) try self.deadlines.append(allocator, 0);
        if (now_ms < self.deadlines.items[index]) return false;
        self.deadlines.items[index] = now_ms +| @as(i64, @intCast(@max(interval_ms, 1)));
        return true;
    }

    fn visit(self: *HealthSchedule, allocator: std.mem.Allocator, pool: *UpstreamPoolConfig, policy: UpstreamRuntimePolicy, callbacks: Callbacks) !void {
        if (!policy.health_check_enabled) return;
        if (try self.due(allocator, callbacks.upstream_now_ms(), policy.health_check_interval_ms)) {
            runHealthCheckForPool(allocator, pool, policy, callbacks);
        }
    }

    fn delay(self: *const HealthSchedule, now_ms: i64) u32 {
        var result: i64 = 250;
        for (self.deadlines.items) |at| result = @min(result, @max(1, at -| now_ms));
        return @intCast(result);
    }
};

fn runHealthCheckCycle(schedule: *HealthSchedule, allocator: std.mem.Allocator, cfg: *ServerConfig, callbacks: Callbacks) !u32 {
    schedule.begin(cfg.cache_generation);
    if (cfg.upstream) |*pool| {
        try schedule.visit(allocator, pool, config_mod.upstreamRuntimePolicyFor(cfg, null, null), callbacks);
    }
    for (cfg.routes.items) |*route| {
        if (route.upstream) |*pool| {
            try schedule.visit(allocator, pool, config_mod.upstreamRuntimePolicyFor(cfg, null, route), callbacks);
        }
    }
    for (cfg.domains.items) |*domain| {
        if (domain.upstream) |*pool| {
            try schedule.visit(allocator, pool, config_mod.upstreamRuntimePolicyFor(cfg, domain, null), callbacks);
        }
        for (domain.routes.items) |*route| {
            if (route.upstream) |*pool| {
                try schedule.visit(allocator, pool, config_mod.upstreamRuntimePolicyFor(cfg, domain, route), callbacks);
            }
        }
    }
    return schedule.delay(callbacks.upstream_now_ms());
}

fn sleepHealthInterval(io: std.Io, interval_ms: u32, callbacks: Callbacks) void {
    var remaining = interval_ms;
    while (remaining > 0 and !callbacks.shutdown_requested.load(.acquire)) {
        const chunk = @min(remaining, 250);
        io.sleep(.fromMilliseconds(chunk), .awake) catch {};
        remaining -= chunk;
    }
}

pub fn healthCheckTask(ctx: HealthCheckContext) void {
    ctx.callbacks.bind_thread_io(ctx.io);
    var schedule = HealthSchedule{};
    defer schedule.deadlines.deinit(std.heap.page_allocator);
    while (!ctx.callbacks.shutdown_requested.load(.acquire)) {
        const delay: u32 = cycle: {
            var lease = ctx.acquire_config();
            defer lease.deinit();
            break :cycle runHealthCheckCycle(&schedule, std.heap.page_allocator, lease.cfg, ctx.callbacks) catch 250;
        };
        sleepHealthInterval(ctx.io, delay, ctx.callbacks);
    }
}

test "health schedules honor each pool interval and reset after reload" {
    var schedule = HealthSchedule{};
    defer schedule.deadlines.deinit(std.testing.allocator);
    schedule.begin(1);
    try std.testing.expect(try schedule.due(std.testing.allocator, 100, 100));
    try std.testing.expect(try schedule.due(std.testing.allocator, 100, 1000));
    schedule.begin(1);
    try std.testing.expect(try schedule.due(std.testing.allocator, 200, 100));
    try std.testing.expect(!try schedule.due(std.testing.allocator, 200, 1000));
    try std.testing.expectEqual(100, schedule.delay(200));
    schedule.begin(2);
    try std.testing.expect(try schedule.due(std.testing.allocator, 200, 100));
    try std.testing.expect(try schedule.due(std.testing.allocator, 200, 1000));
}

pub fn forwardToPool(
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    pool: *UpstreamPoolConfig,
    policy: UpstreamPoolPolicy,
    runtime_policy: UpstreamRuntimePolicy,
    req: HttpRequest,
    cfg: *const ServerConfig,
    callbacks: Callbacks,
) !void {
    const is_head = std.mem.eql(u8, req.method, "HEAD");
    if (pool.targets.items.len == 0) {
        try callbacks.send_cool_error(stream, allocator, 502, "Bad Gateway", "Proxy upstream pool is empty.", true, is_head, null);
        return;
    }

    const attempt_limit = upstream_mod.upstreamAttemptLimit(pool, upstream_mod.requestRetryBudget(req.method, runtime_policy.retries));
    const now_ms = callbacks.upstream_now_ms();
    const start_ticket = upstream_mod.upstreamStartTicket(pool, policy, now_ms, request_mod.upstreamHashInput(req), &runtime_policy);
    var considered: usize = 0;
    var attempts: usize = 0;
    var skipped_ejected: usize = 0;
    var last_error: ?anyerror = null;

    attempt_loop: while (considered < pool.targets.items.len and attempts < attempt_limit) : (considered += 1) {
        const upstream_index = upstream_mod.upstreamAttemptIndex(pool, start_ticket, considered);
        const upstream = &pool.targets.items[upstream_index];
        const lease = upstream_mod.upstreamBeginAttempt(upstream, now_ms, &runtime_policy) orelse {
            skipped_ejected += 1;
            callbacks.metrics.upstreamEjectedSkip();
            continue :attempt_loop;
        };
        defer upstream_mod.upstreamEndAttempt(upstream, lease);

        if (attempts > 0) callbacks.metrics.upstreamRetried();
        attempts += 1;
        callbacks.metrics.upstreamRequestStarted();
        const upstream_label = try std.fmt.allocPrint(
            allocator,
            "{s}://{s}:{d}{s}",
            .{ if (upstream.https) "https" else "http", upstream.host, upstream.port, upstream.base_path },
        );
        callbacks.access_log_set_upstream(upstream_label);
        const sticky_cookie = if (policy == .sticky_cookie)
            try upstream_mod.stickyCookieHeader(allocator, upstream_index)
        else
            null;
        defer if (sticky_cookie) |header| allocator.free(header);

        forwardToUpstream(stream, allocator, upstream, req, cfg, runtime_policy.timeout_ms, sticky_cookie, callbacks) catch |err| switch (err) {
            error.BackendCapacity => {
                try callbacks.send_cool_error(stream, allocator, 503, "Service Unavailable", "Local backend connection capacity is exhausted.", true, is_head, null);
                return;
            },
            error.DownstreamClosed => {
                return error.CloseConnection;
            },
            error.ResponseAborted => {
                callbacks.metrics.upstreamRequestFailed();
                if (upstream_mod.upstreamRecordFailure(upstream, callbacks.upstream_now_ms(), runtime_policy.max_failures, runtime_policy.fail_timeout_ms)) callbacks.metrics.upstreamEjected();
                return error.CloseConnection;
            },
            error.CloseConnection => {
                upstream_mod.upstreamRecordSuccess(upstream, callbacks.upstream_now_ms(), runtime_policy.slow_start_ms);
                return err;
            },
            error.OutOfMemory, error.Canceled => {
                return err;
            },
            else => {
                last_error = err;
                callbacks.metrics.upstreamRequestFailed();
                if (upstream_mod.upstreamRecordFailure(upstream, callbacks.upstream_now_ms(), runtime_policy.max_failures, runtime_policy.fail_timeout_ms)) {
                    callbacks.metrics.upstreamEjected();
                }
                continue :attempt_loop;
            },
        };
        upstream_mod.upstreamRecordSuccess(upstream, callbacks.upstream_now_ms(), runtime_policy.slow_start_ms);
        return;
    }

    if (attempts == 0 and skipped_ejected > 0) {
        try callbacks.send_cool_error(stream, allocator, 503, "Service Unavailable", "All configured upstream targets are unavailable or limited by circuit breaker recovery.", true, is_head, null);
        return;
    }

    if (last_error) |err| switch (err) {
        error.RequestTimeout => {
            try callbacks.send_cool_error(stream, allocator, 504, "Gateway Timeout", "All configured upstream attempts timed out.", true, is_head, null);
            return;
        },
        error.UnsupportedUpstreamScheme => {
            try callbacks.send_cool_error(stream, allocator, 501, "Not Implemented", "HTTPS upstream is not yet supported in this single-file server path. Use HTTPS reverse proxy in front of this binary.", true, is_head, null);
            return;
        },
        else => {},
    };

    try callbacks.send_cool_error(stream, allocator, 502, "Bad Gateway", "All configured upstream attempts failed.", true, is_head, null);
}

test "response read timeout attribution follows deadline ordering including coarse socket wakeups" {
    const now = std.Io.Timestamp.fromNanoseconds(0);
    const response = read_deadline.Deadline.after(now, 350);
    const backend = read_deadline.Deadline.after(now, 2000);
    try std.testing.expect(!response.expired(.fromNanoseconds(349_000_000)));
    try std.testing.expect(responseDeadlineOwnsTimeout(response, backend));
    try std.testing.expect(!responseDeadlineOwnsTimeout(backend, response));
    try std.testing.expect(responseDeadlineOwnsTimeout(response, response));
    try std.testing.expect(responseDeadlineOwnsTimeout(response, .{}));
    try std.testing.expect(!responseDeadlineOwnsTimeout(.{}, backend));
    try std.testing.expect(!responseDeadlineOwnsTimeout(.{}, .{}));
}

test "local dial pressure and cancellation never retry or eject healthy upstreams" {
    const Fake = struct {
        var failure: anyerror = error.BackendCapacity;
        var connects: usize = 0;
        var status: u16 = 0;
        var shutdown: std.atomic.Value(bool) = .init(false);
        fn io() std.Io {
            return std.testing.io;
        }
        fn bind(_: std.Io) void {}
        fn connect(_: std.mem.Allocator, _: []const u8, _: u16) !std.Io.net.Stream {
            connects += 1;
            return failure;
        }
        fn label(_: []const u8) void {}
        fn requestId() []const u8 {
            return "";
        }
        fn errorPage(_: std.Io.net.Stream, _: std.mem.Allocator, code: u16, _: []const u8, _: []const u8, _: bool, _: bool, _: ?[]const u8) !void {
            status = code;
        }
        fn headers(_: std.Io.net.Stream, _: u16, _: []const u8, _: []const u8, _: usize, _: bool, _: ?[]const u8) !void {
            return error.UnexpectedHeaders;
        }
        fn tunnel(_: std.Io.net.Stream, _: std.Io.net.Stream, _: []const u8) !void {
            return error.UnexpectedTunnel;
        }
        fn timeout(_: std.Io.net.Stream, _: u32, _: u32) !void {}
        fn close(_: std.Io.net.Stream) void {}
        fn read(_: std.Io.net.Stream, _: []u8) !usize {
            return error.UnexpectedRead;
        }
        fn write(_: std.Io.net.Stream, _: []const u8) !void {
            return error.UnexpectedWrite;
        }
        fn responseHeaders(_: std.Io.net.Stream) !void {
            return error.UnexpectedHeaders;
        }
        fn now() i64 {
            return 1000;
        }
    };
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var cfg = config_mod.defaultServerConfig();
    cfg.upstream_max_failures = 1;
    cfg.upstream_health_check_enabled = true;
    var pool = try config_mod.parseUpstreamPool(allocator, "http://127.0.0.1:9000,http://127.0.0.1:9001");
    var metrics = metrics_mod.ServerMetrics.init();
    const callbacks: Callbacks = .{
        .send_response_no_body_headers = Fake.headers,
        .access_log_set_upstream = Fake.label,
        .active_io = Fake.io,
        .bind_thread_io = Fake.bind,
        .connect_tcp_host = Fake.connect,
        .current_request_id = Fake.requestId,
        .metrics = &metrics,
        .proxy_raw_bidirectional = Fake.tunnel,
        .send_cool_error = Fake.errorPage,
        .set_stream_timeouts = Fake.timeout,
        .shutdown_requested = &Fake.shutdown,
        .stream_close = Fake.close,
        .stream_read = Fake.read,
        .stream_write_all = Fake.write,
        .upstream_now_ms = Fake.now,
        .write_response_headers = Fake.responseHeaders,
    };
    const stream = std.Io.net.Stream{ .socket = .{ .handle = 123, .address = undefined } };
    const req: HttpRequest = .{ .method = "GET", .path = "/", .query = "", .headers = "Host: local", .body = "", .version = "HTTP/1.1", .close_connection = true };
    const policy = config_mod.upstreamRuntimePolicyFromConfig(&cfg);
    for ([_]anyerror{ error.BackendCapacity, error.OutOfMemory, error.Canceled }) |err| {
        Fake.failure = err;
        Fake.connects = 0;
        Fake.status = 0;
        if (err == error.BackendCapacity) {
            try forwardToPool(stream, allocator, &pool, .round_robin, policy, req, &cfg, callbacks);
            try std.testing.expectEqual(503, Fake.status);
        } else {
            try std.testing.expectError(err, forwardToPool(stream, allocator, &pool, .round_robin, policy, req, &cfg, callbacks));
        }
        try std.testing.expectEqual(1, Fake.connects);
        runHealthCheckForPool(allocator, &pool, policy, callbacks);
        for (pool.targets.items) |target| {
            try std.testing.expectEqual(0, target.active_requests.load(.acquire));
            try std.testing.expectEqual(0, target.passive_failures.load(.acquire));
            try std.testing.expectEqual(0, target.ejected_until_ms.load(.acquire));
        }
    }
    try std.testing.expectEqual(0, metrics.upstream_failures_total.load(.acquire));
    try std.testing.expectEqual(0, metrics.upstream_health_check_failures_total.load(.acquire));
}
