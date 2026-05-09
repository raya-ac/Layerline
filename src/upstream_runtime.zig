const std = @import("std");
const config_mod = @import("config.zig");
const http_headers = @import("http_headers.zig");
const metrics_mod = @import("metrics.zig");
const proxy_utils = @import("proxy_utils.zig");
const request_mod = @import("request.zig");
const upstream_mod = @import("upstream.zig");

const ChunkedBodyScanner = proxy_utils.ChunkedBodyScanner;
const HttpRequest = request_mod.HttpRequest;
const ServerConfig = config_mod.ServerConfig;
const UpstreamConfig = config_mod.UpstreamConfig;
const UpstreamIdleConnection = config_mod.UpstreamIdleConnection;
const UpstreamPoolConfig = config_mod.UpstreamPoolConfig;
const UpstreamPoolPolicy = config_mod.UpstreamPoolPolicy;
const UpstreamRuntimePolicy = config_mod.UpstreamRuntimePolicy;
const UpstreamResponseForwardResult = proxy_utils.UpstreamResponseForwardResult;

pub const Callbacks = struct {
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
    cfg: *ServerConfig,
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

fn acquireConnection(allocator: std.mem.Allocator, upstream: *UpstreamConfig, cfg: *const ServerConfig, now_ms: i64, callbacks: Callbacks) !UpstreamConnectionLease {
    if (keepaliveConfigured(cfg) and !upstream.https) {
        const io = callbacks.active_io();
        upstream.keepalive_pool.mutex.lockUncancelable(io);
        defer upstream.keepalive_pool.mutex.unlock(io);

        while (upstream.keepalive_pool.idle.pop()) |conn| {
            if (conn.expires_at_ms <= now_ms or conn.requests_served >= cfg.upstream_keepalive_max_requests) {
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

fn forwardFixedBody(stream: std.Io.net.Stream, upstream_conn: std.Io.net.Stream, body_tail: []const u8, content_length: usize, callbacks: Callbacks) !bool {
    const initial = @min(body_tail.len, content_length);
    if (initial > 0) callbacks.stream_write_all(stream, body_tail[0..initial]) catch return error.CloseConnection;
    if (body_tail.len > content_length) return false;

    var remaining = content_length - initial;
    var buf: [8192]u8 = undefined;
    while (remaining > 0) {
        const max_read = @min(remaining, buf.len);
        const n = try callbacks.stream_read(upstream_conn, buf[0..max_read]);
        if (n == 0) return error.BadGateway;
        remaining -= n;
        callbacks.stream_write_all(stream, buf[0..n]) catch return error.CloseConnection;
    }
    return true;
}

fn forwardChunkedBody(stream: std.Io.net.Stream, upstream_conn: std.Io.net.Stream, body_tail: []const u8, callbacks: Callbacks) !void {
    var scanner = ChunkedBodyScanner{};

    if (body_tail.len > 0) {
        var consumed: usize = 0;
        while (consumed < body_tail.len) : (consumed += 1) {
            if (try scanner.consume(body_tail[consumed])) {
                callbacks.stream_write_all(stream, body_tail[0 .. consumed + 1]) catch return error.CloseConnection;
                return;
            }
        }
        callbacks.stream_write_all(stream, body_tail) catch return error.CloseConnection;
    }

    var buf: [8192]u8 = undefined;
    while (true) {
        const n = try callbacks.stream_read(upstream_conn, &buf);
        if (n == 0) return error.BadGateway;

        var consumed: usize = 0;
        while (consumed < n) : (consumed += 1) {
            if (try scanner.consume(buf[consumed])) {
                callbacks.stream_write_all(stream, buf[0 .. consumed + 1]) catch return error.CloseConnection;
                return;
            }
        }
        callbacks.stream_write_all(stream, buf[0..n]) catch return error.CloseConnection;
    }
}

fn forwardUnknownLengthBody(stream: std.Io.net.Stream, upstream_conn: std.Io.net.Stream, body_tail: []const u8, callbacks: Callbacks) !void {
    if (body_tail.len > 0) callbacks.stream_write_all(stream, body_tail) catch return error.CloseConnection;

    var buf: [8192]u8 = undefined;
    while (true) {
        const n = try callbacks.stream_read(upstream_conn, &buf);
        if (n == 0) break;
        callbacks.stream_write_all(stream, buf[0..n]) catch return error.CloseConnection;
    }
}

fn forwardResponse(stream: std.Io.net.Stream, upstream_conn: std.Io.net.Stream, req: HttpRequest, sticky_cookie_header: ?[]const u8, callbacks: Callbacks) !UpstreamResponseForwardResult {
    var response_buffer: [16 * 1024]u8 = undefined;
    var used: usize = 0;

    // Buffer only the upstream headers so we can scrub hop-by-hop fields, then
    // stream the body straight through.
    while (used < response_buffer.len) {
        const n = try callbacks.stream_read(upstream_conn, response_buffer[used..]);
        if (n == 0) return error.BadGateway;
        used += n;
        if (std.mem.indexOf(u8, response_buffer[0..used], "\r\n\r\n") != null) break;
    }

    const header_end = (std.mem.indexOf(u8, response_buffer[0..used], "\r\n\r\n") orelse return error.BadGateway) + 4;
    const header_bytes = response_buffer[0..header_end];
    const body_tail = response_buffer[header_end..used];
    const status_line_end = std.mem.indexOf(u8, header_bytes, "\r\n") orelse return error.BadGateway;

    const headers_start = status_line_end + 2;
    const headers_end = header_end - 4;
    const response_headers = header_bytes[headers_start..headers_end];
    const framing = try proxy_utils.parseUpstreamResponseFraming(header_bytes, response_headers);

    callbacks.stream_write_all(stream, header_bytes[0..status_line_end]) catch return error.CloseConnection;
    callbacks.stream_write_all(stream, "\r\n") catch return error.CloseConnection;

    var headers = std.mem.splitSequence(u8, response_headers, "\r\n");
    while (headers.next()) |line| {
        const trimmed = http_headers.trimValue(line);
        if (trimmed.len == 0) continue;
        if (std.mem.indexOfScalar(u8, trimmed, ':')) |colon| {
            const name = http_headers.trimValue(trimmed[0..colon]);
            if (proxy_utils.isSkippedProxyResponseHeader(name)) continue;
        }
        callbacks.stream_write_all(stream, trimmed) catch return error.CloseConnection;
        callbacks.stream_write_all(stream, "\r\n") catch return error.CloseConnection;
    }

    if (sticky_cookie_header) |header| try callbacks.stream_write_all(stream, header);
    try callbacks.write_response_headers(stream);
    callbacks.stream_write_all(stream, "Connection: close\r\n\r\n") catch return error.CloseConnection;

    if (proxy_utils.responseHasNoBody(req.method, framing.status_code)) {
        return .{ .reusable = !framing.connection_close and body_tail.len == 0 };
    }
    if (framing.content_length) |content_length| {
        const completed = try forwardFixedBody(stream, upstream_conn, body_tail, content_length, callbacks);
        return .{ .reusable = completed and !framing.connection_close };
    }
    if (framing.transfer_chunked) {
        try forwardChunkedBody(stream, upstream_conn, body_tail, callbacks);
        return .{ .reusable = !framing.connection_close };
    }

    try forwardUnknownLengthBody(stream, upstream_conn, body_tail, callbacks);
    return .{ .reusable = false };
}

fn forwardUpgradeResponse(stream: std.Io.net.Stream, upstream_conn: std.Io.net.Stream, callbacks: Callbacks) !void {
    var response_buffer: [16 * 1024]u8 = undefined;
    var used: usize = 0;

    while (used < response_buffer.len) {
        const n = try callbacks.stream_read(upstream_conn, response_buffer[used..]);
        if (n == 0) return error.BadGateway;
        used += n;
        if (std.mem.indexOf(u8, response_buffer[0..used], "\r\n\r\n") != null) break;
    }

    const header_end = (std.mem.indexOf(u8, response_buffer[0..used], "\r\n\r\n") orelse return error.BadGateway) + 4;
    const header_bytes = response_buffer[0..header_end];
    const body_tail = response_buffer[header_end..used];
    const status_code = proxy_utils.parseHttpStatusCode(header_bytes) orelse return error.BadGateway;
    if (status_code != 101) return error.BadGateway;

    callbacks.stream_write_all(stream, header_bytes) catch return error.CloseConnection;
    try callbacks.proxy_raw_bidirectional(upstream_conn, stream, body_tail);
}

fn forwardToUpstream(stream: std.Io.net.Stream, allocator: std.mem.Allocator, upstream: *UpstreamConfig, req: HttpRequest, cfg: *const ServerConfig, timeout_ms: u32, sticky_cookie_header: ?[]const u8, callbacks: Callbacks) !void {
    if (upstream.https) {
        return error.UnsupportedUpstreamScheme;
    }

    const upgrade_request = proxy_utils.isHttpUpgradeHeaders(req.headers);
    const keepalive_enabled = keepaliveConfigured(cfg) and !upgrade_request;
    const lease = try acquireConnection(allocator, upstream, cfg, callbacks.upstream_now_ms(), callbacks);
    var lease_released = false;
    defer if (!lease_released) {
        callbacks.stream_close(lease.stream);
        callbacks.metrics.upstreamConnectionDiscarded();
    };
    try callbacks.set_stream_timeouts(lease.stream, timeout_ms, timeout_ms);

    const proxy_path = try proxy_utils.buildProxyPath(allocator, upstream.base_path, req.path, req.query);
    defer allocator.free(proxy_path);

    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);

    const forwarded_host = if (http_headers.findHeaderValue(req.headers, "Host")) |host|
        http_headers.trimValue(host)
    else
        upstream.host;
    const forwarded_proto = if (http_headers.findHeaderValue(req.headers, "X-Forwarded-Proto")) |proto|
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
            if (proxy_utils.isSkippedProxyHeader(name)) continue;
            const value = http_headers.trimValue(trimmed[colon + 1 ..]);
            if (value.len == 0) continue;
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
        try forwardUpgradeResponse(stream, lease.stream, callbacks);
        return error.CloseConnection;
    }

    const result = forwardResponse(stream, lease.stream, req, sticky_cookie_header, callbacks) catch |err| switch (err) {
        error.RequestTimeout => return err,
        else => |e| return e,
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

    const upstream_conn = try callbacks.connect_tcp_host(allocator, upstream.host, upstream.port);
    defer callbacks.stream_close(upstream_conn);
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

        const healthy = checkHealth(allocator, upstream, policy.health_check_path, policy.health_check_timeout_ms, callbacks) catch false;
        const transition = recordActiveHealthResult(upstream, healthy, callbacks.upstream_now_ms(), cooldown_ms, policy.slow_start_ms);
        recordActiveHealthMetrics(transition, healthy, callbacks);
    }
}

fn runHealthCheckCycle(allocator: std.mem.Allocator, cfg: *ServerConfig, callbacks: Callbacks) void {
    if (cfg.upstream) |*pool| {
        runHealthCheckForPool(allocator, pool, config_mod.upstreamRuntimePolicyFor(cfg, null, null), callbacks);
    }
    for (cfg.routes.items) |*route| {
        if (route.upstream) |*pool| {
            runHealthCheckForPool(allocator, pool, config_mod.upstreamRuntimePolicyFor(cfg, null, route), callbacks);
        }
    }
    for (cfg.domains.items) |*domain| {
        if (domain.upstream) |*pool| {
            runHealthCheckForPool(allocator, pool, config_mod.upstreamRuntimePolicyFor(cfg, domain, null), callbacks);
        }
        for (domain.routes.items) |*route| {
            if (route.upstream) |*pool| {
                runHealthCheckForPool(allocator, pool, config_mod.upstreamRuntimePolicyFor(cfg, domain, route), callbacks);
            }
        }
    }
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
    while (!ctx.callbacks.shutdown_requested.load(.acquire)) {
        runHealthCheckCycle(std.heap.page_allocator, ctx.cfg, ctx.callbacks);
        sleepHealthInterval(ctx.io, ctx.cfg.upstream_health_check_interval_ms, ctx.callbacks);
    }
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

    const attempt_limit = upstream_mod.upstreamAttemptLimit(pool, runtime_policy.retries);
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
            error.CloseConnection => {
                upstream_mod.upstreamEndAttempt(upstream, lease);
                upstream_mod.upstreamRecordSuccess(upstream, callbacks.upstream_now_ms(), runtime_policy.slow_start_ms);
                return err;
            },
            error.OutOfMemory => {
                upstream_mod.upstreamEndAttempt(upstream, lease);
                return err;
            },
            else => {
                upstream_mod.upstreamEndAttempt(upstream, lease);
                last_error = err;
                callbacks.metrics.upstreamRequestFailed();
                if (upstream_mod.upstreamRecordFailure(upstream, callbacks.upstream_now_ms(), runtime_policy.max_failures, runtime_policy.fail_timeout_ms)) {
                    callbacks.metrics.upstreamEjected();
                }
                continue :attempt_loop;
            },
        };
        upstream_mod.upstreamEndAttempt(upstream, lease);
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
