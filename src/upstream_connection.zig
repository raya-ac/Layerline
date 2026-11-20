const std = @import("std");
const config = @import("config.zig");
const budget = @import("resource_budget.zig");
const runtime = @import("stream_runtime.zig");
const deadline = @import("backend_deadline.zig");
const idle_socket = @import("upstream_idle.zig");
const tls = @import("upstream_tls.zig");

pub const Lease = struct {
    stream: std.Io.net.Stream,
    tls_channel: ?*tls.Channel = null,
    requests_served: usize = 0,

    pub fn close(self: Lease, callbacks: anytype) void {
        if (self.tls_channel) |channel| channel.destroy();
        callbacks.stream_close(self.stream);
        callbacks.metrics.upstreamConnectionDiscarded();
    }

    pub fn end(self: Lease) void {
        if (self.tls_channel) |channel| channel.end() catch {};
    }
};

pub fn keepaliveConfigured(cfg: *const config.ServerConfig) bool {
    return cfg.upstream_keepalive_enabled and cfg.upstream_keepalive_max_idle > 0;
}

fn quiet(channel: ?*tls.Channel, target: *const config.UpstreamConfig) bool {
    return if (channel) |value| value.quiet() else !target.https;
}

fn fromIdle(conn: config.UpstreamIdleConnection) Lease {
    return .{ .stream = conn.stream, .tls_channel = conn.tls_channel, .requests_served = conn.requests_served };
}

pub fn acquire(allocator: std.mem.Allocator, target: *config.UpstreamConfig, cfg: *const config.ServerConfig, timeout_ms: u32, callbacks: anytype) !Lease {
    if (keepaliveConfigured(cfg)) {
        const io = callbacks.active_io();
        const now_ms = callbacks.upstream_now_ms();
        const pool = &target.keepalive_pool;
        pool.mutex.lockUncancelable(io);
        defer pool.mutex.unlock(io);

        while (pool.idle.pop()) |conn| {
            const lease = fromIdle(conn);
            if (conn.expires_at_ms <= now_ms or conn.requests_served >= cfg.upstream_keepalive_max_requests or
                !quiet(conn.tls_channel, target) or !idle_socket.reusable(conn.stream))
            {
                lease.close(callbacks);
                continue;
            }
            callbacks.metrics.upstreamConnectionReused();
            return lease;
        }
    }
    return open(allocator, target, timeout_ms, callbacks);
}

pub fn release(target: *config.UpstreamConfig, cfg: *const config.ServerConfig, lease: Lease, reusable: bool, callbacks: anytype) void {
    const served = lease.requests_served + 1;
    if (!reusable or !keepaliveConfigured(cfg) or served >= cfg.upstream_keepalive_max_requests or !quiet(lease.tls_channel, target)) {
        lease.end();
        lease.close(callbacks);
        return;
    }

    const io = callbacks.active_io();
    const pool = &target.keepalive_pool;
    pool.mutex.lockUncancelable(io);
    defer pool.mutex.unlock(io);

    while (pool.idle.items.len >= cfg.upstream_keepalive_max_idle) {
        fromIdle(pool.idle.orderedRemove(0)).close(callbacks);
    }
    pool.idle.append(budget.allocator(), .{
        .stream = lease.stream,
        .tls_channel = lease.tls_channel,
        .expires_at_ms = callbacks.upstream_now_ms() + @as(i64, cfg.upstream_keepalive_idle_timeout_ms),
        .requests_served = served,
    }) catch {
        lease.close(callbacks);
        return;
    };
    callbacks.metrics.upstreamConnectionPooled();
}

// Dial, authentication and HTTP I/O all retain the caller's original attempt
// budget. The TLS state outlives a request arena when the lease enters a pool.
pub fn open(allocator: std.mem.Allocator, target: *const config.UpstreamConfig, timeout_ms: u32, callbacks: anytype) !Lease {
    const stream = try callbacks.connect_tcp_host(allocator, target.host, target.port);
    callbacks.metrics.upstreamConnectionOpened();
    errdefer {
        callbacks.stream_close(stream);
        callbacks.metrics.upstreamConnectionDiscarded();
    }
    try deadline.attach(stream);
    try callbacks.set_stream_timeouts(stream, timeout_ms, timeout_ms);
    const channel = if (target.https) blk: {
        const roots = target.tls_trust orelse return error.UpstreamTrustUnavailable;
        break :blk tls.Channel.create(budget.allocator(), callbacks.active_io(), stream, target.tls_server_name orelse target.host, roots.anchors, runtime.rawStreamRead, runtime.rawStreamWriteAll, deadline.checkReadCompletion) catch |err| {
            if (!@import("builtin").is_test) std.debug.print("{{\"event\":\"server.upstream_tls_failure\",\"error\":\"{s}\"}}\n", .{@errorName(err)});
            return err;
        };
    } else null;
    return .{ .stream = stream, .tls_channel = channel };
}
