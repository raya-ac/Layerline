const std = @import("std");
const config = @import("config.zig");
const budget = @import("resource_budget.zig");
const runtime = @import("stream_runtime.zig");
const deadline = @import("backend_deadline.zig");
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
