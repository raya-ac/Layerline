const std = @import("std");

const native_tls = @import("native_tls_runtime.zig");

pub const Callbacks = struct {
    active_io: *const fn () std.Io,
    bind_thread_io: *const fn (std.Io) void,
    clear_tls_channel: *const fn () void,
    current_tls_channel: *const fn () ?*native_tls.Channel,
    set_tls_channel: *const fn (?*native_tls.Channel) void,
    stream_read: *const fn (std.Io.net.Stream, []u8) anyerror!usize,
    stream_write_all: *const fn (std.Io.net.Stream, []const u8) anyerror!void,
};

const StreamContext = struct {
    io: std.Io,
    src: std.Io.net.Stream,
    dst: std.Io.net.Stream,
    tls_channel: ?*native_tls.Channel = null,
    callbacks: Callbacks,
};

fn proxyStream(ctx: StreamContext) void {
    ctx.callbacks.bind_thread_io(ctx.io);
    ctx.callbacks.set_tls_channel(ctx.tls_channel);
    defer ctx.callbacks.clear_tls_channel();

    var buf: [4096]u8 = undefined;
    while (true) {
        const n = ctx.callbacks.stream_read(ctx.src, &buf) catch break;
        if (n == 0) break;
        ctx.callbacks.stream_write_all(ctx.dst, buf[0..n]) catch break;
    }
    ctx.dst.shutdown(ctx.callbacks.active_io(), .send) catch {};
}

pub fn proxyBidirectional(a: std.Io.net.Stream, b: std.Io.net.Stream, initial_payload: []const u8, callbacks: Callbacks) !void {
    if (initial_payload.len > 0) {
        try callbacks.stream_write_all(b, initial_payload);
    }

    const io = callbacks.active_io();
    const tls_channel = callbacks.current_tls_channel();
    const t1 = try std.Thread.spawn(
        .{},
        proxyStream,
        .{StreamContext{ .io = io, .src = a, .dst = b, .tls_channel = tls_channel, .callbacks = callbacks }},
    );
    const t2 = try std.Thread.spawn(
        .{},
        proxyStream,
        .{StreamContext{ .io = io, .src = b, .dst = a, .tls_channel = tls_channel, .callbacks = callbacks }},
    );
    t1.join();
    t2.join();
}
