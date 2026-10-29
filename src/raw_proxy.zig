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
    try proxyWithSpawner(a, b, initial_payload, callbacks, spawnStream);
}

fn spawnStream(ctx: StreamContext) !std.Thread {
    return std.Thread.spawn(.{}, proxyStream, .{ctx});
}

fn proxyWithSpawner(a: std.Io.net.Stream, b: std.Io.net.Stream, initial_payload: []const u8, callbacks: Callbacks, spawn: *const fn (StreamContext) anyerror!std.Thread) !void {
    if (initial_payload.len > 0) {
        try callbacks.stream_write_all(b, initial_payload);
    }

    const io = callbacks.active_io();
    const tls_channel = callbacks.current_tls_channel();
    const t1 = try spawn(.{ .io = io, .src = a, .dst = b, .tls_channel = tls_channel, .callbacks = callbacks });
    errdefer {
        a.shutdown(io, .recv) catch {};
        b.shutdown(io, .send) catch {};
        t1.join();
    }
    const t2 = try spawn(.{ .io = io, .src = b, .dst = a, .tls_channel = tls_channel, .callbacks = callbacks });
    t1.join();
    t2.join();
}

test "second pump spawn failure interrupts and joins the first pump" {
    const fixture = struct {
        var io: std.Io = undefined;
        var spawns: usize = 0;
        var spawned = false;
        var stopped = std.atomic.Value(bool).init(false);
        var finished = std.atomic.Value(bool).init(false);

        fn activeIo() std.Io {
            return io;
        }
        fn bind(_: std.Io) void {}
        fn tls() ?*native_tls.Channel {
            return null;
        }
        fn setTls(_: ?*native_tls.Channel) void {}
        fn clearTls() void {
            finished.store(true, .release);
        }
        fn read(_: std.Io.net.Stream, _: []u8) !usize {
            while (!stopped.load(.acquire)) std.atomic.spinLoopHint();
            return 0;
        }
        fn write(_: std.Io.net.Stream, _: []const u8) !void {}
        fn shutdown(_: ?*anyopaque, _: std.Io.net.Socket.Handle, _: std.Io.net.ShutdownHow) std.Io.net.ShutdownError!void {
            stopped.store(true, .release);
        }
        fn spawn(ctx: StreamContext) !std.Thread {
            spawns += 1;
            if (spawns == 2) return error.InjectedSpawnFailure;
            const thread = try spawnStream(ctx);
            spawned = true;
            return thread;
        }
    };
    fixture.spawns = 0;
    fixture.spawned = false;
    fixture.stopped.store(false, .release);
    fixture.finished.store(false, .release);
    var vtable = std.testing.io.vtable.*;
    vtable.netShutdown = fixture.shutdown;
    fixture.io = .{ .userdata = std.testing.io.userdata, .vtable = &vtable };
    defer {
        fixture.stopped.store(true, .release);
        if (fixture.spawned) while (!fixture.finished.load(.acquire)) std.atomic.spinLoopHint();
    }
    const a = std.Io.net.Stream{ .socket = .{ .handle = 123, .address = undefined } };
    const b = std.Io.net.Stream{ .socket = .{ .handle = 124, .address = undefined } };
    try std.testing.expectError(error.InjectedSpawnFailure, proxyWithSpawner(a, b, "", .{
        .active_io = fixture.activeIo,
        .bind_thread_io = fixture.bind,
        .clear_tls_channel = fixture.clearTls,
        .current_tls_channel = fixture.tls,
        .set_tls_channel = fixture.setTls,
        .stream_read = fixture.read,
        .stream_write_all = fixture.write,
    }, fixture.spawn));
    try std.testing.expect(fixture.stopped.load(.acquire));
    try std.testing.expect(fixture.finished.load(.acquire));
}
