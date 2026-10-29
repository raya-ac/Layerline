const std = @import("std");
const Deadline = @import("read_deadline.zig").Deadline;

pub const State = struct {
    io: std.Io,
    deadline: Deadline,
    timeout_ms: u32,
    handle: ?std.Io.net.Socket.Handle = null,

    pub fn remaining(self: State) !?u32 {
        return self.deadline.remaining(.now(self.io, .awake));
    }
};

threadlocal var active: ?State = null;

pub fn push(io: std.Io, timeout_ms: u32) ?State {
    const previous = active;
    active = .{ .io = io, .deadline = .after(.now(io, .awake), timeout_ms), .timeout_ms = timeout_ms };
    return previous;
}

pub fn restore(previous: ?State) void {
    active = previous;
}

pub fn attach(stream: std.Io.net.Stream) !void {
    if (active) |*state| {
        _ = try state.remaining();
        state.handle = stream.socket.handle;
    }
}

pub fn forStream(stream: std.Io.net.Stream) ?State {
    const state = active orelse return null;
    return if (state.handle == stream.socket.handle) state else null;
}

pub fn clear(stream: std.Io.net.Stream) void {
    if (forStream(stream) != null) active = null;
}

pub fn logTimeout(phase: []const u8) void {
    if (@import("builtin").is_test) return;
    std.debug.print("{{\"event\":\"server.backend_timeout\",\"phase\":\"{s}\"}}\n", .{phase});
}

// ConnectOptions.timeout is not implemented by Zig's threaded IO yet. Race the
// whole dial (including lookup) and join it before any borrowed inputs go away.
pub fn connect(io: std.Io, comptime dial: anytype, args: std.meta.ArgsTuple(@TypeOf(dial))) !std.Io.net.Stream {
    const state = active orelse return @call(.auto, dial, args);
    _ = try state.remaining();
    const at = state.deadline.at orelse return @call(.auto, dial, args);
    return connectUntil(io, at, dial, args) catch |err| switch (err) {
        error.RequestTimeout, error.Timeout, error.TimedOut, error.ConnectionTimedOut => {
            logTimeout("connect");
            return error.RequestTimeout;
        },
        else => return err,
    };
}

fn connectUntil(io: std.Io, at: std.Io.Timestamp, comptime dial: anytype, args: std.meta.ArgsTuple(@TypeOf(dial))) !std.Io.net.Stream {
    const Completion = union(enum) { connected: anyerror!std.Io.net.Stream, timer: std.Io.Cancelable!void };
    var buffer: [2]Completion = undefined;
    var select = std.Io.Select(Completion).init(io, &buffer);
    defer while (select.cancel()) |completion| switch (completion) {
        .connected => |result| if (result) |stream| stream.close(io) else |_| {},
        .timer => {},
    };
    const Dial = struct {
        fn run(arguments: @TypeOf(args)) anyerror!std.Io.net.Stream {
            return @call(.auto, dial, arguments);
        }
    };
    try select.concurrent(.connected, Dial.run, .{args});
    try select.concurrent(.timer, std.Io.Clock.Timestamp.wait, .{ std.Io.Clock.Timestamp{ .raw = at, .clock = .awake }, io });
    switch (try select.await()) {
        .timer => |result| {
            try result;
            return error.RequestTimeout;
        },
        .connected => |result| {
            const stream = try result;
            errdefer stream.close(io);
            _ = try (Deadline{ .at = at }).remaining(.now(io, .awake));
            return stream;
        },
    }
}

test "backend budgets keep their original deadline and match only their socket" {
    const stream = std.Io.net.Stream{ .socket = .{ .handle = 123, .address = undefined } };
    const other = std.Io.net.Stream{ .socket = .{ .handle = 124, .address = undefined } };
    const previous = push(std.testing.io, 1000);
    defer restore(previous);
    const original = active.?.deadline;
    try attach(stream);
    try std.testing.expect(forStream(other) == null);
    try std.testing.expectEqual(original.at, forStream(stream).?.deadline.at);
    const outer = push(std.testing.io, 0);
    try attach(other);
    try std.testing.expect(try forStream(other).?.remaining() == null);
    restore(outer);
    try std.testing.expectEqual(original.at, forStream(stream).?.deadline.at);
    clear(other);
    try std.testing.expect(forStream(stream) != null);
    clear(stream);
    try std.testing.expect(forStream(stream) == null);
}

test "dial timeout cancels and joins work before returning" {
    const Fake = struct {
        var stopped: std.atomic.Value(bool) = .init(false);
        fn dial(io: std.Io) !std.Io.net.Stream {
            defer stopped.store(true, .release);
            try io.sleep(.fromSeconds(30), .awake);
            return error.UnexpectedDialCompletion;
        }
    };
    Fake.stopped.store(false, .release);
    const previous = push(std.testing.io, 30);
    defer restore(previous);
    try std.testing.expectError(error.RequestTimeout, connect(std.testing.io, Fake.dial, .{std.testing.io}));
    try std.testing.expect(Fake.stopped.load(.acquire));
}

test "a connection completing after its deadline is closed, not leaked" {
    const Fake = struct {
        var closed: std.atomic.Value(usize) = .init(0);
        fn dial() anyerror!std.Io.net.Stream {
            return .{ .socket = .{ .handle = 123, .address = undefined } };
        }
        fn close(_: ?*anyopaque, handles: []const std.Io.net.Socket.Handle) void {
            std.debug.assert(handles.len == 1 and handles[0] == 123);
            _ = closed.fetchAdd(1, .acq_rel);
        }
    };
    Fake.closed.store(0, .release);
    var vtable = std.testing.io.vtable.*;
    vtable.netClose = Fake.close;
    var io = std.testing.io;
    io.vtable = &vtable;
    try std.testing.expectError(error.RequestTimeout, connectUntil(io, .zero, Fake.dial, .{}));
    try std.testing.expectEqual(1, Fake.closed.load(.acquire));
}

test "owner cancellation joins both dial and timer without becoming a timeout" {
    const Fake = struct {
        var entered: std.Io.Event = .unset;
        var stopped: std.atomic.Value(bool) = .init(false);
        fn dial(io: std.Io) !std.Io.net.Stream {
            defer stopped.store(true, .release);
            entered.set(io);
            try io.sleep(.fromSeconds(30), .awake);
            return error.UnexpectedDialCompletion;
        }
        fn run(io: std.Io) !void {
            const previous = push(io, 30_000);
            defer restore(previous);
            const stream = try connect(io, dial, .{io});
            stream.close(io);
        }
    };
    Fake.entered = .unset;
    Fake.stopped.store(false, .release);
    var task = try std.testing.io.concurrent(Fake.run, .{std.testing.io});
    defer task.cancel(std.testing.io) catch {};
    try Fake.entered.wait(std.testing.io);
    try std.testing.expectError(error.Canceled, task.cancel(std.testing.io));
    try std.testing.expect(Fake.stopped.load(.acquire));
}
