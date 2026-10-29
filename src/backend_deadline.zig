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

pub fn checkReadCompletion(stream: std.Io.net.Stream) !void {
    if (forStream(stream)) |state| {
        _ = state.remaining() catch |err| {
            logTimeout("read");
            return err;
        };
    }
}

// ConnectOptions.timeout is not implemented by Zig's threaded IO yet. Race the
// whole dial (including lookup) and join it before any borrowed inputs go away.
pub fn connect(io: std.Io, comptime dial: anytype, args: std.meta.ArgsTuple(@TypeOf(dial))) !std.Io.net.Stream {
    const at = if (active) |state| blk: {
        _ = try state.remaining();
        break :blk state.deadline.at;
    } else null;
    const result = if (at) |end| connectUntil(io, end, dial, args) else @call(.auto, dial, args);
    return result catch |err| switch (err) {
        error.BackendCapacity, error.SystemResources, error.ProcessFdQuotaExceeded, error.SystemFdQuotaExceeded => {
            if (!@import("builtin").is_test) std.debug.print("{{\"event\":\"server.backend_capacity\",\"phase\":\"connect\"}}\n", .{});
            return error.BackendCapacity;
        },
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
            return @call(.auto, dial, arguments) catch |err| {
                if (!@import("builtin").is_test and @import("builtin").os.tag == .macos and err == error.Unexpected) {
                    const cause = std.posix.errno(@as(c_int, -1));
                    std.debug.print("{{\"event\":\"server.connect_error\",\"error\":\"Unexpected\",\"errno_snapshot\":\"{s}\"}}\n", .{@tagName(cause)});
                }
                return err;
            };
        }
    };
    select.concurrent(.connected, Dial.run, .{args}) catch return error.BackendCapacity;
    select.concurrent(.timer, std.Io.Clock.Timestamp.wait, .{ std.Io.Clock.Timestamp{ .raw = at, .clock = .awake }, io }) catch return error.BackendCapacity;
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

test "late successful reads still fail the original backend budget" {
    const stream = std.Io.net.Stream{ .socket = .{ .handle = 123, .address = undefined } };
    const other = std.Io.net.Stream{ .socket = .{ .handle = 124, .address = undefined } };
    const previous = active;
    defer active = previous;
    active = .{ .io = std.testing.io, .deadline = .after(.zero, 1), .timeout_ms = 1, .handle = stream.socket.handle };
    try checkReadCompletion(other);
    try std.testing.expectError(error.RequestTimeout, checkReadCompletion(stream));
    active.?.deadline = .{};
    try checkReadCompletion(stream);
    active = null;
    try checkReadCompletion(stream);
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

test "failed dial or timer admission returns local capacity and closes late sockets" {
    const Fake = struct {
        var calls: usize = 0;
        var fail_at: usize = 0;
        var closed: std.atomic.Value(usize) = .init(0);
        fn dial() anyerror!std.Io.net.Stream {
            return .{ .socket = .{ .handle = 123, .address = undefined } };
        }
        fn close(_: ?*anyopaque, handles: []const std.Io.net.Socket.Handle) void {
            std.debug.assert(handles.len == 1 and handles[0] == 123);
            _ = closed.fetchAdd(1, .acq_rel);
        }
        fn start(userdata: ?*anyopaque, group: *std.Io.Group, context: []const u8, alignment: std.mem.Alignment, entry: *const fn (*const anyopaque) void) std.Io.ConcurrentError!void {
            calls += 1;
            if (calls == fail_at) return error.ConcurrencyUnavailable;
            return std.testing.io.vtable.groupConcurrent(userdata, group, context, alignment, entry);
        }
    };
    var vtable = std.testing.io.vtable.*;
    vtable.groupConcurrent = Fake.start;
    vtable.netClose = Fake.close;
    var io = std.testing.io;
    io.vtable = &vtable;
    for (1..3) |fail_at| {
        Fake.calls = 0;
        Fake.fail_at = fail_at;
        Fake.closed.store(0, .release);
        const previous = push(io, 1000);
        defer restore(previous);
        try std.testing.expectError(error.BackendCapacity, connect(io, Fake.dial, .{}));
        try std.testing.expectEqual(fail_at, Fake.calls);
        try std.testing.expectEqual(fail_at - 1, Fake.closed.load(.acquire));
    }
}

test "disabled deadlines still classify local descriptor exhaustion" {
    const Fake = struct {
        fn dial() !std.Io.net.Stream {
            return error.ProcessFdQuotaExceeded;
        }
    };
    const previous = push(std.testing.io, 0);
    defer restore(previous);
    try std.testing.expectError(error.BackendCapacity, connect(std.testing.io, Fake.dial, .{}));
}
