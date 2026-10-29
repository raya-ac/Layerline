const std = @import("std");
const builtin = @import("builtin");
const Deadline = @import("read_deadline.zig").Deadline;
const Direction = @import("socket_timeout.zig").Direction;

pub const Options = struct {
    timeout_ms: ?u32 = null,
    deadline: Deadline = .{},
};

const Result = struct { count: usize = 0, err: std.posix.E = .SUCCESS, events: i16 = 0 };

const Native = struct {
    fn receive(handle: std.Io.net.Socket.Handle, bytes: []u8) Result {
        const n = std.posix.system.recvfrom(handle, bytes.ptr, bytes.len, std.posix.MSG.DONTWAIT, null, null);
        const err = std.posix.errno(n);
        return .{ .err = err, .count = if (err == .SUCCESS) @intCast(n) else 0 };
    }

    fn send(handle: std.Io.net.Socket.Handle, bytes: []const u8) Result {
        const n = std.posix.system.sendto(handle, bytes.ptr, bytes.len, std.posix.MSG.DONTWAIT | std.posix.MSG.NOSIGNAL, null, 0);
        const err = std.posix.errno(n);
        return .{ .err = err, .count = if (err == .SUCCESS) @intCast(n) else 0 };
    }

    fn poll(handle: std.Io.net.Socket.Handle, event: i16, timeout_ms: i32) Result {
        var fd = std.posix.pollfd{ .fd = handle, .events = event, .revents = 0 };
        const n = std.posix.system.poll(@ptrCast(&fd), 1, timeout_ms);
        const err = std.posix.errno(n);
        return .{ .err = err, .count = if (err == .SUCCESS) @intCast(n) else 0, .events = fd.revents };
    }

    fn timeout(handle: std.Io.net.Socket.Handle, direction: Direction) !u32 {
        var value: std.posix.timeval = undefined;
        var size: std.posix.socklen_t = @sizeOf(@TypeOf(value));
        const option: u32 = if (direction == .read) std.posix.SO.RCVTIMEO else std.posix.SO.SNDTIMEO;
        while (true) {
            const result = std.posix.system.getsockopt(handle, std.posix.SOL.SOCKET, option, @ptrCast(&value), &size);
            switch (std.posix.errno(result)) {
                .SUCCESS => break,
                .INTR => continue,
                else => |err| return failure(err, direction),
            }
        }
        if (size != @sizeOf(@TypeOf(value)) or value.sec < 0 or value.usec < 0 or value.usec >= 1_000_000) return error.InvalidSocketTimeout;
        const seconds: u64 = @intCast(value.sec);
        if (seconds >= std.math.maxInt(u32) / 1000) return std.math.maxInt(u32);
        const ms = seconds * 1000 + (@as(u64, @intCast(value.usec)) + 999) / 1000;
        return @intCast(@min(ms, std.math.maxInt(u32)));
    }
};

fn failure(err: std.posix.E, direction: Direction) anyerror {
    return switch (err) {
        .BADF, .NOTSOCK, .NOTCONN, .INVAL => error.SocketClosed,
        .CONNRESET => error.ConnectionResetByPeer,
        .CONNABORTED => error.ConnectionAborted,
        .PIPE => error.BrokenPipe,
        .TIMEDOUT => error.RequestTimeout,
        .NOBUFS, .NOMEM => error.SystemResources,
        .NETDOWN => error.NetworkDown,
        else => blk: {
            if (!builtin.is_test) std.debug.print("{{\"event\":\"server.socket_io_error\",\"direction\":\"{s}\",\"errno\":\"{s}\"}}\n", .{ @tagName(direction), @tagName(err) });
            break :blk error.UnexpectedSocketIo;
        },
    };
}

const Wait = struct {
    io: std.Io,
    handle: std.Io.net.Socket.Handle,
    direction: Direction,
    deadline: Deadline,

    fn check(self: Wait) !void {
        try self.io.checkCancel();
        _ = try self.deadline.remaining(.now(self.io, .awake));
    }

    fn ready(self: Wait, comptime Ops: type) !void {
        while (true) {
            try self.check();
            const remaining = try self.deadline.remaining(.now(self.io, .awake));
            // Nonblocking syscalls never enter Threaded's private cancellation
            // region. Bound each wait so Group.cancel still joins promptly.
            const timeout_ms: i32 = @intCast(@min(remaining orelse 50, 50));
            const result = Ops.poll(self.handle, if (self.direction == .read) std.posix.POLL.IN else std.posix.POLL.OUT, timeout_ms);
            switch (result.err) {
                .SUCCESS => {},
                .INTR => continue,
                else => return failure(result.err, self.direction),
            }
            if (result.events & std.posix.POLL.NVAL != 0) return error.SocketClosed;
            if (result.count != 0) return;
        }
    }
};

fn readWith(io: std.Io, stream: std.Io.net.Stream, bytes: []u8, options: Options, comptime Ops: type) !usize {
    if (bytes.len == 0) return 0;
    const ms = options.timeout_ms orelse try Ops.timeout(stream.socket.handle, .read);
    const wait: Wait = .{ .io = io, .handle = stream.socket.handle, .direction = .read, .deadline = .earliest(.after(.now(io, .awake), ms), options.deadline) };
    while (true) {
        try wait.check();
        const result = Ops.receive(stream.socket.handle, bytes);
        switch (result.err) {
            .SUCCESS => return result.count,
            .INTR => continue,
            .AGAIN => try wait.ready(Ops),
            else => return failure(result.err, .read),
        }
    }
}

fn writeWith(io: std.Io, stream: std.Io.net.Stream, bytes: []const u8, options: Options, comptime Ops: type) !usize {
    if (bytes.len == 0) return 0;
    const ms = options.timeout_ms orelse try Ops.timeout(stream.socket.handle, .write);
    const wait: Wait = .{ .io = io, .handle = stream.socket.handle, .direction = .write, .deadline = .earliest(.after(.now(io, .awake), ms), options.deadline) };
    while (true) {
        try wait.check();
        const result = Ops.send(stream.socket.handle, bytes);
        switch (result.err) {
            .SUCCESS => return result.count,
            .INTR => continue,
            .AGAIN => try wait.ready(Ops),
            else => return failure(result.err, .write),
        }
    }
}

pub fn read(io: std.Io, stream: std.Io.net.Stream, bytes: []u8, options: Options) !usize {
    if (builtin.os.tag == .windows) {
        var data = [_][]u8{bytes};
        return io.vtable.netRead(io.userdata, stream.socket.handle, &data);
    }
    return readWith(io, stream, bytes, options, Native);
}

pub fn write(io: std.Io, stream: std.Io.net.Stream, bytes: []const u8, options: Options) !usize {
    if (builtin.os.tag == .windows) {
        const empty = [_][]const u8{""};
        return io.vtable.netWrite(io.userdata, stream.socket.handle, bytes, &empty, 0);
    }
    return writeWith(io, stream, bytes, options, Native);
}

test "nonblocking socket IO retries EAGAIN and interruption without renewing its deadline" {
    const Fake = struct {
        var attempts: usize = 0;
        var polls: usize = 0;
        fn timeout(_: std.Io.net.Socket.Handle, _: Direction) !u32 {
            return 100;
        }
        fn receive(_: std.Io.net.Socket.Handle, _: []u8) Result {
            attempts += 1;
            return switch (attempts) {
                1 => .{ .err = .INTR },
                2 => .{ .err = .AGAIN },
                else => .{ .count = 3 },
            };
        }
        fn send(handle: std.Io.net.Socket.Handle, _: []const u8) Result {
            var bytes: [1]u8 = undefined;
            return receive(handle, &bytes);
        }
        fn poll(_: std.Io.net.Socket.Handle, _: i16, ms: i32) Result {
            std.debug.assert(ms > 0 and ms <= 50);
            polls += 1;
            return if (polls == 1) .{ .err = .INTR } else .{ .count = 1 };
        }
    };
    const stream = std.Io.net.Stream{ .socket = .{ .handle = 123, .address = undefined } };
    var buffer: [8]u8 = undefined;
    for ([_]Direction{ .read, .write }) |direction| {
        Fake.attempts = 0;
        Fake.polls = 0;
        const n = if (direction == .read) try readWith(std.testing.io, stream, &buffer, .{}, Fake) else try writeWith(std.testing.io, stream, &buffer, .{}, Fake);
        try std.testing.expectEqual(3, n);
        try std.testing.expectEqual(3, Fake.attempts);
        try std.testing.expectEqual(2, Fake.polls);
    }
}

test "socket waits observe IO cancellation without waiting for a long socket timeout" {
    const Fake = struct {
        var entered: std.Io.Event = .unset;
        var stopped: std.atomic.Value(bool) = .init(false);
        fn timeout(_: std.Io.net.Socket.Handle, _: Direction) !u32 {
            return 30_000;
        }
        fn receive(_: std.Io.net.Socket.Handle, _: []u8) Result {
            return .{ .err = .AGAIN };
        }
        fn send(_: std.Io.net.Socket.Handle, _: []const u8) Result {
            return .{ .err = .AGAIN };
        }
        fn poll(_: std.Io.net.Socket.Handle, _: i16, _: i32) Result {
            entered.set(std.testing.io);
            return .{};
        }
        fn run(direction: Direction) !usize {
            defer stopped.store(true, .release);
            var bytes: [1]u8 = undefined;
            const stream = std.Io.net.Stream{ .socket = .{ .handle = 123, .address = undefined } };
            return if (direction == .read) readWith(std.testing.io, stream, &bytes, .{}, @This()) else writeWith(std.testing.io, stream, &bytes, .{}, @This());
        }
    };
    for ([_]Direction{ .read, .write }) |direction| {
        Fake.entered = .unset;
        Fake.stopped.store(false, .release);
        var task = try std.testing.io.concurrent(Fake.run, .{direction});
        defer _ = task.cancel(std.testing.io) catch {};
        try Fake.entered.wait(std.testing.io);
        try std.testing.expectError(error.Canceled, task.cancel(std.testing.io));
        try std.testing.expect(Fake.stopped.load(.acquire));
    }
}

test "repeated ready misses and EINTR consume one absolute socket wait budget" {
    const Fake = struct {
        var elapsed: i96 = 0;
        var polls: usize = 0;
        var attempts: usize = 0;
        var interrupted: bool = false;
        fn now(_: ?*anyopaque, _: std.Io.Clock) std.Io.Timestamp {
            return .fromNanoseconds(elapsed);
        }
        fn timeout(_: std.Io.net.Socket.Handle, _: Direction) !u32 {
            return 100;
        }
        fn receive(_: std.Io.net.Socket.Handle, _: []u8) Result {
            attempts += 1;
            return .{ .err = .AGAIN };
        }
        fn send(_: std.Io.net.Socket.Handle, _: []const u8) Result {
            attempts += 1;
            return .{ .err = .AGAIN };
        }
        fn poll(_: std.Io.net.Socket.Handle, _: i16, ms: i32) Result {
            elapsed += @as(i96, ms) * std.time.ns_per_ms;
            polls += 1;
            return if (interrupted) .{ .err = .INTR } else .{};
        }
    };
    var vtable = std.testing.io.vtable.*;
    vtable.now = Fake.now;
    const io: std.Io = .{ .userdata = std.testing.io.userdata, .vtable = &vtable };
    const stream = std.Io.net.Stream{ .socket = .{ .handle = 123, .address = undefined } };
    var bytes: [1]u8 = undefined;
    for ([_]Direction{ .read, .write }) |direction| {
        for ([_]bool{ false, true }) |interrupted| {
            Fake.elapsed = 0;
            Fake.polls = 0;
            Fake.attempts = 0;
            Fake.interrupted = interrupted;
            if (direction == .read) {
                try std.testing.expectError(error.RequestTimeout, readWith(io, stream, &bytes, .{}, Fake));
            } else {
                try std.testing.expectError(error.RequestTimeout, writeWith(io, stream, &bytes, .{}, Fake));
            }
            try std.testing.expectEqual(2, Fake.polls);
            try std.testing.expectEqual(100 * std.time.ns_per_ms, Fake.elapsed);
        }
        Fake.elapsed = 50 * std.time.ns_per_ms;
        Fake.polls = 0;
        Fake.attempts = 0;
        const options: Options = .{ .deadline = .after(.zero, 25) };
        if (direction == .read) {
            try std.testing.expectError(error.RequestTimeout, readWith(io, stream, &bytes, options, Fake));
        } else {
            try std.testing.expectError(error.RequestTimeout, writeWith(io, stream, &bytes, options, Fake));
        }
        try std.testing.expectEqual(0, Fake.attempts);
        try std.testing.expectEqual(0, Fake.polls);
    }
}
