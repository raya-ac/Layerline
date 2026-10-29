const std = @import("std");
const builtin = @import("builtin");

pub const Direction = enum { read, write };

pub fn set(stream: std.Io.net.Stream, direction: Direction, timeout_ms: u32) !void {
    if (builtin.os.tag == .windows) return;
    try setWith(stream.socket.handle, direction, timeout_ms, setOption);
}

fn setOption(handle: std.Io.net.Socket.Handle, option: u32, bytes: []const u8) std.posix.E {
    return std.posix.errno(std.posix.system.setsockopt(handle, std.posix.SOL.SOCKET, option, bytes.ptr, @intCast(bytes.len)));
}

fn setWith(handle: std.Io.net.Socket.Handle, direction: Direction, timeout_ms: u32, apply: *const fn (std.Io.net.Socket.Handle, u32, []const u8) std.posix.E) !void {
    var value: std.posix.timeval = undefined;
    @memset(std.mem.asBytes(&value), 0);
    value.sec = @intCast(timeout_ms / 1000);
    value.usec = @intCast((timeout_ms % 1000) * 1000);
    const option: u32 = if (direction == .read) std.posix.SO.RCVTIMEO else std.posix.SO.SNDTIMEO;
    while (true) switch (apply(handle, option, std.mem.asBytes(&value))) {
        .SUCCESS => return,
        .INTR => continue,
        // Darwin rejects timeout updates after both directions shut down. A
        // peer reset can put a socket there before our restore defer runs.
        .INVAL, .BADF, .NOTSOCK, .NOTCONN => return error.SocketClosed,
        .CONNRESET => return error.ConnectionResetByPeer,
        .CONNABORTED => return error.ConnectionAborted,
        .PIPE => return error.BrokenPipe,
        .DOM => return error.TimeoutTooBig,
        .NOPROTOOPT => return error.InvalidProtocolOption,
        .NOMEM, .NOBUFS => return error.SystemResources,
        .ACCES, .PERM => return error.PermissionDenied,
        .OPNOTSUPP => return error.OperationUnsupported,
        .NETDOWN => return error.NetworkDown,
        else => |err| {
            if (!builtin.is_test) std.debug.print("{{\"event\":\"server.socket_option_error\",\"direction\":\"{s}\",\"errno\":\"{s}\"}}\n", .{ @tagName(direction), @tagName(err) });
            return error.UnexpectedSocketOption;
        },
    };
}

test "timeout options preserve the timeval ABI and retry interruption" {
    const Fake = struct {
        var calls: usize = 0;
        var option: u32 = 0;
        var milliseconds: u32 = 0;
        fn apply(handle: std.Io.net.Socket.Handle, name: u32, bytes: []const u8) std.posix.E {
            std.debug.assert(handle == 123 and name == option);
            std.debug.assert(bytes.len == @sizeOf(std.posix.timeval));
            const value = std.mem.bytesAsValue(std.posix.timeval, bytes);
            std.debug.assert(value.sec == milliseconds / 1000);
            std.debug.assert(value.usec == (milliseconds % 1000) * 1000);
            for (bytes, 0..) |byte, index| {
                const sec = index < @offsetOf(std.posix.timeval, "sec") + @sizeOf(@TypeOf(value.sec));
                const usec = index >= @offsetOf(std.posix.timeval, "usec") and index < @offsetOf(std.posix.timeval, "usec") + @sizeOf(@TypeOf(value.usec));
                if (!sec and !usec) std.debug.assert(byte == 0);
            }
            calls += 1;
            return if (calls == 1) .INTR else .SUCCESS;
        }
    };
    for ([_]Direction{ .read, .write }) |direction| {
        for ([_]u32{ 0, 1, 999, 1000, std.math.maxInt(u32) }) |ms| {
            Fake.calls = 0;
            Fake.option = if (direction == .read) std.posix.SO.RCVTIMEO else std.posix.SO.SNDTIMEO;
            Fake.milliseconds = ms;
            try setWith(123, direction, ms, Fake.apply);
            try std.testing.expectEqual(2, Fake.calls);
        }
    }
}

test "timeout updates on reset and shut-down sockets return errors instead of panicking" {
    const Fake = struct {
        var result: std.posix.E = .SUCCESS;
        fn apply(_: std.Io.net.Socket.Handle, _: u32, _: []const u8) std.posix.E {
            return result;
        }
    };
    for ([_]Direction{ .read, .write }) |direction| {
        for ([_]std.posix.E{ .INVAL, .BADF, .NOTSOCK, .NOTCONN }) |result| {
            Fake.result = result;
            try std.testing.expectError(error.SocketClosed, setWith(123, direction, 100, Fake.apply));
        }
        Fake.result = .CONNRESET;
        try std.testing.expectError(error.ConnectionResetByPeer, setWith(123, direction, 100, Fake.apply));
        Fake.result = .NOBUFS;
        try std.testing.expectError(error.SystemResources, setWith(123, direction, 100, Fake.apply));
        Fake.result = .FAULT;
        try std.testing.expectError(error.UnexpectedSocketOption, setWith(123, direction, 100, Fake.apply));
    }
}
