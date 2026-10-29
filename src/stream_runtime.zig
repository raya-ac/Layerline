const std = @import("std");
const builtin = @import("builtin");

const config_mod = @import("config.zig");
const native_tls = @import("native_tls_runtime.zig");
const read_deadline = @import("read_deadline.zig");
const write_deadline = @import("write_deadline.zig");
const read_interrupt = @import("read_interrupt.zig");
const backend_deadline = @import("backend_deadline.zig");

const PhpFastcgiEndpoint = config_mod.PhpFastcgiEndpoint;
const TlsChannel = native_tls.Channel;

threadlocal var current_io: ?std.Io = null;
threadlocal var current_tls_channel: ?*TlsChannel = null;

// Zig 0.16 moved sockets behind std.Io, so detached worker threads need their
// own bound handle before they touch a stream.
pub fn bindThreadIo(io: std.Io) void {
    current_io = io;
}

pub fn activeIo() std.Io {
    return current_io orelse @panic("network stream used before std.Io was bound to this thread");
}

pub fn setTlsChannel(channel: ?*TlsChannel) void {
    current_tls_channel = channel;
}

pub fn clearTlsChannel() void {
    current_tls_channel = null;
}

pub fn currentTlsChannel() ?*TlsChannel {
    return current_tls_channel;
}

pub fn isTlsConnection() bool {
    return current_tls_channel != null;
}

fn normalizeSocketIoError(err: anyerror) anyerror {
    return switch (err) {
        error.WouldBlock, error.TimedOut, error.ConnectionTimedOut, error.Unexpected => error.RequestTimeout,
        else => err,
    };
}

pub fn rawStreamRead(stream: std.Io.net.Stream, out: []u8) !usize {
    const io = activeIo();
    if (read_interrupt.active) |scope| {
        if (scope.stream.socket.handle == stream.socket.handle) try scope.wait();
    }
    var timeout: ?u32 = null;
    var restore_timeout: ?u32 = null;
    if (read_deadline.forStream(stream)) |budget| {
        if (try budget.remaining()) |remaining| {
            timeout = if (budget.restore_timeout_ms == 0) remaining else @min(remaining, budget.restore_timeout_ms);
        }
        restore_timeout = budget.restore_timeout_ms;
    }
    if (backend_deadline.forStream(stream)) |budget| {
        const remaining = budget.remaining() catch |err| {
            backend_deadline.logTimeout("read");
            return err;
        };
        if (remaining) |ms| timeout = @min(timeout orelse ms, ms);
        if (restore_timeout == null) restore_timeout = budget.timeout_ms;
    }
    if (timeout) |ms| try setStreamReadTimeout(stream, ms);
    defer if (restore_timeout) |ms| {
        setStreamReadTimeout(stream, ms) catch {};
    };
    var data: [1][]u8 = .{out};
    const n = io.vtable.netRead(io.userdata, stream.socket.handle, &data) catch |err| {
        const normalized = normalizeSocketIoError(err);
        if (normalized == error.RequestTimeout) {
            if (backend_deadline.forStream(stream)) |state| {
                if (state.deadline.expired(.now(io, .awake))) backend_deadline.logTimeout("read");
            }
        }
        return normalized;
    };
    if (n > 0) read_deadline.noteProgress(stream);
    return n;
}

pub fn streamRead(stream: std.Io.net.Stream, out: []u8) !usize {
    if (read_deadline.forStream(stream)) |budget| _ = try budget.remaining();
    if (current_tls_channel) |channel| {
        if (stream.socket.handle == channel.stream.socket.handle) {
            const n = try native_tls.readApplicationData(channel, out);
            if (n > 0) read_deadline.noteProgress(stream);
            return n;
        }
    }
    return rawStreamRead(stream, out);
}

pub fn rawStreamWriteAll(stream: std.Io.net.Stream, bytes: []const u8) !void {
    var written: usize = 0;
    try rawStreamWriteAllCounted(stream, bytes, &written);
}

pub fn rawStreamWriteAllCounted(stream: std.Io.net.Stream, bytes: []const u8, accepted: *usize) !void {
    const io = activeIo();
    const budget = write_deadline.startWrite(stream);
    const backend = backend_deadline.forStream(stream);
    defer if (budget) |state| {
        state.restoreSocketTimeout(stream);
    };
    defer if (backend) |state| {
        setStreamWriteTimeout(stream, state.timeout_ms) catch {};
    };
    var written: usize = 0;
    while (written < bytes.len) {
        if (budget) |state| {
            try state.prepare(stream);
        }
        if (backend) |state| {
            const remaining = state.remaining() catch |err| {
                backend_deadline.logTimeout("write");
                return err;
            };
            if (remaining) |ms| try setStreamWriteTimeout(stream, ms);
        }
        // netWrite expects a real scatter list here. Passing an empty one
        // looked tidy, then crashed in the vtable path.
        const empty: [1][]const u8 = .{""};
        const n = io.vtable.netWrite(io.userdata, stream.socket.handle, bytes[written..], &empty, 0) catch |err| {
            const normalized = normalizeSocketIoError(err);
            if (normalized == error.RequestTimeout and backend != null) backend_deadline.logTimeout("write");
            if (budget) |state| {
                if (normalized == error.RequestTimeout) {
                    state.logTimeout();
                    return error.WriteTimeout;
                }
            }
            return normalized;
        };
        if (n == 0) return error.WriteZero;
        written += n;
        accepted.* +|= n;
    }
}

pub fn streamWriteAll(stream: std.Io.net.Stream, bytes: []const u8) !void {
    var written: usize = 0;
    try streamWriteAllCounted(stream, bytes, &written);
}

pub fn streamWriteAllCounted(stream: std.Io.net.Stream, bytes: []const u8, accepted: *usize) !void {
    if (current_tls_channel) |channel| {
        if (stream.socket.handle == channel.stream.socket.handle) {
            return native_tls.writeApplicationDataCounted(channel, bytes, accepted);
        }
    }
    return rawStreamWriteAllCounted(stream, bytes, accepted);
}

pub fn streamWriteFmt(stream: std.Io.net.Stream, comptime fmt: []const u8, args: anytype) !void {
    var stack_buffer: [4096]u8 = undefined;
    const rendered = try std.fmt.bufPrint(&stack_buffer, fmt, args);
    try streamWriteAll(stream, rendered);
}

fn timeoutMsToTimeval(timeout_ms: u32) std.posix.timeval {
    return .{
        .sec = @intCast(timeout_ms / 1000),
        .usec = @intCast((timeout_ms % 1000) * 1000),
    };
}

pub fn setStreamReadTimeout(stream: std.Io.net.Stream, timeout_ms: u32) !void {
    if (builtin.os.tag == .windows) return;
    var tv = timeoutMsToTimeval(timeout_ms);
    try std.posix.setsockopt(stream.socket.handle, std.posix.SOL.SOCKET, std.posix.SO.RCVTIMEO, std.mem.asBytes(&tv));
}

pub fn setStreamWriteTimeout(stream: std.Io.net.Stream, timeout_ms: u32) !void {
    try write_deadline.setSocketTimeout(stream, timeout_ms);
}

pub fn setStreamTimeouts(stream: std.Io.net.Stream, read_timeout_ms: u32, write_timeout_ms: u32) !void {
    try setStreamReadTimeout(stream, read_timeout_ms);
    try setStreamWriteTimeout(stream, write_timeout_ms);
}

pub fn streamClose(stream: std.Io.net.Stream) void {
    stream.close(activeIo());
}

pub fn connectTcpHost(allocator: std.mem.Allocator, host: []const u8, port: u16) !std.Io.net.Stream {
    _ = allocator;
    if (std.Io.net.IpAddress.parse(host, port)) |address| {
        var addr = address;
        return backend_deadline.connect(activeIo(), std.Io.net.IpAddress.connect, .{ &addr, activeIo(), std.Io.net.IpAddress.ConnectOptions{ .mode = .stream } });
    } else |_| {}

    const host_name = try std.Io.net.HostName.init(host);
    return backend_deadline.connect(activeIo(), std.Io.net.HostName.connect, .{ host_name, activeIo(), port, std.Io.net.IpAddress.ConnectOptions{ .mode = .stream } });
}

pub fn listenerWakeHost(host: []const u8) []const u8 {
    if (std.mem.eql(u8, host, "0.0.0.0")) return "127.0.0.1";
    if (std.mem.eql(u8, host, "::")) return "::1";
    return host;
}

pub fn connectFastcgiEndpoint(allocator: std.mem.Allocator, endpoint: PhpFastcgiEndpoint) !std.Io.net.Stream {
    return switch (endpoint) {
        .tcp => |tcp| try connectTcpHost(allocator, tcp.host, tcp.port),
        .unix => |path| blk: {
            const unix_addr = try std.Io.net.UnixAddress.init(path);
            break :blk try backend_deadline.connect(activeIo(), std.Io.net.UnixAddress.connect, .{ &unix_addr, activeIo() });
        },
    };
}

test "counted socket writes retain accepted bytes on errors and zero writes" {
    const Fake = struct {
        var calls: usize = 0;
        var failure: bool = false;
        var zero: bool = false;
        fn write(_: ?*anyopaque, _: std.Io.net.Socket.Handle, header: []const u8, _: []const []const u8, _: usize) std.Io.net.Stream.Writer.Error!usize {
            calls += 1;
            if (calls == 2) {
                if (failure) return error.ConnectionResetByPeer;
                if (zero) return 0;
            }
            return @min(3, header.len);
        }
    };
    var vtable = std.testing.io.vtable.*;
    vtable.netWrite = Fake.write;
    const previous_io = current_io;
    defer current_io = previous_io;
    bindThreadIo(.{ .userdata = std.testing.io.userdata, .vtable = &vtable });
    const stream = std.Io.net.Stream{ .socket = .{ .handle = 123, .address = undefined } };
    for ([_]u8{ 0, 1, 2 }) |mode| {
        Fake.calls = 0;
        Fake.failure = mode == 1;
        Fake.zero = mode == 2;
        var bytes: usize = 5;
        if (mode == 0) {
            try rawStreamWriteAllCounted(stream, "1234567", &bytes);
            try std.testing.expectEqual(12, bytes);
        } else {
            try std.testing.expectError(if (mode == 1) error.ConnectionResetByPeer else error.WriteZero, rawStreamWriteAllCounted(stream, "1234567", &bytes));
            try std.testing.expectEqual(8, bytes);
        }
    }
}
