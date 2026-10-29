const std = @import("std");
const builtin = @import("builtin");

const config_mod = @import("config.zig");
const native_tls = @import("native_tls_runtime.zig");
const read_deadline = @import("read_deadline.zig");
const write_deadline = @import("write_deadline.zig");
const read_interrupt = @import("read_interrupt.zig");

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
    if (read_deadline.forStream(stream)) |budget| {
        if (try budget.remaining()) |remaining| {
            try setStreamReadTimeout(stream, if (budget.restore_timeout_ms == 0) remaining else @min(remaining, budget.restore_timeout_ms));
        }
    }
    defer if (read_deadline.forStream(stream)) |budget| {
        setStreamReadTimeout(stream, budget.restore_timeout_ms) catch {};
    };
    var data: [1][]u8 = .{out};
    const n = io.vtable.netRead(io.userdata, stream.socket.handle, &data) catch |err| return normalizeSocketIoError(err);
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
    const io = activeIo();
    const budget = write_deadline.startWrite(stream);
    defer if (budget) |state| {
        state.restoreSocketTimeout(stream);
    };
    var written: usize = 0;
    while (written < bytes.len) {
        if (budget) |state| {
            try state.prepare(stream);
        }
        // netWrite expects a real scatter list here. Passing an empty one
        // looked tidy, then crashed in the vtable path.
        const empty: [1][]const u8 = .{""};
        const n = io.vtable.netWrite(io.userdata, stream.socket.handle, bytes[written..], &empty, 0) catch |err| {
            const normalized = normalizeSocketIoError(err);
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
    }
}

pub fn streamWriteAll(stream: std.Io.net.Stream, bytes: []const u8) !void {
    if (current_tls_channel) |channel| {
        if (stream.socket.handle == channel.stream.socket.handle) {
            return native_tls.writeApplicationData(channel, bytes);
        }
    }
    return rawStreamWriteAll(stream, bytes);
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
        return addr.connect(activeIo(), .{ .mode = .stream });
    } else |_| {}

    const host_name = try std.Io.net.HostName.init(host);
    return host_name.connect(activeIo(), port, .{ .mode = .stream });
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
            break :blk try unix_addr.connect(activeIo());
        },
    };
}
