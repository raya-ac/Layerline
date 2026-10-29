const std = @import("std");

const config_mod = @import("config.zig");
const native_tls = @import("native_tls_runtime.zig");
const read_deadline = @import("read_deadline.zig");
const write_deadline = @import("write_deadline.zig");
const read_interrupt = @import("read_interrupt.zig");
const backend_deadline = @import("backend_deadline.zig");
const socket_timeout = @import("socket_timeout.zig");
const socket_io = @import("socket_io.zig");

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
        error.WouldBlock, error.TimedOut, error.ConnectionTimedOut => error.RequestTimeout,
        else => err,
    };
}

pub fn rawStreamRead(stream: std.Io.net.Stream, out: []u8) !usize {
    const io = activeIo();
    if (read_interrupt.active) |scope| {
        if (scope.stream.socket.handle == stream.socket.handle) try scope.wait();
    }
    var timeout: ?u32 = null;
    var limit = read_deadline.Deadline{};
    var restore_timeout: ?u32 = null;
    if (read_deadline.forStream(stream)) |budget| {
        limit = budget.deadline;
        if (try budget.remaining()) |remaining| {
            timeout = if (budget.restore_timeout_ms == 0) remaining else @min(remaining, budget.restore_timeout_ms);
        }
        restore_timeout = budget.restore_timeout_ms;
    }
    if (backend_deadline.forStream(stream)) |budget| {
        limit = .earliest(limit, budget.deadline);
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
    const n = socket_io.read(io, stream, out, .{ .timeout_ms = timeout, .deadline = limit }) catch |err| {
        const normalized = normalizeSocketIoError(err);
        if (normalized == error.RequestTimeout) {
            if (backend_deadline.forStream(stream)) |state| {
                if (state.deadline.expired(.now(io, .awake))) backend_deadline.logTimeout("read");
            }
        }
        return normalized;
    };
    // Socket timers are a wakeup mechanism, not proof that a successful read
    // finished on time. Late backend bytes must not turn a timeout into a 200.
    // Do not drop downstream bytes here: HTTP/2 retains partial TLS/frame input
    // across its soft stream deadlines.
    try backend_deadline.checkReadCompletion(stream);
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
    try rawStreamWriteAllUsing(stream, bytes, accepted, socket_io.write);
}

fn rawStreamWriteAllUsing(stream: std.Io.net.Stream, bytes: []const u8, accepted: *usize, write: *const fn (std.Io, std.Io.net.Stream, []const u8, socket_io.Options) anyerror!usize) !void {
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
        var options = socket_io.Options{};
        if (budget) |state| {
            try state.prepare(stream);
            options.timeout_ms = try state.remaining();
            options.deadline = state.deadline;
        }
        if (backend) |state| {
            const remaining = state.remaining() catch |err| {
                backend_deadline.logTimeout("write");
                return err;
            };
            if (remaining) |ms| try setStreamWriteTimeout(stream, ms);
            if (remaining) |ms| options.timeout_ms = @min(options.timeout_ms orelse ms, ms);
            options.deadline = .earliest(options.deadline, state.deadline);
        }
        const n = write(io, stream, bytes[written..], options) catch |err| {
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
        if (backend) |state| {
            _ = state.remaining() catch |err| {
                backend_deadline.logTimeout("write");
                return err;
            };
        }
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

pub fn setStreamReadTimeout(stream: std.Io.net.Stream, timeout_ms: u32) !void {
    try socket_timeout.set(stream, .read, timeout_ms);
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
        fn write(_: std.Io, _: std.Io.net.Stream, header: []const u8, _: socket_io.Options) !usize {
            calls += 1;
            if (calls == 2) {
                if (failure) return error.ConnectionResetByPeer;
                if (zero) return 0;
            }
            return @min(3, header.len);
        }
    };
    const previous_io = current_io;
    defer current_io = previous_io;
    bindThreadIo(std.testing.io);
    const stream = std.Io.net.Stream{ .socket = .{ .handle = 123, .address = undefined } };
    for ([_]u8{ 0, 1, 2 }) |mode| {
        Fake.calls = 0;
        Fake.failure = mode == 1;
        Fake.zero = mode == 2;
        var bytes: usize = 5;
        if (mode == 0) {
            try rawStreamWriteAllUsing(stream, "1234567", &bytes, Fake.write);
            try std.testing.expectEqual(12, bytes);
        } else {
            try std.testing.expectError(if (mode == 1) error.ConnectionResetByPeer else error.WriteZero, rawStreamWriteAllUsing(stream, "1234567", &bytes, Fake.write));
            try std.testing.expectEqual(8, bytes);
        }
    }
}

test "unexpected socket failures are not disguised as timeouts" {
    try std.testing.expectEqual(error.RequestTimeout, normalizeSocketIoError(error.WouldBlock));
    try std.testing.expectEqual(error.RequestTimeout, normalizeSocketIoError(error.TimedOut));
    try std.testing.expectEqual(error.Unexpected, normalizeSocketIoError(error.Unexpected));
    try std.testing.expectEqual(error.SocketClosed, normalizeSocketIoError(error.SocketClosed));
}
