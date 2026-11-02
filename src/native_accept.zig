const std = @import("std");
const builtin = @import("builtin");
const descriptors = @import("descriptor_budget.zig");
const posix = std.posix;

fn flags(handle: std.Io.net.Socket.Handle, command: i32, value: usize) !usize {
    while (true) {
        const rc = posix.system.fcntl(handle, command, value);
        switch (posix.errno(rc)) {
            .SUCCESS => return @intCast(rc),
            .INTR => continue,
            else => return error.ListenerSetupFailed,
        }
    }
}

pub fn prepare(server: *std.Io.net.Server) !void {
    if (builtin.os.tag == .windows) return;
    const current = try flags(server.socket.handle, posix.F.GETFL, 0);
    _ = try flags(server.socket.handle, posix.F.SETFL, current | (1 << @bitOffsetOf(posix.O, "NONBLOCK")));
}

pub fn retryable(err: anyerror) bool {
    return switch (err) {
        error.WouldBlock,
        error.ConnectionAborted,
        error.BlockedByFirewall,
        error.ProcessFdQuotaExceeded,
        error.SystemFdQuotaExceeded,
        error.SystemResources,
        => true,
        else => false,
    };
}

fn accept(server: *std.Io.net.Server, io: std.Io) !std.Io.net.Stream {
    if (builtin.os.tag == .windows) return server.accept(io);
    var ticket = descriptors.acquire(1) catch |err| if (descriptors.current_class == .normal)
        try descriptors.acquireClass(.emergency, 1)
    else
        return err;
    defer ticket.deinit();
    var address: std.Io.Threaded.PosixAddress = undefined;
    var length: posix.socklen_t = @sizeOf(@TypeOf(address));
    while (true) {
        try io.checkCancel();
        const rc = if (builtin.os.tag == .linux)
            posix.system.accept4(server.socket.handle, &address.any, &length, posix.SOCK.CLOEXEC)
        else
            posix.system.accept(server.socket.handle, &address.any, &length);
        switch (posix.errno(rc)) {
            .SUCCESS => {
                const stream = std.Io.net.Stream{ .socket = .{ .handle = @intCast(rc), .address = std.Io.Threaded.addressFromPosix(&address) } };
                errdefer stream.close(io);
                try ticket.adopt(stream.socket.handle);
                if (builtin.os.tag != .linux) {
                    _ = try flags(stream.socket.handle, posix.F.SETFD, posix.FD_CLOEXEC);
                    const current = try flags(stream.socket.handle, posix.F.GETFL, 0);
                    _ = try flags(stream.socket.handle, posix.F.SETFL, current & ~@as(usize, 1 << @bitOffsetOf(posix.O, "NONBLOCK")));
                }
                return stream;
            },
            .INTR => continue,
            .AGAIN => return error.WouldBlock,
            .CONNABORTED => return error.ConnectionAborted,
            .PERM => return error.BlockedByFirewall,
            .MFILE => return error.ProcessFdQuotaExceeded,
            .NFILE => return error.SystemFdQuotaExceeded,
            .NOBUFS, .NOMEM => return error.SystemResources,
            .BADF, .NOTSOCK, .INVAL, .OPNOTSUPP => return error.SocketClosed,
            .NETDOWN => return error.NetworkDown,
            else => return error.ListenerAcceptFailed,
        }
    }
}

pub fn next(io: std.Io, server: *std.Io.net.Server, shutdown: *const std.atomic.Value(bool)) !?std.Io.net.Stream {
    while (!shutdown.load(.acquire)) {
        const stream = accept(server, io) catch |err| {
            if (shutdown.load(.acquire)) return null;
            if (!retryable(err)) return err;
            if (err != error.WouldBlock and err != error.ConnectionAborted)
                std.debug.print("{{\"event\":\"server.accept_backoff\",\"error\":\"{s}\"}}\n", .{@errorName(err)});
            if (builtin.os.tag != .windows and err == error.WouldBlock) {
                var fd = posix.pollfd{ .fd = server.socket.handle, .events = posix.POLL.IN, .revents = 0 };
                switch (posix.errno(posix.system.poll(@ptrCast(&fd), 1, 50))) {
                    .SUCCESS, .INTR => {},
                    else => return error.ListenerPollFailed,
                }
                if (fd.revents & posix.POLL.NVAL != 0) return error.SocketClosed;
            } else try io.sleep(.fromMilliseconds(100), .awake);
            continue;
        };
        if (!shutdown.load(.acquire)) return stream;
        stream.close(io);
    }
    return null;
}

test "closed listener descriptors fail without entering the blocking IO panic path" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var shutdown = std.atomic.Value(bool).init(false);
    var server = std.Io.net.Server{ .socket = .{ .handle = -1, .address = .{ .ip4 = .loopback(0) } }, .options = {} };
    try std.testing.expectError(error.SocketClosed, next(std.testing.io, &server, &shutdown));
    shutdown.store(true, .release);
    try std.testing.expectEqual(null, try next(std.testing.io, &server, &shutdown));
}

test "accept errors distinguish pressure and aborted peers from a lost listener" {
    for ([_]anyerror{ error.WouldBlock, error.ConnectionAborted, error.BlockedByFirewall, error.ProcessFdQuotaExceeded, error.SystemFdQuotaExceeded, error.SystemResources }) |err|
        try std.testing.expect(retryable(err));
    for ([_]anyerror{ error.SocketClosed, error.NetworkDown, error.ListenerAcceptFailed, error.Canceled }) |err|
        try std.testing.expect(!retryable(err));
}
