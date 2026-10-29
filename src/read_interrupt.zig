const std = @import("std");
const builtin = @import("builtin");
const read_deadline = @import("read_deadline.zig");
const system = std.posix.system;

pub threadlocal var active: ?*Scope = null;

pub const Wake = struct {
    fds: [2]std.posix.fd_t,

    pub fn init() !Wake {
        if (builtin.os.tag == .windows) return error.UnsupportedPlatform;
        return .{ .fds = try std.Io.Threaded.pipe2(.{ .CLOEXEC = true, .NONBLOCK = true }) };
    }

    pub fn deinit(self: *Wake) void {
        _ = system.close(self.fds[0]);
        _ = system.close(self.fds[1]);
    }

    pub fn signal(self: *Wake) void {
        const byte = [_]u8{1};
        while (true) {
            const n = system.write(self.fds[1], &byte, 1);
            if (std.posix.errno(n) != .INTR) return;
        }
    }

    fn drain(self: *Wake) void {
        var bytes: [256]u8 = undefined;
        while (true) {
            const n = system.read(self.fds[0], &bytes, bytes.len);
            const err = std.posix.errno(n);
            if ((err == .SUCCESS and n > 0) or err == .INTR) continue;
            return;
        }
    }
};

pub const Scope = struct {
    stream: std.Io.net.Stream,
    wake: *Wake,
    busy: bool = false,

    pub fn wait(self: *Scope) !void {
        var fds = [_]std.posix.pollfd{
            .{ .fd = self.stream.socket.handle, .events = std.posix.POLL.IN, .revents = 0 },
            .{ .fd = self.wake.fds[0], .events = std.posix.POLL.IN, .revents = 0 },
        };
        while (true) {
            const remaining = if (read_deadline.forStream(self.stream)) |budget| try budget.remaining() else null;
            // Active connections must also observe graceful shutdown when no
            // client bytes arrive. Idle connections are woken by the registry.
            const timeout: i32 = if (self.busy) @intCast(@min(remaining orelse 100, 100)) else if (remaining) |ms| @intCast(@min(ms, std.math.maxInt(i32))) else -1;
            const n = system.poll(&fds, fds.len, timeout);
            switch (std.posix.errno(n)) {
                .SUCCESS => {},
                .INTR => continue,
                else => return error.PollFailed,
            }
            if (n == 0) {
                if (read_deadline.forStream(self.stream)) |budget| _ = try budget.remaining();
                return error.DispatchReady;
            }
            if (fds[1].revents != 0) {
                self.wake.drain();
                return error.DispatchReady;
            }
            if (fds[0].revents != 0) return;
        }
    }
};

test "wakeups interrupt polling without client bytes and descriptors are private" {
    var wake = try Wake.init();
    defer wake.deinit();
    var peer = try Wake.init();
    defer peer.deinit();
    for (wake.fds) |fd| {
        const flags = system.fcntl(fd, std.posix.F.GETFD, @as(usize, 0));
        try std.testing.expect(std.posix.errno(flags) == .SUCCESS and flags & std.posix.FD_CLOEXEC != 0);
    }
    var scope: Scope = .{ .stream = .{ .socket = .{ .handle = peer.fds[0], .address = undefined } }, .wake = &wake };
    wake.signal();
    wake.signal();
    try std.testing.expectError(error.DispatchReady, scope.wait());
    wake.signal();
    try std.testing.expectError(error.DispatchReady, scope.wait());
}
