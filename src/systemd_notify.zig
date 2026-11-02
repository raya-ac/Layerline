const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;

pub var failures: std.atomic.Value(usize) = .init(0);

// Keep supervisor authority in the server, never in CGI or certificate helpers.
pub fn privateEnvironmentKey(key: []const u8) bool {
    for ([_][]const u8{ "NOTIFY_SOCKET", "WATCHDOG_PID", "WATCHDOG_USEC" }) |name| {
        if (std.mem.eql(u8, key, name)) return true;
    }
    return false;
}

pub const Notifier = struct {
    path: [108]u8 = @splat(0),
    length: usize = 0,
    mutex: std.Io.Mutex = .init,
    phase: enum { starting, running, reloading, stopping } = .starting,

    pub fn init(environment: *const std.process.Environ.Map) !Notifier {
        var self: Notifier = .{};
        if (environment.get("NOTIFY_SOCKET")) |path| {
            if (path.len < 2 or path.len >= self.path.len or
                (path[0] != '/' and path[0] != '@') or std.mem.indexOfScalar(u8, path, 0) != null)
                return error.InvalidNotifySocket;
            if (builtin.os.tag != .linux) return error.NotifyPlatformUnsupported;
            @memcpy(self.path[0..path.len], path);
            self.length = path.len;
        }
        return self;
    }

    fn send(self: *const Notifier, message: []const u8) !void {
        if (self.length == 0) return;
        if (builtin.os.tag != .linux) return error.NotifyPlatformUnsupported;
        const linux = std.os.linux;
        // One nonblocking datagram, no allocation or retained descriptor. A full
        // manager queue must not stall request handling or the shutdown guard.
        const result = linux.socket(linux.AF.UNIX, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC | linux.SOCK.NONBLOCK, 0);
        if (posix.errno(result) != .SUCCESS) return error.NotifySocketFailed;
        const fd: posix.fd_t = @intCast(result);
        defer _ = linux.close(fd);
        var address: linux.sockaddr.un = std.mem.zeroes(linux.sockaddr.un);
        address.family = linux.AF.UNIX;
        @memcpy(address.path[0..self.length], self.path[0..self.length]);
        if (address.path[0] == '@') address.path[0] = 0;
        const length: posix.socklen_t = @intCast(@offsetOf(linux.sockaddr.un, "path") + self.length + @intFromBool(self.path[0] == '/'));
        const sent = linux.sendto(fd, message.ptr, message.len, linux.MSG.NOSIGNAL | linux.MSG.DONTWAIT, @ptrCast(&address), length);
        if (posix.errno(sent) != .SUCCESS or sent != message.len) return error.NotifySendFailed;
    }

    fn report(self: *const Notifier, message: []const u8) void {
        self.send(message) catch {
            // stderr can block too. Record the failure without putting a log
            // write between the lifecycle lock and the shutdown deadline.
            _ = failures.fetchAdd(1, .monotonic);
        };
    }

    pub fn starting(self: *Notifier) !void {
        try self.send("STATUS=Loading configuration and preparing listeners");
    }

    pub fn ready(self: *Notifier, io: std.Io, shutdown: *const std.atomic.Value(bool)) !void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        if (self.phase != .starting or shutdown.load(.acquire)) return error.Canceled;
        // Startup fails closed if the configured manager cannot be notified.
        try self.send("READY=1\nSTATUS=Listening; configuration active");
        self.phase = .running;
    }

    pub fn beginReload(self: *Notifier, io: std.Io, shutdown: *const std.atomic.Value(bool)) !void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        if (self.phase != .running or shutdown.load(.acquire)) return error.ServerNotReady;
        self.phase = .reloading;
        self.report("RELOADING=1\nSTATUS=Validating replacement configuration");
    }

    pub fn endReload(self: *Notifier, io: std.Io, shutdown: *const std.atomic.Value(bool), success: bool) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        if (self.phase != .reloading or shutdown.load(.acquire)) return;
        self.phase = .running;
        self.report(if (success) "READY=1\nSTATUS=Listening; replacement configuration active" else "READY=1\nSTATUS=Reload rejected; previous configuration remains active");
    }

    pub fn stopping(self: *Notifier, io: std.Io) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        if (self.phase == .stopping) return;
        self.phase = .stopping;
        self.report("STOPPING=1\nSTATUS=Draining connections and stopping workers");
    }
};

test "supervisor environment capabilities are not child environment" {
    try std.testing.expect(privateEnvironmentKey("NOTIFY_SOCKET"));
    try std.testing.expect(privateEnvironmentKey("WATCHDOG_PID"));
    try std.testing.expect(privateEnvironmentKey("WATCHDOG_USEC"));
    try std.testing.expect(!privateEnvironmentKey("PATH"));
    try std.testing.expect(!privateEnvironmentKey("NOTIFY_SOCKET_OTHER"));
}

test "notify rejects malformed addresses before any syscall" {
    var env: std.process.Environ.Map = .init(std.testing.allocator);
    defer env.deinit();
    for ([_][]const u8{ "", "@", "/", "relative", "/bad\x00socket", &@as([108]u8, @splat('x')) }) |path| {
        try env.put("NOTIFY_SOCKET", path);
        try std.testing.expectError(error.InvalidNotifySocket, Notifier.init(&env));
    }
}

test "stopping is terminal and rejected reloads can return to ready" {
    var notifier: Notifier = .{};
    var shutdown = std.atomic.Value(bool).init(false);
    try std.testing.expectError(error.ServerNotReady, notifier.beginReload(std.testing.io, &shutdown));
    try notifier.ready(std.testing.io, &shutdown);
    try notifier.beginReload(std.testing.io, &shutdown);
    notifier.endReload(std.testing.io, &shutdown, false);
    try notifier.beginReload(std.testing.io, &shutdown);
    shutdown.store(true, .release);
    notifier.endReload(std.testing.io, &shutdown, true);
    notifier.stopping(std.testing.io);
    try std.testing.expectEqual(.stopping, notifier.phase);
    shutdown.store(false, .release);
    notifier.endReload(std.testing.io, &shutdown, true);
    try std.testing.expectError(error.Canceled, notifier.ready(std.testing.io, &shutdown));
    try std.testing.expectError(error.ServerNotReady, notifier.beginReload(std.testing.io, &shutdown));
}
