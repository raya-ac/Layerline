const std = @import("std");

pub const State = struct {
    shutdown: *std.atomic.Value(bool),
    ready: std.atomic.Value(bool) = .init(false),
    failure: std.atomic.Value(u16) = .init(0),

    pub fn awaitReady(self: *State, io: std.Io) bool {
        while (!self.shutdown.load(.acquire)) {
            if (self.ready.load(.acquire)) return true;
            io.sleep(.fromMilliseconds(1), .awake) catch |err| {
                if (!self.shutdown.load(.acquire)) self.fail("startup", err);
                return false;
            };
        }
        return false;
    }

    pub fn fail(self: *State, listener: []const u8, err: anyerror) void {
        if (self.failure.cmpxchgStrong(0, @intFromError(err), .acq_rel, .acquire) == null and !@import("builtin").is_test)
            std.debug.print("{{\"event\":\"server.listener_failure\",\"listener\":\"{s}\",\"error\":\"{s}\"}}\n", .{ listener, @errorName(err) });
        self.shutdown.store(true, .release);
    }

    pub fn result(self: *const State) !void {
        const code = self.failure.load(.acquire);
        if (code != 0) return @errorFromInt(code);
    }
};

test "the first listener failure requests shutdown and survives later errors" {
    var shutdown = std.atomic.Value(bool).init(false);
    var state: State = .{ .shutdown = &shutdown };
    try state.result();
    state.fail("fixture", error.SocketClosed);
    state.fail("fixture", error.NetworkDown);
    try std.testing.expect(shutdown.load(.acquire));
    try std.testing.expectError(error.SocketClosed, state.result());
}
