const std = @import("std");
const Deadline = @import("read_deadline.zig").Deadline;

pub const State = struct {
    io: std.Io,
    handle: std.Io.net.Socket.Handle,
    deadline: Deadline,
    restore_timeout_ms: u32,
    stream_id: u32,

    pub fn remaining(self: State) !?u32 {
        return self.deadline.remaining(.now(self.io, .awake)) catch return error.WriteTimeout;
    }

    pub fn logTimeout(self: State) void {
        if (@import("builtin").is_test) return;
        std.debug.print("{{\"event\":\"server.write_timeout\",\"protocol\":\"h2\",\"phase\":\"wire\",\"stream_id\":{d}}}\n", .{self.stream_id});
    }
};

threadlocal var active: ?State = null;

pub fn forStream(stream: std.Io.net.Stream) ?State {
    const state = active orelse return null;
    return if (state.handle == stream.socket.handle) state else null;
}

pub fn push(state: State) ?State {
    const previous = active;
    active = state;
    return previous;
}

pub fn restore(previous: ?State) void {
    active = previous;
}

test "response write budgets are scoped to one downstream socket" {
    const stream = std.Io.net.Stream{ .socket = .{ .handle = 123, .address = undefined } };
    const backend = std.Io.net.Stream{ .socket = .{ .handle = 124, .address = undefined } };
    const previous = push(.{ .io = std.testing.io, .handle = stream.socket.handle, .deadline = .after(.fromNanoseconds(0), 1), .restore_timeout_ms = 100, .stream_id = 1 });
    defer restore(previous);
    try std.testing.expect(forStream(backend) == null);
    try std.testing.expectError(error.WriteTimeout, forStream(stream).?.remaining());
    const outer = push(.{ .io = std.testing.io, .handle = backend.socket.handle, .deadline = .{}, .restore_timeout_ms = 100, .stream_id = 3 });
    try std.testing.expect(forStream(stream) == null);
    try std.testing.expect(try forStream(backend).?.remaining() == null);
    restore(outer);
    try std.testing.expectEqual(1, forStream(stream).?.stream_id);
}
