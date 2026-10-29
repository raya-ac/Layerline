const std = @import("std");
const Deadline = @import("read_deadline.zig").Deadline;
const socket_timeout = @import("socket_timeout.zig");
const Protocol = enum { h1, h2 };

pub const State = struct {
    io: std.Io,
    handle: std.Io.net.Socket.Handle,
    deadline: Deadline,
    restore_timeout_ms: u32,
    stream_id: u32 = 0,
    protocol: Protocol = .h2,
    lazy: bool = false,

    pub fn remaining(self: State) !?u32 {
        return self.deadline.remaining(.now(self.io, .awake)) catch return error.WriteTimeout;
    }

    pub fn logTimeout(self: State) void {
        self.logTimeoutPhase("wire");
    }

    pub fn logTimeoutPhase(self: State, phase: []const u8) void {
        if (@import("builtin").is_test) return;
        std.debug.print("{{\"event\":\"server.write_timeout\",\"protocol\":\"{s}\",\"phase\":\"{s}\",\"stream_id\":{d}}}\n", .{ @tagName(self.protocol), phase, self.stream_id });
    }

    pub fn prepare(self: State, stream: std.Io.net.Stream) !void {
        try self.preparePhase(stream, "wire");
    }

    pub fn preparePhase(self: State, stream: std.Io.net.Stream, phase: []const u8) !void {
        const remaining_ms = self.remaining() catch |err| {
            self.logTimeoutPhase(phase);
            return err;
        };
        if (remaining_ms) |timeout_ms| try setSocketTimeout(stream, timeout_ms);
    }

    pub fn restoreSocketTimeout(self: State, stream: std.Io.net.Stream) void {
        setSocketTimeout(stream, self.restore_timeout_ms) catch {};
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

pub fn startWrite(stream: std.Io.net.Stream) ?State {
    const state = if (active) |*state| state else return null;
    if (state.handle != stream.socket.handle) return null;
    if (state.lazy and state.deadline.at == null) state.deadline = .after(.now(state.io, .awake), state.restore_timeout_ms);
    return state.*;
}

pub fn pushHttp1(io: std.Io, stream: std.Io.net.Stream, timeout_ms: u32) ?State {
    return push(.{ .io = io, .handle = stream.socket.handle, .deadline = .{}, .restore_timeout_ms = timeout_ms, .protocol = .h1, .lazy = true });
}

pub fn restart(stream: std.Io.net.Stream) void {
    const state = if (active) |*state| state else return;
    if (state.handle == stream.socket.handle and state.lazy) state.deadline = .{};
}

pub fn started(stream: std.Io.net.Stream) bool {
    return if (forStream(stream)) |state| state.deadline.at != null else false;
}

pub fn clear(stream: std.Io.net.Stream) void {
    if (forStream(stream) != null) active = null;
}

pub fn setSocketTimeout(stream: std.Io.net.Stream, timeout_ms: u32) !void {
    try socket_timeout.set(stream, .write, timeout_ms);
}

test "HTTP1 arms lazily, keeps one deadline, and resets after interim responses" {
    const stream = std.Io.net.Stream{ .socket = .{ .handle = 123, .address = undefined } };
    const backend = std.Io.net.Stream{ .socket = .{ .handle = 124, .address = undefined } };
    const previous = pushHttp1(std.testing.io, stream, 100);
    defer restore(previous);
    try std.testing.expect(!started(stream));
    try std.testing.expect(startWrite(backend) == null);
    const first = startWrite(stream).?.deadline.at.?.nanoseconds;
    try std.testing.expectEqual(first, startWrite(stream).?.deadline.at.?.nanoseconds);
    restart(stream);
    try std.testing.expect(!started(stream));
    _ = startWrite(stream);
    try std.testing.expect(started(stream));
    clear(stream);
    try std.testing.expect(forStream(stream) == null);
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
