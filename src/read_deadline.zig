const std = @import("std");

pub const Deadline = struct {
    at: ?std.Io.Timestamp = null,

    pub fn after(now: std.Io.Timestamp, timeout_ms: u32) Deadline {
        return .{ .at = if (timeout_ms == 0) null else now.addDuration(.fromMilliseconds(timeout_ms)) };
    }

    pub fn earliest(a: Deadline, b: Deadline) Deadline {
        const left = a.at orelse return b;
        const right = b.at orelse return a;
        return if (left.nanoseconds <= right.nanoseconds) a else b;
    }

    pub fn expired(self: Deadline, now: std.Io.Timestamp) bool {
        return if (self.at) |at| now.nanoseconds >= at.nanoseconds else false;
    }

    pub fn remaining(self: Deadline, now: std.Io.Timestamp) !?u32 {
        const at = self.at orelse return null;
        if (now.nanoseconds >= at.nanoseconds) return error.RequestTimeout;
        const ns = at.nanoseconds - now.nanoseconds;
        // Round up: a sub-millisecond remainder must not become a zero socket timeout,
        // which means an unlimited wait on the supported socket backends.
        return @intCast(@min(@divTrunc(ns + std.time.ns_per_ms - 1, std.time.ns_per_ms), std.math.maxInt(u32)));
    }
};

pub const State = struct {
    io: std.Io,
    handle: std.Io.net.Socket.Handle,
    deadline: Deadline,
    restore_timeout_ms: u32,
    progress_timeout_ms: u32 = 0,
    track_progress: bool = false,
    progress_started: ?std.Io.Timestamp = null,
    replace_on_progress: bool = false,
    limit: Deadline = .{},

    pub fn remaining(self: State) !?u32 {
        return self.deadline.remaining(std.Io.Timestamp.now(self.io, .awake));
    }
};

// Like the native TLS channel, a read budget belongs to the connection worker.
// Matching the socket keeps downstream deadlines out of backend/pool traffic.
threadlocal var active: ?State = null;

pub fn forStream(stream: std.Io.net.Stream) ?State {
    const state = active orelse return null;
    return if (state.handle == stream.socket.handle) state else null;
}

pub fn install(state: State) void {
    active = state;
}

pub fn push(state: State) ?State {
    const previous = active;
    active = state;
    return previous;
}

pub fn restore(previous: ?State) void {
    active = previous;
}

pub fn begin(io: std.Io, stream: std.Io.net.Stream, timeout_ms: u32) void {
    active = .{ .io = io, .handle = stream.socket.handle, .deadline = .after(.now(io, .awake), timeout_ms), .restore_timeout_ms = timeout_ms };
}

pub fn restart(stream: std.Io.net.Stream, timeout_ms: u32) void {
    const state = forStream(stream) orelse return;
    begin(state.io, stream, timeout_ms);
}

pub fn clear(stream: std.Io.net.Stream) void {
    if (forStream(stream) != null) active = null;
}

pub fn noteProgress(stream: std.Io.net.Stream) void {
    const state = if (active) |*state| state else return;
    if (state.handle != stream.socket.handle or !state.track_progress or state.progress_started != null) return;
    const now = std.Io.Timestamp.now(state.io, .awake);
    state.progress_started = now;
    const progress = Deadline.after(now, state.progress_timeout_ms);
    state.deadline = Deadline.earliest(if (state.replace_on_progress) state.limit else state.deadline, progress);
}

test "absolute deadlines do not renew and round tiny waits up" {
    const now = std.Io.Timestamp.fromNanoseconds(0);
    const deadline = Deadline.after(now, 100);
    try std.testing.expectEqual(100, (try deadline.remaining(now)).?);
    try std.testing.expectEqual(1, (try deadline.remaining(.fromNanoseconds(99_999_999))).?);
    try std.testing.expectError(error.RequestTimeout, deadline.remaining(.fromNanoseconds(100_000_000)));
    try std.testing.expect(Deadline.after(now, 0).at == null);
    try std.testing.expectEqual(deadline.at.?.nanoseconds, Deadline.earliest(.{}, deadline).at.?.nanoseconds);
}

test "read phases only affect their own socket and zero progress timeout stays unlimited" {
    const stream = std.Io.net.Stream{ .socket = .{ .handle = 123, .address = undefined } };
    const backend = std.Io.net.Stream{ .socket = .{ .handle = 124, .address = undefined } };
    begin(std.testing.io, stream, 500);
    defer clear(stream);
    const original = forStream(stream).?.deadline.at.?;
    restart(backend, 1);
    clear(backend);
    try std.testing.expect(forStream(backend) == null);
    try std.testing.expectEqual(original.nanoseconds, forStream(stream).?.deadline.at.?.nanoseconds);
    var state = forStream(stream).?;
    state.track_progress = true;
    state.replace_on_progress = true;
    state.progress_timeout_ms = 0;
    install(state);
    noteProgress(stream);
    try std.testing.expect(forStream(stream).?.progress_started != null);
    try std.testing.expect(forStream(stream).?.deadline.at == null);
}
