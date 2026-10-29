const std = @import("std");

const metrics_mod = @import("metrics.zig");

pub const Connection = struct {
    state: *State,
    stream: std.Io.net.Stream,
    previous: ?*Connection = null,
    next: ?*Connection = null,
    idle: bool = true,
};

threadlocal var current_connection: ?*Connection = null;

pub fn setCurrentIdle(io: std.Io, idle: bool) void {
    const node = current_connection orelse return;
    node.state.mutex.lockUncancelable(io);
    defer node.state.mutex.unlock(io);
    node.idle = idle;
    if (idle and node.state.draining) node.stream.shutdown(io, .recv) catch {};
}

pub const State = struct {
    active_connections: std.atomic.Value(usize),
    metrics: *metrics_mod.ServerMetrics,
    mutex: std.Io.Mutex = .init,
    head: ?*Connection = null,
    draining: bool = false,

    pub fn init(metrics: *metrics_mod.ServerMetrics) State {
        return .{
            .active_connections = std.atomic.Value(usize).init(0),
            .metrics = metrics,
        };
    }

    pub fn tryAcquire(self: *State, limit: usize) bool {
        while (true) {
            const current = self.active_connections.load(.acquire);
            if (current >= limit) return false;
            if (self.active_connections.cmpxchgWeak(current, current + 1, .acq_rel, .acquire) == null) {
                self.metrics.connectionAccepted();
                return true;
            }
        }
    }

    pub fn register(self: *State, io: std.Io, node: *Connection) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        node.next = self.head;
        if (self.head) |head| head.previous = node;
        self.head = node;
        current_connection = node;
        if (self.draining) node.stream.shutdown(io, .recv) catch {};
    }

    pub fn unregister(self: *State, io: std.Io, node: *Connection) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        if (node.previous) |previous| previous.next = node.next else self.head = node.next;
        if (node.next) |next| next.previous = node.previous;
        current_connection = null;
    }

    pub fn beginDrain(self: *State, io: std.Io) void {
        self.mutex.lockUncancelable(io);
        defer self.mutex.unlock(io);
        self.draining = true;
        // The registry lock keeps socket ownership stable until shutdown returns;
        // workers unlink before close, so a reused descriptor cannot be targeted.
        var cursor = self.head;
        while (cursor) |node| : (cursor = node.next) {
            if (node.idle) node.stream.shutdown(io, .recv) catch {};
        }
    }

    pub fn release(self: *State) void {
        self.metrics.connectionClosed();
        // Publishing zero is the worker's final access to shared runtime state.
        _ = self.active_connections.fetchSub(1, .acq_rel);
    }

    pub fn active(self: *State) usize {
        return self.active_connections.load(.acquire);
    }
};

pub fn waitForDrain(io: std.Io, state: *State, timeout_ms: u32) void {
    var remaining = timeout_ms;
    while (state.active() > 0 and remaining > 0) {
        const step_ms: u32 = @min(@as(u32, 50), remaining);
        io.sleep(.fromMilliseconds(step_ms), .awake) catch {};
        remaining -= step_ms;
    }
}

test "connection gate stops at its limit and released capacity is reusable" {
    var metrics = metrics_mod.ServerMetrics.init();
    var state = State.init(&metrics);
    try std.testing.expect(!state.tryAcquire(0));
    try std.testing.expect(state.tryAcquire(2));
    try std.testing.expect(state.tryAcquire(2));
    try std.testing.expect(!state.tryAcquire(2));
    try std.testing.expectEqual(2, state.active());
    state.release();
    try std.testing.expect(state.tryAcquire(2));
    state.release();
    state.release();
    try std.testing.expectEqual(0, state.active());
    try std.testing.expectEqual(0, metrics.active_connections.load(.monotonic));
    try std.testing.expectEqual(3, metrics.connections_total.load(.monotonic));
}
