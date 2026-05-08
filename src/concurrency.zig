const std = @import("std");

const metrics_mod = @import("metrics.zig");

pub const State = struct {
    active_connections: std.atomic.Value(usize),
    metrics: *metrics_mod.ServerMetrics,

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

    pub fn release(self: *State) void {
        _ = self.active_connections.fetchSub(1, .acq_rel);
        self.metrics.connectionClosed();
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
