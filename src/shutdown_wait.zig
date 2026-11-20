const std = @import("std");

pub fn sleepUntilShutdown(io: std.Io, shutdown: *std.Io.Event, interval_ms: u32) void {
    const timeout = (std.Io.Timeout{ .duration = .{ .raw = .fromMilliseconds(interval_ms), .clock = .awake } }).toDeadline(io);
    while (true) {
        shutdown.waitTimeout(io, timeout) catch |err| switch (err) {
            error.Canceled => return,
            // A spurious wake should not run maintenance early or reset its interval.
            error.Timeout => {
                if (timeout.deadline.durationFromNow(io).raw.nanoseconds <= 0) return;
                continue;
            },
        };
        return;
    }
}

test "the shutdown event releases maintenance waiters and stays set" {
    const Waiter = struct {
        fn run(shutdown: *std.Io.Event, ready: *std.Io.Event, done: *std.atomic.Value(usize)) void {
            ready.set(std.testing.io);
            sleepUntilShutdown(std.testing.io, shutdown, 5000);
            if (shutdown.isSet()) _ = done.fetchAdd(1, .monotonic);
        }
    };
    var shutdown: std.Io.Event = .unset;
    var ready_a: std.Io.Event = .unset;
    var ready_b: std.Io.Event = .unset;
    var done = std.atomic.Value(usize).init(0);
    const first = try std.Thread.spawn(.{}, Waiter.run, .{ &shutdown, &ready_a, &done });
    const second = std.Thread.spawn(.{}, Waiter.run, .{ &shutdown, &ready_b, &done }) catch |err| {
        shutdown.set(std.testing.io);
        first.join();
        return err;
    };
    ready_a.waitUncancelable(std.testing.io);
    ready_b.waitUncancelable(std.testing.io);
    const start = std.Io.Timestamp.now(std.testing.io, .awake);
    shutdown.set(std.testing.io);
    first.join();
    second.join();
    // A late waiter must not miss the wake even if both others have returned.
    sleepUntilShutdown(std.testing.io, &shutdown, 5000);
    try std.testing.expectEqual(2, done.load(.monotonic));
    try std.testing.expect(start.durationTo(.now(std.testing.io, .awake)).toMilliseconds() < 3000);
}

test "maintenance still wakes after its interval without shutdown" {
    const io = std.testing.io;
    var shutdown: std.Io.Event = .unset;
    const start = std.Io.Timestamp.now(io, .awake);
    sleepUntilShutdown(io, &shutdown, 5);
    try std.testing.expect(start.durationTo(.now(io, .awake)).toMilliseconds() >= 5);
    try std.testing.expect(!shutdown.isSet());
}
