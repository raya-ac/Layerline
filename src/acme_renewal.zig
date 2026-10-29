const std = @import("std");
const config_mod = @import("config.zig");
const config_store = @import("config_store.zig");

pub const Context = struct {
    io: std.Io,
    acquire_config: *const fn () config_store.Lease,
    shutdown_requested: *std.atomic.Value(bool),
    bind_thread_io: *const fn (std.Io) void,
    renew_certs: *const fn (std.Io, std.mem.Allocator, *const config_mod.ServerConfig) anyerror!void,
};

const Schedule = struct {
    enabled: bool = false,
    interval_ms: u32 = 0,
    next_ms: i64 = 0,

    fn ready(self: *Schedule, enabled: bool, now_ms: i64, interval_ms: u32) bool {
        if (!enabled) {
            self.enabled = false;
            return false;
        }
        const next = now_ms +| @as(i64, @intCast(@max(interval_ms, 1)));
        if (!self.enabled) {
            self.enabled = true;
            self.interval_ms = interval_ms;
            self.next_ms = next;
            return false;
        }
        // Unrelated reloads must not keep postponing certificate renewal.
        if (self.interval_ms != interval_ms) {
            self.interval_ms = interval_ms;
            self.next_ms = @min(self.next_ms, next);
        }
        if (now_ms < self.next_ms) return false;
        self.next_ms = next;
        return true;
    }
};

pub fn renewalTask(ctx: Context) void {
    ctx.bind_thread_io(ctx.io);
    var schedule = Schedule{};
    while (!ctx.shutdown_requested.load(.acquire)) {
        {
            var lease = ctx.acquire_config();
            defer lease.deinit();
            const cfg = lease.cfg;
            const now_ms = std.Io.Timestamp.now(ctx.io, .awake).toMilliseconds();
            if (schedule.ready(cfg.tls_auto and cfg.letsencrypt_renew, now_ms, cfg.letsencrypt_renew_interval_ms)) {
                ctx.renew_certs(ctx.io, std.heap.page_allocator, cfg) catch |err| {
                    std.debug.print("Let's Encrypt renewal failed: {}\n", .{err});
                };
            }
        }
        // Only numeric schedule state survives sleep, never a config pointer.
        ctx.io.sleep(.fromMilliseconds(250), .awake) catch {};
    }
}

test "renewal scheduling follows current policy without starvation from reloads" {
    var schedule = Schedule{};
    try std.testing.expect(!schedule.ready(false, 100, 1000));
    try std.testing.expect(!schedule.ready(false, 1200, 1000));
    try std.testing.expect(!schedule.ready(true, 1200, 500));
    try std.testing.expect(!schedule.ready(true, 1699, 500));
    try std.testing.expect(schedule.ready(true, 1700, 500));
    try std.testing.expect(!schedule.ready(true, 1800, 100));
    try std.testing.expect(schedule.ready(true, 1900, 1000));
    try std.testing.expect(!schedule.ready(true, 2899, 1000));
    try std.testing.expect(schedule.ready(true, 2900, 1000));
    try std.testing.expect(!schedule.ready(false, 3000, 500));
    try std.testing.expect(!schedule.ready(false, 5000, 500));
    try std.testing.expect(!schedule.ready(true, 5100, 500));
    try std.testing.expect(schedule.ready(true, 5600, 500));
}
