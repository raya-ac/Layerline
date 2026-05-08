const std = @import("std");

const acme_mod = @import("acme.zig");
const config_mod = @import("config.zig");
const metrics_mod = @import("metrics.zig");

const ServerConfig = config_mod.ServerConfig;
const ServerMetrics = metrics_mod.ServerMetrics;

pub const Context = struct {
    io: std.Io,
    cfg: *const ServerConfig,
    metrics: *ServerMetrics,
    shutdown_requested: *std.atomic.Value(bool),
    bind_thread_io: *const fn (std.Io) void,
};

fn sleepUntilShutdown(io: std.Io, shutdown_requested: *std.atomic.Value(bool), total_ms: u32) bool {
    var remaining = total_ms;
    while (remaining > 0 and !shutdown_requested.load(.acquire)) {
        const step_ms: u32 = @min(@as(u32, 1_000), remaining);
        io.sleep(.fromMilliseconds(step_ms), .awake) catch {};
        remaining -= step_ms;
    }
    return shutdown_requested.load(.acquire);
}

pub fn renewalTask(ctx: Context) void {
    ctx.bind_thread_io(ctx.io);
    std.debug.print("Let's Encrypt renewal loop: interval={d}ms webroot={s}\n", .{ ctx.cfg.letsencrypt_renew_interval_ms, ctx.cfg.letsencrypt_webroot });

    while (!ctx.shutdown_requested.load(.acquire)) {
        if (sleepUntilShutdown(ctx.io, ctx.shutdown_requested, ctx.cfg.letsencrypt_renew_interval_ms)) break;
        acme_mod.runLetsEncryptRenewal(ctx.io, std.heap.page_allocator, ctx.cfg, ctx.metrics) catch |err| {
            std.debug.print("Let's Encrypt renewal failed: {}\n", .{err});
        };
    }
}
