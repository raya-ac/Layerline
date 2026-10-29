const std = @import("std");

const acme_renewal = @import("acme_renewal.zig");
const admin_runtime = @import("admin_runtime.zig");
const concurrency_mod = @import("concurrency.zig");
const config_mod = @import("config.zig");
const config_store = @import("config_store.zig");
const http1_runtime = @import("http1_runtime.zig");
const http3_server = @import("http3_server.zig");
const metrics_mod = @import("metrics.zig");
const static_cache = @import("static_cache.zig");
const stream_runtime = @import("stream_runtime.zig");
const upstream_mod = @import("upstream.zig");
const upstream_runtime = @import("upstream_runtime.zig");

const ServerConfig = config_mod.ServerConfig;
const ServerMetrics = metrics_mod.ServerMetrics;

pub const Callbacks = struct {
    acquire_config: *const fn () config_store.Lease,
    admin: admin_runtime.Callbacks,
    bind_thread_io: *const fn (std.Io) void,
    http1: http1_runtime.Callbacks,
    http3: http3_server.Callbacks,
    reload_signal: *const fn (std.Io) void,
    send_cool_error: *const fn (std.Io.net.Stream, std.mem.Allocator, u16, []const u8, []const u8) anyerror!void,
    upstream: upstream_runtime.Callbacks,
};

pub const Context = struct {
    io: std.Io,
    allocator: std.mem.Allocator,
    cfg: *ServerConfig,
    process_env: *const std.process.Environ.Map,
    metrics: *ServerMetrics,
    response_cache: *static_cache.Store,
    shutdown_requested: *std.atomic.Value(bool),
    default_admin_socket_path: []const u8,
    server_header: []const u8,
    callbacks: Callbacks,
};

const Workers = struct {
    threads: [8]?std.Thread = @splat(null),
    count: usize = 0,

    fn start(self: *Workers, comptime task: anytype, args: anytype) !void {
        if (self.count == self.threads.len) return error.TooManyBackgroundWorkers;
        self.threads[self.count] = try std.Thread.spawn(.{}, task, args);
        self.count += 1;
    }

    fn join(self: *Workers) void {
        while (self.count > 0) {
            self.count -= 1;
            self.threads[self.count].?.join();
            self.threads[self.count] = null;
        }
    }
};

const ShutdownDeadlineContext = struct {
    ctx: Context,
    complete: *std.atomic.Value(bool),
    connections: *concurrency_mod.State,
};

fn forceShutdown(ctx: Context, connections: *concurrency_mod.State) noreturn {
    std.debug.print("{{\"event\":\"server.shutdown_timeout\",\"active_connections\":{d},\"timeout_ms\":{d}}}\n", .{ connections.active(), ctx.cfg.graceful_shutdown_timeout_ms });
    if (ctx.cfg.admin_enabled) {
        admin_runtime.unlinkUnixSocket(ctx.cfg.admin_socket_path orelse ctx.default_admin_socket_path, ctx.callbacks.admin);
    }
    // A worker may still borrow config, caches, or stack-owned state.
    // Let the OS reclaim them together; unwinding would free live memory.
    std.process.exit(1);
}

fn shutdownDeadlineTask(state: ShutdownDeadlineContext) void {
    const ctx = state.ctx;
    ctx.callbacks.bind_thread_io(ctx.io);
    while (!ctx.shutdown_requested.load(.acquire)) {
        if (state.complete.load(.acquire)) return;
        ctx.io.sleep(.fromMilliseconds(10), .awake) catch {};
    }
    const start = std.Io.Timestamp.now(ctx.io, .awake);
    while (!state.complete.load(.acquire)) {
        const elapsed = start.durationTo(std.Io.Timestamp.now(ctx.io, .awake)).toMilliseconds();
        if (elapsed >= ctx.cfg.graceful_shutdown_timeout_ms) {
            forceShutdown(ctx, state.connections);
        }
        ctx.io.sleep(.fromMilliseconds(10), .awake) catch {};
    }
}

fn wakeAdminListener(ctx: Context) void {
    if (!ctx.cfg.admin_enabled) return;
    const address = std.Io.net.UnixAddress.init(ctx.cfg.admin_socket_path orelse ctx.default_admin_socket_path) catch return;
    const conn = address.connect(ctx.io) catch return;
    conn.close(ctx.io);
}

fn reloadSignalTask(ctx: Context) void {
    ctx.callbacks.reload_signal(ctx.io);
}

fn http3Task(ctx: Context) void {
    ctx.callbacks.bind_thread_io(ctx.io);
    http3_server.serveProbeTask(ctx.io, ctx.cfg, ctx.process_env, ctx.metrics, ctx.server_header, ctx.callbacks.acquire_config, ctx.shutdown_requested, ctx.callbacks.http3);
}

const ShutdownWatcherContext = struct {
    io: std.Io,
    server: *std.Io.net.Server,
    closed: *std.atomic.Value(bool),
    shutdown_requested: *std.atomic.Value(bool),
    wake_host: ?[]const u8 = null,
    wake_port: u16 = 0,
};

fn shutdownWatcherTask(ctx: ShutdownWatcherContext) void {
    stream_runtime.bindThreadIo(ctx.io);
    while (!ctx.shutdown_requested.load(.acquire)) {
        ctx.io.sleep(.fromMilliseconds(25), .awake) catch {};
    }

    if (ctx.wake_host) |host| {
        if (ctx.wake_port != 0) {
            if (stream_runtime.connectTcpHost(std.heap.page_allocator, host, ctx.wake_port)) |wake| {
                stream_runtime.streamClose(wake);
            } else |_| {}
        }
    }
    if (!ctx.closed.swap(true, .acq_rel)) {
        ctx.server.socket.close(ctx.io);
    }
}

fn startShutdownWatcher(
    workers: *Workers,
    io: std.Io,
    server: *std.Io.net.Server,
    closed: *std.atomic.Value(bool),
    cfg: *const ServerConfig,
    port: u16,
    shutdown_requested: *std.atomic.Value(bool),
    label: []const u8,
) !void {
    workers.start(
        shutdownWatcherTask,
        .{ShutdownWatcherContext{
            .io = io,
            .server = server,
            .closed = closed,
            .shutdown_requested = shutdown_requested,
            .wake_host = stream_runtime.listenerWakeHost(cfg.host),
            .wake_port = port,
        }},
    ) catch |err| {
        std.debug.print("Failed to start {s} shutdown watcher: {}\n", .{ label, err });
        return err;
    };
}

fn printStartupSummary(cfg: *const ServerConfig) void {
    std.debug.print("Serving on {s}://{s}:{d}\n", .{ if (cfg.tls_enabled) "https" else "http", cfg.host, cfg.port });
    std.debug.print("Concurrency limit: {d} concurrent connection handlers\n", .{cfg.max_concurrent_connections});
    if (cfg.upstream != null) {
        const pool = cfg.upstream.?;
        std.debug.print(
            "Reverse proxy pool: {s} over {d} target(s), retries={d}, max_failures={d}, fail_timeout={d}ms, circuit={s} half_open={d}, slow_start={d}ms, keepalive={s} max_idle={d}\n",
            .{
                config_mod.upstreamPoolPolicyName(cfg.upstream_policy),
                upstream_mod.upstreamPoolTargetCount(pool),
                cfg.upstream_retries,
                cfg.upstream_max_failures,
                cfg.upstream_fail_timeout_ms,
                if (cfg.upstream_circuit_breaker_enabled) "on" else "off",
                cfg.upstream_circuit_half_open_max,
                cfg.upstream_slow_start_ms,
                if (cfg.upstream_keepalive_enabled and cfg.upstream_keepalive_max_idle > 0) "on" else "off",
                cfg.upstream_keepalive_max_idle,
            },
        );
    }
    if (cfg.h2_upstream != null) {
        const hup = cfg.h2_upstream.?;
        std.debug.print("HTTP/2 cleartext passthrough to: {s}:{d} (base {s})\n", .{ hup.host, hup.port, hup.base_path });
    }
    std.debug.print(
        "Timeouts: header={d}ms body={d}ms idle={d}ms write={d}ms upstream={d}ms upstream_retries={d} graceful_shutdown={d}ms\n",
        .{
            cfg.read_header_timeout_ms,
            cfg.read_body_timeout_ms,
            cfg.idle_timeout_ms,
            cfg.write_timeout_ms,
            cfg.upstream_timeout_ms,
            cfg.upstream_retries,
            cfg.graceful_shutdown_timeout_ms,
        },
    );
}

fn startRedirectListener(
    ctx: Context,
    workers: *Workers,
    redirect_server: *std.Io.net.Server,
    concurrency: *concurrency_mod.State,
    redirect_closed: *std.atomic.Value(bool),
) !void {
    try startShutdownWatcher(workers, ctx.io, redirect_server, redirect_closed, ctx.cfg, ctx.cfg.http_redirect_port, ctx.shutdown_requested, "HTTP redirect");

    workers.start(
        http1_runtime.serveHttpRedirectListenerTask,
        .{http1_runtime.HttpRedirectListenerContext{
            .io = ctx.io,
            .server = redirect_server,
            .cfg = ctx.cfg,
            .allocator = ctx.allocator,
            .state = concurrency,
            .callbacks = ctx.callbacks.http1,
        }},
    ) catch |err| {
        std.debug.print("Failed to start HTTP redirect listener: {}\n", .{err});
        return err;
    };
    std.debug.print("HTTP redirect listener on http://{s}:{d} -> https port {d} status {d}\n", .{ ctx.cfg.host, ctx.cfg.http_redirect_port, ctx.cfg.http_redirect_https_port, ctx.cfg.http_redirect_status });
}

fn startBackgroundWorkers(ctx: Context, workers: *Workers) !void {
    try workers.start(reloadSignalTask, .{ctx});
    {
        workers.start(upstream_runtime.healthCheckTask, .{upstream_runtime.HealthCheckContext{ .io = ctx.io, .acquire_config = ctx.callbacks.acquire_config, .callbacks = ctx.callbacks.upstream }}) catch |err| {
            std.debug.print("Failed to start upstream health checker: {}\n", .{err});
            return err;
        };
        if (config_mod.configCanRunHealthChecks(ctx.cfg)) std.debug.print("Active upstream health checks enabled for configured upstream pools\n", .{});
    }
    if (ctx.cfg.http3_enabled) {
        workers.start(http3Task, .{ctx}) catch |err| {
            std.debug.print("Failed to start HTTP/3 native listener: {}\n", .{err});
            return err;
        };
    }
    if (ctx.cfg.admin_enabled) {
        const admin_socket_path = ctx.cfg.admin_socket_path orelse ctx.default_admin_socket_path;
        workers.start(admin_runtime.serveSocketTask, .{admin_runtime.SocketContext{ .io = ctx.io, .cfg = ctx.cfg, .socket_path = admin_socket_path, .callbacks = ctx.callbacks.admin }}) catch |err| {
            std.debug.print("Failed to start admin socket: {}\n", .{err});
            return err;
        };
    }
    if (ctx.cfg.tls_auto) {
        workers.start(acme_renewal.renewalTask, .{acme_renewal.Context{
            .io = ctx.io,
            .acquire_config = ctx.callbacks.acquire_config,
            .shutdown_requested = ctx.shutdown_requested,
            .bind_thread_io = ctx.callbacks.bind_thread_io,
            .renew_certs = ctx.callbacks.admin.renew_certs,
        }}) catch |err| {
            std.debug.print("Failed to start Let's Encrypt renewal loop: {}\n", .{err});
            return err;
        };
    }
}

fn acceptConnections(ctx: Context, server: *std.Io.net.Server, concurrency: *concurrency_mod.State) void {
    while (!ctx.shutdown_requested.load(.acquire)) {
        const conn = server.accept(ctx.io) catch |err| {
            if (ctx.shutdown_requested.load(.acquire)) break;
            std.debug.print("Accept failed: {}. Continuing to accept.\n", .{err});
            ctx.io.sleep(.fromMilliseconds(25), .awake) catch {};
            continue;
        };
        if (ctx.shutdown_requested.load(.acquire)) {
            stream_runtime.streamClose(conn);
            break;
        }

        var lease = ctx.callbacks.acquire_config();
        const active_cfg = lease.cfg;
        if (!concurrency.tryAcquire(active_cfg.max_concurrent_connections)) {
            ctx.metrics.connectionRejected();
            std.debug.print("Rejecting connection: max concurrency reached ({d})\n", .{active_cfg.max_concurrent_connections});
            ctx.callbacks.send_cool_error(
                conn,
                ctx.allocator,
                503,
                "Service Unavailable",
                "Maximum concurrent connections reached. Try again in a moment.",
            ) catch {};
            stream_runtime.streamClose(conn);
            lease.deinit();
            continue;
        }

        const worker = std.Thread.spawn(
            .{
                .stack_size = active_cfg.worker_stack_size,
            },
            http1_runtime.serveConnectionTask,
            .{
                ctx.io,
                conn,
                lease,
                ctx.allocator,
                concurrency,
                ctx.process_env,
                ctx.callbacks.http1,
            },
        ) catch |err| {
            std.debug.print("Failed to start connection worker: {}\n", .{err});
            stream_runtime.streamClose(conn);
            lease.deinit();
            concurrency.release();
            continue;
        };
        worker.detach();
    }
}

pub fn run(ctx: Context) !void {
    var concurrency = concurrency_mod.State.init(ctx.metrics);

    var address = try std.Io.net.IpAddress.parse(ctx.cfg.host, ctx.cfg.port);
    var server = try address.listen(ctx.io, .{ .reuse_address = true });
    var listener_closed_by_shutdown = std.atomic.Value(bool).init(false);
    var redirect_listener_closed_by_shutdown = std.atomic.Value(bool).init(false);
    var redirect_server: ?std.Io.net.Server = null;
    defer {
        if (!listener_closed_by_shutdown.load(.acquire)) {
            server.deinit(ctx.io);
        }
    }
    defer {
        if (redirect_server) |*http_server| {
            if (!redirect_listener_closed_by_shutdown.load(.acquire)) {
                http_server.deinit(ctx.io);
            }
        }
    }
    if (ctx.cfg.http_redirect_enabled) {
        const redirect_address = try std.Io.net.IpAddress.parse(ctx.cfg.host, ctx.cfg.http_redirect_port);
        redirect_server = try redirect_address.listen(ctx.io, .{ .reuse_address = true });
    }

    var workers = Workers{};
    var shutdown_complete = std.atomic.Value(bool).init(false);
    const deadline_worker = try std.Thread.spawn(.{}, shutdownDeadlineTask, .{ShutdownDeadlineContext{ .ctx = ctx, .complete = &shutdown_complete, .connections = &concurrency }});
    defer {
        ctx.shutdown_requested.store(true, .release);
        std.debug.print("Shutdown requested; draining workers for up to {d}ms.\n", .{ctx.cfg.graceful_shutdown_timeout_ms});
        concurrency.beginDrain(ctx.io);
        wakeAdminListener(ctx);
        workers.join();
        concurrency_mod.waitForDrain(ctx.io, &concurrency, ctx.cfg.graceful_shutdown_timeout_ms);
        if (concurrency.active() != 0) {
            // The independent deadline guard exits before this wait can overrun.
            // Do not return through stack/config destructors with live readers.
            forceShutdown(ctx, &concurrency);
        }
        shutdown_complete.store(true, .release);
        deadline_worker.join();
        std.debug.print("All connection and background workers stopped.\n", .{});
    }

    try startShutdownWatcher(&workers, ctx.io, &server, &listener_closed_by_shutdown, ctx.cfg, ctx.cfg.port, ctx.shutdown_requested, "primary");
    if (redirect_server) |*http_server| {
        try startRedirectListener(ctx, &workers, http_server, &concurrency, &redirect_listener_closed_by_shutdown);
    }

    printStartupSummary(ctx.cfg);
    try startBackgroundWorkers(ctx, &workers);
    acceptConnections(ctx, &server, &concurrency);
}

fn testWorker(counter: *std.atomic.Value(usize)) void {
    _ = counter.fetchAdd(1, .monotonic);
}

test "managed workers remain joinable after a later startup failure" {
    var workers = Workers{};
    defer workers.join();
    var counter = std.atomic.Value(usize).init(0);
    for (0..workers.threads.len) |_| try workers.start(testWorker, .{&counter});
    try std.testing.expectError(error.TooManyBackgroundWorkers, workers.start(testWorker, .{&counter}));
    workers.join();
    try std.testing.expectEqual(workers.threads.len, counter.load(.monotonic));
    try std.testing.expectEqual(0, workers.count);
}
