const std = @import("std");
const resource_budget = @import("resource_budget.zig");
const builtin = @import("builtin");

const acme_renewal = @import("acme_renewal.zig");
const admin_runtime = @import("admin_runtime.zig");
const admin_listener = @import("admin_listener.zig");
const listener_state = @import("listener_state.zig");
const native_accept = @import("native_accept.zig");
const concurrency_mod = @import("concurrency.zig");
const config_mod = @import("config.zig");
const config_store = @import("config_store.zig");
const http1_runtime = @import("http1_runtime.zig");
const http3_server = @import("http3_server.zig");
const metrics_mod = @import("metrics.zig");
const native_connect = @import("native_connect.zig");
const native_spawn = @import("native_spawn.zig");
const static_cache = @import("static_cache.zig");
const systemd_notify = @import("systemd_notify.zig");
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
    supervisor: *systemd_notify.Notifier,
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
    workers_stopped: *std.atomic.Value(bool),
    connections: *concurrency_mod.State,
    admin: ?*admin_listener.Listener,
};

fn forceShutdown(ctx: Context, connections: *concurrency_mod.State, admin: ?*admin_listener.Listener) noreturn {
    _ = native_spawn.tryStopAll(ctx.io);
    std.debug.print("{{\"event\":\"server.shutdown_timeout\",\"active_connections\":{d},\"timeout_ms\":{d}}}\n", .{ connections.active(), ctx.cfg.graceful_shutdown_timeout_ms });
    if (admin) |listener| listener.removePath(ctx.io);
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
    ctx.supervisor.stopping(ctx.io);
    var children_stopped = false;
    while (!state.complete.load(.acquire)) {
        const elapsed = start.durationTo(std.Io.Timestamp.now(ctx.io, .awake)).toMilliseconds();
        const child_cutoff = ctx.cfg.graceful_shutdown_timeout_ms -| @as(u32, 100);
        if (!children_stopped and elapsed >= child_cutoff) {
            children_stopped = native_spawn.tryStopAll(ctx.io);
        }
        if (elapsed >= ctx.cfg.graceful_shutdown_timeout_ms) {
            // The main thread can still be asleep in its drain poll after the
            // last worker releases its lease. Nothing remains to force-kill.
            if (state.workers_stopped.load(.acquire) and state.connections.active() == 0) return;
            forceShutdown(ctx, state.connections, state.admin);
        }
        ctx.io.sleep(.fromMilliseconds(10), .awake) catch {};
    }
}

fn reloadSignalTask(ctx: Context, state: *listener_state.State) void {
    if (!state.awaitReady(ctx.io)) return;
    ctx.callbacks.reload_signal(ctx.io);
}

fn http3Task(ctx: Context, listener: *http3_server.Listener, state: *listener_state.State) void {
    ctx.callbacks.bind_thread_io(ctx.io);
    if (!state.awaitReady(ctx.io)) return;
    http3_server.serveProbeTask(ctx.io, listener, ctx.cfg, ctx.process_env, ctx.metrics, ctx.server_header, ctx.callbacks.acquire_config, ctx.shutdown_requested, ctx.callbacks.http3) catch |err| {
        if (!ctx.shutdown_requested.load(.acquire)) state.fail("http3", err);
    };
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
            if (stream_runtime.connectTcpHost(resource_budget.allocator(), host, ctx.wake_port)) |wake| {
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
    // POSIX listeners poll owned nonblocking descriptors; no other thread
    // closes them underneath accept. Windows retains its existing wake path.
    if (builtin.os.tag != .windows) return;
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
    std.debug.print("Worker stack: {d} bytes\n", .{cfg.worker_stack_size});
    std.debug.print("I/O pool: at most {d} workers, {d} bytes per stack\n", .{ cfg.io_thread_limit, cfg.io_stack_size });
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
    state: *listener_state.State,
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
            .listeners = state,
            .callbacks = ctx.callbacks.http1,
        }},
    ) catch |err| {
        std.debug.print("Failed to start HTTP redirect listener: {}\n", .{err});
        return err;
    };
    std.debug.print("HTTP redirect listener on http://{s}:{d} -> https port {d} status {d}\n", .{ ctx.cfg.host, ctx.cfg.http_redirect_port, ctx.cfg.http_redirect_https_port, ctx.cfg.http_redirect_status });
}

fn startBackgroundWorkers(ctx: Context, workers: *Workers, h3: ?*http3_server.Listener, admin: ?*admin_listener.Listener, state: *listener_state.State) !void {
    try workers.start(reloadSignalTask, .{ ctx, state });
    {
        workers.start(upstream_runtime.healthCheckTask, .{upstream_runtime.HealthCheckContext{ .io = ctx.io, .acquire_config = ctx.callbacks.acquire_config, .callbacks = ctx.callbacks.upstream }}) catch |err| {
            std.debug.print("Failed to start upstream health checker: {}\n", .{err});
            return err;
        };
        if (config_mod.configCanRunHealthChecks(ctx.cfg)) std.debug.print("Active upstream health checks enabled for configured upstream pools\n", .{});
    }
    if (h3) |listener| {
        workers.start(http3Task, .{ ctx, listener, state }) catch |err| {
            std.debug.print("Failed to start HTTP/3 native listener: {}\n", .{err});
            return err;
        };
    }
    if (admin) |listener| {
        const admin_socket_path = ctx.cfg.admin_socket_path orelse ctx.default_admin_socket_path;
        workers.start(admin_runtime.serveSocketTask, .{admin_runtime.SocketContext{ .io = ctx.io, .cfg = ctx.cfg, .socket_path = admin_socket_path, .listener = listener, .state = state, .callbacks = ctx.callbacks.admin }}) catch |err| {
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

fn acceptConnections(ctx: Context, server: *std.Io.net.Server, concurrency: *concurrency_mod.State) !void {
    while (!ctx.shutdown_requested.load(.acquire)) {
        const conn = (try native_accept.next(ctx.io, server, ctx.shutdown_requested)) orelse break;

        var lease = ctx.callbacks.acquire_config();
        const active_cfg = lease.cfg;
        if (!concurrency.tryAcquire(active_cfg.max_concurrent_connections)) {
            ctx.metrics.connectionRejected();
            std.debug.print("Rejecting connection: max concurrency reached ({d})\n", .{active_cfg.max_concurrent_connections});
            // No TLS session exists at admission. Close overloaded HTTPS
            // sockets rather than sending an unencrypted HTTP error.
            if (!active_cfg.tls_enabled) http1_runtime.sendOverload(ctx.io, conn, false, ctx.callbacks.http1) catch {};
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
    try native_accept.prepare(&server);
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
        try native_accept.prepare(&redirect_server.?);
    }

    var h3: ?http3_server.Listener = if (ctx.cfg.http3_enabled) try .init(ctx.io, ctx.cfg) else null;
    defer if (h3) |*listener| listener.deinit(ctx.io);
    var admin: ?admin_listener.Listener = if (ctx.cfg.admin_enabled) try .init(ctx.io, ctx.allocator, ctx.cfg.admin_socket_path orelse ctx.default_admin_socket_path) else null;
    defer if (admin) |*listener| listener.deinit(ctx.io);
    var listeners: listener_state.State = .{ .shutdown = ctx.shutdown_requested };

    var workers = Workers{};
    var shutdown_complete = std.atomic.Value(bool).init(false);
    var workers_stopped = std.atomic.Value(bool).init(false);
    const deadline_worker = try std.Thread.spawn(.{}, shutdownDeadlineTask, .{ShutdownDeadlineContext{ .ctx = ctx, .complete = &shutdown_complete, .workers_stopped = &workers_stopped, .connections = &concurrency, .admin = if (admin) |*value| value else null }});
    defer {
        ctx.shutdown_requested.store(true, .release);
        ctx.supervisor.stopping(ctx.io);
        std.debug.print("Shutdown requested; draining workers for up to {d}ms.\n", .{ctx.cfg.graceful_shutdown_timeout_ms});
        concurrency.beginDrain(ctx.io);
        workers.join();
        workers_stopped.store(true, .release);
        concurrency_mod.waitForDrain(ctx.io, &concurrency, ctx.cfg.graceful_shutdown_timeout_ms);
        if (concurrency.active() != 0) {
            // The independent deadline guard exits before this wait can overrun.
            // Do not return through stack/config destructors with live readers.
            forceShutdown(ctx, &concurrency, if (admin) |*value| value else null);
        }
        shutdown_complete.store(true, .release);
        deadline_worker.join();
        std.debug.print("All connection and background workers stopped.\n", .{});
    }

    try startShutdownWatcher(&workers, ctx.io, &server, &listener_closed_by_shutdown, ctx.cfg, ctx.cfg.port, ctx.shutdown_requested, "primary");
    if (redirect_server) |*http_server| {
        try startRedirectListener(ctx, &workers, http_server, &concurrency, &redirect_listener_closed_by_shutdown, &listeners);
    }

    try startBackgroundWorkers(ctx, &workers, if (h3) |*value| value else null, if (admin) |*value| value else null, &listeners);
    if (ctx.shutdown_requested.load(.acquire)) {
        try listeners.result();
        return;
    }
    try ctx.supervisor.ready(ctx.io, ctx.shutdown_requested);
    printStartupSummary(ctx.cfg);
    listeners.ready.store(true, .release);
    std.debug.print("{{\"event\":\"server.ready\"}}\n", .{});
    acceptConnections(ctx, &server, &concurrency) catch |err| {
        if (!ctx.shutdown_requested.load(.acquire)) listeners.fail("primary", err);
    };
    try listeners.result();
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
