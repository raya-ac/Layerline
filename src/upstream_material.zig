const std = @import("std");
const config = @import("config.zig");
const trust = @import("upstream_trust.zig");

pub fn loadAll(io: std.Io, allocator: std.mem.Allocator, cfg: *config.ServerConfig) !void {
    if (cfg.upstream_trust_snapshot != null) return error.UpstreamTrustAlreadyLoaded;
    errdefer deinitAll(cfg);
    if (cfg.h2_upstream) |*target| try loadTarget(io, allocator, cfg, target);
    if (cfg.upstream) |*pool| try loadPool(io, allocator, cfg, pool);
    for (cfg.routes.items) |*route| if (route.upstream) |*pool| try loadPool(io, allocator, cfg, pool);
    for (cfg.domains.items) |*domain| {
        if (domain.upstream) |*pool| try loadPool(io, allocator, cfg, pool);
        for (domain.routes.items) |*route| if (route.upstream) |*pool| try loadPool(io, allocator, cfg, pool);
    }
}

fn loadPool(io: std.Io, allocator: std.mem.Allocator, cfg: *config.ServerConfig, pool: *config.UpstreamPoolConfig) !void {
    for (pool.targets.items) |*target| try loadTarget(io, allocator, cfg, target);
}

fn loadTarget(io: std.Io, allocator: std.mem.Allocator, cfg: *config.ServerConfig, target: *config.UpstreamConfig) !void {
    if (!target.https) return;
    if (cfg.upstream_trust_snapshot == null) cfg.upstream_trust_snapshot = try trust.Snapshot.create(allocator);
    target.tls_trust = try cfg.upstream_trust_snapshot.?.get(io, target.tls_ca_file);
}

// Run only after the snapshot's last reader and its idle TLS connections have
// gone. The boot config and arena-owned reloads use the same ownership rule.
pub fn deinitAll(cfg: *config.ServerConfig) void {
    if (cfg.upstream_trust_snapshot) |snapshot| snapshot.destroy();
    cfg.upstream_trust_snapshot = null;
    if (cfg.h2_upstream) |*target| target.tls_trust = null;
    if (cfg.upstream) |*pool| clearPool(pool);
    for (cfg.routes.items) |*route| if (route.upstream) |*pool| clearPool(pool);
    for (cfg.domains.items) |*domain| {
        if (domain.upstream) |*pool| clearPool(pool);
        for (domain.routes.items) |*route| if (route.upstream) |*pool| clearPool(pool);
    }
}

fn clearPool(pool: *config.UpstreamPoolConfig) void {
    for (pool.targets.items) |*target| target.tls_trust = null;
}

test "every HTTPS scope enforces its worker floor and rolls back failed trust preflight" {
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    var path_buffer: [4096]u8 = undefined;
    const size = try temporary.dir.realPath(std.testing.io, &path_buffer);
    for (0..5) |scope| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        const allocator = arena.allocator();
        var cfg = config.defaultServerConfig();
        defer deinitAll(&cfg);
        const target = try std.fmt.allocPrint(allocator, "https://origin.example.test tls_ca_file={s}/missing.pem", .{path_buffer[0..size]});
        switch (scope) {
            0 => try config.applyConfigLine(&cfg, allocator, "h2_upstream", target),
            1 => try config.applyConfigLine(&cfg, allocator, "proxy", target),
            2 => {
                try config.applyConfigLine(&cfg, allocator, "route", "app /app/* proxy");
                try config.applyConfigLine(&cfg, allocator, "route_proxy.app", target);
            },
            3, 4 => {
                try config.applyConfigLine(&cfg, allocator, "server", "site");
                try config.applyConfigLine(&cfg, allocator, "server_name.site", "site.example.test");
                if (scope == 3) try config.applyConfigLine(&cfg, allocator, "server_proxy.site", target) else {
                    try config.applyConfigLine(&cfg, allocator, "server_route.site", "app /app/* proxy");
                    try config.applyConfigLine(&cfg, allocator, "server_route_proxy.site.app", target);
                }
            },
            else => unreachable,
        }
        try std.testing.expectError(error.InvalidConfigValue, config.validateConfig(&cfg));
        config.normalizeConfig(&cfg);
        try config.validateConfig(&cfg);
        try std.testing.expect(cfg.worker_stack_size >= @import("upstream_tls.zig").handshake_stack_bytes);
        try std.testing.expectError(error.FileNotFound, loadAll(std.testing.io, allocator, &cfg));
        try std.testing.expect(cfg.upstream_trust_snapshot == null);
    }
}
