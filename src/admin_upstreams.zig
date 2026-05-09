const std = @import("std");

const admin_support = @import("admin_support.zig");
const config_mod = @import("config.zig");
const routing = @import("routing.zig");
const upstream_mod = @import("upstream.zig");

const DomainConfig = config_mod.DomainConfig;
const RouteConfig = config_mod.RouteConfig;
const ServerConfig = config_mod.ServerConfig;
const UpstreamConfig = config_mod.UpstreamConfig;
const UpstreamPoolConfig = config_mod.UpstreamPoolConfig;
const UpstreamPoolPolicy = config_mod.UpstreamPoolPolicy;
const UpstreamRuntimePolicy = config_mod.UpstreamRuntimePolicy;

pub const DEFAULT_MANUAL_EJECT_MS: u32 = 60_000;

pub const ControlAction = enum {
    eject,
    recover,
};

pub const TargetAddress = struct {
    scope: []const u8,
    domain: []const u8 = "",
    route: []const u8 = "",
    index: usize,
};

fn nowMs(io: std.Io) i64 {
    return std.Io.Timestamp.now(io, .awake).toMilliseconds();
}

fn findRouteMutable(routes: []RouteConfig, name: []const u8) ?*RouteConfig {
    for (routes) |*route| {
        if (std.mem.eql(u8, route.name, name)) return route;
    }
    return null;
}

fn findDomainMutable(cfg: *ServerConfig, name: []const u8) ?*DomainConfig {
    for (cfg.domains.items) |*domain| {
        if (std.mem.eql(u8, domain.name, name)) return domain;
    }
    return null;
}

fn poolTarget(pool: *UpstreamPoolConfig, index: usize) !*UpstreamConfig {
    if (index >= pool.targets.items.len) return error.UpstreamIndexOutOfRange;
    return &pool.targets.items[index];
}

pub fn findTarget(cfg: *ServerConfig, address: TargetAddress) !*UpstreamConfig {
    if (std.mem.eql(u8, address.scope, "global")) {
        if (cfg.upstream) |*pool| return poolTarget(pool, address.index);
        return error.UpstreamPoolMissing;
    }

    if (std.mem.eql(u8, address.scope, "route")) {
        const route = findRouteMutable(cfg.routes.items, address.route) orelse return error.RouteNotFound;
        if (route.upstream) |*pool| return poolTarget(pool, address.index);
        return error.UpstreamPoolMissing;
    }

    if (std.mem.eql(u8, address.scope, "domain")) {
        const domain = findDomainMutable(cfg, address.domain) orelse return error.DomainNotFound;
        if (domain.upstream) |*pool| return poolTarget(pool, address.index);
        return error.UpstreamPoolMissing;
    }

    if (std.mem.eql(u8, address.scope, "domain-route")) {
        const domain = findDomainMutable(cfg, address.domain) orelse return error.DomainNotFound;
        const route = findRouteMutable(domain.routes.items, address.route) orelse return error.RouteNotFound;
        if (route.upstream) |*pool| return poolTarget(pool, address.index);
        return error.UpstreamPoolMissing;
    }

    return error.InvalidUpstreamScope;
}

pub fn applyControlAt(now_ms: i64, cfg: *ServerConfig, action: ControlAction, address: TargetAddress, duration_ms: u32) !void {
    const target = try findTarget(cfg, address);
    switch (action) {
        .eject => {
            const effective_ms = if (duration_ms == 0) DEFAULT_MANUAL_EJECT_MS else duration_ms;
            const until_ms = now_ms + @as(i64, @intCast(effective_ms));
            if (target.passive_failures.load(.monotonic) == 0) target.passive_failures.store(1, .monotonic);
            target.ejected_until_ms.store(until_ms, .monotonic);
            target.recovered_at_ms.store(0, .monotonic);
        },
        .recover => {
            target.passive_failures.store(0, .monotonic);
            target.ejected_until_ms.store(0, .monotonic);
            target.recovered_at_ms.store(now_ms, .monotonic);
        },
    }
}

pub fn applyControl(io: std.Io, cfg: *ServerConfig, action: ControlAction, address: TargetAddress, duration_ms: u32) !void {
    return applyControlAt(nowMs(io), cfg, action, address, duration_ms);
}

fn boolText(value: bool) []const u8 {
    return if (value) "true" else "false";
}

fn targetState(upstream: *const UpstreamConfig, now_ms: i64, policy: UpstreamRuntimePolicy) []const u8 {
    const ejected_until = upstream.ejected_until_ms.load(.monotonic);
    if (ejected_until > now_ms) return "ejected";
    if (ejected_until != 0 and policy.circuit_breaker_enabled) return "half-open";
    const recovered_at = upstream.recovered_at_ms.load(.monotonic);
    if (recovered_at != 0 and policy.slow_start_ms > 0 and now_ms >= recovered_at and now_ms - recovered_at < @as(i64, @intCast(policy.slow_start_ms))) return "slow-start";
    return "healthy";
}

fn ejectedForMs(upstream: *const UpstreamConfig, now_ms: i64) i64 {
    const ejected_until = upstream.ejected_until_ms.load(.monotonic);
    if (ejected_until <= now_ms) return 0;
    return ejected_until - now_ms;
}

fn appendPoolReport(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    label: []const u8,
    pool: *const UpstreamPoolConfig,
    effective_policy: UpstreamPoolPolicy,
    runtime_policy: UpstreamRuntimePolicy,
    now_ms: i64,
) !void {
    try out.print(
        allocator,
        "{s} policy={s} targets={d} timeout_ms={d} retries={d} health={s} circuit_breaker={s}\n",
        .{
            label,
            config_mod.upstreamPoolPolicyName(effective_policy),
            pool.targets.items.len,
            runtime_policy.timeout_ms,
            runtime_policy.retries,
            boolText(runtime_policy.health_check_enabled),
            boolText(runtime_policy.circuit_breaker_enabled),
        },
    );

    for (pool.targets.items, 0..) |*target, index| {
        try out.print(
            allocator,
            "  {s} {d} {s}://{s}:{d}{s} weight={d} state={s} active={d} half_open={d} failures={d} ejected_for_ms={d}\n",
            .{
                label,
                index,
                if (target.https) "https" else "http",
                target.host,
                target.port,
                target.base_path,
                target.weight,
                targetState(target, now_ms, runtime_policy),
                target.active_requests.load(.monotonic),
                target.half_open_requests.load(.monotonic),
                target.passive_failures.load(.monotonic),
                ejectedForMs(target, now_ms),
            },
        );
    }
}

pub fn renderReport(io: std.Io, allocator: std.mem.Allocator, cfg: *const ServerConfig) ![]const u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);

    const now_ms = nowMs(io);
    var count: usize = 0;
    if (cfg.upstream) |*pool| {
        try appendPoolReport(&out, allocator, "global", pool, cfg.upstream_policy, config_mod.upstreamRuntimePolicyFor(cfg, null, null), now_ms);
        count += 1;
    }

    for (cfg.routes.items) |*route| {
        if (route.upstream) |*pool| {
            const label = try std.fmt.allocPrint(allocator, "route {s}", .{route.name});
            defer allocator.free(label);
            try appendPoolReport(&out, allocator, label, pool, routing.routeUpstreamPolicy(cfg, null, route), config_mod.upstreamRuntimePolicyFor(cfg, null, route), now_ms);
            count += 1;
        }
    }

    for (cfg.domains.items) |*domain| {
        if (domain.upstream) |*pool| {
            const label = try std.fmt.allocPrint(allocator, "domain {s}", .{domain.name});
            defer allocator.free(label);
            try appendPoolReport(&out, allocator, label, pool, routing.domainUpstreamPolicy(cfg, domain), config_mod.upstreamRuntimePolicyFor(cfg, domain, null), now_ms);
            count += 1;
        }

        for (domain.routes.items) |*route| {
            if (route.upstream) |*pool| {
                const label = try std.fmt.allocPrint(allocator, "domain-route {s} {s}", .{ domain.name, route.name });
                defer allocator.free(label);
                try appendPoolReport(&out, allocator, label, pool, routing.routeUpstreamPolicy(cfg, domain, route), config_mod.upstreamRuntimePolicyFor(cfg, domain, route), now_ms);
                count += 1;
            }
        }
    }

    if (count == 0) try out.appendSlice(allocator, "no upstream pools configured\n");
    return out.toOwnedSlice(allocator);
}

fn appendHidden(out: *std.ArrayList(u8), allocator: std.mem.Allocator, name: []const u8, value: []const u8) !void {
    try out.appendSlice(allocator, "<input type=\"hidden\" name=\"");
    try admin_support.appendHtmlEscaped(out, allocator, name);
    try out.appendSlice(allocator, "\" value=\"");
    try admin_support.appendHtmlEscaped(out, allocator, value);
    try out.appendSlice(allocator, "\">");
}

fn appendTargetActionForm(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    admin_ui_path: []const u8,
    action: []const u8,
    label: []const u8,
    scope: []const u8,
    domain_name: []const u8,
    route_name: []const u8,
    index: usize,
) !void {
    try out.appendSlice(allocator, "<form method=\"post\" action=\"");
    try admin_support.appendHtmlEscaped(out, allocator, admin_ui_path);
    try out.print(allocator, "/upstreams/{s}\">", .{action});
    try appendHidden(out, allocator, "scope", scope);
    try appendHidden(out, allocator, "domain", domain_name);
    try appendHidden(out, allocator, "route", route_name);
    try out.print(allocator, "<input type=\"hidden\" name=\"index\" value=\"{d}\">", .{index});
    try out.print(allocator, "<input type=\"hidden\" name=\"duration_ms\" value=\"{d}\">", .{DEFAULT_MANUAL_EJECT_MS});
    try out.appendSlice(allocator, "<button type=\"submit\">");
    try admin_support.appendHtmlEscaped(out, allocator, label);
    try out.appendSlice(allocator, "</button></form>");
}

fn appendPoolRows(
    out: *std.ArrayList(u8),
    allocator: std.mem.Allocator,
    admin_ui_path: []const u8,
    scope: []const u8,
    domain_name: []const u8,
    route_name: []const u8,
    label: []const u8,
    pool: *const UpstreamPoolConfig,
    runtime_policy: UpstreamRuntimePolicy,
    now_ms: i64,
) !void {
    for (pool.targets.items, 0..) |*target, index| {
        try out.appendSlice(allocator, "<tr><td><code>");
        try admin_support.appendHtmlEscaped(out, allocator, label);
        try out.appendSlice(allocator, "</code></td><td>");
        try out.print(allocator, "<code>{s}://", .{if (target.https) "https" else "http"});
        try admin_support.appendHtmlEscaped(out, allocator, target.host);
        try out.print(allocator, ":{d}", .{target.port});
        try admin_support.appendHtmlEscaped(out, allocator, target.base_path);
        try out.appendSlice(allocator, "</code></td><td>");
        try out.appendSlice(allocator, targetState(target, now_ms, runtime_policy));
        try out.appendSlice(allocator, "</td><td>");
        try out.print(allocator, "{d}", .{target.active_requests.load(.monotonic)});
        try out.appendSlice(allocator, "</td><td>");
        try out.print(allocator, "{d}", .{target.passive_failures.load(.monotonic)});
        try out.appendSlice(allocator, "</td><td>");
        try out.print(allocator, "{d}", .{ejectedForMs(target, now_ms)});
        try out.appendSlice(allocator, "</td><td><div class=\"inline-actions\">");
        try appendTargetActionForm(out, allocator, admin_ui_path, "eject", "Eject 60s", scope, domain_name, route_name, index);
        try appendTargetActionForm(out, allocator, admin_ui_path, "recover", "Recover", scope, domain_name, route_name, index);
        try out.appendSlice(allocator, "</div></td></tr>\n");
    }
}

pub fn appendAdminPanel(io: std.Io, out: *std.ArrayList(u8), allocator: std.mem.Allocator, cfg: *const ServerConfig) !void {
    try out.appendSlice(allocator,
        \\<section class="block span-all" id="upstreams">
        \\  <div class="section-head"><div><h2>Upstreams</h2><p>Live proxy targets with manual ejection and recovery controls.</p></div><span class="pill">runtime state</span></div>
        \\
    );

    const now_ms = nowMs(io);
    var count: usize = 0;
    try out.appendSlice(allocator,
        \\<div class="table-wrap"><table>
        \\  <thead><tr><th>Scope</th><th>Target</th><th>State</th><th>Active</th><th>Failures</th><th>Ejected ms</th><th>Controls</th></tr></thead>
        \\  <tbody>
        \\
    );

    if (cfg.upstream) |*pool| {
        try appendPoolRows(out, allocator, cfg.admin_ui_path, "global", "", "", "global", pool, config_mod.upstreamRuntimePolicyFor(cfg, null, null), now_ms);
        count += pool.targets.items.len;
    }
    for (cfg.routes.items) |*route| {
        if (route.upstream) |*pool| {
            const label = try std.fmt.allocPrint(allocator, "route {s}", .{route.name});
            defer allocator.free(label);
            try appendPoolRows(out, allocator, cfg.admin_ui_path, "route", "", route.name, label, pool, config_mod.upstreamRuntimePolicyFor(cfg, null, route), now_ms);
            count += pool.targets.items.len;
        }
    }
    for (cfg.domains.items) |*domain| {
        if (domain.upstream) |*pool| {
            const label = try std.fmt.allocPrint(allocator, "domain {s}", .{domain.name});
            defer allocator.free(label);
            try appendPoolRows(out, allocator, cfg.admin_ui_path, "domain", domain.name, "", label, pool, config_mod.upstreamRuntimePolicyFor(cfg, domain, null), now_ms);
            count += pool.targets.items.len;
        }
        for (domain.routes.items) |*route| {
            if (route.upstream) |*pool| {
                const label = try std.fmt.allocPrint(allocator, "domain {s} route {s}", .{ domain.name, route.name });
                defer allocator.free(label);
                try appendPoolRows(out, allocator, cfg.admin_ui_path, "domain-route", domain.name, route.name, label, pool, config_mod.upstreamRuntimePolicyFor(cfg, domain, route), now_ms);
                count += pool.targets.items.len;
            }
        }
    }

    if (count == 0) {
        try out.appendSlice(allocator, "<tr><td colspan=\"7\"><span class=\"muted\">No upstream pools configured.</span></td></tr>\n");
    }
    try out.appendSlice(allocator, "</tbody></table></div></section>\n");
}

test "admin upstream controls eject and recover route target" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var cfg = config_mod.defaultServerConfig();
    try config_mod.setRouteLine(&cfg, allocator, "api /api/* proxy");
    try config_mod.setRouteProxyProperty(&cfg.routes, allocator, "api", "http://127.0.0.1:9000");

    try applyControlAt(1_000, &cfg, .eject, .{ .scope = "route", .route = "api", .index = 0 }, 10_000);
    const target = try findTarget(&cfg, .{ .scope = "route", .route = "api", .index = 0 });
    try std.testing.expect(upstream_mod.upstreamIsEjected(target, 1_001));

    try applyControlAt(1_002, &cfg, .recover, .{ .scope = "route", .route = "api", .index = 0 }, 0);
    try std.testing.expect(!upstream_mod.upstreamIsEjected(target, 1_003));
    try std.testing.expectEqual(@as(usize, 0), target.passive_failures.load(.monotonic));
}
