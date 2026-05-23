const std = @import("std");

const config_mod = @import("config.zig");

const DomainConfig = config_mod.DomainConfig;
const RouteConfig = config_mod.RouteConfig;
const ServerConfig = config_mod.ServerConfig;
const UpstreamPoolConfig = config_mod.UpstreamPoolConfig;

fn boolText(value: bool) []const u8 {
    return if (value) "true" else "false";
}

fn optionalText(value: ?[]const u8) []const u8 {
    return value orelse "<none>";
}

fn optionalBoolText(value: ?bool) []const u8 {
    return if (value) |v| boolText(v) else "<inherit>";
}

fn routeHandlerText(route: *const RouteConfig) []const u8 {
    return config_mod.routeHandlerName(route.handler);
}

fn appendStringChange(out: *std.ArrayList(u8), allocator: std.mem.Allocator, label: []const u8, active: []const u8, candidate: []const u8) !usize {
    if (std.mem.eql(u8, active, candidate)) return 0;
    try out.print(allocator, "~ {s}: {s} -> {s}\n", .{ label, active, candidate });
    return 1;
}

fn appendOptionalStringChange(out: *std.ArrayList(u8), allocator: std.mem.Allocator, label: []const u8, active: ?[]const u8, candidate: ?[]const u8) !usize {
    const active_text = optionalText(active);
    const candidate_text = optionalText(candidate);
    return appendStringChange(out, allocator, label, active_text, candidate_text);
}

fn appendBoolChange(out: *std.ArrayList(u8), allocator: std.mem.Allocator, label: []const u8, active: bool, candidate: bool) !usize {
    return appendStringChange(out, allocator, label, boolText(active), boolText(candidate));
}

fn appendOptionalBoolChange(out: *std.ArrayList(u8), allocator: std.mem.Allocator, label: []const u8, active: ?bool, candidate: ?bool) !usize {
    return appendStringChange(out, allocator, label, optionalBoolText(active), optionalBoolText(candidate));
}

fn appendIntChange(out: *std.ArrayList(u8), allocator: std.mem.Allocator, comptime T: type, label: []const u8, active: T, candidate: T) !usize {
    if (active == candidate) return 0;
    try out.print(allocator, "~ {s}: {d} -> {d}\n", .{ label, active, candidate });
    return 1;
}

fn appendUpstreamSummary(out: *std.ArrayList(u8), allocator: std.mem.Allocator, pool: ?UpstreamPoolConfig) !void {
    if (pool) |upstream| {
        try out.print(allocator, "{s}[", .{config_mod.upstreamPoolPolicyName(upstream.policy)});
        for (upstream.targets.items, 0..) |target, index| {
            if (index > 0) try out.appendSlice(allocator, ",");
            try out.print(allocator, "{s}://{s}:{d}{s}", .{ if (target.https) "https" else "http", target.host, target.port, target.base_path });
            if (target.weight != 1) try out.print(allocator, " weight={d}", .{target.weight});
        }
        try out.append(allocator, ']');
    } else {
        try out.appendSlice(allocator, "<none>");
    }
}

fn upstreamSummary(allocator: std.mem.Allocator, pool: ?UpstreamPoolConfig) ![]const u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    try appendUpstreamSummary(&out, allocator, pool);
    return out.toOwnedSlice(allocator);
}

fn appendUpstreamChange(out: *std.ArrayList(u8), allocator: std.mem.Allocator, label: []const u8, active: ?UpstreamPoolConfig, candidate: ?UpstreamPoolConfig) !usize {
    const active_text = try upstreamSummary(allocator, active);
    defer allocator.free(active_text);
    const candidate_text = try upstreamSummary(allocator, candidate);
    defer allocator.free(candidate_text);
    return appendStringChange(out, allocator, label, active_text, candidate_text);
}

fn findRoute(routes: []const RouteConfig, name: []const u8) ?*const RouteConfig {
    for (routes) |*route| {
        if (std.mem.eql(u8, route.name, name)) return route;
    }
    return null;
}

fn findDomain(domains: []const DomainConfig, name: []const u8) ?*const DomainConfig {
    for (domains) |*domain| {
        if (std.mem.eql(u8, domain.name, name)) return domain;
    }
    return null;
}

fn routeKey(allocator: std.mem.Allocator, prefix: []const u8, route_name: []const u8, suffix: []const u8) ![]const u8 {
    return std.fmt.allocPrint(allocator, "{s}.{s}.{s}", .{ prefix, route_name, suffix });
}

fn appendRouteDiff(out: *std.ArrayList(u8), allocator: std.mem.Allocator, prefix: []const u8, active: *const RouteConfig, candidate: *const RouteConfig) !usize {
    var changes: usize = 0;
    {
        const key = try routeKey(allocator, prefix, active.name, "pattern");
        defer allocator.free(key);
        changes += try appendStringChange(out, allocator, key, active.pattern, candidate.pattern);
    }
    {
        const key = try routeKey(allocator, prefix, active.name, "handler");
        defer allocator.free(key);
        changes += try appendStringChange(out, allocator, key, routeHandlerText(active), routeHandlerText(candidate));
    }
    {
        const key = try routeKey(allocator, prefix, active.name, "static_dir");
        defer allocator.free(key);
        changes += try appendOptionalStringChange(out, allocator, key, active.static_dir, candidate.static_dir);
    }
    {
        const key = try routeKey(allocator, prefix, active.name, "proxy");
        defer allocator.free(key);
        changes += try appendUpstreamChange(out, allocator, key, active.upstream, candidate.upstream);
    }
    {
        const key = try routeKey(allocator, prefix, active.name, "php_fastcgi");
        defer allocator.free(key);
        changes += try appendOptionalStringChange(out, allocator, key, active.php_fastcgi, candidate.php_fastcgi);
    }
    {
        const key = try routeKey(allocator, prefix, active.name, "response_cache");
        defer allocator.free(key);
        changes += try appendOptionalBoolChange(out, allocator, key, active.response_cache_enabled, candidate.response_cache_enabled);
    }

    return changes;
}

fn appendRoutesDiff(out: *std.ArrayList(u8), allocator: std.mem.Allocator, prefix: []const u8, active: []const RouteConfig, candidate: []const RouteConfig) !usize {
    var changes: usize = 0;
    for (active) |*route| {
        if (findRoute(candidate, route.name)) |candidate_route| {
            changes += try appendRouteDiff(out, allocator, prefix, route, candidate_route);
        } else {
            try out.print(allocator, "- {s}.{s}\n", .{ prefix, route.name });
            changes += 1;
        }
    }
    for (candidate) |*route| {
        if (findRoute(active, route.name) == null) {
            try out.print(allocator, "+ {s}.{s}: {s} {s} -> {s}\n", .{ prefix, route.name, config_mod.routeMatchName(route.match_kind), route.pattern, routeHandlerText(route) });
            changes += 1;
        }
    }
    return changes;
}

fn domainServerNames(allocator: std.mem.Allocator, domain: *const DomainConfig) ![]const u8 {
    var names = std.ArrayList(u8).empty;
    errdefer names.deinit(allocator);
    for (domain.server_names.items, 0..) |name, index| {
        if (index > 0) try names.append(allocator, ',');
        try names.appendSlice(allocator, name);
    }
    return names.toOwnedSlice(allocator);
}

fn appendDomainDiff(out: *std.ArrayList(u8), allocator: std.mem.Allocator, active: *const DomainConfig, candidate: *const DomainConfig) !usize {
    var changes: usize = 0;

    const active_names = try domainServerNames(allocator, active);
    defer allocator.free(active_names);
    const candidate_names = try domainServerNames(allocator, candidate);
    defer allocator.free(candidate_names);

    {
        const key = try std.fmt.allocPrint(allocator, "domain.{s}.server_names", .{active.name});
        defer allocator.free(key);
        changes += try appendStringChange(out, allocator, key, active_names, candidate_names);
    }
    {
        const key = try std.fmt.allocPrint(allocator, "domain.{s}.root", .{active.name});
        defer allocator.free(key);
        changes += try appendOptionalStringChange(out, allocator, key, active.static_dir, candidate.static_dir);
    }
    {
        const key = try std.fmt.allocPrint(allocator, "domain.{s}.serve_static_root", .{active.name});
        defer allocator.free(key);
        changes += try appendOptionalBoolChange(out, allocator, key, active.serve_static_root, candidate.serve_static_root);
    }
    {
        const key = try std.fmt.allocPrint(allocator, "domain.{s}.proxy", .{active.name});
        defer allocator.free(key);
        changes += try appendUpstreamChange(out, allocator, key, active.upstream, candidate.upstream);
    }
    {
        const key = try std.fmt.allocPrint(allocator, "domain.{s}.tls_cert", .{active.name});
        defer allocator.free(key);
        changes += try appendOptionalStringChange(out, allocator, key, active.tls_cert, candidate.tls_cert);
    }

    const route_prefix = try std.fmt.allocPrint(allocator, "domain.{s}.route", .{active.name});
    defer allocator.free(route_prefix);
    changes += try appendRoutesDiff(out, allocator, route_prefix, active.routes.items, candidate.routes.items);

    return changes;
}

fn appendDomainsDiff(out: *std.ArrayList(u8), allocator: std.mem.Allocator, active: []const DomainConfig, candidate: []const DomainConfig) !usize {
    var changes: usize = 0;
    for (active) |*domain| {
        if (findDomain(candidate, domain.name)) |candidate_domain| {
            changes += try appendDomainDiff(out, allocator, domain, candidate_domain);
        } else {
            try out.print(allocator, "- domain.{s}\n", .{domain.name});
            changes += 1;
        }
    }
    for (candidate) |*domain| {
        if (findDomain(active, domain.name) == null) {
            try out.print(allocator, "+ domain.{s}", .{domain.name});
            if (domain.server_names.items.len > 0) {
                try out.appendSlice(allocator, " names=");
                for (domain.server_names.items, 0..) |name, index| {
                    if (index > 0) try out.append(allocator, ',');
                    try out.appendSlice(allocator, name);
                }
            }
            try out.append(allocator, '\n');
            changes += 1;
        }
    }
    return changes;
}

pub fn render(allocator: std.mem.Allocator, active: *const ServerConfig, candidate: *const ServerConfig) ![]const u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);

    try out.appendSlice(allocator, "activation diff\n");
    var changes: usize = 0;

    changes += try appendStringChange(&out, allocator, "global.host", active.host, candidate.host);
    changes += try appendIntChange(&out, allocator, u16, "global.port", active.port, candidate.port);
    changes += try appendStringChange(&out, allocator, "global.static_dir", active.static_dir, candidate.static_dir);
    changes += try appendStringChange(&out, allocator, "global.index_file", active.index_file, candidate.index_file);
    changes += try appendBoolChange(&out, allocator, "global.serve_static_root", active.serve_static_root, candidate.serve_static_root);
    changes += try appendBoolChange(&out, allocator, "global.compression", active.compression_enabled, candidate.compression_enabled);
    changes += try appendBoolChange(&out, allocator, "global.response_cache", active.response_cache_enabled, candidate.response_cache_enabled);
    changes += try appendBoolChange(&out, allocator, "global.tls", active.tls_enabled, candidate.tls_enabled);
    changes += try appendOptionalStringChange(&out, allocator, "global.tls_cert", active.tls_cert, candidate.tls_cert);
    changes += try appendBoolChange(&out, allocator, "global.http_redirect", active.http_redirect_enabled, candidate.http_redirect_enabled);
    changes += try appendBoolChange(&out, allocator, "global.http3", active.http3_enabled, candidate.http3_enabled);
    changes += try appendBoolChange(&out, allocator, "global.admin_ui", active.admin_ui_enabled, candidate.admin_ui_enabled);
    changes += try appendUpstreamChange(&out, allocator, "global.proxy", active.upstream, candidate.upstream);
    changes += try appendRoutesDiff(&out, allocator, "route", active.routes.items, candidate.routes.items);
    changes += try appendDomainsDiff(&out, allocator, active.domains.items, candidate.domains.items);

    if (changes == 0) try out.appendSlice(allocator, "no activation changes\n");
    return out.toOwnedSlice(allocator);
}
