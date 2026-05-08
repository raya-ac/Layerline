const std = @import("std");

const config_mod = @import("config.zig");
const http_headers = @import("http_headers.zig");

const findHeaderValue = http_headers.findHeaderValue;
const disablesOptionalUrl = config_mod.disablesOptionalUrl;
const DomainConfig = config_mod.DomainConfig;
const RedirectRule = config_mod.RedirectRule;
const RouteConfig = config_mod.RouteConfig;
const ServerConfig = config_mod.ServerConfig;
const UpstreamPoolConfig = config_mod.UpstreamPoolConfig;
const UpstreamPoolPolicy = config_mod.UpstreamPoolPolicy;

pub fn findRedirectRuleIn(rules: []const RedirectRule, path: []const u8) ?RedirectRule {
    for (rules) |rule| {
        if (rule.prefix_match) {
            if (std.mem.startsWith(u8, path, rule.from)) return rule;
        } else if (std.mem.eql(u8, path, rule.from)) {
            return rule;
        }
    }
    return null;
}

pub fn findRedirectRule(cfg: *const ServerConfig, path: []const u8) ?RedirectRule {
    return findRedirectRuleIn(cfg.redirects.items, path);
}

pub fn makeStaticPathFromRequest(allocator: std.mem.Allocator, request_path: []const u8, index_file: []const u8) ![]const u8 {
    if (request_path.len == 0) return allocator.dupe(u8, index_file);

    const rel = if (request_path[0] == '/') request_path[1..] else request_path;
    if (std.mem.eql(u8, rel, "")) return allocator.dupe(u8, index_file);

    if (std.mem.endsWith(u8, rel, "/")) {
        const full_len = rel.len + index_file.len;
        const out = try allocator.alloc(u8, full_len);
        @memcpy(out[0..rel.len], rel);
        @memcpy(out[rel.len..full_len], index_file);
        return out;
    }

    return allocator.dupe(u8, rel);
}

fn routeMatches(route: *const RouteConfig, path: []const u8) bool {
    return switch (route.match_kind) {
        .exact => std.mem.eql(u8, path, route.pattern),
        .prefix => std.mem.startsWith(u8, path, route.pattern),
    };
}

pub fn findNamedRoute(cfg: *const ServerConfig, path: []const u8) ?*const RouteConfig {
    return findNamedRouteIn(cfg.routes.items, path);
}

pub fn findNamedRouteMutable(cfg: *ServerConfig, path: []const u8) ?*RouteConfig {
    return findNamedRouteInMutable(&cfg.routes, path);
}

fn findNamedRouteIn(routes: []const RouteConfig, path: []const u8) ?*const RouteConfig {
    var best: ?*const RouteConfig = null;
    var best_len: usize = 0;
    for (routes) |*route| {
        if (!routeMatches(route, path)) continue;
        if (route.match_kind == .exact) return route;
        if (route.pattern.len >= best_len) {
            best = route;
            best_len = route.pattern.len;
        }
    }
    return best;
}

fn findNamedRouteInMutable(routes: *std.ArrayList(RouteConfig), path: []const u8) ?*RouteConfig {
    var best: ?*RouteConfig = null;
    var best_len: usize = 0;
    for (routes.items) |*route| {
        if (!routeMatches(route, path)) continue;
        if (route.match_kind == .exact) return route;
        if (route.pattern.len >= best_len) {
            best = route;
            best_len = route.pattern.len;
        }
    }
    return best;
}

fn stripHostPort(raw_host: []const u8) []const u8 {
    const host = std.mem.trim(u8, raw_host, " \t\r\n");
    if (host.len == 0) return host;

    if (host[0] == '[') {
        if (std.mem.indexOfScalar(u8, host, ']')) |close| {
            return host[0 .. close + 1];
        }
        return host;
    }

    if (std.mem.lastIndexOfScalar(u8, host, ':')) |colon| {
        if (std.mem.indexOfScalar(u8, host[0..colon], ':') == null) {
            return host[0..colon];
        }
    }

    return host;
}

fn asciiEndsWithIgnoreCase(value: []const u8, suffix: []const u8) bool {
    if (suffix.len > value.len) return false;
    return std.ascii.eqlIgnoreCase(value[value.len - suffix.len ..], suffix);
}

fn serverNameMatchScore(server_name: []const u8, host: []const u8) usize {
    const pattern = std.mem.trim(u8, server_name, " \t\r\n");
    if (pattern.len == 0 or host.len == 0) return 0;

    if (std.mem.eql(u8, pattern, "_") or std.ascii.eqlIgnoreCase(pattern, "default")) {
        return 1;
    }

    if (std.ascii.eqlIgnoreCase(pattern, host)) {
        return 1_000_000 + pattern.len;
    }

    if (std.mem.startsWith(u8, pattern, "*.")) {
        const suffix = pattern[1..];
        if (host.len > suffix.len and asciiEndsWithIgnoreCase(host, suffix)) {
            return 1000 + suffix.len;
        }
    }

    return 0;
}

pub fn findDomainForHost(cfg: *const ServerConfig, raw_host: []const u8) ?*const DomainConfig {
    const host = stripHostPort(raw_host);
    var best: ?*const DomainConfig = null;
    var best_score: usize = 0;

    for (cfg.domains.items) |*domain| {
        for (domain.server_names.items) |server_name| {
            const score = serverNameMatchScore(server_name, host);
            if (score > best_score) {
                best = domain;
                best_score = score;
            }
        }
    }

    return best;
}

pub fn findDomainForHostMutable(cfg: *ServerConfig, raw_host: []const u8) ?*DomainConfig {
    const host = stripHostPort(raw_host);
    var best: ?*DomainConfig = null;
    var best_score: usize = 0;

    for (cfg.domains.items) |*domain| {
        for (domain.server_names.items) |server_name| {
            const score = serverNameMatchScore(server_name, host);
            if (score > best_score) {
                best = domain;
                best_score = score;
            }
        }
    }

    return best;
}

pub fn findDomainForRequest(cfg: *const ServerConfig, headers: []const u8) ?*const DomainConfig {
    const host = findHeaderValue(headers, "Host") orelse return null;
    return findDomainForHost(cfg, host);
}

pub fn findDomainForRequestMutable(cfg: *ServerConfig, headers: []const u8) ?*DomainConfig {
    const host = findHeaderValue(headers, "Host") orelse return null;
    return findDomainForHostMutable(cfg, host);
}

pub fn domainStaticDir(cfg: *const ServerConfig, domain: ?*const DomainConfig) []const u8 {
    if (domain) |d| {
        if (d.static_dir) |value| return value;
    }
    return cfg.static_dir;
}

pub fn domainServeStaticRoot(cfg: *const ServerConfig, domain: ?*const DomainConfig) bool {
    if (domain) |d| {
        if (d.serve_static_root) |value| return value;
    }
    return cfg.serve_static_root;
}

pub fn domainIndexFile(cfg: *const ServerConfig, domain: ?*const DomainConfig) []const u8 {
    if (domain) |d| {
        if (d.index_file) |value| return value;
    }
    return cfg.index_file;
}

pub fn domainPhpRoot(cfg: *const ServerConfig, domain: ?*const DomainConfig) []const u8 {
    if (domain) |d| {
        if (d.php_root) |value| return value;
    }
    return cfg.php_root;
}

pub fn domainPhpBinary(cfg: *const ServerConfig, domain: ?*const DomainConfig) []const u8 {
    if (domain) |d| {
        if (d.php_binary) |value| return value;
    }
    return cfg.php_binary;
}

pub fn domainPhpFastcgi(cfg: *const ServerConfig, domain: ?*const DomainConfig) ?[]const u8 {
    if (domain) |d| {
        if (d.php_fastcgi) |value| {
            if (disablesOptionalUrl(value)) return null;
            return value;
        }
    }
    return cfg.php_fastcgi;
}

pub fn domainPhpIndex(cfg: *const ServerConfig, domain: ?*const DomainConfig) []const u8 {
    if (domain) |d| {
        if (d.php_index) |value| return value;
    }
    return cfg.php_index;
}

pub fn domainPhpInfoPage(cfg: *const ServerConfig, domain: ?*const DomainConfig) bool {
    if (domain) |d| {
        if (d.php_info_page) |value| return value;
    }
    return cfg.php_info_page;
}

pub fn domainPhpFrontController(cfg: *const ServerConfig, domain: ?*const DomainConfig) bool {
    if (domain) |d| {
        if (d.php_front_controller) |value| return value;
    }
    return cfg.php_front_controller;
}

pub fn routePhpIndex(cfg: *const ServerConfig, domain: ?*const DomainConfig, route: *const RouteConfig) []const u8 {
    if (route.php_index) |value| return value;
    return domainPhpIndex(cfg, domain);
}

pub fn routePhpFrontController(cfg: *const ServerConfig, domain: ?*const DomainConfig, route: *const RouteConfig) bool {
    if (route.php_front_controller) |value| return value;
    return domainPhpFrontController(cfg, domain);
}

pub fn routePhpFastcgi(cfg: *const ServerConfig, domain: ?*const DomainConfig, route: *const RouteConfig) ?[]const u8 {
    if (route.php_fastcgi) |value| {
        if (disablesOptionalUrl(value)) return null;
        return value;
    }
    return domainPhpFastcgi(cfg, domain);
}

pub fn domainUpstream(cfg: *const ServerConfig, domain: ?*const DomainConfig) ?UpstreamPoolConfig {
    if (domain) |d| {
        if (d.upstream) |value| return value;
    }
    return cfg.upstream;
}

pub fn domainUpstreamMutable(cfg: *ServerConfig, domain: ?*DomainConfig) ?*UpstreamPoolConfig {
    if (domain) |d| {
        if (d.upstream) |*value| return value;
    }
    if (cfg.upstream) |*value| return value;
    return null;
}

pub fn domainUpstreamPolicy(cfg: *const ServerConfig, domain: ?*const DomainConfig) UpstreamPoolPolicy {
    if (domain) |d| {
        if (d.upstream_policy) |policy| return policy;
    }
    return cfg.upstream_policy;
}

pub fn routeUpstreamPolicy(cfg: *const ServerConfig, domain: ?*const DomainConfig, route: *const RouteConfig) UpstreamPoolPolicy {
    if (route.upstream_policy) |policy| return policy;
    return domainUpstreamPolicy(cfg, domain);
}

pub fn domainUpstreamTimeoutMs(cfg: *const ServerConfig, domain: ?*const DomainConfig) u32 {
    if (domain) |d| {
        if (d.upstream_timeout_ms) |value| return value;
    }
    return cfg.upstream_timeout_ms;
}

pub fn routeUpstreamTimeoutMs(cfg: *const ServerConfig, domain: ?*const DomainConfig, route: *const RouteConfig) u32 {
    if (route.upstream_timeout_ms) |value| return value;
    return domainUpstreamTimeoutMs(cfg, domain);
}

pub fn findDomainRedirectRule(domain: ?*const DomainConfig, path: []const u8) ?RedirectRule {
    if (domain) |d| {
        if (findRedirectRuleIn(d.redirects.items, path)) |rule| return rule;
    }
    return null;
}

pub fn findDomainRoute(domain: ?*const DomainConfig, path: []const u8) ?*const RouteConfig {
    if (domain) |d| {
        return findNamedRouteIn(d.routes.items, path);
    }
    return null;
}

pub fn findDomainRouteMutable(domain: ?*DomainConfig, path: []const u8) ?*RouteConfig {
    if (domain) |d| {
        return findNamedRouteInMutable(&d.routes, path);
    }
    return null;
}

pub fn routeFileRelativePath(allocator: std.mem.Allocator, route: *const RouteConfig, request_path: []const u8, index_file: []const u8) ![]const u8 {
    if (!route.strip_prefix) {
        return makeStaticPathFromRequest(allocator, request_path, index_file);
    }

    const raw_rel = switch (route.match_kind) {
        .exact => "",
        .prefix => if (request_path.len > route.pattern.len) request_path[route.pattern.len..] else "",
    };
    const rel = if (raw_rel.len > 0 and raw_rel[0] == '/') raw_rel[1..] else raw_rel;
    if (rel.len == 0) return allocator.dupe(u8, index_file);
    return allocator.dupe(u8, rel);
}
