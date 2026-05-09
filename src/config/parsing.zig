const std = @import("std");
const http_headers = @import("../http_headers.zig");
const types = @import("types.zig");

const trimValue = http_headers.trimValue;
const PhpFastcgiEndpoint = types.PhpFastcgiEndpoint;
const PhpFastcgiTcpEndpoint = types.PhpFastcgiTcpEndpoint;
const RedirectRule = types.RedirectRule;
const ResponseHeaderRule = types.ResponseHeaderRule;
const RouteConfig = types.RouteConfig;
const RouteHandlerKind = types.RouteHandlerKind;
const RouteMatchKind = types.RouteMatchKind;
const UpstreamConfig = types.UpstreamConfig;
const UpstreamKeepAlivePool = types.UpstreamKeepAlivePool;
const UpstreamPoolConfig = types.UpstreamPoolConfig;
const UpstreamPoolPolicy = types.UpstreamPoolPolicy;

pub fn parseUpstream(allocator: std.mem.Allocator, raw: []const u8) !UpstreamConfig {
    const scheme_https = std.mem.startsWith(u8, raw, "https://");
    const scheme_http = std.mem.startsWith(u8, raw, "http://");
    var rest = raw;

    if (scheme_https) {
        rest = raw["https://".len..];
    } else if (scheme_http) {
        rest = raw["http://".len..];
    }

    const slash_pos = std.mem.indexOfScalar(u8, rest, '/');
    const host_port = if (slash_pos) |p| rest[0..p] else rest;
    const base_path = if (slash_pos) |p| rest[p..] else "/";

    const colon = std.mem.lastIndexOfScalar(u8, host_port, ':');
    var host = host_port;
    var port: u16 = if (scheme_https) 443 else 80;

    if (colon) |col| {
        host = host_port[0..col];
        port = std.fmt.parseInt(u16, host_port[col + 1 ..], 10) catch if (scheme_https) 443 else 80;
    }
    if (host.len == 0) return error.InvalidUpstream;

    const dupe_host = try allocator.dupe(u8, host);
    const dupe_path = try allocator.dupe(u8, if (base_path.len == 0) "/" else base_path);

    return UpstreamConfig{
        .host = dupe_host,
        .port = port,
        .base_path = dupe_path,
        .https = scheme_https,
        .weight = 1,
        .keepalive_pool = UpstreamKeepAlivePool.init(),
        .active_requests = std.atomic.Value(usize).init(0),
        .half_open_requests = std.atomic.Value(usize).init(0),
        .passive_failures = std.atomic.Value(usize).init(0),
        .ejected_until_ms = std.atomic.Value(i64).init(0),
        .recovered_at_ms = std.atomic.Value(i64).init(0),
    };
}

pub fn applyUpstreamOption(upstream: *UpstreamConfig, raw: []const u8) !bool {
    const token = std.mem.trim(u8, raw, " \t\r\n;");
    const eq = std.mem.indexOfScalar(u8, token, '=') orelse return false;
    const key = token[0..eq];
    const value = token[eq + 1 ..];

    if (std.ascii.eqlIgnoreCase(key, "weight") or std.ascii.eqlIgnoreCase(key, "w")) {
        const weight = std.fmt.parseInt(usize, value, 10) catch return error.InvalidUpstream;
        if (weight == 0 or weight > 1_000_000) return error.InvalidUpstream;
        upstream.weight = weight;
        return true;
    }

    if (!std.mem.startsWith(u8, token, "http://") and !std.mem.startsWith(u8, token, "https://")) {
        return error.InvalidUpstream;
    }
    return false;
}

pub fn parseUpstreamPool(allocator: std.mem.Allocator, raw: []const u8) !UpstreamPoolConfig {
    var pool = UpstreamPoolConfig{
        .targets = .empty,
        .policy = .round_robin,
    };

    var parts = std.mem.tokenizeAny(u8, raw, " \t,");
    while (parts.next()) |part| {
        const value = trimValue(part);
        if (value.len == 0) continue;

        if (pool.targets.items.len > 0) {
            if (try applyUpstreamOption(&pool.targets.items[pool.targets.items.len - 1], value)) continue;
        } else if (std.mem.indexOfScalar(u8, value, '=') != null and
            !std.mem.startsWith(u8, value, "http://") and
            !std.mem.startsWith(u8, value, "https://"))
        {
            return error.InvalidUpstream;
        }

        try pool.targets.append(allocator, try parseUpstream(allocator, value));
    }

    if (pool.targets.items.len == 0) return error.InvalidUpstream;
    return pool;
}

// Parse CLI/config booleans without crashing on odd values.
pub fn parseBool(value: []const u8) ?bool {
    if (std.ascii.eqlIgnoreCase(value, "true") or std.ascii.eqlIgnoreCase(value, "on") or std.ascii.eqlIgnoreCase(value, "yes") or std.ascii.eqlIgnoreCase(value, "1")) {
        return true;
    }
    if (std.ascii.eqlIgnoreCase(value, "false") or std.ascii.eqlIgnoreCase(value, "off") or std.ascii.eqlIgnoreCase(value, "no") or std.ascii.eqlIgnoreCase(value, "0")) {
        return false;
    }
    return null;
}

pub fn parseConfigBool(value: []const u8) !bool {
    return parseBool(value) orelse error.InvalidConfigValue;
}

pub fn parseConfigU16(value: []const u8) !u16 {
    return std.fmt.parseInt(u16, value, 10) catch error.InvalidConfigValue;
}

pub fn parseConfigU32(value: []const u8) !u32 {
    return std.fmt.parseInt(u32, value, 10) catch error.InvalidConfigValue;
}

pub fn parseConfigUsize(value: []const u8) !usize {
    return std.fmt.parseInt(usize, value, 10) catch error.InvalidConfigValue;
}

pub fn isSupportedCloudflareRecordType(value: []const u8) bool {
    return std.ascii.eqlIgnoreCase(value, "A") or
        std.ascii.eqlIgnoreCase(value, "AAAA") or
        std.ascii.eqlIgnoreCase(value, "CNAME") or
        std.ascii.eqlIgnoreCase(value, "TXT");
}

pub fn disablesOptionalUrl(value: []const u8) bool {
    if (value.len == 0) return true;
    if (parseBool(value)) |enabled| return !enabled;
    if (std.ascii.eqlIgnoreCase(value, "none") or std.ascii.eqlIgnoreCase(value, "null")) return true;
    return false;
}

pub fn parseFastcgiHostPort(value: []const u8) !PhpFastcgiTcpEndpoint {
    if (value.len == 0) return error.InvalidConfigValue;

    if (value[0] == '[') {
        const close = std.mem.indexOfScalar(u8, value, ']') orelse return error.InvalidConfigValue;
        if (close + 2 > value.len or value[close + 1] != ':') return error.InvalidConfigValue;
        const host = value[1..close];
        const port = std.fmt.parseInt(u16, value[close + 2 ..], 10) catch return error.InvalidConfigValue;
        if (host.len == 0 or port == 0) return error.InvalidConfigValue;
        return .{ .host = host, .port = port };
    }

    const colon = std.mem.lastIndexOfScalar(u8, value, ':') orelse return error.InvalidConfigValue;
    const host = value[0..colon];
    const port = std.fmt.parseInt(u16, value[colon + 1 ..], 10) catch return error.InvalidConfigValue;
    if (host.len == 0 or port == 0) return error.InvalidConfigValue;
    return .{ .host = host, .port = port };
}

pub fn normalizeFastcgiUnixPath(raw: []const u8) []const u8 {
    var path = raw;
    while (path.len > 1 and path[0] == '/' and path[1] == '/') {
        path = path[1..];
    }
    return path;
}

pub fn parseFastcgiEndpoint(raw: []const u8) !PhpFastcgiEndpoint {
    const value = trimValue(raw);
    if (disablesOptionalUrl(value)) return error.InvalidConfigValue;

    if (std.mem.startsWith(u8, value, "unix:")) {
        const path = normalizeFastcgiUnixPath(value["unix:".len..]);
        if (path.len == 0 or path[0] != '/') return error.InvalidConfigValue;
        return .{ .unix = path };
    }

    if (value[0] == '/') return .{ .unix = value };

    const host_port = if (std.mem.startsWith(u8, value, "tcp://"))
        value["tcp://".len..]
    else if (std.mem.startsWith(u8, value, "fastcgi://"))
        value["fastcgi://".len..]
    else
        value;

    return .{ .tcp = try parseFastcgiHostPort(host_port) };
}

pub fn validateFastcgiEndpoint(raw: []const u8) !void {
    _ = try parseFastcgiEndpoint(raw);
}

pub fn isValidHeaderName(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |c| {
        if (c <= 32 or c >= 127 or c == ':' or c == '\r' or c == '\n') return false;
    }
    return true;
}

pub fn isSafeHeaderValue(value: []const u8) bool {
    return std.mem.indexOfAny(u8, value, "\r\n") == null;
}

pub fn parseResponseHeaderRule(allocator: std.mem.Allocator, raw: []const u8) !ResponseHeaderRule {
    const colon = std.mem.indexOfScalar(u8, raw, ':') orelse return error.InvalidHeader;
    const name = trimValue(raw[0..colon]);
    const value = trimValue(raw[colon + 1 ..]);
    return makeResponseHeaderRule(allocator, name, value);
}

pub fn makeResponseHeaderRule(allocator: std.mem.Allocator, name: []const u8, value: []const u8) !ResponseHeaderRule {
    if (!isValidHeaderName(name) or !isSafeHeaderValue(value)) return error.InvalidHeader;
    return .{
        .name = try allocator.dupe(u8, name),
        .value = try allocator.dupe(u8, value),
    };
}

pub fn isSafeRedirectLocation(value: []const u8) bool {
    return value.len > 0 and std.mem.indexOfAny(u8, value, "\r\n") == null;
}

pub fn parseRedirectRule(allocator: std.mem.Allocator, raw: []const u8) !RedirectRule {
    var tokens = std.ArrayList([]const u8).empty;
    defer tokens.deinit(allocator);

    var it = std.mem.tokenizeAny(u8, raw, " \t");
    while (it.next()) |token| {
        if (std.mem.eql(u8, token, "->")) continue;
        try tokens.append(allocator, token);
    }

    if (tokens.items.len < 2) return error.InvalidRedirect;

    const from_raw = trimValue(tokens.items[0]);
    const to = trimValue(tokens.items[1]);
    if (from_raw.len == 0 or from_raw[0] != '/' or !isSafeRedirectLocation(to)) return error.InvalidRedirect;

    const status_code = if (tokens.items.len >= 3)
        std.fmt.parseInt(u16, tokens.items[2], 10) catch 308
    else
        308;
    if (status_code != 301 and status_code != 302 and status_code != 303 and status_code != 307 and status_code != 308) return error.InvalidRedirect;

    const prefix_match = std.mem.endsWith(u8, from_raw, "*");
    const from = if (prefix_match) from_raw[0 .. from_raw.len - 1] else from_raw;
    if (from.len == 0 or from[0] != '/') return error.InvalidRedirect;

    return .{
        .from = try allocator.dupe(u8, from),
        .to = try allocator.dupe(u8, to),
        .status_code = status_code,
        .prefix_match = prefix_match,
    };
}

pub fn routeHandlerName(handler: RouteHandlerKind) []const u8 {
    return switch (handler) {
        .static => "static",
        .php => "php",
        .proxy => "proxy",
    };
}

pub fn routeMatchName(match_kind: RouteMatchKind) []const u8 {
    return switch (match_kind) {
        .exact => "exact",
        .prefix => "prefix",
    };
}

pub fn parseRouteHandler(value: []const u8) !RouteHandlerKind {
    if (std.mem.eql(u8, value, "static")) return .static;
    if (std.mem.eql(u8, value, "php")) return .php;
    if (std.mem.eql(u8, value, "proxy")) return .proxy;
    return error.InvalidConfigValue;
}

pub fn upstreamPoolPolicyName(policy: UpstreamPoolPolicy) []const u8 {
    return switch (policy) {
        .round_robin => "round_robin",
        .random => "random",
        .least_connections => "least_connections",
        .weighted => "weighted",
        .consistent_hash => "consistent_hash",
    };
}

pub fn parseUpstreamPoolPolicy(value: []const u8) !UpstreamPoolPolicy {
    if (std.ascii.eqlIgnoreCase(value, "round_robin") or
        std.ascii.eqlIgnoreCase(value, "round-robin") or
        std.ascii.eqlIgnoreCase(value, "roundrobin") or
        std.ascii.eqlIgnoreCase(value, "rr"))
    {
        return .round_robin;
    }
    if (std.ascii.eqlIgnoreCase(value, "random") or std.ascii.eqlIgnoreCase(value, "rand")) {
        return .random;
    }
    if (std.ascii.eqlIgnoreCase(value, "least_connections") or
        std.ascii.eqlIgnoreCase(value, "least-connections") or
        std.ascii.eqlIgnoreCase(value, "least_conn") or
        std.ascii.eqlIgnoreCase(value, "leastconn"))
    {
        return .least_connections;
    }
    if (std.ascii.eqlIgnoreCase(value, "weighted") or
        std.ascii.eqlIgnoreCase(value, "weighted_round_robin") or
        std.ascii.eqlIgnoreCase(value, "weighted-round-robin") or
        std.ascii.eqlIgnoreCase(value, "wrr"))
    {
        return .weighted;
    }
    if (std.ascii.eqlIgnoreCase(value, "consistent_hash") or
        std.ascii.eqlIgnoreCase(value, "consistent-hash") or
        std.ascii.eqlIgnoreCase(value, "hash") or
        std.ascii.eqlIgnoreCase(value, "uri_hash") or
        std.ascii.eqlIgnoreCase(value, "uri-hash"))
    {
        return .consistent_hash;
    }
    return error.InvalidConfigValue;
}

pub fn parseOptionalUpstreamPoolPolicy(value: []const u8) !?UpstreamPoolPolicy {
    if (std.ascii.eqlIgnoreCase(value, "inherit") or
        std.ascii.eqlIgnoreCase(value, "default") or
        std.ascii.eqlIgnoreCase(value, "auto"))
    {
        return null;
    }
    return try parseUpstreamPoolPolicy(value);
}

pub fn isRouteNameValid(name: []const u8) bool {
    if (name.len == 0) return false;
    for (name) |c| {
        if (std.ascii.isAlphanumeric(c) or c == '_' or c == '-') continue;
        return false;
    }
    return true;
}

pub fn findRouteConfigMutable(routes: *std.ArrayList(RouteConfig), name: []const u8) ?*RouteConfig {
    for (routes.items) |*route| {
        if (std.mem.eql(u8, route.name, name)) return route;
    }
    return null;
}

pub fn findRoutePropertyName(key: []const u8, prefix: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, key, prefix)) return null;
    const name = key[prefix.len..];
    if (name.len == 0) return null;
    return name;
}

pub fn findAnyRoutePropertyName(key: []const u8, comptime prefixes: []const []const u8) ?[]const u8 {
    inline for (prefixes) |prefix| {
        if (findRoutePropertyName(key, prefix)) |name| return name;
    }
    return null;
}

pub fn isCompressionEnabledKey(key: []const u8) bool {
    return std.mem.eql(u8, key, "compression") or
        std.mem.eql(u8, key, "compress") or
        std.mem.eql(u8, key, "encode");
}

pub fn isGzipEnabledKey(key: []const u8) bool {
    return std.mem.eql(u8, key, "gzip") or
        std.mem.eql(u8, key, "gzip_enabled");
}

pub fn isCompressionMinBytesKey(key: []const u8) bool {
    return std.mem.eql(u8, key, "compression_min_bytes") or
        std.mem.eql(u8, key, "gzip_min_bytes");
}

pub fn isCompressionMaxBytesKey(key: []const u8) bool {
    return std.mem.eql(u8, key, "compression_max_bytes") or
        std.mem.eql(u8, key, "gzip_max_bytes");
}
