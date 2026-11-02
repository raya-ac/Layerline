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
    var parts = std.mem.tokenizeAny(u8, raw, " \t");
    var target = try parseUpstreamEndpoint(allocator, parts.next() orelse return error.InvalidUpstream);
    errdefer freeParsedUpstream(allocator, target);
    while (parts.next()) |part| if (!try applyUpstreamOption(allocator, &target, part)) return error.InvalidUpstream;
    return target;
}

fn freeParsedUpstream(allocator: std.mem.Allocator, target: UpstreamConfig) void {
    allocator.free(target.host);
    allocator.free(target.base_path);
    if (target.tls_ca_file) |path| allocator.free(path);
    if (target.tls_server_name) |name| allocator.free(name);
}

fn parseUpstreamEndpoint(allocator: std.mem.Allocator, value: []const u8) !UpstreamConfig {
    if (value.len == 0) return error.InvalidUpstream;
    for (value) |c| if (c <= 32 or c >= 127 or c == '\\') return error.InvalidUpstream;
    const text = if (std.mem.indexOf(u8, value, "://") == null) try std.fmt.allocPrint(allocator, "http://{s}", .{value}) else try allocator.dupe(u8, value);
    defer allocator.free(text);
    const uri = std.Uri.parse(text) catch return error.InvalidUpstream;
    const scheme_https = std.ascii.eqlIgnoreCase(uri.scheme, "https");
    if (!scheme_https and !std.ascii.eqlIgnoreCase(uri.scheme, "http")) return error.InvalidUpstream;
    if (uri.user != null or uri.password != null or uri.query != null or uri.fragment != null) return error.InvalidUpstream;
    const encoded_host = switch (uri.host orelse return error.InvalidUpstream) {
        .raw, .percent_encoded => |bytes| bytes,
    };
    if (encoded_host.len == 0 or std.mem.indexOfScalar(u8, encoded_host, '%') != null) return error.InvalidUpstream;
    const bracketed = encoded_host[0] == '[';
    const host = if (bracketed) blk: {
        if (!std.mem.endsWith(u8, encoded_host, "]")) return error.InvalidUpstream;
        const name = encoded_host[1 .. encoded_host.len - 1];
        const ip = std.Io.net.IpAddress.parse(name, 0) catch return error.InvalidUpstream;
        if (ip != .ip6) return error.InvalidUpstream;
        break :blk name;
    } else blk: {
        std.Io.net.HostName.validate(encoded_host) catch return error.InvalidUpstream;
        break :blk encoded_host;
    };
    // Uri is deliberately permissive. Check that it consumed the complete
    // authority, rather than discarding junk after a bracketed IPv6 literal.
    const authority_start = uri.scheme.len + 3;
    if (text.len < authority_start or !std.mem.eql(u8, text[uri.scheme.len..authority_start], "://")) return error.InvalidUpstream;
    const authority_end = std.mem.indexOfScalarPos(u8, text, authority_start, '/') orelse text.len;
    const authority = text[authority_start..authority_end];
    if (!std.mem.startsWith(u8, authority, encoded_host)) return error.InvalidUpstream;
    const suffix = authority[encoded_host.len..];
    if (suffix.len != 0) {
        if (suffix[0] != ':' or suffix.len == 1) return error.InvalidUpstream;
        for (suffix[1..]) |c| if (!std.ascii.isDigit(c)) return error.InvalidUpstream;
        if (uri.port == null) return error.InvalidUpstream;
    } else if (uri.port != null) return error.InvalidUpstream;
    const port = uri.port orelse if (scheme_https) @as(u16, 443) else @as(u16, 80);
    if (port == 0) return error.InvalidUpstream;
    if (scheme_https) _ = @import("../upstream_certificate.zig").referenceName(host) catch return error.InvalidUpstream;
    const path = switch (uri.path) {
        .raw, .percent_encoded => |bytes| bytes,
    };
    const base_path = if (path.len == 0) "/" else path;
    if (base_path[0] != '/') return error.InvalidUpstream;
    var cursor: usize = 0;
    while (cursor < base_path.len) : (cursor += 1) if (base_path[cursor] == '%') {
        if (base_path.len - cursor < 3 or !std.ascii.isHex(base_path[cursor + 1]) or !std.ascii.isHex(base_path[cursor + 2])) return error.InvalidUpstream;
        cursor += 2;
    };

    const dupe_host = try allocator.dupe(u8, host);
    errdefer allocator.free(dupe_host);
    const dupe_path = try allocator.dupe(u8, base_path);

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

pub fn applyUpstreamOption(allocator: std.mem.Allocator, upstream: *UpstreamConfig, raw: []const u8) !bool {
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

    if (std.ascii.eqlIgnoreCase(key, "tls_ca_file")) {
        if (!upstream.https or upstream.tls_ca_file != null or value.len == 0) return error.InvalidUpstream;
        for (value) |c| if (c < 32 or c == 127) return error.InvalidUpstream;
        upstream.tls_ca_file = try allocator.dupe(u8, value);
        return true;
    }
    if (std.ascii.eqlIgnoreCase(key, "tls_server_name")) {
        if (!upstream.https or upstream.tls_server_name != null) return error.InvalidUpstream;
        _ = @import("../upstream_certificate.zig").referenceName(value) catch return error.InvalidUpstream;
        upstream.tls_server_name = try allocator.dupe(u8, value);
        return true;
    }
    return false;
}

pub fn parseUpstreamPool(allocator: std.mem.Allocator, raw: []const u8) !UpstreamPoolConfig {
    var pool = UpstreamPoolConfig{
        .targets = .empty,
        .policy = .round_robin,
    };
    errdefer {
        for (pool.targets.items) |target| freeParsedUpstream(allocator, target);
        pool.targets.deinit(allocator);
    }

    var parts = std.mem.tokenizeAny(u8, raw, " \t,");
    while (parts.next()) |part| {
        const value = trimValue(part);
        if (value.len == 0) continue;

        if (pool.targets.items.len > 0) {
            if (try applyUpstreamOption(allocator, &pool.targets.items[pool.targets.items.len - 1], value)) continue;
        }

        const target = try parseUpstream(allocator, value);
        pool.targets.append(allocator, target) catch |err| {
            freeParsedUpstream(allocator, target);
            return err;
        };
    }

    if (pool.targets.items.len == 0) return error.InvalidUpstream;
    return pool;
}

test "upstream authorities ports schemes and base paths are unambiguous" {
    const allocator = std.testing.allocator;
    for ([_][]const u8{ "localhost:8080/app", "HTTP://example.test/", "https://[::1]:8443/a%20b", "[2001:db8::1]:9000", "https://EXAMPLE.TEST./x=a" }) |value| {
        const target = try parseUpstream(allocator, value);
        defer freeParsedUpstream(allocator, target);
        const text = try std.fmt.allocPrint(allocator, "{f}", .{&target});
        defer allocator.free(text);
        const copy = try parseUpstream(allocator, text);
        defer freeParsedUpstream(allocator, copy);
        try std.testing.expectEqualSlices(u8, target.host, copy.host);
        try std.testing.expectEqualSlices(u8, target.base_path, copy.base_path);
        try std.testing.expectEqual(target.port, copy.port);
        try std.testing.expectEqual(target.https, copy.https);
    }
    for ([_][]const u8{
        "",                                    "https://",                      "ftp://example.test",        "http://user:pass@example.test", "http://example.test:",
        "http://example.test:wrong",           "http://example.test:0",         "http://example.test:65536", "http://example.test:+80",       "http://example.test:8_0",
        "http://example.test?x=1",             "http://example.test/#fragment", "http://example.test/%xx",   "http://example.test/%0",        "http://ex%61mple.test",
        "http://[::1]junk:80/",                "http://[::1]:4:80/",            "http://::1:80/",            "http://[127.0.0.1]:80/",        "http://example.test\\evil/",
        "http://example.test/\r\nInjected: x",
    }) |value| try std.testing.expectError(error.InvalidUpstream, parseUpstream(allocator, value));
}

test "upstream TLS options are owned and survive formatter round trips" {
    const allocator = std.testing.allocator;
    const target = try parseUpstream(allocator, "https://[::1]:8443/app weight=2 tls_ca_file=/tmp/roots.pem tls_server_name=origin.example.test");
    defer freeParsedUpstream(allocator, target);
    const text = try std.fmt.allocPrint(allocator, "{f}", .{&target});
    defer allocator.free(text);
    const copy = try parseUpstream(allocator, text);
    defer freeParsedUpstream(allocator, copy);
    try std.testing.expectEqual(2, copy.weight);
    try std.testing.expectEqualStrings("/tmp/roots.pem", copy.tls_ca_file.?);
    try std.testing.expectEqualStrings("origin.example.test", copy.tls_server_name.?);
    for ([_][]const u8{
        "http://localhost tls_ca_file=/tmp/ca.pem",                            "http://localhost tls_server_name=origin.test",
        "https://localhost tls_server_name=bad_name",                          "https://localhost tls_server_name=*.example.test",
        "https://localhost tls_server_name=one.test tls_server_name=two.test", "https://localhost tls_ca_file=a tls_ca_file=b",
        "https://localhost tls_ca_file=",                                      "https://localhost typo=1",
    }) |value| try std.testing.expectError(error.InvalidUpstream, parseUpstream(allocator, value));
}

test "upstream parsing cleans up every allocation failure" {
    const Check = struct {
        fn parse(allocator: std.mem.Allocator) !void {
            var pool = try parseUpstreamPool(allocator, "https://[::1]:8443/app weight=2 tls_ca_file=/tmp/roots.pem tls_server_name=origin.test http://localhost:9000");
            defer {
                for (pool.targets.items) |target| freeParsedUpstream(allocator, target);
                pool.targets.deinit(allocator);
            }
            try std.testing.expectEqual(2, pool.targets.items.len);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Check.parse, .{});
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
        .sticky_cookie => "sticky_cookie",
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
    if (std.ascii.eqlIgnoreCase(value, "sticky_cookie") or
        std.ascii.eqlIgnoreCase(value, "sticky-cookie") or
        std.ascii.eqlIgnoreCase(value, "sticky") or
        std.ascii.eqlIgnoreCase(value, "cookie"))
    {
        return .sticky_cookie;
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
