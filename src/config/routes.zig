const std = @import("std");
const parsing = @import("parsing.zig");
const policy = @import("policy.zig");
const types = @import("types.zig");

const CacheStaleProperty = types.CacheStaleProperty;
const CompressionBoolProperty = types.CompressionBoolProperty;
const CompressionSizeProperty = types.CompressionSizeProperty;
const ResponseCacheBoolProperty = types.ResponseCacheBoolProperty;
const ResponseCacheSizeProperty = types.ResponseCacheSizeProperty;
const ResponseCacheU32Property = types.ResponseCacheU32Property;
const ResponseHeaderRule = types.ResponseHeaderRule;
const RouteBoolProperty = types.RouteBoolProperty;
const RouteConfig = types.RouteConfig;
const RouteHandlerKind = types.RouteHandlerKind;
const RouteMatchKind = types.RouteMatchKind;
const RouteStringProperty = types.RouteStringProperty;
const RouteU32Property = types.RouteU32Property;
const SecurityHeaderPreset = types.SecurityHeaderPreset;
const ServerConfig = types.ServerConfig;
const UpstreamUsizeProperty = types.UpstreamUsizeProperty;

const disablesOptionalUrl = parsing.disablesOptionalUrl;
const findRouteConfigMutable = parsing.findRouteConfigMutable;
const isRouteNameValid = parsing.isRouteNameValid;
const makeResponseHeaderRule = parsing.makeResponseHeaderRule;
const parseConfigBool = parsing.parseConfigBool;
const parseConfigU32 = parsing.parseConfigU32;
const parseConfigUsize = parsing.parseConfigUsize;
const parseOptionalUpstreamPoolPolicy = parsing.parseOptionalUpstreamPoolPolicy;
const parseResponseHeaderRule = parsing.parseResponseHeaderRule;
const parseRouteHandler = parsing.parseRouteHandler;
const parseUpstreamPool = parsing.parseUpstreamPool;
const parseSecurityHeaderPreset = policy.parseSecurityHeaderPreset;

pub fn setRouteLineFor(routes: *std.ArrayList(RouteConfig), allocator: std.mem.Allocator, raw: []const u8) !void {
    var parts = std.mem.tokenizeAny(u8, raw, " \t");
    const name = parts.next() orelse return error.InvalidConfigValue;
    const pattern_raw = parts.next() orelse return error.InvalidConfigValue;
    const handler_raw = parts.next() orelse return error.InvalidConfigValue;
    if (parts.next() != null) return error.InvalidConfigValue;
    if (!isRouteNameValid(name)) return error.InvalidConfigValue;
    if (findRouteConfigMutable(routes, name) != null) return error.DuplicateConfigRoute;
    if (pattern_raw.len == 0 or pattern_raw[0] != '/') return error.InvalidConfigValue;

    const match_kind: RouteMatchKind = if (std.mem.endsWith(u8, pattern_raw, "*")) .prefix else .exact;
    const pattern_without_star = if (match_kind == .prefix) pattern_raw[0 .. pattern_raw.len - 1] else pattern_raw;
    const normalized_pattern = if (pattern_without_star.len == 0) "/" else pattern_without_star;

    try routes.append(allocator, .{
        .name = try allocator.dupe(u8, name),
        .pattern = try allocator.dupe(u8, normalized_pattern),
        .match_kind = match_kind,
        .handler = try parseRouteHandler(handler_raw),
        .strip_prefix = true,
        .static_dir = null,
        .index_file = null,
        .php_root = null,
        .php_binary = null,
        .php_index = null,
        .php_fastcgi = null,
        .php_info_page = null,
        .php_front_controller = null,
        .upstream = null,
        .upstream_policy = null,
        .upstream_timeout_ms = null,
        .compression_enabled = null,
        .gzip_enabled = null,
        .compression_min_bytes = null,
        .compression_max_bytes = null,
        .response_cache_enabled = null,
        .response_cache_max_bytes = null,
        .response_cache_max_entry_bytes = null,
        .response_cache_ttl_ms = null,
        .security_headers = null,
        .max_static_file_bytes = null,
        .upstream_retries = null,
        .upstream_max_failures = null,
        .upstream_fail_timeout_ms = null,
        .upstream_health_check_enabled = null,
        .upstream_health_check_path = null,
        .upstream_health_check_interval_ms = null,
        .upstream_health_check_timeout_ms = null,
        .upstream_circuit_breaker_enabled = null,
        .upstream_circuit_half_open_max = null,
        .upstream_slow_start_ms = null,
        .response_headers = .empty,
    });
}

pub fn setRouteLine(cfg: *ServerConfig, allocator: std.mem.Allocator, raw: []const u8) !void {
    try setRouteLineFor(&cfg.routes, allocator, raw);
}

pub fn setRouteStringProperty(
    routes: *std.ArrayList(RouteConfig),
    allocator: std.mem.Allocator,
    route_name: []const u8,
    value: []const u8,
    field: RouteStringProperty,
) !void {
    if (value.len == 0) return error.InvalidConfigValue;
    const route = findRouteConfigMutable(routes, route_name) orelse return error.UnknownConfigRoute;
    const dupe_value = try allocator.dupe(u8, value);
    switch (field) {
        .static_dir => route.static_dir = dupe_value,
        .index_file => route.index_file = dupe_value,
        .php_root => route.php_root = dupe_value,
        .php_binary => route.php_binary = dupe_value,
        .php_index => route.php_index = dupe_value,
        .php_fastcgi => route.php_fastcgi = dupe_value,
        .upstream_health_check_path => route.upstream_health_check_path = dupe_value,
    }
}

pub fn setRouteProxyProperty(routes: *std.ArrayList(RouteConfig), allocator: std.mem.Allocator, route_name: []const u8, value: []const u8) !void {
    const route = findRouteConfigMutable(routes, route_name) orelse return error.UnknownConfigRoute;
    if (disablesOptionalUrl(value)) {
        route.upstream = null;
    } else {
        route.upstream = try parseUpstreamPool(allocator, value);
    }
}

pub fn setRouteUpstreamPolicyProperty(routes: *std.ArrayList(RouteConfig), route_name: []const u8, value: []const u8) !void {
    const route = findRouteConfigMutable(routes, route_name) orelse return error.UnknownConfigRoute;
    route.upstream_policy = try parseOptionalUpstreamPoolPolicy(value);
}

pub fn setRouteU32Property(routes: *std.ArrayList(RouteConfig), route_name: []const u8, value: []const u8, field: RouteU32Property) !void {
    const route = findRouteConfigMutable(routes, route_name) orelse return error.UnknownConfigRoute;
    const parsed = try parseConfigU32(value);
    switch (field) {
        .upstream_timeout_ms => {
            if (parsed == 0) return error.InvalidConfigValue;
            route.upstream_timeout_ms = parsed;
        },
        .upstream_fail_timeout_ms => route.upstream_fail_timeout_ms = parsed,
        .upstream_health_check_interval_ms => {
            if (parsed == 0) return error.InvalidConfigValue;
            route.upstream_health_check_interval_ms = parsed;
        },
        .upstream_health_check_timeout_ms => {
            if (parsed == 0) return error.InvalidConfigValue;
            route.upstream_health_check_timeout_ms = parsed;
        },
        .upstream_slow_start_ms => route.upstream_slow_start_ms = parsed,
    }
}

pub fn setRouteBoolProperty(routes: *std.ArrayList(RouteConfig), route_name: []const u8, value: []const u8, field: RouteBoolProperty) !void {
    const route = findRouteConfigMutable(routes, route_name) orelse return error.UnknownConfigRoute;
    const parsed = try parseConfigBool(value);
    switch (field) {
        .php_info_page => route.php_info_page = parsed,
        .php_front_controller => route.php_front_controller = parsed,
        .strip_prefix => route.strip_prefix = parsed,
        .upstream_health_check_enabled => route.upstream_health_check_enabled = parsed,
        .upstream_circuit_breaker_enabled => route.upstream_circuit_breaker_enabled = parsed,
    }
}

pub fn setRouteCompressionBoolProperty(routes: *std.ArrayList(RouteConfig), route_name: []const u8, value: []const u8, field: CompressionBoolProperty) !void {
    const route = findRouteConfigMutable(routes, route_name) orelse return error.UnknownConfigRoute;
    const parsed = try parseConfigBool(value);
    switch (field) {
        .enabled => route.compression_enabled = parsed,
        .gzip_enabled => route.gzip_enabled = parsed,
    }
}

pub fn setRouteCompressionSizeProperty(routes: *std.ArrayList(RouteConfig), route_name: []const u8, value: []const u8, field: CompressionSizeProperty) !void {
    const route = findRouteConfigMutable(routes, route_name) orelse return error.UnknownConfigRoute;
    const parsed = try parseConfigUsize(value);
    if (parsed == 0) return error.InvalidConfigValue;
    switch (field) {
        .min_bytes => route.compression_min_bytes = parsed,
        .max_bytes => route.compression_max_bytes = parsed,
    }
}

pub fn setRouteResponseCacheBoolProperty(routes: *std.ArrayList(RouteConfig), route_name: []const u8, value: []const u8, field: ResponseCacheBoolProperty) !void {
    const route = findRouteConfigMutable(routes, route_name) orelse return error.UnknownConfigRoute;
    const parsed = try parseConfigBool(value);
    switch (field) {
        .enabled => route.response_cache_enabled = parsed,
    }
}

pub fn setRouteResponseCacheSizeProperty(routes: *std.ArrayList(RouteConfig), route_name: []const u8, value: []const u8, field: ResponseCacheSizeProperty) !void {
    const route = findRouteConfigMutable(routes, route_name) orelse return error.UnknownConfigRoute;
    const parsed = try parseConfigUsize(value);
    if (parsed == 0) return error.InvalidConfigValue;
    switch (field) {
        .max_bytes => route.response_cache_max_bytes = parsed,
        .max_entry_bytes => route.response_cache_max_entry_bytes = parsed,
    }
}

pub fn setRouteResponseCacheU32Property(routes: *std.ArrayList(RouteConfig), route_name: []const u8, value: []const u8, field: ResponseCacheU32Property) !void {
    const route = findRouteConfigMutable(routes, route_name) orelse return error.UnknownConfigRoute;
    const parsed = try parseConfigU32(value);
    if (parsed == 0) return error.InvalidConfigValue;
    switch (field) {
        .ttl_ms => route.response_cache_ttl_ms = parsed,
    }
}

pub fn setRouteSecurityHeadersProperty(routes: *std.ArrayList(RouteConfig), route_name: []const u8, value: []const u8) !void {
    const route = findRouteConfigMutable(routes, route_name) orelse return error.UnknownConfigRoute;
    route.security_headers = try parseSecurityHeaderPreset(value);
}

pub fn setRouteMaxStaticFileBytes(routes: *std.ArrayList(RouteConfig), route_name: []const u8, value: []const u8) !void {
    const route = findRouteConfigMutable(routes, route_name) orelse return error.UnknownConfigRoute;
    const parsed = try parseConfigUsize(value);
    if (parsed == 0) return error.InvalidConfigValue;
    route.max_static_file_bytes = parsed;
}

pub fn setRouteUpstreamUsizeProperty(routes: *std.ArrayList(RouteConfig), route_name: []const u8, value: []const u8, field: UpstreamUsizeProperty) !void {
    const route = findRouteConfigMutable(routes, route_name) orelse return error.UnknownConfigRoute;
    const parsed = try parseConfigUsize(value);
    switch (field) {
        .retries => route.upstream_retries = parsed,
        .max_failures => route.upstream_max_failures = parsed,
        .circuit_half_open_max => {
            if (parsed == 0) return error.InvalidConfigValue;
            route.upstream_circuit_half_open_max = parsed;
        },
    }
}

pub fn appendRouteResponseHeader(routes: *std.ArrayList(RouteConfig), allocator: std.mem.Allocator, route_name: []const u8, value: []const u8) !void {
    const route = findRouteConfigMutable(routes, route_name) orelse return error.UnknownConfigRoute;
    if (value.len > 0) try route.response_headers.append(allocator, try parseResponseHeaderRule(allocator, value));
}

pub fn appendRouteCacheControl(routes: *std.ArrayList(RouteConfig), allocator: std.mem.Allocator, route_name: []const u8, value: []const u8) !void {
    const route = findRouteConfigMutable(routes, route_name) orelse return error.UnknownConfigRoute;
    if (value.len > 0) try route.response_headers.append(allocator, try makeResponseHeaderRule(allocator, "Cache-Control", value));
}

fn cacheStaleDirectiveName(field: CacheStaleProperty) []const u8 {
    return switch (field) {
        .stale_while_revalidate => "stale-while-revalidate",
        .stale_if_error => "stale-if-error",
    };
}

pub fn appendCacheStaleDirective(headers: *std.ArrayList(ResponseHeaderRule), allocator: std.mem.Allocator, value: []const u8, field: CacheStaleProperty) !void {
    const seconds = try parseConfigU32(value);
    if (seconds == 0) return error.InvalidConfigValue;
    try headers.append(allocator, .{
        .name = try allocator.dupe(u8, "Cache-Control"),
        .value = try std.fmt.allocPrint(allocator, "{s}={d}", .{ cacheStaleDirectiveName(field), seconds }),
    });
}

pub fn appendRouteCacheStaleDirective(routes: *std.ArrayList(RouteConfig), allocator: std.mem.Allocator, route_name: []const u8, value: []const u8, field: CacheStaleProperty) !void {
    const route = findRouteConfigMutable(routes, route_name) orelse return error.UnknownConfigRoute;
    try appendCacheStaleDirective(&route.response_headers, allocator, value, field);
}
