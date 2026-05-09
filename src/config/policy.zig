const std = @import("std");
const types = @import("types.zig");

const CompressionPolicy = types.CompressionPolicy;
const DomainConfig = types.DomainConfig;
const ResponseHeaderRule = types.ResponseHeaderRule;
const RouteConfig = types.RouteConfig;
const SecurityHeaderPreset = types.SecurityHeaderPreset;
const ServerConfig = types.ServerConfig;

pub const ResponseHeaderContext = struct {
    items: []const ResponseHeaderRule,
    owned: ?[]ResponseHeaderRule = null,

    pub fn deinit(self: ResponseHeaderContext, allocator: std.mem.Allocator) void {
        if (self.owned) |owned| allocator.free(owned);
    }
};

pub fn appendResponseHeaderSlice(dest: []ResponseHeaderRule, cursor: *usize, source: []const ResponseHeaderRule) void {
    if (source.len == 0) return;
    @memcpy(dest[cursor.* .. cursor.* + source.len], source);
    cursor.* += source.len;
}

const SECURITY_BASIC_HEADERS = [_]ResponseHeaderRule{
    .{ .name = "X-Content-Type-Options", .value = "nosniff" },
    .{ .name = "X-Frame-Options", .value = "DENY" },
    .{ .name = "Referrer-Policy", .value = "strict-origin-when-cross-origin" },
};

const SECURITY_STRICT_HEADERS = [_]ResponseHeaderRule{
    .{ .name = "X-Content-Type-Options", .value = "nosniff" },
    .{ .name = "X-Frame-Options", .value = "DENY" },
    .{ .name = "Referrer-Policy", .value = "strict-origin-when-cross-origin" },
    .{ .name = "Cross-Origin-Opener-Policy", .value = "same-origin" },
    .{ .name = "Cross-Origin-Resource-Policy", .value = "same-origin" },
    .{ .name = "Permissions-Policy", .value = "geolocation=(), microphone=(), camera=()" },
    .{ .name = "Content-Security-Policy", .value = "default-src 'self'; base-uri 'self'; frame-ancestors 'none'" },
};

pub fn securityHeaderPresetName(preset: SecurityHeaderPreset) []const u8 {
    return switch (preset) {
        .off => "off",
        .basic => "basic",
        .strict => "strict",
    };
}

pub fn parseSecurityHeaderPreset(value: []const u8) !SecurityHeaderPreset {
    if (std.ascii.eqlIgnoreCase(value, "off") or std.ascii.eqlIgnoreCase(value, "false") or std.mem.eql(u8, value, "0")) return .off;
    if (std.ascii.eqlIgnoreCase(value, "basic") or std.ascii.eqlIgnoreCase(value, "on") or std.ascii.eqlIgnoreCase(value, "true") or std.mem.eql(u8, value, "1")) return .basic;
    if (std.ascii.eqlIgnoreCase(value, "strict") or std.ascii.eqlIgnoreCase(value, "hardened")) return .strict;
    return error.InvalidConfigValue;
}

pub fn securityHeaderPresetFor(cfg: *const ServerConfig, domain: ?*const DomainConfig, route: ?*const RouteConfig) SecurityHeaderPreset {
    var preset = cfg.security_headers;
    if (domain) |d| {
        if (d.security_headers) |value| preset = value;
    }
    if (route) |r| {
        if (r.security_headers) |value| preset = value;
    }
    return preset;
}

fn securityHeaderRulesForPreset(preset: SecurityHeaderPreset) []const ResponseHeaderRule {
    return switch (preset) {
        .off => &.{},
        .basic => &SECURITY_BASIC_HEADERS,
        .strict => &SECURITY_STRICT_HEADERS,
    };
}

fn responseHeaderSourcesContain(name: []const u8, global_headers: []const ResponseHeaderRule, domain_headers: []const ResponseHeaderRule, route_headers: []const ResponseHeaderRule) bool {
    return responseHeaderRulesContain(global_headers, name) or
        responseHeaderRulesContain(domain_headers, name) or
        responseHeaderRulesContain(route_headers, name);
}

fn appendSecurityHeaderRules(dest: []ResponseHeaderRule, cursor: *usize, preset_headers: []const ResponseHeaderRule, global_headers: []const ResponseHeaderRule, domain_headers: []const ResponseHeaderRule, route_headers: []const ResponseHeaderRule) void {
    for (preset_headers) |header| {
        if (responseHeaderSourcesContain(header.name, global_headers, domain_headers, route_headers)) continue;
        dest[cursor.*] = header;
        cursor.* += 1;
    }
}

pub fn buildResponseHeaderContext(allocator: std.mem.Allocator, cfg: *const ServerConfig, domain: ?*const DomainConfig, route: ?*const RouteConfig) !ResponseHeaderContext {
    const domain_headers = if (domain) |d| d.response_headers.items else &.{};
    const route_headers = if (route) |r| r.response_headers.items else &.{};
    const preset_headers = securityHeaderRulesForPreset(securityHeaderPresetFor(cfg, domain, route));
    var preset_count: usize = 0;
    for (preset_headers) |header| {
        if (!responseHeaderSourcesContain(header.name, cfg.response_headers.items, domain_headers, route_headers)) preset_count += 1;
    }
    const count = preset_count + cfg.response_headers.items.len + domain_headers.len + route_headers.len;
    if (count == 0) return .{ .items = &.{} };

    const owned = try allocator.alloc(ResponseHeaderRule, count);
    var cursor: usize = 0;
    appendSecurityHeaderRules(owned, &cursor, preset_headers, cfg.response_headers.items, domain_headers, route_headers);
    appendResponseHeaderSlice(owned, &cursor, cfg.response_headers.items);
    appendResponseHeaderSlice(owned, &cursor, domain_headers);
    appendResponseHeaderSlice(owned, &cursor, route_headers);
    return .{ .items = owned, .owned = owned };
}

pub const ResponseCachePolicy = struct {
    enabled: bool,
    max_bytes: usize,
    max_entry_bytes: usize,
    ttl_ms: u32,
};

pub fn responseCachePolicyFromConfig(cfg: *const ServerConfig) ResponseCachePolicy {
    return .{
        .enabled = cfg.response_cache_enabled,
        .max_bytes = cfg.response_cache_max_bytes,
        .max_entry_bytes = cfg.response_cache_max_entry_bytes,
        .ttl_ms = cfg.response_cache_ttl_ms,
    };
}

fn applyDomainResponseCacheOverrides(policy: *ResponseCachePolicy, domain: *const DomainConfig) void {
    if (domain.response_cache_enabled) |value| policy.enabled = value;
    if (domain.response_cache_max_bytes) |value| policy.max_bytes = value;
    if (domain.response_cache_max_entry_bytes) |value| policy.max_entry_bytes = value;
    if (domain.response_cache_ttl_ms) |value| policy.ttl_ms = value;
}

fn applyRouteResponseCacheOverrides(policy: *ResponseCachePolicy, route: *const RouteConfig) void {
    if (route.response_cache_enabled) |value| policy.enabled = value;
    if (route.response_cache_max_bytes) |value| policy.max_bytes = value;
    if (route.response_cache_max_entry_bytes) |value| policy.max_entry_bytes = value;
    if (route.response_cache_ttl_ms) |value| policy.ttl_ms = value;
}

pub fn responseCachePolicyFor(cfg: *const ServerConfig, domain: ?*const DomainConfig, route: ?*const RouteConfig) ResponseCachePolicy {
    var policy = responseCachePolicyFromConfig(cfg);
    if (domain) |d| applyDomainResponseCacheOverrides(&policy, d);
    if (route) |r| applyRouteResponseCacheOverrides(&policy, r);
    return policy;
}

pub fn maxStaticFileBytesFor(cfg: *const ServerConfig, domain: ?*const DomainConfig, route: ?*const RouteConfig) usize {
    var value = cfg.max_static_file_bytes;
    if (domain) |d| {
        if (d.max_static_file_bytes) |domain_value| value = domain_value;
    }
    if (route) |r| {
        if (r.max_static_file_bytes) |route_value| value = route_value;
    }
    return value;
}

pub const UpstreamRuntimePolicy = struct {
    timeout_ms: u32,
    retries: usize,
    max_failures: usize,
    fail_timeout_ms: u32,
    health_check_enabled: bool,
    health_check_path: []const u8,
    health_check_interval_ms: u32,
    health_check_timeout_ms: u32,
    circuit_breaker_enabled: bool,
    circuit_half_open_max: usize,
    slow_start_ms: u32,
};

pub fn upstreamRuntimePolicyFromConfig(cfg: *const ServerConfig) UpstreamRuntimePolicy {
    return .{
        .timeout_ms = cfg.upstream_timeout_ms,
        .retries = cfg.upstream_retries,
        .max_failures = cfg.upstream_max_failures,
        .fail_timeout_ms = cfg.upstream_fail_timeout_ms,
        .health_check_enabled = cfg.upstream_health_check_enabled,
        .health_check_path = cfg.upstream_health_check_path,
        .health_check_interval_ms = cfg.upstream_health_check_interval_ms,
        .health_check_timeout_ms = cfg.upstream_health_check_timeout_ms,
        .circuit_breaker_enabled = cfg.upstream_circuit_breaker_enabled,
        .circuit_half_open_max = cfg.upstream_circuit_half_open_max,
        .slow_start_ms = cfg.upstream_slow_start_ms,
    };
}

fn applyDomainUpstreamRuntimeOverrides(policy: *UpstreamRuntimePolicy, domain: *const DomainConfig) void {
    if (domain.upstream_timeout_ms) |value| policy.timeout_ms = value;
    if (domain.upstream_retries) |value| policy.retries = value;
    if (domain.upstream_max_failures) |value| policy.max_failures = value;
    if (domain.upstream_fail_timeout_ms) |value| policy.fail_timeout_ms = value;
    if (domain.upstream_health_check_enabled) |value| policy.health_check_enabled = value;
    if (domain.upstream_health_check_path) |value| policy.health_check_path = value;
    if (domain.upstream_health_check_interval_ms) |value| policy.health_check_interval_ms = value;
    if (domain.upstream_health_check_timeout_ms) |value| policy.health_check_timeout_ms = value;
    if (domain.upstream_circuit_breaker_enabled) |value| policy.circuit_breaker_enabled = value;
    if (domain.upstream_circuit_half_open_max) |value| policy.circuit_half_open_max = value;
    if (domain.upstream_slow_start_ms) |value| policy.slow_start_ms = value;
}

fn applyRouteUpstreamRuntimeOverrides(policy: *UpstreamRuntimePolicy, route: *const RouteConfig) void {
    if (route.upstream_timeout_ms) |value| policy.timeout_ms = value;
    if (route.upstream_retries) |value| policy.retries = value;
    if (route.upstream_max_failures) |value| policy.max_failures = value;
    if (route.upstream_fail_timeout_ms) |value| policy.fail_timeout_ms = value;
    if (route.upstream_health_check_enabled) |value| policy.health_check_enabled = value;
    if (route.upstream_health_check_path) |value| policy.health_check_path = value;
    if (route.upstream_health_check_interval_ms) |value| policy.health_check_interval_ms = value;
    if (route.upstream_health_check_timeout_ms) |value| policy.health_check_timeout_ms = value;
    if (route.upstream_circuit_breaker_enabled) |value| policy.circuit_breaker_enabled = value;
    if (route.upstream_circuit_half_open_max) |value| policy.circuit_half_open_max = value;
    if (route.upstream_slow_start_ms) |value| policy.slow_start_ms = value;
}

pub fn upstreamRuntimePolicyFor(cfg: *const ServerConfig, domain: ?*const DomainConfig, route: ?*const RouteConfig) UpstreamRuntimePolicy {
    var policy = upstreamRuntimePolicyFromConfig(cfg);
    if (domain) |d| applyDomainUpstreamRuntimeOverrides(&policy, d);
    if (route) |r| applyRouteUpstreamRuntimeOverrides(&policy, r);
    return policy;
}

pub fn compressionPolicyFromConfig(cfg: *const ServerConfig) CompressionPolicy {
    return .{
        .enabled = cfg.compression_enabled,
        .gzip_enabled = cfg.gzip_enabled,
        .min_bytes = cfg.compression_min_bytes,
        .max_bytes = cfg.compression_max_bytes,
    };
}

fn applyDomainCompressionOverrides(policy: *CompressionPolicy, domain: *const DomainConfig) void {
    if (domain.compression_enabled) |value| policy.enabled = value;
    if (domain.gzip_enabled) |value| policy.gzip_enabled = value;
    if (domain.compression_min_bytes) |value| policy.min_bytes = value;
    if (domain.compression_max_bytes) |value| policy.max_bytes = value;
}

fn applyRouteCompressionOverrides(policy: *CompressionPolicy, route: *const RouteConfig) void {
    if (route.compression_enabled) |value| policy.enabled = value;
    if (route.gzip_enabled) |value| policy.gzip_enabled = value;
    if (route.compression_min_bytes) |value| policy.min_bytes = value;
    if (route.compression_max_bytes) |value| policy.max_bytes = value;
}

pub fn compressionPolicyFor(cfg: *const ServerConfig, domain: ?*const DomainConfig, route: ?*const RouteConfig) CompressionPolicy {
    var policy = compressionPolicyFromConfig(cfg);
    if (domain) |d| applyDomainCompressionOverrides(&policy, d);
    if (route) |r| applyRouteCompressionOverrides(&policy, r);
    return policy;
}

pub fn configCanEnableCompression(cfg: *const ServerConfig) bool {
    if (cfg.compression_enabled) return true;
    for (cfg.routes.items) |route| {
        if (route.compression_enabled orelse false) return true;
    }
    for (cfg.domains.items) |domain| {
        if (domain.compression_enabled orelse false) return true;
        for (domain.routes.items) |route| {
            if (route.compression_enabled orelse false) return true;
        }
    }
    return false;
}

pub fn configCanRunHealthChecks(cfg: *const ServerConfig) bool {
    if (cfg.upstream != null and upstreamRuntimePolicyFor(cfg, null, null).health_check_enabled) return true;
    for (cfg.routes.items) |*route| {
        if (route.upstream != null and upstreamRuntimePolicyFor(cfg, null, route).health_check_enabled) return true;
    }
    for (cfg.domains.items) |*domain| {
        if (domain.upstream != null and upstreamRuntimePolicyFor(cfg, domain, null).health_check_enabled) return true;
        for (domain.routes.items) |*route| {
            if (route.upstream != null and upstreamRuntimePolicyFor(cfg, domain, route).health_check_enabled) return true;
        }
    }
    return false;
}

pub fn responseHeaderRulesContain(headers: []const ResponseHeaderRule, name: []const u8) bool {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return true;
    }
    return false;
}
