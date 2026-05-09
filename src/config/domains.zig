const std = @import("std");
const http_headers = @import("../http_headers.zig");
const parsing = @import("parsing.zig");
const policy = @import("policy.zig");
const routes_mod = @import("routes.zig");
const types = @import("types.zig");

const CacheStaleProperty = types.CacheStaleProperty;
const CompressionBoolProperty = types.CompressionBoolProperty;
const CompressionSizeProperty = types.CompressionSizeProperty;
const DomainBoolProperty = types.DomainBoolProperty;
const DomainConfig = types.DomainConfig;
const DomainStringProperty = types.DomainStringProperty;
const DomainU32Property = types.DomainU32Property;
const ResponseCacheBoolProperty = types.ResponseCacheBoolProperty;
const ResponseCacheSizeProperty = types.ResponseCacheSizeProperty;
const ResponseCacheU32Property = types.ResponseCacheU32Property;
const ResponseHeaderRule = types.ResponseHeaderRule;
const RouteBoolProperty = types.RouteBoolProperty;
const RouteStringProperty = types.RouteStringProperty;
const RouteU32Property = types.RouteU32Property;
const ServerConfig = types.ServerConfig;
const UpstreamUsizeProperty = types.UpstreamUsizeProperty;

const disablesOptionalUrl = parsing.disablesOptionalUrl;
const findRouteConfigMutable = parsing.findRouteConfigMutable;
const isDomainConfigNameValidBase = parsing.isRouteNameValid;
const makeResponseHeaderRule = parsing.makeResponseHeaderRule;
const parseConfigBool = parsing.parseConfigBool;
const parseConfigU32 = parsing.parseConfigU32;
const parseConfigUsize = parsing.parseConfigUsize;
const parseOptionalUpstreamPoolPolicy = parsing.parseOptionalUpstreamPoolPolicy;
const parseResponseHeaderRule = parsing.parseResponseHeaderRule;
const parseUpstreamPool = parsing.parseUpstreamPool;
const parseSecurityHeaderPreset = policy.parseSecurityHeaderPreset;
const trimValue = http_headers.trimValue;
const appendCacheStaleDirective = routes_mod.appendCacheStaleDirective;
const appendRouteCacheControl = routes_mod.appendRouteCacheControl;
const appendRouteCacheStaleDirective = routes_mod.appendRouteCacheStaleDirective;
const appendRouteResponseHeader = routes_mod.appendRouteResponseHeader;
const setRouteBoolProperty = routes_mod.setRouteBoolProperty;
const setRouteCompressionBoolProperty = routes_mod.setRouteCompressionBoolProperty;
const setRouteCompressionSizeProperty = routes_mod.setRouteCompressionSizeProperty;
const setRouteLineFor = routes_mod.setRouteLineFor;
const setRouteMaxStaticFileBytes = routes_mod.setRouteMaxStaticFileBytes;
const setRouteProxyProperty = routes_mod.setRouteProxyProperty;
const setRouteResponseCacheBoolProperty = routes_mod.setRouteResponseCacheBoolProperty;
const setRouteResponseCacheSizeProperty = routes_mod.setRouteResponseCacheSizeProperty;
const setRouteResponseCacheU32Property = routes_mod.setRouteResponseCacheU32Property;
const setRouteSecurityHeadersProperty = routes_mod.setRouteSecurityHeadersProperty;
const setRouteStringProperty = routes_mod.setRouteStringProperty;
const setRouteU32Property = routes_mod.setRouteU32Property;
const setRouteUpstreamPolicyProperty = routes_mod.setRouteUpstreamPolicyProperty;
const setRouteUpstreamUsizeProperty = routes_mod.setRouteUpstreamUsizeProperty;

pub fn isDomainConfigNameValid(name: []const u8) bool {
    return isDomainConfigNameValidBase(name);
}

pub fn findDomainConfigMutable(cfg: *ServerConfig, name: []const u8) ?*DomainConfig {
    for (cfg.domains.items) |*domain| {
        if (std.mem.eql(u8, domain.name, name)) return domain;
    }
    return null;
}

pub fn initDomainConfig(allocator: std.mem.Allocator, name: []const u8) !DomainConfig {
    if (!isDomainConfigNameValid(name)) return error.InvalidConfigValue;
    return .{
        .name = try allocator.dupe(u8, name),
        .server_names = .empty,
        .static_dir = null,
        .serve_static_root = null,
        .index_file = null,
        .php_root = null,
        .php_binary = null,
        .php_index = null,
        .php_fastcgi = null,
        .php_info_page = null,
        .php_front_controller = null,
        .tls_cert = null,
        .tls_key = null,
        .tls_material = null,
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
        .redirects = .empty,
        .routes = .empty,
    };
}

pub fn splitDomainRoutePropertyName(value: []const u8) ?struct { domain: []const u8, route: []const u8 } {
    const dot = std.mem.indexOfScalar(u8, value, '.') orelse return null;
    const domain = value[0..dot];
    const route = value[dot + 1 ..];
    if (domain.len == 0 or route.len == 0) return null;
    return .{ .domain = domain, .route = route };
}

pub fn appendServerNames(allocator: std.mem.Allocator, domain: *DomainConfig, value: []const u8) !void {
    var parts = std.mem.tokenizeAny(u8, value, " \t,");
    var added = false;
    while (parts.next()) |name| {
        if (name.len == 0) continue;
        try domain.server_names.append(allocator, try allocator.dupe(u8, name));
        added = true;
    }
    if (!added) return error.InvalidConfigValue;
}

pub fn setDomainLine(cfg: *ServerConfig, allocator: std.mem.Allocator, raw: []const u8) !void {
    const name = trimValue(raw);
    if (!isDomainConfigNameValid(name)) return error.InvalidConfigValue;
    if (findDomainConfigMutable(cfg, name) != null) return error.DuplicateConfigDomain;

    try cfg.domains.append(allocator, try initDomainConfig(allocator, name));
}

pub fn setDomainStringProperty(
    cfg: *ServerConfig,
    allocator: std.mem.Allocator,
    domain_name: []const u8,
    value: []const u8,
    field: DomainStringProperty,
) !void {
    if (value.len == 0) return error.InvalidConfigValue;
    const domain = findDomainConfigMutable(cfg, domain_name) orelse return error.UnknownConfigDomain;
    const dupe_value = try allocator.dupe(u8, value);
    switch (field) {
        .static_dir => domain.static_dir = dupe_value,
        .index_file => domain.index_file = dupe_value,
        .php_root => domain.php_root = dupe_value,
        .php_binary => domain.php_binary = dupe_value,
        .php_index => domain.php_index = dupe_value,
        .php_fastcgi => domain.php_fastcgi = dupe_value,
        .tls_cert => domain.tls_cert = dupe_value,
        .tls_key => domain.tls_key = dupe_value,
        .upstream_health_check_path => domain.upstream_health_check_path = dupe_value,
    }
}

pub fn setDomainBoolProperty(cfg: *ServerConfig, domain_name: []const u8, value: []const u8, field: DomainBoolProperty) !void {
    const domain = findDomainConfigMutable(cfg, domain_name) orelse return error.UnknownConfigDomain;
    const parsed = try parseConfigBool(value);
    switch (field) {
        .serve_static_root => domain.serve_static_root = parsed,
        .php_info_page => domain.php_info_page = parsed,
        .php_front_controller => domain.php_front_controller = parsed,
        .upstream_health_check_enabled => domain.upstream_health_check_enabled = parsed,
        .upstream_circuit_breaker_enabled => domain.upstream_circuit_breaker_enabled = parsed,
    }
}

pub fn setDomainProxyProperty(cfg: *ServerConfig, allocator: std.mem.Allocator, domain_name: []const u8, value: []const u8) !void {
    const domain = findDomainConfigMutable(cfg, domain_name) orelse return error.UnknownConfigDomain;
    if (disablesOptionalUrl(value)) {
        domain.upstream = null;
    } else {
        domain.upstream = try parseUpstreamPool(allocator, value);
    }
}

pub fn setDomainUpstreamPolicyProperty(cfg: *ServerConfig, domain_name: []const u8, value: []const u8) !void {
    const domain = findDomainConfigMutable(cfg, domain_name) orelse return error.UnknownConfigDomain;
    domain.upstream_policy = try parseOptionalUpstreamPoolPolicy(value);
}

pub fn setDomainU32Property(cfg: *ServerConfig, domain_name: []const u8, value: []const u8, field: DomainU32Property) !void {
    const domain = findDomainConfigMutable(cfg, domain_name) orelse return error.UnknownConfigDomain;
    const parsed = try parseConfigU32(value);
    switch (field) {
        .upstream_timeout_ms => {
            if (parsed == 0) return error.InvalidConfigValue;
            domain.upstream_timeout_ms = parsed;
        },
        .upstream_fail_timeout_ms => domain.upstream_fail_timeout_ms = parsed,
        .upstream_health_check_interval_ms => {
            if (parsed == 0) return error.InvalidConfigValue;
            domain.upstream_health_check_interval_ms = parsed;
        },
        .upstream_health_check_timeout_ms => {
            if (parsed == 0) return error.InvalidConfigValue;
            domain.upstream_health_check_timeout_ms = parsed;
        },
        .upstream_slow_start_ms => domain.upstream_slow_start_ms = parsed,
    }
}

pub fn setDomainCompressionBoolProperty(cfg: *ServerConfig, domain_name: []const u8, value: []const u8, field: CompressionBoolProperty) !void {
    const domain = findDomainConfigMutable(cfg, domain_name) orelse return error.UnknownConfigDomain;
    const parsed = try parseConfigBool(value);
    switch (field) {
        .enabled => domain.compression_enabled = parsed,
        .gzip_enabled => domain.gzip_enabled = parsed,
    }
}

pub fn setDomainCompressionSizeProperty(cfg: *ServerConfig, domain_name: []const u8, value: []const u8, field: CompressionSizeProperty) !void {
    const domain = findDomainConfigMutable(cfg, domain_name) orelse return error.UnknownConfigDomain;
    const parsed = try parseConfigUsize(value);
    if (parsed == 0) return error.InvalidConfigValue;
    switch (field) {
        .min_bytes => domain.compression_min_bytes = parsed,
        .max_bytes => domain.compression_max_bytes = parsed,
    }
}

pub fn setDomainResponseCacheBoolProperty(cfg: *ServerConfig, domain_name: []const u8, value: []const u8, field: ResponseCacheBoolProperty) !void {
    const domain = findDomainConfigMutable(cfg, domain_name) orelse return error.UnknownConfigDomain;
    const parsed = try parseConfigBool(value);
    switch (field) {
        .enabled => domain.response_cache_enabled = parsed,
    }
}

pub fn setDomainResponseCacheSizeProperty(cfg: *ServerConfig, domain_name: []const u8, value: []const u8, field: ResponseCacheSizeProperty) !void {
    const domain = findDomainConfigMutable(cfg, domain_name) orelse return error.UnknownConfigDomain;
    const parsed = try parseConfigUsize(value);
    if (parsed == 0) return error.InvalidConfigValue;
    switch (field) {
        .max_bytes => domain.response_cache_max_bytes = parsed,
        .max_entry_bytes => domain.response_cache_max_entry_bytes = parsed,
    }
}

pub fn setDomainResponseCacheU32Property(cfg: *ServerConfig, domain_name: []const u8, value: []const u8, field: ResponseCacheU32Property) !void {
    const domain = findDomainConfigMutable(cfg, domain_name) orelse return error.UnknownConfigDomain;
    const parsed = try parseConfigU32(value);
    if (parsed == 0) return error.InvalidConfigValue;
    switch (field) {
        .ttl_ms => domain.response_cache_ttl_ms = parsed,
    }
}

pub fn setDomainSecurityHeadersProperty(cfg: *ServerConfig, domain_name: []const u8, value: []const u8) !void {
    const domain = findDomainConfigMutable(cfg, domain_name) orelse return error.UnknownConfigDomain;
    domain.security_headers = try parseSecurityHeaderPreset(value);
}

pub fn setDomainMaxStaticFileBytes(cfg: *ServerConfig, domain_name: []const u8, value: []const u8) !void {
    const domain = findDomainConfigMutable(cfg, domain_name) orelse return error.UnknownConfigDomain;
    const parsed = try parseConfigUsize(value);
    if (parsed == 0) return error.InvalidConfigValue;
    domain.max_static_file_bytes = parsed;
}

pub fn setDomainUpstreamUsizeProperty(cfg: *ServerConfig, domain_name: []const u8, value: []const u8, field: UpstreamUsizeProperty) !void {
    const domain = findDomainConfigMutable(cfg, domain_name) orelse return error.UnknownConfigDomain;
    const parsed = try parseConfigUsize(value);
    switch (field) {
        .retries => domain.upstream_retries = parsed,
        .max_failures => domain.upstream_max_failures = parsed,
        .circuit_half_open_max => {
            if (parsed == 0) return error.InvalidConfigValue;
            domain.upstream_circuit_half_open_max = parsed;
        },
    }
}

pub fn appendDomainResponseHeader(cfg: *ServerConfig, allocator: std.mem.Allocator, domain_name: []const u8, value: []const u8) !void {
    const domain = findDomainConfigMutable(cfg, domain_name) orelse return error.UnknownConfigDomain;
    if (value.len > 0) try domain.response_headers.append(allocator, try parseResponseHeaderRule(allocator, value));
}

pub fn appendDomainCacheControl(cfg: *ServerConfig, allocator: std.mem.Allocator, domain_name: []const u8, value: []const u8) !void {
    const domain = findDomainConfigMutable(cfg, domain_name) orelse return error.UnknownConfigDomain;
    if (value.len > 0) try domain.response_headers.append(allocator, try makeResponseHeaderRule(allocator, "Cache-Control", value));
}

pub fn appendDomainCacheStaleDirective(cfg: *ServerConfig, allocator: std.mem.Allocator, domain_name: []const u8, value: []const u8, field: CacheStaleProperty) !void {
    const domain = findDomainConfigMutable(cfg, domain_name) orelse return error.UnknownConfigDomain;
    try appendCacheStaleDirective(&domain.response_headers, allocator, value, field);
}

pub fn setDomainRouteLine(cfg: *ServerConfig, allocator: std.mem.Allocator, domain_name: []const u8, value: []const u8) !void {
    const domain = findDomainConfigMutable(cfg, domain_name) orelse return error.UnknownConfigDomain;
    try setRouteLineFor(&domain.routes, allocator, value);
}

pub fn setDomainRouteStringProperty(
    cfg: *ServerConfig,
    allocator: std.mem.Allocator,
    property_name: []const u8,
    value: []const u8,
    field: RouteStringProperty,
) !void {
    const split = splitDomainRoutePropertyName(property_name) orelse return error.InvalidConfigValue;
    const domain = findDomainConfigMutable(cfg, split.domain) orelse return error.UnknownConfigDomain;
    try setRouteStringProperty(&domain.routes, allocator, split.route, value, field);
}

pub fn setDomainRouteBoolProperty(cfg: *ServerConfig, property_name: []const u8, value: []const u8, field: RouteBoolProperty) !void {
    const split = splitDomainRoutePropertyName(property_name) orelse return error.InvalidConfigValue;
    const domain = findDomainConfigMutable(cfg, split.domain) orelse return error.UnknownConfigDomain;
    try setRouteBoolProperty(&domain.routes, split.route, value, field);
}

pub fn setDomainRouteProxyProperty(cfg: *ServerConfig, allocator: std.mem.Allocator, property_name: []const u8, value: []const u8) !void {
    const split = splitDomainRoutePropertyName(property_name) orelse return error.InvalidConfigValue;
    const domain = findDomainConfigMutable(cfg, split.domain) orelse return error.UnknownConfigDomain;
    try setRouteProxyProperty(&domain.routes, allocator, split.route, value);
}

pub fn setDomainRouteUpstreamPolicyProperty(cfg: *ServerConfig, property_name: []const u8, value: []const u8) !void {
    const split = splitDomainRoutePropertyName(property_name) orelse return error.InvalidConfigValue;
    const domain = findDomainConfigMutable(cfg, split.domain) orelse return error.UnknownConfigDomain;
    try setRouteUpstreamPolicyProperty(&domain.routes, split.route, value);
}

pub fn setDomainRouteU32Property(cfg: *ServerConfig, property_name: []const u8, value: []const u8, field: RouteU32Property) !void {
    const split = splitDomainRoutePropertyName(property_name) orelse return error.InvalidConfigValue;
    const domain = findDomainConfigMutable(cfg, split.domain) orelse return error.UnknownConfigDomain;
    try setRouteU32Property(&domain.routes, split.route, value, field);
}

pub fn setDomainRouteCompressionBoolProperty(cfg: *ServerConfig, property_name: []const u8, value: []const u8, field: CompressionBoolProperty) !void {
    const split = splitDomainRoutePropertyName(property_name) orelse return error.InvalidConfigValue;
    const domain = findDomainConfigMutable(cfg, split.domain) orelse return error.UnknownConfigDomain;
    try setRouteCompressionBoolProperty(&domain.routes, split.route, value, field);
}

pub fn setDomainRouteCompressionSizeProperty(cfg: *ServerConfig, property_name: []const u8, value: []const u8, field: CompressionSizeProperty) !void {
    const split = splitDomainRoutePropertyName(property_name) orelse return error.InvalidConfigValue;
    const domain = findDomainConfigMutable(cfg, split.domain) orelse return error.UnknownConfigDomain;
    try setRouteCompressionSizeProperty(&domain.routes, split.route, value, field);
}

pub fn setDomainRouteResponseCacheBoolProperty(cfg: *ServerConfig, property_name: []const u8, value: []const u8, field: ResponseCacheBoolProperty) !void {
    const split = splitDomainRoutePropertyName(property_name) orelse return error.InvalidConfigValue;
    const domain = findDomainConfigMutable(cfg, split.domain) orelse return error.UnknownConfigDomain;
    try setRouteResponseCacheBoolProperty(&domain.routes, split.route, value, field);
}

pub fn setDomainRouteResponseCacheSizeProperty(cfg: *ServerConfig, property_name: []const u8, value: []const u8, field: ResponseCacheSizeProperty) !void {
    const split = splitDomainRoutePropertyName(property_name) orelse return error.InvalidConfigValue;
    const domain = findDomainConfigMutable(cfg, split.domain) orelse return error.UnknownConfigDomain;
    try setRouteResponseCacheSizeProperty(&domain.routes, split.route, value, field);
}

pub fn setDomainRouteResponseCacheU32Property(cfg: *ServerConfig, property_name: []const u8, value: []const u8, field: ResponseCacheU32Property) !void {
    const split = splitDomainRoutePropertyName(property_name) orelse return error.InvalidConfigValue;
    const domain = findDomainConfigMutable(cfg, split.domain) orelse return error.UnknownConfigDomain;
    try setRouteResponseCacheU32Property(&domain.routes, split.route, value, field);
}

pub fn setDomainRouteSecurityHeadersProperty(cfg: *ServerConfig, property_name: []const u8, value: []const u8) !void {
    const split = splitDomainRoutePropertyName(property_name) orelse return error.InvalidConfigValue;
    const domain = findDomainConfigMutable(cfg, split.domain) orelse return error.UnknownConfigDomain;
    try setRouteSecurityHeadersProperty(&domain.routes, split.route, value);
}

pub fn setDomainRouteMaxStaticFileBytes(cfg: *ServerConfig, property_name: []const u8, value: []const u8) !void {
    const split = splitDomainRoutePropertyName(property_name) orelse return error.InvalidConfigValue;
    const domain = findDomainConfigMutable(cfg, split.domain) orelse return error.UnknownConfigDomain;
    try setRouteMaxStaticFileBytes(&domain.routes, split.route, value);
}

pub fn setDomainRouteUpstreamUsizeProperty(cfg: *ServerConfig, property_name: []const u8, value: []const u8, field: UpstreamUsizeProperty) !void {
    const split = splitDomainRoutePropertyName(property_name) orelse return error.InvalidConfigValue;
    const domain = findDomainConfigMutable(cfg, split.domain) orelse return error.UnknownConfigDomain;
    try setRouteUpstreamUsizeProperty(&domain.routes, split.route, value, field);
}

pub fn appendDomainRouteResponseHeader(cfg: *ServerConfig, allocator: std.mem.Allocator, property_name: []const u8, value: []const u8) !void {
    const split = splitDomainRoutePropertyName(property_name) orelse return error.InvalidConfigValue;
    const domain = findDomainConfigMutable(cfg, split.domain) orelse return error.UnknownConfigDomain;
    try appendRouteResponseHeader(&domain.routes, allocator, split.route, value);
}

pub fn appendDomainRouteCacheControl(cfg: *ServerConfig, allocator: std.mem.Allocator, property_name: []const u8, value: []const u8) !void {
    const split = splitDomainRoutePropertyName(property_name) orelse return error.InvalidConfigValue;
    const domain = findDomainConfigMutable(cfg, split.domain) orelse return error.UnknownConfigDomain;
    try appendRouteCacheControl(&domain.routes, allocator, split.route, value);
}

pub fn appendDomainRouteCacheStaleDirective(cfg: *ServerConfig, allocator: std.mem.Allocator, property_name: []const u8, value: []const u8, field: CacheStaleProperty) !void {
    const split = splitDomainRoutePropertyName(property_name) orelse return error.InvalidConfigValue;
    const domain = findDomainConfigMutable(cfg, split.domain) orelse return error.UnknownConfigDomain;
    try appendRouteCacheStaleDirective(&domain.routes, allocator, split.route, value, field);
}

pub fn setDomainStringPropertyDirect(allocator: std.mem.Allocator, domain: *DomainConfig, value: []const u8, field: DomainStringProperty) !void {
    if (value.len == 0) return error.InvalidConfigValue;
    const dupe_value = try allocator.dupe(u8, value);
    switch (field) {
        .static_dir => domain.static_dir = dupe_value,
        .index_file => domain.index_file = dupe_value,
        .php_root => domain.php_root = dupe_value,
        .php_binary => domain.php_binary = dupe_value,
        .php_index => domain.php_index = dupe_value,
        .php_fastcgi => domain.php_fastcgi = dupe_value,
        .tls_cert => domain.tls_cert = dupe_value,
        .tls_key => domain.tls_key = dupe_value,
        .upstream_health_check_path => domain.upstream_health_check_path = dupe_value,
    }
}

pub fn setDomainBoolPropertyDirect(domain: *DomainConfig, value: []const u8, field: DomainBoolProperty) !void {
    const parsed = try parseConfigBool(value);
    switch (field) {
        .serve_static_root => domain.serve_static_root = parsed,
        .php_info_page => domain.php_info_page = parsed,
        .php_front_controller => domain.php_front_controller = parsed,
        .upstream_health_check_enabled => domain.upstream_health_check_enabled = parsed,
        .upstream_circuit_breaker_enabled => domain.upstream_circuit_breaker_enabled = parsed,
    }
}

pub fn setDomainProxyPropertyDirect(allocator: std.mem.Allocator, domain: *DomainConfig, value: []const u8) !void {
    if (disablesOptionalUrl(value)) {
        domain.upstream = null;
    } else {
        domain.upstream = try parseUpstreamPool(allocator, value);
    }
}

pub fn setDomainUpstreamPolicyPropertyDirect(domain: *DomainConfig, value: []const u8) !void {
    domain.upstream_policy = try parseOptionalUpstreamPoolPolicy(value);
}

pub fn setDomainU32PropertyDirect(domain: *DomainConfig, value: []const u8, field: DomainU32Property) !void {
    const parsed = try parseConfigU32(value);
    switch (field) {
        .upstream_timeout_ms => {
            if (parsed == 0) return error.InvalidConfigValue;
            domain.upstream_timeout_ms = parsed;
        },
        .upstream_fail_timeout_ms => domain.upstream_fail_timeout_ms = parsed,
        .upstream_health_check_interval_ms => {
            if (parsed == 0) return error.InvalidConfigValue;
            domain.upstream_health_check_interval_ms = parsed;
        },
        .upstream_health_check_timeout_ms => {
            if (parsed == 0) return error.InvalidConfigValue;
            domain.upstream_health_check_timeout_ms = parsed;
        },
        .upstream_slow_start_ms => domain.upstream_slow_start_ms = parsed,
    }
}

pub fn setDomainCompressionBoolPropertyDirect(domain: *DomainConfig, value: []const u8, field: CompressionBoolProperty) !void {
    const parsed = try parseConfigBool(value);
    switch (field) {
        .enabled => domain.compression_enabled = parsed,
        .gzip_enabled => domain.gzip_enabled = parsed,
    }
}

pub fn setDomainCompressionSizePropertyDirect(domain: *DomainConfig, value: []const u8, field: CompressionSizeProperty) !void {
    const parsed = try parseConfigUsize(value);
    if (parsed == 0) return error.InvalidConfigValue;
    switch (field) {
        .min_bytes => domain.compression_min_bytes = parsed,
        .max_bytes => domain.compression_max_bytes = parsed,
    }
}

pub fn setDomainResponseCacheBoolPropertyDirect(domain: *DomainConfig, value: []const u8, field: ResponseCacheBoolProperty) !void {
    const parsed = try parseConfigBool(value);
    switch (field) {
        .enabled => domain.response_cache_enabled = parsed,
    }
}

pub fn setDomainResponseCacheSizePropertyDirect(domain: *DomainConfig, value: []const u8, field: ResponseCacheSizeProperty) !void {
    const parsed = try parseConfigUsize(value);
    if (parsed == 0) return error.InvalidConfigValue;
    switch (field) {
        .max_bytes => domain.response_cache_max_bytes = parsed,
        .max_entry_bytes => domain.response_cache_max_entry_bytes = parsed,
    }
}

pub fn setDomainResponseCacheU32PropertyDirect(domain: *DomainConfig, value: []const u8, field: ResponseCacheU32Property) !void {
    const parsed = try parseConfigU32(value);
    if (parsed == 0) return error.InvalidConfigValue;
    switch (field) {
        .ttl_ms => domain.response_cache_ttl_ms = parsed,
    }
}

pub fn setDomainSecurityHeadersPropertyDirect(domain: *DomainConfig, value: []const u8) !void {
    domain.security_headers = try parseSecurityHeaderPreset(value);
}

pub fn setDomainMaxStaticFileBytesDirect(domain: *DomainConfig, value: []const u8) !void {
    const parsed = try parseConfigUsize(value);
    if (parsed == 0) return error.InvalidConfigValue;
    domain.max_static_file_bytes = parsed;
}

pub fn setDomainUpstreamUsizePropertyDirect(domain: *DomainConfig, value: []const u8, field: UpstreamUsizeProperty) !void {
    const parsed = try parseConfigUsize(value);
    switch (field) {
        .retries => domain.upstream_retries = parsed,
        .max_failures => domain.upstream_max_failures = parsed,
        .circuit_half_open_max => {
            if (parsed == 0) return error.InvalidConfigValue;
            domain.upstream_circuit_half_open_max = parsed;
        },
    }
}
