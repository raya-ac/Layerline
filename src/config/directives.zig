const std = @import("std");
const http_headers = @import("../http_headers.zig");
const domains_mod = @import("domains.zig");
const parsing = @import("parsing.zig");
const policy = @import("policy.zig");
const routes_mod = @import("routes.zig");
const types = @import("types.zig");

const trimValue = http_headers.trimValue;
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

const appendCacheStaleDirective = routes_mod.appendCacheStaleDirective;
const appendDomainCacheControl = domains_mod.appendDomainCacheControl;
const appendDomainCacheStaleDirective = domains_mod.appendDomainCacheStaleDirective;
const appendDomainResponseHeader = domains_mod.appendDomainResponseHeader;
const appendDomainRouteCacheControl = domains_mod.appendDomainRouteCacheControl;
const appendDomainRouteCacheStaleDirective = domains_mod.appendDomainRouteCacheStaleDirective;
const appendDomainRouteResponseHeader = domains_mod.appendDomainRouteResponseHeader;
const appendResponseHeaderSlice = policy.appendResponseHeaderSlice;
const appendRouteCacheControl = routes_mod.appendRouteCacheControl;
const appendRouteCacheStaleDirective = routes_mod.appendRouteCacheStaleDirective;
const appendRouteResponseHeader = routes_mod.appendRouteResponseHeader;
const appendServerNames = domains_mod.appendServerNames;
const disablesOptionalUrl = parsing.disablesOptionalUrl;
const findDomainConfigMutable = domains_mod.findDomainConfigMutable;
const findAnyRoutePropertyName = parsing.findAnyRoutePropertyName;
const findRoutePropertyName = parsing.findRoutePropertyName;
const initDomainConfig = domains_mod.initDomainConfig;
const isCompressionEnabledKey = parsing.isCompressionEnabledKey;
const isCompressionMaxBytesKey = parsing.isCompressionMaxBytesKey;
const isCompressionMinBytesKey = parsing.isCompressionMinBytesKey;
const isGzipEnabledKey = parsing.isGzipEnabledKey;
const isDomainConfigNameValid = domains_mod.isDomainConfigNameValid;
const isSupportedCloudflareRecordType = parsing.isSupportedCloudflareRecordType;
const makeResponseHeaderRule = parsing.makeResponseHeaderRule;
const parseConfigBool = parsing.parseConfigBool;
const parseConfigU16 = parsing.parseConfigU16;
const parseConfigU32 = parsing.parseConfigU32;
const parseConfigUsize = parsing.parseConfigUsize;
const parseOptionalUpstreamPoolPolicy = parsing.parseOptionalUpstreamPoolPolicy;
const parseRedirectRule = parsing.parseRedirectRule;
const parseResponseHeaderRule = parsing.parseResponseHeaderRule;
const parseSecurityHeaderPreset = policy.parseSecurityHeaderPreset;
const parseUpstream = parsing.parseUpstream;
const parseUpstreamPool = parsing.parseUpstreamPool;
const parseUpstreamPoolPolicy = parsing.parseUpstreamPoolPolicy;
const setDomainBoolProperty = domains_mod.setDomainBoolProperty;
const setDomainBoolPropertyDirect = domains_mod.setDomainBoolPropertyDirect;
const setDomainCompressionBoolProperty = domains_mod.setDomainCompressionBoolProperty;
const setDomainCompressionBoolPropertyDirect = domains_mod.setDomainCompressionBoolPropertyDirect;
const setDomainCompressionSizeProperty = domains_mod.setDomainCompressionSizeProperty;
const setDomainCompressionSizePropertyDirect = domains_mod.setDomainCompressionSizePropertyDirect;
const setDomainLine = domains_mod.setDomainLine;
const setDomainMaxStaticFileBytes = domains_mod.setDomainMaxStaticFileBytes;
const setDomainMaxStaticFileBytesDirect = domains_mod.setDomainMaxStaticFileBytesDirect;
const setDomainProxyProperty = domains_mod.setDomainProxyProperty;
const setDomainProxyPropertyDirect = domains_mod.setDomainProxyPropertyDirect;
const setDomainResponseCacheBoolProperty = domains_mod.setDomainResponseCacheBoolProperty;
const setDomainResponseCacheBoolPropertyDirect = domains_mod.setDomainResponseCacheBoolPropertyDirect;
const setDomainResponseCacheSizeProperty = domains_mod.setDomainResponseCacheSizeProperty;
const setDomainResponseCacheSizePropertyDirect = domains_mod.setDomainResponseCacheSizePropertyDirect;
const setDomainResponseCacheU32Property = domains_mod.setDomainResponseCacheU32Property;
const setDomainResponseCacheU32PropertyDirect = domains_mod.setDomainResponseCacheU32PropertyDirect;
const setDomainRouteBoolProperty = domains_mod.setDomainRouteBoolProperty;
const setDomainRouteCompressionBoolProperty = domains_mod.setDomainRouteCompressionBoolProperty;
const setDomainRouteCompressionSizeProperty = domains_mod.setDomainRouteCompressionSizeProperty;
const setDomainRouteLine = domains_mod.setDomainRouteLine;
const setDomainRouteMaxStaticFileBytes = domains_mod.setDomainRouteMaxStaticFileBytes;
const setDomainRouteProxyProperty = domains_mod.setDomainRouteProxyProperty;
const setDomainRouteResponseCacheBoolProperty = domains_mod.setDomainRouteResponseCacheBoolProperty;
const setDomainRouteResponseCacheSizeProperty = domains_mod.setDomainRouteResponseCacheSizeProperty;
const setDomainRouteResponseCacheU32Property = domains_mod.setDomainRouteResponseCacheU32Property;
const setDomainRouteSecurityHeadersProperty = domains_mod.setDomainRouteSecurityHeadersProperty;
const setDomainRouteStringProperty = domains_mod.setDomainRouteStringProperty;
const setDomainRouteU32Property = domains_mod.setDomainRouteU32Property;
const setDomainRouteUpstreamPolicyProperty = domains_mod.setDomainRouteUpstreamPolicyProperty;
const setDomainRouteUpstreamUsizeProperty = domains_mod.setDomainRouteUpstreamUsizeProperty;
const setDomainSecurityHeadersProperty = domains_mod.setDomainSecurityHeadersProperty;
const setDomainSecurityHeadersPropertyDirect = domains_mod.setDomainSecurityHeadersPropertyDirect;
const setDomainStringProperty = domains_mod.setDomainStringProperty;
const setDomainStringPropertyDirect = domains_mod.setDomainStringPropertyDirect;
const setDomainU32Property = domains_mod.setDomainU32Property;
const setDomainU32PropertyDirect = domains_mod.setDomainU32PropertyDirect;
const setDomainUpstreamPolicyProperty = domains_mod.setDomainUpstreamPolicyProperty;
const setDomainUpstreamPolicyPropertyDirect = domains_mod.setDomainUpstreamPolicyPropertyDirect;
const setDomainUpstreamUsizeProperty = domains_mod.setDomainUpstreamUsizeProperty;
const setDomainUpstreamUsizePropertyDirect = domains_mod.setDomainUpstreamUsizePropertyDirect;
const setRouteBoolProperty = routes_mod.setRouteBoolProperty;
const setRouteCompressionBoolProperty = routes_mod.setRouteCompressionBoolProperty;
const setRouteCompressionSizeProperty = routes_mod.setRouteCompressionSizeProperty;
const setRouteLine = routes_mod.setRouteLine;
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
const validateFastcgiEndpoint = parsing.validateFastcgiEndpoint;

pub fn applyConfigLine(cfg: *ServerConfig, allocator: std.mem.Allocator, key: []const u8, value: []const u8) !void {
    const k = std.mem.trim(u8, key, " \t\r\n");
    const v = trimValue(value);

    if (std.mem.eql(u8, k, "host")) {
        if (v.len == 0) return error.InvalidConfigValue;
        cfg.host = try allocator.dupe(u8, v);
    } else if (std.mem.eql(u8, k, "port")) {
        cfg.port = try parseConfigU16(v);
    } else if (std.mem.eql(u8, k, "static_dir") or std.mem.eql(u8, k, "dir")) {
        if (v.len == 0) return error.InvalidConfigValue;
        cfg.static_dir = try allocator.dupe(u8, v);
    } else if (std.mem.eql(u8, k, "serve_static_root")) {
        cfg.serve_static_root = try parseConfigBool(v);
    } else if (std.mem.eql(u8, k, "index_file") or std.mem.eql(u8, k, "index")) {
        if (v.len == 0) return error.InvalidConfigValue;
        cfg.index_file = try allocator.dupe(u8, v);
    } else if (std.mem.eql(u8, k, "php_root")) {
        if (v.len == 0) return error.InvalidConfigValue;
        cfg.php_root = try allocator.dupe(u8, v);
    } else if (std.mem.eql(u8, k, "php_binary") or std.mem.eql(u8, k, "php_bin")) {
        if (v.len == 0) return error.InvalidConfigValue;
        cfg.php_binary = try allocator.dupe(u8, v);
    } else if (std.mem.eql(u8, k, "php_fastcgi") or std.mem.eql(u8, k, "php_fpm") or std.mem.eql(u8, k, "fastcgi")) {
        if (disablesOptionalUrl(v)) {
            cfg.php_fastcgi = null;
        } else {
            try validateFastcgiEndpoint(v);
            cfg.php_fastcgi = try allocator.dupe(u8, v);
        }
    } else if (std.mem.eql(u8, k, "php_index") or std.mem.eql(u8, k, "php_index_file")) {
        if (v.len == 0 or std.mem.indexOf(u8, v, "..") != null or std.mem.startsWith(u8, v, "/")) return error.InvalidConfigValue;
        cfg.php_index = try allocator.dupe(u8, v);
    } else if (std.mem.eql(u8, k, "php_info_page") or std.mem.eql(u8, k, "phpinfo_page") or std.mem.eql(u8, k, "enable_php_info_page")) {
        cfg.php_info_page = try parseConfigBool(v);
    } else if (std.mem.eql(u8, k, "php_front_controller") or std.mem.eql(u8, k, "php_front_controller_enabled")) {
        cfg.php_front_controller = try parseConfigBool(v);
    } else if (std.mem.eql(u8, k, "proxy")) {
        if (disablesOptionalUrl(v)) {
            cfg.upstream = null;
        } else {
            cfg.upstream = try parseUpstreamPool(allocator, v);
        }
    } else if (std.mem.eql(u8, k, "upstream_policy") or std.mem.eql(u8, k, "proxy_policy") or std.mem.eql(u8, k, "load_balance")) {
        cfg.upstream_policy = try parseUpstreamPoolPolicy(v);
    } else if (std.mem.eql(u8, k, "tls")) {
        cfg.tls_enabled = try parseConfigBool(v);
    } else if (std.mem.eql(u8, k, "tls_cert")) {
        if (v.len == 0) return error.InvalidConfigValue;
        cfg.tls_cert = try allocator.dupe(u8, v);
    } else if (std.mem.eql(u8, k, "tls_key")) {
        if (v.len == 0) return error.InvalidConfigValue;
        cfg.tls_key = try allocator.dupe(u8, v);
    } else if (std.mem.eql(u8, k, "tls_auto")) {
        cfg.tls_auto = try parseConfigBool(v);
    } else if (std.mem.eql(u8, k, "letsencrypt_email")) {
        if (v.len == 0) {
            cfg.letsencrypt_email = null;
        } else {
            cfg.letsencrypt_email = try allocator.dupe(u8, v);
        }
    } else if (std.mem.eql(u8, k, "letsencrypt_domains")) {
        if (v.len == 0) {
            cfg.letsencrypt_domains = null;
        } else {
            cfg.letsencrypt_domains = try allocator.dupe(u8, v);
        }
    } else if (std.mem.eql(u8, k, "letsencrypt_webroot")) {
        cfg.letsencrypt_webroot = try allocator.dupe(u8, v);
    } else if (std.mem.eql(u8, k, "letsencrypt_certbot")) {
        if (v.len == 0) return error.InvalidConfigValue;
        cfg.letsencrypt_certbot = try allocator.dupe(u8, v);
    } else if (std.mem.eql(u8, k, "letsencrypt_staging")) {
        cfg.letsencrypt_staging = try parseConfigBool(v);
    } else if (std.mem.eql(u8, k, "letsencrypt_renew") or std.mem.eql(u8, k, "tls_renew") or std.mem.eql(u8, k, "acme_renew")) {
        cfg.letsencrypt_renew = try parseConfigBool(v);
    } else if (std.mem.eql(u8, k, "letsencrypt_renew_interval_ms") or std.mem.eql(u8, k, "tls_renew_interval_ms") or std.mem.eql(u8, k, "acme_renew_interval_ms")) {
        cfg.letsencrypt_renew_interval_ms = try parseConfigU32(v);
    } else if (std.mem.eql(u8, k, "http_redirect") or std.mem.eql(u8, k, "http_to_https") or std.mem.eql(u8, k, "http_redirect_enabled")) {
        cfg.http_redirect_enabled = try parseConfigBool(v);
    } else if (std.mem.eql(u8, k, "http_redirect_port") or std.mem.eql(u8, k, "http_to_https_port")) {
        cfg.http_redirect_port = try parseConfigU16(v);
    } else if (std.mem.eql(u8, k, "http_redirect_https_port") or std.mem.eql(u8, k, "https_port")) {
        cfg.http_redirect_https_port = try parseConfigU16(v);
    } else if (std.mem.eql(u8, k, "http_redirect_status") or std.mem.eql(u8, k, "http_to_https_status")) {
        cfg.http_redirect_status = try parseConfigU16(v);
    } else if (std.mem.eql(u8, k, "h2_upstream") or std.mem.eql(u8, k, "http2_upstream")) {
        if (disablesOptionalUrl(v)) {
            cfg.h2_upstream = null;
        } else {
            cfg.h2_upstream = try parseUpstream(allocator, v);
        }
    } else if (std.mem.eql(u8, k, "http3")) {
        cfg.http3_enabled = try parseConfigBool(v);
    } else if (std.mem.eql(u8, k, "http3_port")) {
        cfg.http3_port = try parseConfigU16(v);
    } else if (std.mem.eql(u8, k, "admin") or std.mem.eql(u8, k, "admin_enabled")) {
        cfg.admin_enabled = try parseConfigBool(v);
    } else if (std.mem.eql(u8, k, "admin_socket") or std.mem.eql(u8, k, "admin_socket_path")) {
        if (disablesOptionalUrl(v)) {
            cfg.admin_enabled = false;
            cfg.admin_socket_path = null;
        } else {
            if (v.len == 0) return error.InvalidConfigValue;
            cfg.admin_enabled = true;
            cfg.admin_socket_path = try allocator.dupe(u8, v);
        }
    } else if (std.mem.eql(u8, k, "admin_ui") or std.mem.eql(u8, k, "admin_ui_enabled")) {
        cfg.admin_ui_enabled = try parseConfigBool(v);
    } else if (std.mem.eql(u8, k, "admin_ui_path")) {
        if (v.len == 0) return error.InvalidConfigValue;
        cfg.admin_ui_path = try allocator.dupe(u8, v);
    } else if (std.mem.eql(u8, k, "admin_credentials_path") or std.mem.eql(u8, k, "admin_state_path")) {
        if (v.len == 0) return error.InvalidConfigValue;
        cfg.admin_credentials_path = try allocator.dupe(u8, v);
    } else if (std.mem.eql(u8, k, "access_log")) {
        if (disablesOptionalUrl(v)) {
            cfg.access_log_enabled = false;
        } else if (std.ascii.eqlIgnoreCase(v, "true") or std.ascii.eqlIgnoreCase(v, "on") or std.ascii.eqlIgnoreCase(v, "yes") or std.mem.eql(u8, v, "1")) {
            cfg.access_log_enabled = true;
        } else {
            if (v.len == 0) return error.InvalidConfigValue;
            cfg.access_log_enabled = true;
            cfg.access_log_path = try allocator.dupe(u8, v);
        }
    } else if (std.mem.eql(u8, k, "access_log_path")) {
        if (v.len == 0) return error.InvalidConfigValue;
        cfg.access_log_enabled = true;
        cfg.access_log_path = try allocator.dupe(u8, v);
    } else if (isCompressionEnabledKey(k)) {
        cfg.compression_enabled = try parseConfigBool(v);
    } else if (isGzipEnabledKey(k)) {
        cfg.gzip_enabled = try parseConfigBool(v);
    } else if (isCompressionMinBytesKey(k)) {
        cfg.compression_min_bytes = try parseConfigUsize(v);
    } else if (isCompressionMaxBytesKey(k)) {
        cfg.compression_max_bytes = try parseConfigUsize(v);
    } else if (std.mem.eql(u8, k, "response_cache") or std.mem.eql(u8, k, "static_response_cache")) {
        cfg.response_cache_enabled = try parseConfigBool(v);
    } else if (std.mem.eql(u8, k, "response_cache_max_bytes") or std.mem.eql(u8, k, "static_response_cache_max_bytes")) {
        cfg.response_cache_max_bytes = try parseConfigUsize(v);
    } else if (std.mem.eql(u8, k, "response_cache_max_entry_bytes") or std.mem.eql(u8, k, "static_response_cache_max_entry_bytes")) {
        cfg.response_cache_max_entry_bytes = try parseConfigUsize(v);
    } else if (std.mem.eql(u8, k, "response_cache_ttl_ms") or std.mem.eql(u8, k, "static_response_cache_ttl_ms")) {
        cfg.response_cache_ttl_ms = try parseConfigU32(v);
    } else if (std.mem.eql(u8, k, "security_headers") or std.mem.eql(u8, k, "security_header_preset") or std.mem.eql(u8, k, "secure_headers")) {
        cfg.security_headers = try parseSecurityHeaderPreset(v);
    } else if (std.mem.eql(u8, k, "header") or std.mem.eql(u8, k, "response_header") or std.mem.eql(u8, k, "add_header")) {
        if (v.len > 0) try cfg.response_headers.append(allocator, try parseResponseHeaderRule(allocator, v));
    } else if (std.mem.eql(u8, k, "cache_control") or std.mem.eql(u8, k, "cache-control")) {
        if (v.len > 0) try cfg.response_headers.append(allocator, try makeResponseHeaderRule(allocator, "Cache-Control", v));
    } else if (std.mem.eql(u8, k, "stale_while_revalidate") or std.mem.eql(u8, k, "cache_stale_while_revalidate")) {
        try appendCacheStaleDirective(&cfg.response_headers, allocator, v, .stale_while_revalidate);
    } else if (std.mem.eql(u8, k, "stale_if_error") or std.mem.eql(u8, k, "cache_stale_if_error")) {
        try appendCacheStaleDirective(&cfg.response_headers, allocator, v, .stale_if_error);
    } else if (std.mem.eql(u8, k, "redirect") or std.mem.eql(u8, k, "redir")) {
        if (v.len > 0) try cfg.redirects.append(allocator, try parseRedirectRule(allocator, v));
    } else if (std.mem.eql(u8, k, "domain_config_dir") or std.mem.eql(u8, k, "domains_dir") or std.mem.eql(u8, k, "sites_enabled") or std.mem.eql(u8, k, "sites_dir")) {
        cfg.domain_config_dir = if (v.len == 0) null else try allocator.dupe(u8, v);
    } else if (std.mem.eql(u8, k, "server") or std.mem.eql(u8, k, "domain") or std.mem.eql(u8, k, "vhost")) {
        try setDomainLine(cfg, allocator, v);
    } else if (findRoutePropertyName(k, "server_name.")) |name| {
        const domain = findDomainConfigMutable(cfg, name) orelse return error.UnknownConfigDomain;
        try appendServerNames(allocator, domain, v);
    } else if (findRoutePropertyName(k, "server_names.")) |name| {
        const domain = findDomainConfigMutable(cfg, name) orelse return error.UnknownConfigDomain;
        try appendServerNames(allocator, domain, v);
    } else if (findAnyRoutePropertyName(k, &.{ "server_compression.", "server_compress.", "server_encode." })) |name| {
        try setDomainCompressionBoolProperty(cfg, name, v, .enabled);
    } else if (findAnyRoutePropertyName(k, &.{ "server_gzip.", "server_gzip_enabled." })) |name| {
        try setDomainCompressionBoolProperty(cfg, name, v, .gzip_enabled);
    } else if (findAnyRoutePropertyName(k, &.{ "server_compression_min_bytes.", "server_gzip_min_bytes." })) |name| {
        try setDomainCompressionSizeProperty(cfg, name, v, .min_bytes);
    } else if (findAnyRoutePropertyName(k, &.{ "server_compression_max_bytes.", "server_gzip_max_bytes." })) |name| {
        try setDomainCompressionSizeProperty(cfg, name, v, .max_bytes);
    } else if (findRoutePropertyName(k, "server_response_cache.")) |name| {
        try setDomainResponseCacheBoolProperty(cfg, name, v, .enabled);
    } else if (findRoutePropertyName(k, "server_static_response_cache.")) |name| {
        try setDomainResponseCacheBoolProperty(cfg, name, v, .enabled);
    } else if (findRoutePropertyName(k, "server_response_cache_max_bytes.")) |name| {
        try setDomainResponseCacheSizeProperty(cfg, name, v, .max_bytes);
    } else if (findRoutePropertyName(k, "server_response_cache_max_entry_bytes.")) |name| {
        try setDomainResponseCacheSizeProperty(cfg, name, v, .max_entry_bytes);
    } else if (findRoutePropertyName(k, "server_response_cache_ttl_ms.")) |name| {
        try setDomainResponseCacheU32Property(cfg, name, v, .ttl_ms);
    } else if (findAnyRoutePropertyName(k, &.{ "server_security_headers.", "server_security_header_preset.", "server_secure_headers." })) |name| {
        try setDomainSecurityHeadersProperty(cfg, name, v);
    } else if (findRoutePropertyName(k, "server_header.")) |name| {
        try appendDomainResponseHeader(cfg, allocator, name, v);
    } else if (findRoutePropertyName(k, "server_response_header.")) |name| {
        try appendDomainResponseHeader(cfg, allocator, name, v);
    } else if (findRoutePropertyName(k, "server_add_header.")) |name| {
        try appendDomainResponseHeader(cfg, allocator, name, v);
    } else if (findRoutePropertyName(k, "server_cache_control.")) |name| {
        try appendDomainCacheControl(cfg, allocator, name, v);
    } else if (findRoutePropertyName(k, "server_cache-control.")) |name| {
        try appendDomainCacheControl(cfg, allocator, name, v);
    } else if (findAnyRoutePropertyName(k, &.{ "server_stale_while_revalidate.", "server_cache_stale_while_revalidate." })) |name| {
        try appendDomainCacheStaleDirective(cfg, allocator, name, v, .stale_while_revalidate);
    } else if (findAnyRoutePropertyName(k, &.{ "server_stale_if_error.", "server_cache_stale_if_error." })) |name| {
        try appendDomainCacheStaleDirective(cfg, allocator, name, v, .stale_if_error);
    } else if (findRoutePropertyName(k, "server_root.")) |name| {
        try setDomainStringProperty(cfg, allocator, name, v, .static_dir);
    } else if (findRoutePropertyName(k, "server_dir.")) |name| {
        try setDomainStringProperty(cfg, allocator, name, v, .static_dir);
    } else if (findRoutePropertyName(k, "server_static_dir.")) |name| {
        try setDomainStringProperty(cfg, allocator, name, v, .static_dir);
    } else if (findRoutePropertyName(k, "server_max_static_file_bytes.")) |name| {
        try setDomainMaxStaticFileBytes(cfg, name, v);
    } else if (findRoutePropertyName(k, "server_max_static_bytes.")) |name| {
        try setDomainMaxStaticFileBytes(cfg, name, v);
    } else if (findRoutePropertyName(k, "server_index.")) |name| {
        try setDomainStringProperty(cfg, allocator, name, v, .index_file);
    } else if (findRoutePropertyName(k, "server_index_file.")) |name| {
        try setDomainStringProperty(cfg, allocator, name, v, .index_file);
    } else if (findRoutePropertyName(k, "server_serve_static.")) |name| {
        try setDomainBoolProperty(cfg, name, v, .serve_static_root);
    } else if (findRoutePropertyName(k, "server_serve_static_root.")) |name| {
        try setDomainBoolProperty(cfg, name, v, .serve_static_root);
    } else if (findRoutePropertyName(k, "server_php_root.")) |name| {
        try setDomainStringProperty(cfg, allocator, name, v, .php_root);
    } else if (findRoutePropertyName(k, "server_php_bin.")) |name| {
        try setDomainStringProperty(cfg, allocator, name, v, .php_binary);
    } else if (findRoutePropertyName(k, "server_php_binary.")) |name| {
        try setDomainStringProperty(cfg, allocator, name, v, .php_binary);
    } else if (findRoutePropertyName(k, "server_php_fastcgi.")) |name| {
        try setDomainStringProperty(cfg, allocator, name, v, .php_fastcgi);
    } else if (findRoutePropertyName(k, "server_php_fpm.")) |name| {
        try setDomainStringProperty(cfg, allocator, name, v, .php_fastcgi);
    } else if (findRoutePropertyName(k, "server_fastcgi.")) |name| {
        try setDomainStringProperty(cfg, allocator, name, v, .php_fastcgi);
    } else if (findRoutePropertyName(k, "server_php_index.")) |name| {
        try setDomainStringProperty(cfg, allocator, name, v, .php_index);
    } else if (findRoutePropertyName(k, "server_php_index_file.")) |name| {
        try setDomainStringProperty(cfg, allocator, name, v, .php_index);
    } else if (findRoutePropertyName(k, "server_tls_cert.")) |name| {
        try setDomainStringProperty(cfg, allocator, name, v, .tls_cert);
    } else if (findRoutePropertyName(k, "server_tls_key.")) |name| {
        try setDomainStringProperty(cfg, allocator, name, v, .tls_key);
    } else if (findRoutePropertyName(k, "server_php_info_page.")) |name| {
        try setDomainBoolProperty(cfg, name, v, .php_info_page);
    } else if (findRoutePropertyName(k, "server_phpinfo_page.")) |name| {
        try setDomainBoolProperty(cfg, name, v, .php_info_page);
    } else if (findRoutePropertyName(k, "server_php_front_controller.")) |name| {
        try setDomainBoolProperty(cfg, name, v, .php_front_controller);
    } else if (findRoutePropertyName(k, "server_proxy.")) |name| {
        try setDomainProxyProperty(cfg, allocator, name, v);
    } else if (findRoutePropertyName(k, "server_upstream.")) |name| {
        try setDomainProxyProperty(cfg, allocator, name, v);
    } else if (findRoutePropertyName(k, "server_proxy_policy.")) |name| {
        try setDomainUpstreamPolicyProperty(cfg, name, v);
    } else if (findRoutePropertyName(k, "server_upstream_policy.")) |name| {
        try setDomainUpstreamPolicyProperty(cfg, name, v);
    } else if (findRoutePropertyName(k, "server_load_balance.")) |name| {
        try setDomainUpstreamPolicyProperty(cfg, name, v);
    } else if (findRoutePropertyName(k, "server_upstream_timeout_ms.")) |name| {
        try setDomainU32Property(cfg, name, v, .upstream_timeout_ms);
    } else if (findRoutePropertyName(k, "server_proxy_timeout_ms.")) |name| {
        try setDomainU32Property(cfg, name, v, .upstream_timeout_ms);
    } else if (findRoutePropertyName(k, "server_php_timeout_ms.")) |name| {
        try setDomainU32Property(cfg, name, v, .upstream_timeout_ms);
    } else if (findRoutePropertyName(k, "server_fastcgi_timeout_ms.")) |name| {
        try setDomainU32Property(cfg, name, v, .upstream_timeout_ms);
    } else if (findRoutePropertyName(k, "server_upstream_retries.")) |name| {
        try setDomainUpstreamUsizeProperty(cfg, name, v, .retries);
    } else if (findAnyRoutePropertyName(k, &.{ "server_upstream_max_failures.", "server_upstream_max_fails.", "server_proxy_max_fails." })) |name| {
        try setDomainUpstreamUsizeProperty(cfg, name, v, .max_failures);
    } else if (findAnyRoutePropertyName(k, &.{ "server_upstream_fail_timeout_ms.", "server_proxy_fail_timeout_ms." })) |name| {
        try setDomainU32Property(cfg, name, v, .upstream_fail_timeout_ms);
    } else if (findAnyRoutePropertyName(k, &.{ "server_upstream_health_check.", "server_proxy_health_check." })) |name| {
        try setDomainBoolProperty(cfg, name, v, .upstream_health_check_enabled);
    } else if (findAnyRoutePropertyName(k, &.{ "server_upstream_health_check_path.", "server_proxy_health_check_path." })) |name| {
        try setDomainStringProperty(cfg, allocator, name, v, .upstream_health_check_path);
    } else if (findAnyRoutePropertyName(k, &.{ "server_upstream_health_check_interval_ms.", "server_proxy_health_check_interval_ms." })) |name| {
        try setDomainU32Property(cfg, name, v, .upstream_health_check_interval_ms);
    } else if (findAnyRoutePropertyName(k, &.{ "server_upstream_health_check_timeout_ms.", "server_proxy_health_check_timeout_ms." })) |name| {
        try setDomainU32Property(cfg, name, v, .upstream_health_check_timeout_ms);
    } else if (findAnyRoutePropertyName(k, &.{ "server_upstream_circuit_breaker.", "server_proxy_circuit_breaker." })) |name| {
        try setDomainBoolProperty(cfg, name, v, .upstream_circuit_breaker_enabled);
    } else if (findAnyRoutePropertyName(k, &.{ "server_upstream_circuit_half_open_max.", "server_proxy_circuit_half_open_max." })) |name| {
        try setDomainUpstreamUsizeProperty(cfg, name, v, .circuit_half_open_max);
    } else if (findAnyRoutePropertyName(k, &.{ "server_upstream_slow_start_ms.", "server_proxy_slow_start_ms." })) |name| {
        try setDomainU32Property(cfg, name, v, .upstream_slow_start_ms);
    } else if (findRoutePropertyName(k, "server_redirect.")) |name| {
        const domain = findDomainConfigMutable(cfg, name) orelse return error.UnknownConfigDomain;
        if (v.len > 0) try domain.redirects.append(allocator, try parseRedirectRule(allocator, v));
    } else if (findRoutePropertyName(k, "server_route.")) |name| {
        try setDomainRouteLine(cfg, allocator, name, v);
    } else if (findRoutePropertyName(k, "server_route_dir.")) |name| {
        try setDomainRouteStringProperty(cfg, allocator, name, v, .static_dir);
    } else if (findRoutePropertyName(k, "server_route_static_dir.")) |name| {
        try setDomainRouteStringProperty(cfg, allocator, name, v, .static_dir);
    } else if (findRoutePropertyName(k, "server_route_max_static_file_bytes.")) |name| {
        try setDomainRouteMaxStaticFileBytes(cfg, name, v);
    } else if (findRoutePropertyName(k, "server_route_max_static_bytes.")) |name| {
        try setDomainRouteMaxStaticFileBytes(cfg, name, v);
    } else if (findRoutePropertyName(k, "server_route_index.")) |name| {
        try setDomainRouteStringProperty(cfg, allocator, name, v, .index_file);
    } else if (findRoutePropertyName(k, "server_route_index_file.")) |name| {
        try setDomainRouteStringProperty(cfg, allocator, name, v, .index_file);
    } else if (findRoutePropertyName(k, "server_route_php_root.")) |name| {
        try setDomainRouteStringProperty(cfg, allocator, name, v, .php_root);
    } else if (findRoutePropertyName(k, "server_route_php_bin.")) |name| {
        try setDomainRouteStringProperty(cfg, allocator, name, v, .php_binary);
    } else if (findRoutePropertyName(k, "server_route_php_binary.")) |name| {
        try setDomainRouteStringProperty(cfg, allocator, name, v, .php_binary);
    } else if (findRoutePropertyName(k, "server_route_php_fastcgi.")) |name| {
        try setDomainRouteStringProperty(cfg, allocator, name, v, .php_fastcgi);
    } else if (findRoutePropertyName(k, "server_route_php_fpm.")) |name| {
        try setDomainRouteStringProperty(cfg, allocator, name, v, .php_fastcgi);
    } else if (findRoutePropertyName(k, "server_route_fastcgi.")) |name| {
        try setDomainRouteStringProperty(cfg, allocator, name, v, .php_fastcgi);
    } else if (findRoutePropertyName(k, "server_route_php_index.")) |name| {
        try setDomainRouteStringProperty(cfg, allocator, name, v, .php_index);
    } else if (findRoutePropertyName(k, "server_route_php_index_file.")) |name| {
        try setDomainRouteStringProperty(cfg, allocator, name, v, .php_index);
    } else if (findRoutePropertyName(k, "server_route_php_info_page.")) |name| {
        try setDomainRouteBoolProperty(cfg, name, v, .php_info_page);
    } else if (findRoutePropertyName(k, "server_route_phpinfo_page.")) |name| {
        try setDomainRouteBoolProperty(cfg, name, v, .php_info_page);
    } else if (findRoutePropertyName(k, "server_route_php_front_controller.")) |name| {
        try setDomainRouteBoolProperty(cfg, name, v, .php_front_controller);
    } else if (findRoutePropertyName(k, "server_route_proxy.")) |name| {
        try setDomainRouteProxyProperty(cfg, allocator, name, v);
    } else if (findRoutePropertyName(k, "server_route_upstream.")) |name| {
        try setDomainRouteProxyProperty(cfg, allocator, name, v);
    } else if (findRoutePropertyName(k, "server_route_proxy_policy.")) |name| {
        try setDomainRouteUpstreamPolicyProperty(cfg, name, v);
    } else if (findRoutePropertyName(k, "server_route_upstream_policy.")) |name| {
        try setDomainRouteUpstreamPolicyProperty(cfg, name, v);
    } else if (findRoutePropertyName(k, "server_route_load_balance.")) |name| {
        try setDomainRouteUpstreamPolicyProperty(cfg, name, v);
    } else if (findRoutePropertyName(k, "server_route_upstream_timeout_ms.")) |name| {
        try setDomainRouteU32Property(cfg, name, v, .upstream_timeout_ms);
    } else if (findRoutePropertyName(k, "server_route_proxy_timeout_ms.")) |name| {
        try setDomainRouteU32Property(cfg, name, v, .upstream_timeout_ms);
    } else if (findRoutePropertyName(k, "server_route_php_timeout_ms.")) |name| {
        try setDomainRouteU32Property(cfg, name, v, .upstream_timeout_ms);
    } else if (findRoutePropertyName(k, "server_route_fastcgi_timeout_ms.")) |name| {
        try setDomainRouteU32Property(cfg, name, v, .upstream_timeout_ms);
    } else if (findRoutePropertyName(k, "server_route_upstream_retries.")) |name| {
        try setDomainRouteUpstreamUsizeProperty(cfg, name, v, .retries);
    } else if (findAnyRoutePropertyName(k, &.{ "server_route_upstream_max_failures.", "server_route_upstream_max_fails.", "server_route_proxy_max_fails." })) |name| {
        try setDomainRouteUpstreamUsizeProperty(cfg, name, v, .max_failures);
    } else if (findAnyRoutePropertyName(k, &.{ "server_route_upstream_fail_timeout_ms.", "server_route_proxy_fail_timeout_ms." })) |name| {
        try setDomainRouteU32Property(cfg, name, v, .upstream_fail_timeout_ms);
    } else if (findAnyRoutePropertyName(k, &.{ "server_route_upstream_health_check.", "server_route_proxy_health_check." })) |name| {
        try setDomainRouteBoolProperty(cfg, name, v, .upstream_health_check_enabled);
    } else if (findAnyRoutePropertyName(k, &.{ "server_route_upstream_health_check_path.", "server_route_proxy_health_check_path." })) |name| {
        try setDomainRouteStringProperty(cfg, allocator, name, v, .upstream_health_check_path);
    } else if (findAnyRoutePropertyName(k, &.{ "server_route_upstream_health_check_interval_ms.", "server_route_proxy_health_check_interval_ms." })) |name| {
        try setDomainRouteU32Property(cfg, name, v, .upstream_health_check_interval_ms);
    } else if (findAnyRoutePropertyName(k, &.{ "server_route_upstream_health_check_timeout_ms.", "server_route_proxy_health_check_timeout_ms." })) |name| {
        try setDomainRouteU32Property(cfg, name, v, .upstream_health_check_timeout_ms);
    } else if (findAnyRoutePropertyName(k, &.{ "server_route_upstream_circuit_breaker.", "server_route_proxy_circuit_breaker." })) |name| {
        try setDomainRouteBoolProperty(cfg, name, v, .upstream_circuit_breaker_enabled);
    } else if (findAnyRoutePropertyName(k, &.{ "server_route_upstream_circuit_half_open_max.", "server_route_proxy_circuit_half_open_max." })) |name| {
        try setDomainRouteUpstreamUsizeProperty(cfg, name, v, .circuit_half_open_max);
    } else if (findAnyRoutePropertyName(k, &.{ "server_route_upstream_slow_start_ms.", "server_route_proxy_slow_start_ms." })) |name| {
        try setDomainRouteU32Property(cfg, name, v, .upstream_slow_start_ms);
    } else if (findRoutePropertyName(k, "server_route_strip_prefix.")) |name| {
        try setDomainRouteBoolProperty(cfg, name, v, .strip_prefix);
    } else if (findAnyRoutePropertyName(k, &.{ "server_route_compression.", "server_route_compress.", "server_route_encode." })) |name| {
        try setDomainRouteCompressionBoolProperty(cfg, name, v, .enabled);
    } else if (findAnyRoutePropertyName(k, &.{ "server_route_gzip.", "server_route_gzip_enabled." })) |name| {
        try setDomainRouteCompressionBoolProperty(cfg, name, v, .gzip_enabled);
    } else if (findAnyRoutePropertyName(k, &.{ "server_route_compression_min_bytes.", "server_route_gzip_min_bytes." })) |name| {
        try setDomainRouteCompressionSizeProperty(cfg, name, v, .min_bytes);
    } else if (findAnyRoutePropertyName(k, &.{ "server_route_compression_max_bytes.", "server_route_gzip_max_bytes." })) |name| {
        try setDomainRouteCompressionSizeProperty(cfg, name, v, .max_bytes);
    } else if (findRoutePropertyName(k, "server_route_response_cache.")) |name| {
        try setDomainRouteResponseCacheBoolProperty(cfg, name, v, .enabled);
    } else if (findRoutePropertyName(k, "server_route_static_response_cache.")) |name| {
        try setDomainRouteResponseCacheBoolProperty(cfg, name, v, .enabled);
    } else if (findRoutePropertyName(k, "server_route_response_cache_max_bytes.")) |name| {
        try setDomainRouteResponseCacheSizeProperty(cfg, name, v, .max_bytes);
    } else if (findRoutePropertyName(k, "server_route_response_cache_max_entry_bytes.")) |name| {
        try setDomainRouteResponseCacheSizeProperty(cfg, name, v, .max_entry_bytes);
    } else if (findRoutePropertyName(k, "server_route_response_cache_ttl_ms.")) |name| {
        try setDomainRouteResponseCacheU32Property(cfg, name, v, .ttl_ms);
    } else if (findAnyRoutePropertyName(k, &.{ "server_route_security_headers.", "server_route_security_header_preset.", "server_route_secure_headers." })) |name| {
        try setDomainRouteSecurityHeadersProperty(cfg, name, v);
    } else if (findRoutePropertyName(k, "server_route_header.")) |name| {
        try appendDomainRouteResponseHeader(cfg, allocator, name, v);
    } else if (findRoutePropertyName(k, "server_route_response_header.")) |name| {
        try appendDomainRouteResponseHeader(cfg, allocator, name, v);
    } else if (findRoutePropertyName(k, "server_route_add_header.")) |name| {
        try appendDomainRouteResponseHeader(cfg, allocator, name, v);
    } else if (findRoutePropertyName(k, "server_route_cache_control.")) |name| {
        try appendDomainRouteCacheControl(cfg, allocator, name, v);
    } else if (findRoutePropertyName(k, "server_route_cache-control.")) |name| {
        try appendDomainRouteCacheControl(cfg, allocator, name, v);
    } else if (findAnyRoutePropertyName(k, &.{ "server_route_stale_while_revalidate.", "server_route_cache_stale_while_revalidate." })) |name| {
        try appendDomainRouteCacheStaleDirective(cfg, allocator, name, v, .stale_while_revalidate);
    } else if (findAnyRoutePropertyName(k, &.{ "server_route_stale_if_error.", "server_route_cache_stale_if_error." })) |name| {
        try appendDomainRouteCacheStaleDirective(cfg, allocator, name, v, .stale_if_error);
    } else if (std.mem.eql(u8, k, "route")) {
        try setRouteLine(cfg, allocator, v);
    } else if (findRoutePropertyName(k, "route_dir.")) |name| {
        try setRouteStringProperty(&cfg.routes, allocator, name, v, .static_dir);
    } else if (findRoutePropertyName(k, "route_static_dir.")) |name| {
        try setRouteStringProperty(&cfg.routes, allocator, name, v, .static_dir);
    } else if (findRoutePropertyName(k, "route_max_static_file_bytes.")) |name| {
        try setRouteMaxStaticFileBytes(&cfg.routes, name, v);
    } else if (findRoutePropertyName(k, "route_max_static_bytes.")) |name| {
        try setRouteMaxStaticFileBytes(&cfg.routes, name, v);
    } else if (findRoutePropertyName(k, "route_index.")) |name| {
        try setRouteStringProperty(&cfg.routes, allocator, name, v, .index_file);
    } else if (findRoutePropertyName(k, "route_index_file.")) |name| {
        try setRouteStringProperty(&cfg.routes, allocator, name, v, .index_file);
    } else if (findRoutePropertyName(k, "route_php_root.")) |name| {
        try setRouteStringProperty(&cfg.routes, allocator, name, v, .php_root);
    } else if (findRoutePropertyName(k, "route_php_bin.")) |name| {
        try setRouteStringProperty(&cfg.routes, allocator, name, v, .php_binary);
    } else if (findRoutePropertyName(k, "route_php_binary.")) |name| {
        try setRouteStringProperty(&cfg.routes, allocator, name, v, .php_binary);
    } else if (findRoutePropertyName(k, "route_php_fastcgi.")) |name| {
        try setRouteStringProperty(&cfg.routes, allocator, name, v, .php_fastcgi);
    } else if (findRoutePropertyName(k, "route_php_fpm.")) |name| {
        try setRouteStringProperty(&cfg.routes, allocator, name, v, .php_fastcgi);
    } else if (findRoutePropertyName(k, "route_fastcgi.")) |name| {
        try setRouteStringProperty(&cfg.routes, allocator, name, v, .php_fastcgi);
    } else if (findRoutePropertyName(k, "route_php_index.")) |name| {
        try setRouteStringProperty(&cfg.routes, allocator, name, v, .php_index);
    } else if (findRoutePropertyName(k, "route_php_index_file.")) |name| {
        try setRouteStringProperty(&cfg.routes, allocator, name, v, .php_index);
    } else if (findRoutePropertyName(k, "route_php_info_page.")) |name| {
        try setRouteBoolProperty(&cfg.routes, name, v, .php_info_page);
    } else if (findRoutePropertyName(k, "route_phpinfo_page.")) |name| {
        try setRouteBoolProperty(&cfg.routes, name, v, .php_info_page);
    } else if (findRoutePropertyName(k, "route_php_front_controller.")) |name| {
        try setRouteBoolProperty(&cfg.routes, name, v, .php_front_controller);
    } else if (findRoutePropertyName(k, "route_proxy.")) |name| {
        try setRouteProxyProperty(&cfg.routes, allocator, name, v);
    } else if (findRoutePropertyName(k, "route_upstream.")) |name| {
        try setRouteProxyProperty(&cfg.routes, allocator, name, v);
    } else if (findRoutePropertyName(k, "route_proxy_policy.")) |name| {
        try setRouteUpstreamPolicyProperty(&cfg.routes, name, v);
    } else if (findRoutePropertyName(k, "route_upstream_policy.")) |name| {
        try setRouteUpstreamPolicyProperty(&cfg.routes, name, v);
    } else if (findRoutePropertyName(k, "route_load_balance.")) |name| {
        try setRouteUpstreamPolicyProperty(&cfg.routes, name, v);
    } else if (findRoutePropertyName(k, "route_upstream_timeout_ms.")) |name| {
        try setRouteU32Property(&cfg.routes, name, v, .upstream_timeout_ms);
    } else if (findRoutePropertyName(k, "route_proxy_timeout_ms.")) |name| {
        try setRouteU32Property(&cfg.routes, name, v, .upstream_timeout_ms);
    } else if (findRoutePropertyName(k, "route_php_timeout_ms.")) |name| {
        try setRouteU32Property(&cfg.routes, name, v, .upstream_timeout_ms);
    } else if (findRoutePropertyName(k, "route_fastcgi_timeout_ms.")) |name| {
        try setRouteU32Property(&cfg.routes, name, v, .upstream_timeout_ms);
    } else if (findRoutePropertyName(k, "route_upstream_retries.")) |name| {
        try setRouteUpstreamUsizeProperty(&cfg.routes, name, v, .retries);
    } else if (findAnyRoutePropertyName(k, &.{ "route_upstream_max_failures.", "route_upstream_max_fails.", "route_proxy_max_fails." })) |name| {
        try setRouteUpstreamUsizeProperty(&cfg.routes, name, v, .max_failures);
    } else if (findAnyRoutePropertyName(k, &.{ "route_upstream_fail_timeout_ms.", "route_proxy_fail_timeout_ms." })) |name| {
        try setRouteU32Property(&cfg.routes, name, v, .upstream_fail_timeout_ms);
    } else if (findAnyRoutePropertyName(k, &.{ "route_upstream_health_check.", "route_proxy_health_check." })) |name| {
        try setRouteBoolProperty(&cfg.routes, name, v, .upstream_health_check_enabled);
    } else if (findAnyRoutePropertyName(k, &.{ "route_upstream_health_check_path.", "route_proxy_health_check_path." })) |name| {
        try setRouteStringProperty(&cfg.routes, allocator, name, v, .upstream_health_check_path);
    } else if (findAnyRoutePropertyName(k, &.{ "route_upstream_health_check_interval_ms.", "route_proxy_health_check_interval_ms." })) |name| {
        try setRouteU32Property(&cfg.routes, name, v, .upstream_health_check_interval_ms);
    } else if (findAnyRoutePropertyName(k, &.{ "route_upstream_health_check_timeout_ms.", "route_proxy_health_check_timeout_ms." })) |name| {
        try setRouteU32Property(&cfg.routes, name, v, .upstream_health_check_timeout_ms);
    } else if (findAnyRoutePropertyName(k, &.{ "route_upstream_circuit_breaker.", "route_proxy_circuit_breaker." })) |name| {
        try setRouteBoolProperty(&cfg.routes, name, v, .upstream_circuit_breaker_enabled);
    } else if (findAnyRoutePropertyName(k, &.{ "route_upstream_circuit_half_open_max.", "route_proxy_circuit_half_open_max." })) |name| {
        try setRouteUpstreamUsizeProperty(&cfg.routes, name, v, .circuit_half_open_max);
    } else if (findAnyRoutePropertyName(k, &.{ "route_upstream_slow_start_ms.", "route_proxy_slow_start_ms." })) |name| {
        try setRouteU32Property(&cfg.routes, name, v, .upstream_slow_start_ms);
    } else if (findRoutePropertyName(k, "route_strip_prefix.")) |name| {
        try setRouteBoolProperty(&cfg.routes, name, v, .strip_prefix);
    } else if (findAnyRoutePropertyName(k, &.{ "route_compression.", "route_compress.", "route_encode." })) |name| {
        try setRouteCompressionBoolProperty(&cfg.routes, name, v, .enabled);
    } else if (findAnyRoutePropertyName(k, &.{ "route_gzip.", "route_gzip_enabled." })) |name| {
        try setRouteCompressionBoolProperty(&cfg.routes, name, v, .gzip_enabled);
    } else if (findAnyRoutePropertyName(k, &.{ "route_compression_min_bytes.", "route_gzip_min_bytes." })) |name| {
        try setRouteCompressionSizeProperty(&cfg.routes, name, v, .min_bytes);
    } else if (findAnyRoutePropertyName(k, &.{ "route_compression_max_bytes.", "route_gzip_max_bytes." })) |name| {
        try setRouteCompressionSizeProperty(&cfg.routes, name, v, .max_bytes);
    } else if (findRoutePropertyName(k, "route_response_cache.")) |name| {
        try setRouteResponseCacheBoolProperty(&cfg.routes, name, v, .enabled);
    } else if (findRoutePropertyName(k, "route_static_response_cache.")) |name| {
        try setRouteResponseCacheBoolProperty(&cfg.routes, name, v, .enabled);
    } else if (findRoutePropertyName(k, "route_response_cache_max_bytes.")) |name| {
        try setRouteResponseCacheSizeProperty(&cfg.routes, name, v, .max_bytes);
    } else if (findRoutePropertyName(k, "route_response_cache_max_entry_bytes.")) |name| {
        try setRouteResponseCacheSizeProperty(&cfg.routes, name, v, .max_entry_bytes);
    } else if (findRoutePropertyName(k, "route_response_cache_ttl_ms.")) |name| {
        try setRouteResponseCacheU32Property(&cfg.routes, name, v, .ttl_ms);
    } else if (findAnyRoutePropertyName(k, &.{ "route_security_headers.", "route_security_header_preset.", "route_secure_headers." })) |name| {
        try setRouteSecurityHeadersProperty(&cfg.routes, name, v);
    } else if (findRoutePropertyName(k, "route_header.")) |name| {
        try appendRouteResponseHeader(&cfg.routes, allocator, name, v);
    } else if (findRoutePropertyName(k, "route_response_header.")) |name| {
        try appendRouteResponseHeader(&cfg.routes, allocator, name, v);
    } else if (findRoutePropertyName(k, "route_add_header.")) |name| {
        try appendRouteResponseHeader(&cfg.routes, allocator, name, v);
    } else if (findRoutePropertyName(k, "route_cache_control.")) |name| {
        try appendRouteCacheControl(&cfg.routes, allocator, name, v);
    } else if (findRoutePropertyName(k, "route_cache-control.")) |name| {
        try appendRouteCacheControl(&cfg.routes, allocator, name, v);
    } else if (findAnyRoutePropertyName(k, &.{ "route_stale_while_revalidate.", "route_cache_stale_while_revalidate." })) |name| {
        try appendRouteCacheStaleDirective(&cfg.routes, allocator, name, v, .stale_while_revalidate);
    } else if (findAnyRoutePropertyName(k, &.{ "route_stale_if_error.", "route_cache_stale_if_error." })) |name| {
        try appendRouteCacheStaleDirective(&cfg.routes, allocator, name, v, .stale_if_error);
    } else if (std.mem.eql(u8, k, "max_request_bytes")) {
        cfg.max_request_bytes = try parseConfigUsize(v);
    } else if (std.mem.eql(u8, k, "max_body_bytes")) {
        cfg.max_body_bytes = try parseConfigUsize(v);
    } else if (std.mem.eql(u8, k, "max_static_file_bytes")) {
        cfg.max_static_file_bytes = try parseConfigUsize(v);
    } else if (std.mem.eql(u8, k, "max_requests_per_connection")) {
        cfg.max_requests_per_connection = try parseConfigUsize(v);
    } else if (std.mem.eql(u8, k, "max_concurrent_connections")) {
        cfg.max_concurrent_connections = try parseConfigUsize(v);
    } else if (std.mem.eql(u8, k, "worker_stack_size")) {
        cfg.worker_stack_size = try parseConfigUsize(v);
    } else if (std.mem.eql(u8, k, "read_header_timeout_ms")) {
        cfg.read_header_timeout_ms = try parseConfigU32(v);
    } else if (std.mem.eql(u8, k, "read_body_timeout_ms")) {
        cfg.read_body_timeout_ms = try parseConfigU32(v);
    } else if (std.mem.eql(u8, k, "idle_timeout_ms")) {
        cfg.idle_timeout_ms = try parseConfigU32(v);
    } else if (std.mem.eql(u8, k, "write_timeout_ms")) {
        cfg.write_timeout_ms = try parseConfigU32(v);
    } else if (std.mem.eql(u8, k, "upstream_timeout_ms")) {
        cfg.upstream_timeout_ms = try parseConfigU32(v);
    } else if (std.mem.eql(u8, k, "upstream_retries")) {
        cfg.upstream_retries = try parseConfigUsize(v);
    } else if (std.mem.eql(u8, k, "upstream_max_failures") or std.mem.eql(u8, k, "upstream_max_fails") or std.mem.eql(u8, k, "proxy_max_fails")) {
        cfg.upstream_max_failures = try parseConfigUsize(v);
    } else if (std.mem.eql(u8, k, "upstream_fail_timeout_ms") or std.mem.eql(u8, k, "proxy_fail_timeout_ms")) {
        cfg.upstream_fail_timeout_ms = try parseConfigU32(v);
    } else if (std.mem.eql(u8, k, "upstream_keepalive") or std.mem.eql(u8, k, "proxy_keepalive")) {
        cfg.upstream_keepalive_enabled = try parseConfigBool(v);
    } else if (std.mem.eql(u8, k, "upstream_keepalive_max_idle") or std.mem.eql(u8, k, "proxy_keepalive_max_idle")) {
        cfg.upstream_keepalive_max_idle = try parseConfigUsize(v);
    } else if (std.mem.eql(u8, k, "upstream_keepalive_idle_timeout_ms") or std.mem.eql(u8, k, "proxy_keepalive_idle_timeout_ms")) {
        cfg.upstream_keepalive_idle_timeout_ms = try parseConfigU32(v);
    } else if (std.mem.eql(u8, k, "upstream_keepalive_max_requests") or std.mem.eql(u8, k, "proxy_keepalive_max_requests")) {
        cfg.upstream_keepalive_max_requests = try parseConfigUsize(v);
    } else if (std.mem.eql(u8, k, "fastcgi_keepalive") or std.mem.eql(u8, k, "php_fastcgi_keepalive") or std.mem.eql(u8, k, "fastcgi_keep_conn")) {
        cfg.fastcgi_keepalive_enabled = try parseConfigBool(v);
    } else if (std.mem.eql(u8, k, "fastcgi_keepalive_max_idle") or std.mem.eql(u8, k, "php_fastcgi_keepalive_max_idle")) {
        cfg.fastcgi_keepalive_max_idle = try parseConfigUsize(v);
    } else if (std.mem.eql(u8, k, "fastcgi_keepalive_idle_timeout_ms") or std.mem.eql(u8, k, "php_fastcgi_keepalive_idle_timeout_ms")) {
        cfg.fastcgi_keepalive_idle_timeout_ms = try parseConfigU32(v);
    } else if (std.mem.eql(u8, k, "fastcgi_keepalive_max_requests") or std.mem.eql(u8, k, "php_fastcgi_keepalive_max_requests")) {
        cfg.fastcgi_keepalive_max_requests = try parseConfigUsize(v);
    } else if (std.mem.eql(u8, k, "upstream_health_check") or std.mem.eql(u8, k, "upstream_health_check_enabled") or std.mem.eql(u8, k, "active_health_check") or std.mem.eql(u8, k, "proxy_health_check")) {
        cfg.upstream_health_check_enabled = try parseConfigBool(v);
    } else if (std.mem.eql(u8, k, "upstream_health_check_path") or std.mem.eql(u8, k, "proxy_health_check_path")) {
        cfg.upstream_health_check_path = try allocator.dupe(u8, v);
    } else if (std.mem.eql(u8, k, "upstream_health_check_interval_ms") or std.mem.eql(u8, k, "proxy_health_check_interval_ms")) {
        cfg.upstream_health_check_interval_ms = try parseConfigU32(v);
    } else if (std.mem.eql(u8, k, "upstream_health_check_timeout_ms") or std.mem.eql(u8, k, "proxy_health_check_timeout_ms")) {
        cfg.upstream_health_check_timeout_ms = try parseConfigU32(v);
    } else if (std.mem.eql(u8, k, "upstream_circuit_breaker") or std.mem.eql(u8, k, "upstream_circuit_breaker_enabled") or std.mem.eql(u8, k, "proxy_circuit_breaker")) {
        cfg.upstream_circuit_breaker_enabled = try parseConfigBool(v);
    } else if (std.mem.eql(u8, k, "upstream_circuit_half_open_max") or std.mem.eql(u8, k, "proxy_circuit_half_open_max")) {
        cfg.upstream_circuit_half_open_max = try parseConfigUsize(v);
    } else if (std.mem.eql(u8, k, "upstream_slow_start_ms") or std.mem.eql(u8, k, "proxy_slow_start_ms")) {
        cfg.upstream_slow_start_ms = try parseConfigU32(v);
    } else if (std.mem.eql(u8, k, "graceful_shutdown_timeout_ms")) {
        cfg.graceful_shutdown_timeout_ms = try parseConfigU32(v);
    } else if (std.mem.eql(u8, k, "max_php_output_bytes")) {
        cfg.max_php_output_bytes = try parseConfigUsize(v);
    } else if (std.mem.eql(u8, k, "cf_auto_deploy")) {
        cfg.cloudflare_auto_deploy = try parseConfigBool(v);
    } else if (std.mem.eql(u8, k, "cf_api_base")) {
        if (v.len == 0) return error.InvalidConfigValue;
        cfg.cloudflare_api_base = try allocator.dupe(u8, v);
    } else if (std.mem.eql(u8, k, "cf_token")) {
        if (v.len == 0) {
            cfg.cloudflare_token = null;
        } else {
            cfg.cloudflare_token = try allocator.dupe(u8, v);
        }
    } else if (std.mem.eql(u8, k, "cf_zone_id")) {
        if (v.len == 0) {
            cfg.cloudflare_zone_id = null;
        } else {
            cfg.cloudflare_zone_id = try allocator.dupe(u8, v);
        }
    } else if (std.mem.eql(u8, k, "cf_zone_name")) {
        if (v.len == 0) {
            cfg.cloudflare_zone_name = null;
        } else {
            cfg.cloudflare_zone_name = try allocator.dupe(u8, v);
        }
    } else if (std.mem.eql(u8, k, "cf_record_name")) {
        if (v.len == 0) {
            cfg.cloudflare_record_name = null;
        } else {
            cfg.cloudflare_record_name = try allocator.dupe(u8, v);
        }
    } else if (std.mem.eql(u8, k, "cf_record_type")) {
        if (v.len == 0) {
            cfg.cloudflare_record_type = "A";
        } else {
            if (!isSupportedCloudflareRecordType(v)) return error.InvalidConfigValue;
            cfg.cloudflare_record_type = try allocator.dupe(u8, v);
        }
    } else if (std.mem.eql(u8, k, "cf_record_content")) {
        if (v.len == 0) {
            cfg.cloudflare_record_content = null;
        } else {
            cfg.cloudflare_record_content = try allocator.dupe(u8, v);
        }
    } else if (std.mem.eql(u8, k, "cf_record_ttl")) {
        cfg.cloudflare_record_ttl = try parseConfigU32(v);
    } else if (std.mem.eql(u8, k, "cf_record_proxied")) {
        cfg.cloudflare_record_proxied = try parseConfigBool(v);
    } else if (std.mem.eql(u8, k, "cf_record_comment")) {
        if (v.len == 0) {
            cfg.cloudflare_record_comment = null;
        } else {
            cfg.cloudflare_record_comment = try allocator.dupe(u8, v);
        }
    } else {
        return error.UnknownConfigKey;
    }
}

pub fn applyDomainConfigLine(domain: *DomainConfig, allocator: std.mem.Allocator, key: []const u8, value: []const u8) !void {
    const k = std.mem.trim(u8, key, " \t\r\n");
    const v = trimValue(value);

    if (std.mem.eql(u8, k, "server") or std.mem.eql(u8, k, "domain") or std.mem.eql(u8, k, "vhost") or std.mem.eql(u8, k, "name")) {
        if (!isDomainConfigNameValid(v)) return error.InvalidConfigValue;
        domain.name = try allocator.dupe(u8, v);
    } else if (std.mem.eql(u8, k, "server_name") or std.mem.eql(u8, k, "server_names")) {
        try appendServerNames(allocator, domain, v);
    } else if (std.mem.eql(u8, k, "root") or std.mem.eql(u8, k, "dir") or std.mem.eql(u8, k, "static_dir") or std.mem.eql(u8, k, "server_root")) {
        try setDomainStringPropertyDirect(allocator, domain, v, .static_dir);
    } else if (std.mem.eql(u8, k, "max_static_file_bytes") or std.mem.eql(u8, k, "max_static_bytes")) {
        try setDomainMaxStaticFileBytesDirect(domain, v);
    } else if (std.mem.eql(u8, k, "index") or std.mem.eql(u8, k, "index_file") or std.mem.eql(u8, k, "server_index")) {
        try setDomainStringPropertyDirect(allocator, domain, v, .index_file);
    } else if (std.mem.eql(u8, k, "serve_static") or std.mem.eql(u8, k, "serve_static_root")) {
        try setDomainBoolPropertyDirect(domain, v, .serve_static_root);
    } else if (std.mem.eql(u8, k, "php_root")) {
        try setDomainStringPropertyDirect(allocator, domain, v, .php_root);
    } else if (std.mem.eql(u8, k, "php_binary") or std.mem.eql(u8, k, "php_bin")) {
        try setDomainStringPropertyDirect(allocator, domain, v, .php_binary);
    } else if (std.mem.eql(u8, k, "php_fastcgi") or std.mem.eql(u8, k, "php_fpm") or std.mem.eql(u8, k, "fastcgi")) {
        try setDomainStringPropertyDirect(allocator, domain, v, .php_fastcgi);
    } else if (std.mem.eql(u8, k, "php_index") or std.mem.eql(u8, k, "php_index_file")) {
        try setDomainStringPropertyDirect(allocator, domain, v, .php_index);
    } else if (std.mem.eql(u8, k, "php_info_page") or std.mem.eql(u8, k, "phpinfo_page")) {
        try setDomainBoolPropertyDirect(domain, v, .php_info_page);
    } else if (std.mem.eql(u8, k, "php_front_controller") or std.mem.eql(u8, k, "php_front_controller_enabled")) {
        try setDomainBoolPropertyDirect(domain, v, .php_front_controller);
    } else if (std.mem.eql(u8, k, "tls_cert") or std.mem.eql(u8, k, "ssl_certificate")) {
        try setDomainStringPropertyDirect(allocator, domain, v, .tls_cert);
    } else if (std.mem.eql(u8, k, "tls_key") or std.mem.eql(u8, k, "ssl_certificate_key")) {
        try setDomainStringPropertyDirect(allocator, domain, v, .tls_key);
    } else if (std.mem.eql(u8, k, "proxy") or std.mem.eql(u8, k, "upstream")) {
        try setDomainProxyPropertyDirect(allocator, domain, v);
    } else if (std.mem.eql(u8, k, "upstream_policy") or std.mem.eql(u8, k, "proxy_policy") or std.mem.eql(u8, k, "load_balance")) {
        try setDomainUpstreamPolicyPropertyDirect(domain, v);
    } else if (std.mem.eql(u8, k, "upstream_timeout_ms") or std.mem.eql(u8, k, "proxy_timeout_ms") or std.mem.eql(u8, k, "php_timeout_ms") or std.mem.eql(u8, k, "fastcgi_timeout_ms")) {
        try setDomainU32PropertyDirect(domain, v, .upstream_timeout_ms);
    } else if (std.mem.eql(u8, k, "upstream_retries") or std.mem.eql(u8, k, "proxy_retries")) {
        try setDomainUpstreamUsizePropertyDirect(domain, v, .retries);
    } else if (std.mem.eql(u8, k, "upstream_max_failures") or std.mem.eql(u8, k, "upstream_max_fails") or std.mem.eql(u8, k, "proxy_max_fails")) {
        try setDomainUpstreamUsizePropertyDirect(domain, v, .max_failures);
    } else if (std.mem.eql(u8, k, "upstream_fail_timeout_ms") or std.mem.eql(u8, k, "proxy_fail_timeout_ms")) {
        try setDomainU32PropertyDirect(domain, v, .upstream_fail_timeout_ms);
    } else if (std.mem.eql(u8, k, "upstream_health_check") or std.mem.eql(u8, k, "upstream_health_check_enabled") or std.mem.eql(u8, k, "proxy_health_check")) {
        try setDomainBoolPropertyDirect(domain, v, .upstream_health_check_enabled);
    } else if (std.mem.eql(u8, k, "upstream_health_check_path") or std.mem.eql(u8, k, "proxy_health_check_path")) {
        try setDomainStringPropertyDirect(allocator, domain, v, .upstream_health_check_path);
    } else if (std.mem.eql(u8, k, "upstream_health_check_interval_ms") or std.mem.eql(u8, k, "proxy_health_check_interval_ms")) {
        try setDomainU32PropertyDirect(domain, v, .upstream_health_check_interval_ms);
    } else if (std.mem.eql(u8, k, "upstream_health_check_timeout_ms") or std.mem.eql(u8, k, "proxy_health_check_timeout_ms")) {
        try setDomainU32PropertyDirect(domain, v, .upstream_health_check_timeout_ms);
    } else if (std.mem.eql(u8, k, "upstream_circuit_breaker") or std.mem.eql(u8, k, "upstream_circuit_breaker_enabled") or std.mem.eql(u8, k, "proxy_circuit_breaker")) {
        try setDomainBoolPropertyDirect(domain, v, .upstream_circuit_breaker_enabled);
    } else if (std.mem.eql(u8, k, "upstream_circuit_half_open_max") or std.mem.eql(u8, k, "proxy_circuit_half_open_max")) {
        try setDomainUpstreamUsizePropertyDirect(domain, v, .circuit_half_open_max);
    } else if (std.mem.eql(u8, k, "upstream_slow_start_ms") or std.mem.eql(u8, k, "proxy_slow_start_ms")) {
        try setDomainU32PropertyDirect(domain, v, .upstream_slow_start_ms);
    } else if (isCompressionEnabledKey(k)) {
        try setDomainCompressionBoolPropertyDirect(domain, v, .enabled);
    } else if (isGzipEnabledKey(k)) {
        try setDomainCompressionBoolPropertyDirect(domain, v, .gzip_enabled);
    } else if (isCompressionMinBytesKey(k)) {
        try setDomainCompressionSizePropertyDirect(domain, v, .min_bytes);
    } else if (isCompressionMaxBytesKey(k)) {
        try setDomainCompressionSizePropertyDirect(domain, v, .max_bytes);
    } else if (std.mem.eql(u8, k, "response_cache") or std.mem.eql(u8, k, "static_response_cache")) {
        try setDomainResponseCacheBoolPropertyDirect(domain, v, .enabled);
    } else if (std.mem.eql(u8, k, "response_cache_max_bytes") or std.mem.eql(u8, k, "static_response_cache_max_bytes")) {
        try setDomainResponseCacheSizePropertyDirect(domain, v, .max_bytes);
    } else if (std.mem.eql(u8, k, "response_cache_max_entry_bytes") or std.mem.eql(u8, k, "static_response_cache_max_entry_bytes")) {
        try setDomainResponseCacheSizePropertyDirect(domain, v, .max_entry_bytes);
    } else if (std.mem.eql(u8, k, "response_cache_ttl_ms") or std.mem.eql(u8, k, "static_response_cache_ttl_ms")) {
        try setDomainResponseCacheU32PropertyDirect(domain, v, .ttl_ms);
    } else if (std.mem.eql(u8, k, "security_headers") or std.mem.eql(u8, k, "security_header_preset") or std.mem.eql(u8, k, "secure_headers")) {
        try setDomainSecurityHeadersPropertyDirect(domain, v);
    } else if (std.mem.eql(u8, k, "header") or std.mem.eql(u8, k, "response_header") or std.mem.eql(u8, k, "add_header")) {
        if (v.len > 0) try domain.response_headers.append(allocator, try parseResponseHeaderRule(allocator, v));
    } else if (std.mem.eql(u8, k, "cache_control") or std.mem.eql(u8, k, "cache-control")) {
        if (v.len > 0) try domain.response_headers.append(allocator, try makeResponseHeaderRule(allocator, "Cache-Control", v));
    } else if (std.mem.eql(u8, k, "stale_while_revalidate") or std.mem.eql(u8, k, "cache_stale_while_revalidate")) {
        try appendCacheStaleDirective(&domain.response_headers, allocator, v, .stale_while_revalidate);
    } else if (std.mem.eql(u8, k, "stale_if_error") or std.mem.eql(u8, k, "cache_stale_if_error")) {
        try appendCacheStaleDirective(&domain.response_headers, allocator, v, .stale_if_error);
    } else if (std.mem.eql(u8, k, "redirect") or std.mem.eql(u8, k, "redir")) {
        if (v.len > 0) try domain.redirects.append(allocator, try parseRedirectRule(allocator, v));
    } else if (std.mem.eql(u8, k, "route")) {
        try setRouteLineFor(&domain.routes, allocator, v);
    } else if (findRoutePropertyName(k, "route_dir.")) |name| {
        try setRouteStringProperty(&domain.routes, allocator, name, v, .static_dir);
    } else if (findRoutePropertyName(k, "route_static_dir.")) |name| {
        try setRouteStringProperty(&domain.routes, allocator, name, v, .static_dir);
    } else if (findRoutePropertyName(k, "route_max_static_file_bytes.")) |name| {
        try setRouteMaxStaticFileBytes(&domain.routes, name, v);
    } else if (findRoutePropertyName(k, "route_max_static_bytes.")) |name| {
        try setRouteMaxStaticFileBytes(&domain.routes, name, v);
    } else if (findRoutePropertyName(k, "route_index.")) |name| {
        try setRouteStringProperty(&domain.routes, allocator, name, v, .index_file);
    } else if (findRoutePropertyName(k, "route_index_file.")) |name| {
        try setRouteStringProperty(&domain.routes, allocator, name, v, .index_file);
    } else if (findRoutePropertyName(k, "route_php_root.")) |name| {
        try setRouteStringProperty(&domain.routes, allocator, name, v, .php_root);
    } else if (findRoutePropertyName(k, "route_php_bin.")) |name| {
        try setRouteStringProperty(&domain.routes, allocator, name, v, .php_binary);
    } else if (findRoutePropertyName(k, "route_php_binary.")) |name| {
        try setRouteStringProperty(&domain.routes, allocator, name, v, .php_binary);
    } else if (findRoutePropertyName(k, "route_php_fastcgi.")) |name| {
        try setRouteStringProperty(&domain.routes, allocator, name, v, .php_fastcgi);
    } else if (findRoutePropertyName(k, "route_php_fpm.")) |name| {
        try setRouteStringProperty(&domain.routes, allocator, name, v, .php_fastcgi);
    } else if (findRoutePropertyName(k, "route_fastcgi.")) |name| {
        try setRouteStringProperty(&domain.routes, allocator, name, v, .php_fastcgi);
    } else if (findRoutePropertyName(k, "route_php_index.")) |name| {
        try setRouteStringProperty(&domain.routes, allocator, name, v, .php_index);
    } else if (findRoutePropertyName(k, "route_php_index_file.")) |name| {
        try setRouteStringProperty(&domain.routes, allocator, name, v, .php_index);
    } else if (findRoutePropertyName(k, "route_php_info_page.")) |name| {
        try setRouteBoolProperty(&domain.routes, name, v, .php_info_page);
    } else if (findRoutePropertyName(k, "route_phpinfo_page.")) |name| {
        try setRouteBoolProperty(&domain.routes, name, v, .php_info_page);
    } else if (findRoutePropertyName(k, "route_php_front_controller.")) |name| {
        try setRouteBoolProperty(&domain.routes, name, v, .php_front_controller);
    } else if (findRoutePropertyName(k, "route_proxy.")) |name| {
        try setRouteProxyProperty(&domain.routes, allocator, name, v);
    } else if (findRoutePropertyName(k, "route_upstream.")) |name| {
        try setRouteProxyProperty(&domain.routes, allocator, name, v);
    } else if (findRoutePropertyName(k, "route_proxy_policy.")) |name| {
        try setRouteUpstreamPolicyProperty(&domain.routes, name, v);
    } else if (findRoutePropertyName(k, "route_upstream_policy.")) |name| {
        try setRouteUpstreamPolicyProperty(&domain.routes, name, v);
    } else if (findRoutePropertyName(k, "route_load_balance.")) |name| {
        try setRouteUpstreamPolicyProperty(&domain.routes, name, v);
    } else if (findRoutePropertyName(k, "route_upstream_timeout_ms.")) |name| {
        try setRouteU32Property(&domain.routes, name, v, .upstream_timeout_ms);
    } else if (findRoutePropertyName(k, "route_proxy_timeout_ms.")) |name| {
        try setRouteU32Property(&domain.routes, name, v, .upstream_timeout_ms);
    } else if (findRoutePropertyName(k, "route_php_timeout_ms.")) |name| {
        try setRouteU32Property(&domain.routes, name, v, .upstream_timeout_ms);
    } else if (findRoutePropertyName(k, "route_fastcgi_timeout_ms.")) |name| {
        try setRouteU32Property(&domain.routes, name, v, .upstream_timeout_ms);
    } else if (findRoutePropertyName(k, "route_upstream_retries.")) |name| {
        try setRouteUpstreamUsizeProperty(&domain.routes, name, v, .retries);
    } else if (findAnyRoutePropertyName(k, &.{ "route_upstream_max_failures.", "route_upstream_max_fails.", "route_proxy_max_fails." })) |name| {
        try setRouteUpstreamUsizeProperty(&domain.routes, name, v, .max_failures);
    } else if (findAnyRoutePropertyName(k, &.{ "route_upstream_fail_timeout_ms.", "route_proxy_fail_timeout_ms." })) |name| {
        try setRouteU32Property(&domain.routes, name, v, .upstream_fail_timeout_ms);
    } else if (findAnyRoutePropertyName(k, &.{ "route_upstream_health_check.", "route_proxy_health_check." })) |name| {
        try setRouteBoolProperty(&domain.routes, name, v, .upstream_health_check_enabled);
    } else if (findAnyRoutePropertyName(k, &.{ "route_upstream_health_check_path.", "route_proxy_health_check_path." })) |name| {
        try setRouteStringProperty(&domain.routes, allocator, name, v, .upstream_health_check_path);
    } else if (findAnyRoutePropertyName(k, &.{ "route_upstream_health_check_interval_ms.", "route_proxy_health_check_interval_ms." })) |name| {
        try setRouteU32Property(&domain.routes, name, v, .upstream_health_check_interval_ms);
    } else if (findAnyRoutePropertyName(k, &.{ "route_upstream_health_check_timeout_ms.", "route_proxy_health_check_timeout_ms." })) |name| {
        try setRouteU32Property(&domain.routes, name, v, .upstream_health_check_timeout_ms);
    } else if (findAnyRoutePropertyName(k, &.{ "route_upstream_circuit_breaker.", "route_proxy_circuit_breaker." })) |name| {
        try setRouteBoolProperty(&domain.routes, name, v, .upstream_circuit_breaker_enabled);
    } else if (findAnyRoutePropertyName(k, &.{ "route_upstream_circuit_half_open_max.", "route_proxy_circuit_half_open_max." })) |name| {
        try setRouteUpstreamUsizeProperty(&domain.routes, name, v, .circuit_half_open_max);
    } else if (findAnyRoutePropertyName(k, &.{ "route_upstream_slow_start_ms.", "route_proxy_slow_start_ms." })) |name| {
        try setRouteU32Property(&domain.routes, name, v, .upstream_slow_start_ms);
    } else if (findRoutePropertyName(k, "route_strip_prefix.")) |name| {
        try setRouteBoolProperty(&domain.routes, name, v, .strip_prefix);
    } else if (findAnyRoutePropertyName(k, &.{ "route_compression.", "route_compress.", "route_encode." })) |name| {
        try setRouteCompressionBoolProperty(&domain.routes, name, v, .enabled);
    } else if (findAnyRoutePropertyName(k, &.{ "route_gzip.", "route_gzip_enabled." })) |name| {
        try setRouteCompressionBoolProperty(&domain.routes, name, v, .gzip_enabled);
    } else if (findAnyRoutePropertyName(k, &.{ "route_compression_min_bytes.", "route_gzip_min_bytes." })) |name| {
        try setRouteCompressionSizeProperty(&domain.routes, name, v, .min_bytes);
    } else if (findAnyRoutePropertyName(k, &.{ "route_compression_max_bytes.", "route_gzip_max_bytes." })) |name| {
        try setRouteCompressionSizeProperty(&domain.routes, name, v, .max_bytes);
    } else if (findRoutePropertyName(k, "route_response_cache.")) |name| {
        try setRouteResponseCacheBoolProperty(&domain.routes, name, v, .enabled);
    } else if (findRoutePropertyName(k, "route_static_response_cache.")) |name| {
        try setRouteResponseCacheBoolProperty(&domain.routes, name, v, .enabled);
    } else if (findRoutePropertyName(k, "route_response_cache_max_bytes.")) |name| {
        try setRouteResponseCacheSizeProperty(&domain.routes, name, v, .max_bytes);
    } else if (findRoutePropertyName(k, "route_response_cache_max_entry_bytes.")) |name| {
        try setRouteResponseCacheSizeProperty(&domain.routes, name, v, .max_entry_bytes);
    } else if (findRoutePropertyName(k, "route_response_cache_ttl_ms.")) |name| {
        try setRouteResponseCacheU32Property(&domain.routes, name, v, .ttl_ms);
    } else if (findAnyRoutePropertyName(k, &.{ "route_security_headers.", "route_security_header_preset.", "route_secure_headers." })) |name| {
        try setRouteSecurityHeadersProperty(&domain.routes, name, v);
    } else if (findRoutePropertyName(k, "route_header.")) |name| {
        try appendRouteResponseHeader(&domain.routes, allocator, name, v);
    } else if (findRoutePropertyName(k, "route_response_header.")) |name| {
        try appendRouteResponseHeader(&domain.routes, allocator, name, v);
    } else if (findRoutePropertyName(k, "route_add_header.")) |name| {
        try appendRouteResponseHeader(&domain.routes, allocator, name, v);
    } else if (findRoutePropertyName(k, "route_cache_control.")) |name| {
        try appendRouteCacheControl(&domain.routes, allocator, name, v);
    } else if (findRoutePropertyName(k, "route_cache-control.")) |name| {
        try appendRouteCacheControl(&domain.routes, allocator, name, v);
    } else if (findAnyRoutePropertyName(k, &.{ "route_stale_while_revalidate.", "route_cache_stale_while_revalidate." })) |name| {
        try appendRouteCacheStaleDirective(&domain.routes, allocator, name, v, .stale_while_revalidate);
    } else if (findAnyRoutePropertyName(k, &.{ "route_stale_if_error.", "route_cache_stale_if_error." })) |name| {
        try appendRouteCacheStaleDirective(&domain.routes, allocator, name, v, .stale_if_error);
    } else {
        return error.UnknownConfigKey;
    }
}
