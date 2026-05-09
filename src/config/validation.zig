const std = @import("std");
const parsing = @import("parsing.zig");
const policy_mod = @import("policy.zig");
const types = @import("types.zig");

const CompressionPolicy = types.CompressionPolicy;
const DomainConfig = types.DomainConfig;
const ResponseCachePolicy = policy_mod.ResponseCachePolicy;
const RouteConfig = types.RouteConfig;
const ServerConfig = types.ServerConfig;
const UpstreamPoolConfig = types.UpstreamPoolConfig;
const UpstreamRuntimePolicy = policy_mod.UpstreamRuntimePolicy;

const DEFAULT_COMPRESSION_WORKER_STACK_BYTES = types.DEFAULT_COMPRESSION_WORKER_STACK_BYTES;
const DEFAULT_FASTCGI_KEEPALIVE_IDLE_TIMEOUT_MS = types.DEFAULT_FASTCGI_KEEPALIVE_IDLE_TIMEOUT_MS;
const DEFAULT_FASTCGI_KEEPALIVE_MAX_REQUESTS = types.DEFAULT_FASTCGI_KEEPALIVE_MAX_REQUESTS;
const DEFAULT_MAX_PHP_OUTPUT_BYTES = types.DEFAULT_MAX_PHP_OUTPUT_BYTES;
const DEFAULT_MAX_REQUESTS_PER_CONNECTION = types.DEFAULT_MAX_REQUESTS_PER_CONNECTION;
const DEFAULT_UPSTREAM_KEEPALIVE_IDLE_TIMEOUT_MS = types.DEFAULT_UPSTREAM_KEEPALIVE_IDLE_TIMEOUT_MS;
const DEFAULT_UPSTREAM_KEEPALIVE_MAX_REQUESTS = types.DEFAULT_UPSTREAM_KEEPALIVE_MAX_REQUESTS;

const compressionPolicyFor = policy_mod.compressionPolicyFor;
const compressionPolicyFromConfig = policy_mod.compressionPolicyFromConfig;
const disablesOptionalUrl = parsing.disablesOptionalUrl;
const isDomainConfigNameValid = @import("domains.zig").isDomainConfigNameValid;
const isRouteNameValid = parsing.isRouteNameValid;
const configCanEnableCompression = policy_mod.configCanEnableCompression;
const responseCachePolicyFor = policy_mod.responseCachePolicyFor;
const responseCachePolicyFromConfig = policy_mod.responseCachePolicyFromConfig;
const upstreamRuntimePolicyFor = policy_mod.upstreamRuntimePolicyFor;
const upstreamRuntimePolicyFromConfig = policy_mod.upstreamRuntimePolicyFromConfig;
const validateFastcgiEndpoint = parsing.validateFastcgiEndpoint;

pub fn normalizeConfig(cfg: *ServerConfig) void {
    if (cfg.max_concurrent_connections == 0) {
        cfg.max_concurrent_connections = 1024;
    }
    if (cfg.max_requests_per_connection == 0) {
        cfg.max_requests_per_connection = DEFAULT_MAX_REQUESTS_PER_CONNECTION;
    }
    if (cfg.max_php_output_bytes == 0) {
        cfg.max_php_output_bytes = DEFAULT_MAX_PHP_OUTPUT_BYTES;
    }
    if (cfg.upstream_keepalive_max_requests == 0) {
        cfg.upstream_keepalive_max_requests = DEFAULT_UPSTREAM_KEEPALIVE_MAX_REQUESTS;
    }
    if (cfg.upstream_keepalive_idle_timeout_ms == 0) {
        cfg.upstream_keepalive_idle_timeout_ms = DEFAULT_UPSTREAM_KEEPALIVE_IDLE_TIMEOUT_MS;
    }
    if (cfg.fastcgi_keepalive_max_requests == 0) {
        cfg.fastcgi_keepalive_max_requests = DEFAULT_FASTCGI_KEEPALIVE_MAX_REQUESTS;
    }
    if (cfg.fastcgi_keepalive_idle_timeout_ms == 0) {
        cfg.fastcgi_keepalive_idle_timeout_ms = DEFAULT_FASTCGI_KEEPALIVE_IDLE_TIMEOUT_MS;
    }
    if (cfg.worker_stack_size < 16 * 1024) {
        cfg.worker_stack_size = 16 * 1024;
    }
    if (configCanEnableCompression(cfg) and cfg.worker_stack_size < DEFAULT_COMPRESSION_WORKER_STACK_BYTES) {
        cfg.worker_stack_size = DEFAULT_COMPRESSION_WORKER_STACK_BYTES;
    }
}

pub fn validateUpstreamPool(pool: UpstreamPoolConfig) !void {
    if (pool.targets.items.len == 0) return error.InvalidConfigValue;
    for (pool.targets.items) |target| {
        if (target.host.len == 0) return error.InvalidConfigValue;
        if (target.port == 0) return error.InvalidConfigValue;
        if (target.base_path.len == 0 or target.base_path[0] != '/') return error.InvalidConfigValue;
    }
}

pub fn isSafeRelativeScriptPath(path: []const u8) bool {
    return path.len > 0 and
        path[0] != '/' and
        std.mem.indexOf(u8, path, "..") == null and
        std.mem.indexOfScalar(u8, path, '\x00') == null;
}

fn validateCompressionPolicy(policy: CompressionPolicy) !void {
    if (!policy.enabled) return;
    if (!policy.gzip_enabled) return error.InvalidConfigValue;
    if (policy.min_bytes == 0) return error.InvalidConfigValue;
    if (policy.max_bytes < policy.min_bytes) return error.InvalidConfigValue;
}

fn validateRouteCompressionOverrides(route: *const RouteConfig) !void {
    if (route.compression_min_bytes) |min_bytes| {
        if (min_bytes == 0) return error.InvalidConfigValue;
    }
    if (route.compression_max_bytes) |max_bytes| {
        if (max_bytes == 0) return error.InvalidConfigValue;
    }
    if (route.compression_min_bytes != null and route.compression_max_bytes != null and
        route.compression_max_bytes.? < route.compression_min_bytes.?)
    {
        return error.InvalidConfigValue;
    }
}

fn validateDomainCompressionOverrides(domain: *const DomainConfig) !void {
    if (domain.compression_min_bytes) |min_bytes| {
        if (min_bytes == 0) return error.InvalidConfigValue;
    }
    if (domain.compression_max_bytes) |max_bytes| {
        if (max_bytes == 0) return error.InvalidConfigValue;
    }
    if (domain.compression_min_bytes != null and domain.compression_max_bytes != null and
        domain.compression_max_bytes.? < domain.compression_min_bytes.?)
    {
        return error.InvalidConfigValue;
    }
}

fn validateResponseCachePolicy(policy: ResponseCachePolicy) !void {
    if (!policy.enabled) return;
    if (policy.max_bytes == 0) return error.InvalidConfigValue;
    if (policy.max_entry_bytes == 0) return error.InvalidConfigValue;
    if (policy.max_entry_bytes > policy.max_bytes) return error.InvalidConfigValue;
    if (policy.ttl_ms == 0) return error.InvalidConfigValue;
}

fn validateUpstreamRuntimePolicy(policy: UpstreamRuntimePolicy) !void {
    if (policy.timeout_ms == 0) return error.InvalidConfigValue;
    if (policy.max_failures > 0 and policy.fail_timeout_ms == 0) return error.InvalidConfigValue;
    if (policy.health_check_enabled) {
        if (policy.health_check_path.len == 0 or policy.health_check_path[0] != '/') return error.InvalidConfigValue;
        if (policy.health_check_interval_ms == 0) return error.InvalidConfigValue;
        if (policy.health_check_timeout_ms == 0) return error.InvalidConfigValue;
    }
    if (policy.circuit_breaker_enabled and policy.circuit_half_open_max == 0) return error.InvalidConfigValue;
}

pub fn validateRouteConfig(route: *const RouteConfig, fallback_upstream: ?UpstreamPoolConfig) !void {
    if (!isRouteNameValid(route.name)) return error.InvalidConfigValue;
    if (route.pattern.len == 0 or route.pattern[0] != '/') return error.InvalidConfigValue;
    if (route.static_dir) |static_dir| {
        if (static_dir.len == 0) return error.InvalidConfigValue;
    }
    if (route.index_file) |index_file| {
        if (index_file.len == 0) return error.InvalidConfigValue;
    }
    if (route.php_root) |php_root| {
        if (php_root.len == 0) return error.InvalidConfigValue;
    }
    if (route.php_binary) |php_binary| {
        if (php_binary.len == 0) return error.InvalidConfigValue;
    }
    if (route.php_fastcgi) |endpoint| {
        if (!disablesOptionalUrl(endpoint)) try validateFastcgiEndpoint(endpoint);
    }
    if (route.php_index) |php_index| {
        if (!isSafeRelativeScriptPath(php_index)) return error.InvalidConfigValue;
    }
    if (route.upstream) |pool| {
        try validateUpstreamPool(pool);
    }
    if (route.handler == .proxy and route.upstream == null and fallback_upstream == null) {
        return error.InvalidConfigValue;
    }
    if (route.upstream_timeout_ms) |timeout_ms| {
        if (timeout_ms == 0) return error.InvalidConfigValue;
    }
    if (route.max_static_file_bytes) |limit| {
        if (limit == 0) return error.InvalidConfigValue;
    }
    try validateRouteCompressionOverrides(route);
}

pub fn validateConfig(cfg: *const ServerConfig) !void {
    if (cfg.host.len == 0) return error.InvalidConfigValue;
    if (cfg.port == 0) return error.InvalidConfigValue;
    if (cfg.static_dir.len == 0) return error.InvalidConfigValue;
    if (cfg.index_file.len == 0) return error.InvalidConfigValue;
    if (cfg.php_root.len == 0) return error.InvalidConfigValue;
    if (cfg.php_binary.len == 0) return error.InvalidConfigValue;
    if (cfg.php_fastcgi) |endpoint| try validateFastcgiEndpoint(endpoint);
    if (!isSafeRelativeScriptPath(cfg.php_index)) return error.InvalidConfigValue;
    if (cfg.http3_enabled and cfg.http3_port == 0) return error.InvalidConfigValue;
    if (cfg.admin_enabled) {
        const socket_path = cfg.admin_socket_path orelse return error.InvalidConfigValue;
        if (socket_path.len == 0) return error.InvalidConfigValue;
        _ = std.Io.net.UnixAddress.init(socket_path) catch return error.InvalidConfigValue;
    }
    if (cfg.admin_ui_enabled) {
        try validateAdminUiPath(cfg.admin_ui_path);
        if (cfg.admin_credentials_path.len == 0) return error.InvalidConfigValue;
        if (std.mem.indexOfAny(u8, cfg.admin_credentials_path, "\r\n\x00") != null) return error.InvalidConfigValue;
    }
    if (cfg.access_log_enabled) {
        if (cfg.access_log_path.len == 0) return error.InvalidConfigValue;
        if (std.mem.indexOfAny(u8, cfg.access_log_path, "\r\n\x00") != null) return error.InvalidConfigValue;
    }
    try validateCompressionPolicy(compressionPolicyFromConfig(cfg));
    try validateResponseCachePolicy(responseCachePolicyFromConfig(cfg));
    try validateUpstreamRuntimePolicy(upstreamRuntimePolicyFromConfig(cfg));
    if (cfg.max_request_bytes < 1024) return error.InvalidConfigValue;
    if (cfg.max_body_bytes == 0) return error.InvalidConfigValue;
    if (cfg.max_static_file_bytes == 0) return error.InvalidConfigValue;
    if (cfg.max_concurrent_connections == 0) return error.InvalidConfigValue;
    if (cfg.worker_stack_size < 16 * 1024) return error.InvalidConfigValue;
    if (cfg.read_header_timeout_ms == 0) return error.InvalidConfigValue;
    if (cfg.read_body_timeout_ms == 0) return error.InvalidConfigValue;
    if (cfg.idle_timeout_ms == 0) return error.InvalidConfigValue;
    if (cfg.write_timeout_ms == 0) return error.InvalidConfigValue;
    if (cfg.upstream_timeout_ms == 0) return error.InvalidConfigValue;
    if (cfg.fastcgi_keepalive_enabled and cfg.fastcgi_keepalive_max_requests == 0) return error.InvalidConfigValue;
    if (cfg.upstream_max_failures > 0 and cfg.upstream_fail_timeout_ms == 0) return error.InvalidConfigValue;
    if (cfg.upstream_health_check_enabled) {
        if (cfg.upstream_health_check_path.len == 0 or cfg.upstream_health_check_path[0] != '/') return error.InvalidConfigValue;
        if (cfg.upstream_health_check_interval_ms == 0) return error.InvalidConfigValue;
        if (cfg.upstream_health_check_timeout_ms == 0) return error.InvalidConfigValue;
    }
    if (cfg.upstream_circuit_breaker_enabled and cfg.upstream_circuit_half_open_max == 0) return error.InvalidConfigValue;
    if (cfg.upstream) |pool| {
        try validateUpstreamPool(pool);
    }

    if (cfg.tls_auto and (cfg.letsencrypt_domains == null or cfg.letsencrypt_domains.?.len == 0)) {
        return error.InvalidConfigValue;
    }
    if (cfg.tls_auto and cfg.letsencrypt_renew) {
        if (cfg.letsencrypt_renew_interval_ms < 60_000) return error.InvalidConfigValue;
    }
    if (cfg.http_redirect_enabled) {
        if (!cfg.tls_enabled) return error.InvalidConfigValue;
        if (cfg.http_redirect_port == 0 or cfg.http_redirect_https_port == 0) return error.InvalidConfigValue;
        if (cfg.http_redirect_port == cfg.port) return error.InvalidConfigValue;
        if (!isRedirectStatusCode(cfg.http_redirect_status)) return error.InvalidConfigValue;
    }
    if (cfg.cloudflare_auto_deploy) {
        if (cfg.cloudflare_token == null or cfg.cloudflare_token.?.len == 0) return error.InvalidConfigValue;
        if ((cfg.cloudflare_zone_id == null or cfg.cloudflare_zone_id.?.len == 0) and (cfg.cloudflare_zone_name == null or cfg.cloudflare_zone_name.?.len == 0)) return error.InvalidConfigValue;
        if (cfg.cloudflare_record_name == null or cfg.cloudflare_record_name.?.len == 0) return error.InvalidConfigValue;
        if (cfg.cloudflare_record_content == null or cfg.cloudflare_record_content.?.len == 0) return error.InvalidConfigValue;
    }

    for (cfg.routes.items) |*route| {
        try validateRouteConfig(route, cfg.upstream);
        try validateCompressionPolicy(compressionPolicyFor(cfg, null, route));
        try validateResponseCachePolicy(responseCachePolicyFor(cfg, null, route));
        try validateUpstreamRuntimePolicy(upstreamRuntimePolicyFor(cfg, null, route));
    }

    for (cfg.domains.items) |*domain| {
        if (!isDomainConfigNameValid(domain.name)) return error.InvalidConfigValue;
        if (domain.server_names.items.len == 0) return error.InvalidConfigValue;
        for (domain.server_names.items) |name| {
            if (std.mem.trim(u8, name, " \t\r\n").len == 0) return error.InvalidConfigValue;
        }
        if (domain.static_dir) |static_dir| {
            if (static_dir.len == 0) return error.InvalidConfigValue;
        }
        if (domain.index_file) |index_file| {
            if (index_file.len == 0) return error.InvalidConfigValue;
        }
        if (domain.php_root) |php_root| {
            if (php_root.len == 0) return error.InvalidConfigValue;
        }
        if (domain.php_binary) |php_binary| {
            if (php_binary.len == 0) return error.InvalidConfigValue;
        }
        if (domain.php_fastcgi) |endpoint| {
            if (!disablesOptionalUrl(endpoint)) try validateFastcgiEndpoint(endpoint);
        }
        if (domain.php_index) |php_index| {
            if (!isSafeRelativeScriptPath(php_index)) return error.InvalidConfigValue;
        }
        if ((domain.tls_cert == null) != (domain.tls_key == null)) return error.InvalidConfigValue;
        if (domain.upstream) |pool| {
            try validateUpstreamPool(pool);
        }
        if (domain.upstream_timeout_ms) |timeout_ms| {
            if (timeout_ms == 0) return error.InvalidConfigValue;
        }
        if (domain.max_static_file_bytes) |limit| {
            if (limit == 0) return error.InvalidConfigValue;
        }
        try validateDomainCompressionOverrides(domain);
        try validateCompressionPolicy(compressionPolicyFor(cfg, domain, null));
        try validateResponseCachePolicy(responseCachePolicyFor(cfg, domain, null));
        try validateUpstreamRuntimePolicy(upstreamRuntimePolicyFor(cfg, domain, null));

        const fallback_upstream = if (domain.upstream) |upstream| upstream else cfg.upstream;
        for (domain.routes.items) |*route| {
            try validateRouteConfig(route, fallback_upstream);
            try validateCompressionPolicy(compressionPolicyFor(cfg, domain, route));
            try validateResponseCachePolicy(responseCachePolicyFor(cfg, domain, route));
            try validateUpstreamRuntimePolicy(upstreamRuntimePolicyFor(cfg, domain, route));
        }
    }
}

fn validateAdminUiPath(path: []const u8) !void {
    if (path.len == 0 or path[0] != '/') return error.InvalidConfigValue;
    if (path.len > 128) return error.InvalidConfigValue;
    if (std.mem.indexOfAny(u8, path, " \t\r\n\x00?#") != null) return error.InvalidConfigValue;
    if (std.mem.endsWith(u8, path, "/")) return error.InvalidConfigValue;
}

fn isRedirectStatusCode(status_code: u16) bool {
    return status_code == 301 or status_code == 302 or status_code == 303 or status_code == 307 or status_code == 308;
}
