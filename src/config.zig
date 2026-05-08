const std = @import("std");
const http_headers = @import("http_headers.zig");
const tls_pem = @import("tls_pem.zig");

const trimValue = http_headers.trimValue;

pub const DEFAULT_MAX_REQUEST_BYTES = 16 * 1024;
pub const DEFAULT_MAX_BODY_BYTES = 1024 * 1024;
pub const DEFAULT_MAX_STATIC_FILE_BYTES = 10 * 1024 * 1024;
pub const DEFAULT_MAX_REQUESTS_PER_CONNECTION = 256;
pub const DEFAULT_MAX_CONCURRENT_CONNECTIONS = 1_000_000;
pub const DEFAULT_WORKER_STACK_BYTES = 64 * 1024;
pub const DEFAULT_MAX_PHP_OUTPUT_BYTES = 2 * 1024 * 1024;
pub const DEFAULT_PHP_INDEX = "index.php";
pub const DEFAULT_READ_HEADER_TIMEOUT_MS = 10_000;
pub const DEFAULT_READ_BODY_TIMEOUT_MS = 30_000;
pub const DEFAULT_IDLE_TIMEOUT_MS = 60_000;
pub const DEFAULT_WRITE_TIMEOUT_MS = 30_000;
pub const DEFAULT_UPSTREAM_TIMEOUT_MS = 30_000;
pub const DEFAULT_UPSTREAM_RETRIES = 1;
pub const DEFAULT_UPSTREAM_MAX_FAILURES = 2;
pub const DEFAULT_UPSTREAM_FAIL_TIMEOUT_MS = 10_000;
pub const DEFAULT_UPSTREAM_KEEPALIVE_MAX_IDLE = 16;
pub const DEFAULT_UPSTREAM_KEEPALIVE_IDLE_TIMEOUT_MS = 30_000;
pub const DEFAULT_UPSTREAM_KEEPALIVE_MAX_REQUESTS = 100;
pub const DEFAULT_FASTCGI_KEEPALIVE_MAX_IDLE = 8;
pub const DEFAULT_FASTCGI_KEEPALIVE_IDLE_TIMEOUT_MS = 30_000;
pub const DEFAULT_FASTCGI_KEEPALIVE_MAX_REQUESTS = 100;
pub const DEFAULT_UPSTREAM_HEALTH_CHECK_INTERVAL_MS = 5_000;
pub const DEFAULT_UPSTREAM_HEALTH_CHECK_TIMEOUT_MS = 1_000;
pub const DEFAULT_UPSTREAM_HEALTH_CHECK_PATH = "/health";
pub const DEFAULT_UPSTREAM_CIRCUIT_HALF_OPEN_MAX = 1;
pub const DEFAULT_UPSTREAM_SLOW_START_MS = 10_000;
pub const DEFAULT_GRACEFUL_SHUTDOWN_TIMEOUT_MS = 10_000;
pub const DEFAULT_LETSENCRYPT_RENEW_INTERVAL_MS = 12 * 60 * 60 * 1000;
pub const DEFAULT_COMPRESSION_MIN_BYTES = 512;
pub const DEFAULT_COMPRESSION_MAX_BYTES = 1024 * 1024;
pub const DEFAULT_COMPRESSION_WORKER_STACK_BYTES = 512 * 1024;
pub const MAX_CONFIG_BYTES = 64 * 1024;
pub const DEFAULT_CONFIG_PATH = "server.conf";
pub const DEFAULT_ADMIN_SOCKET_PATH = "/tmp/layerline-admin.sock";
pub const DEFAULT_ADMIN_UI_PATH = "/_layerline/admin";
pub const DEFAULT_ADMIN_CREDENTIALS_PATH = ".layerline-admin";
pub const DEFAULT_ACCESS_LOG_PATH = "stderr";

pub const UpstreamIdleConnection = struct {
    stream: std.Io.net.Stream,
    expires_at_ms: i64,
    requests_served: usize,
};

pub const UpstreamKeepAlivePool = struct {
    mutex: std.Io.Mutex,
    idle: std.ArrayList(UpstreamIdleConnection),

    pub fn init() UpstreamKeepAlivePool {
        return .{
            .mutex = .init,
            .idle = .empty,
        };
    }
};

pub const FastcgiIdleConnection = struct {
    stream: std.Io.net.Stream,
    endpoint_name: []const u8,
    expires_at_ms: i64,
    requests_served: usize,
};

pub const FastcgiKeepAlivePool = struct {
    mutex: std.Io.Mutex,
    idle: std.ArrayList(FastcgiIdleConnection),

    pub fn init() FastcgiKeepAlivePool {
        return .{
            .mutex = .init,
            .idle = .empty,
        };
    }
};

// Parsed form of a configured upstream endpoint.
pub const UpstreamConfig = struct {
    host: []const u8,
    port: u16,
    base_path: []const u8,
    https: bool,
    weight: usize,
    keepalive_pool: UpstreamKeepAlivePool,
    active_requests: std.atomic.Value(usize),
    half_open_requests: std.atomic.Value(usize),
    passive_failures: std.atomic.Value(usize),
    ejected_until_ms: std.atomic.Value(i64),
    recovered_at_ms: std.atomic.Value(i64),
};

pub const PhpFastcgiTcpEndpoint = struct {
    host: []const u8,
    port: u16,
};

pub const PhpFastcgiEndpoint = union(enum) {
    tcp: PhpFastcgiTcpEndpoint,
    unix: []const u8,
};

pub const UpstreamPoolPolicy = enum {
    round_robin,
    random,
    least_connections,
    weighted,
    consistent_hash,
};

pub const UpstreamPoolConfig = struct {
    targets: std.ArrayList(UpstreamConfig),
    policy: UpstreamPoolPolicy,
};

pub const ResponseHeaderRule = struct {
    name: []const u8,
    value: []const u8,
};

pub const CompressionPolicy = struct {
    enabled: bool,
    gzip_enabled: bool,
    min_bytes: usize,
    max_bytes: usize,

    pub const disabled = CompressionPolicy{
        .enabled = false,
        .gzip_enabled = true,
        .min_bytes = DEFAULT_COMPRESSION_MIN_BYTES,
        .max_bytes = DEFAULT_COMPRESSION_MAX_BYTES,
    };
};

pub const RedirectRule = struct {
    from: []const u8,
    to: []const u8,
    status_code: u16,
    prefix_match: bool,
};

pub const RouteMatchKind = enum {
    exact,
    prefix,
};

pub const RouteHandlerKind = enum {
    static,
    php,
    proxy,
};

pub const RouteStringProperty = enum {
    static_dir,
    index_file,
    php_root,
    php_binary,
    php_index,
    php_fastcgi,
};

pub const RouteBoolProperty = enum {
    php_info_page,
    php_front_controller,
    strip_prefix,
};

pub const RouteU32Property = enum {
    upstream_timeout_ms,
};

pub const CompressionBoolProperty = enum {
    enabled,
    gzip_enabled,
};

pub const CompressionSizeProperty = enum {
    min_bytes,
    max_bytes,
};

pub const CacheStaleProperty = enum {
    stale_while_revalidate,
    stale_if_error,
};

pub const DomainStringProperty = enum {
    static_dir,
    index_file,
    php_root,
    php_binary,
    php_index,
    php_fastcgi,
    tls_cert,
    tls_key,
};

pub const DomainBoolProperty = enum {
    serve_static_root,
    php_info_page,
    php_front_controller,
};

pub const DomainU32Property = enum {
    upstream_timeout_ms,
};

pub const RouteConfig = struct {
    name: []const u8,
    pattern: []const u8,
    match_kind: RouteMatchKind,
    handler: RouteHandlerKind,
    strip_prefix: bool,
    static_dir: ?[]const u8,
    index_file: ?[]const u8,
    php_root: ?[]const u8,
    php_binary: ?[]const u8,
    php_index: ?[]const u8,
    php_fastcgi: ?[]const u8,
    php_info_page: ?bool,
    php_front_controller: ?bool,
    upstream: ?UpstreamPoolConfig,
    upstream_policy: ?UpstreamPoolPolicy,
    upstream_timeout_ms: ?u32,
    compression_enabled: ?bool,
    gzip_enabled: ?bool,
    compression_min_bytes: ?usize,
    compression_max_bytes: ?usize,
    response_headers: std.ArrayList(ResponseHeaderRule),
};

pub const DomainConfig = struct {
    name: []const u8,
    server_names: std.ArrayList([]const u8),
    static_dir: ?[]const u8,
    serve_static_root: ?bool,
    index_file: ?[]const u8,
    php_root: ?[]const u8,
    php_binary: ?[]const u8,
    php_index: ?[]const u8,
    php_fastcgi: ?[]const u8,
    php_info_page: ?bool,
    php_front_controller: ?bool,
    tls_cert: ?[]const u8,
    tls_key: ?[]const u8,
    tls_material: ?tls_pem.ConfiguredTlsMaterial,
    upstream: ?UpstreamPoolConfig,
    upstream_policy: ?UpstreamPoolPolicy,
    upstream_timeout_ms: ?u32,
    compression_enabled: ?bool,
    gzip_enabled: ?bool,
    compression_min_bytes: ?usize,
    compression_max_bytes: ?usize,
    response_headers: std.ArrayList(ResponseHeaderRule),
    redirects: std.ArrayList(RedirectRule),
    routes: std.ArrayList(RouteConfig),
};

// All server behavior is described in this single config object.
pub const ServerConfig = struct {
    config_path: []const u8,
    host: []const u8,
    port: u16,
    static_dir: []const u8,
    serve_static_root: bool,
    index_file: []const u8,
    php_root: []const u8,
    php_binary: []const u8,
    php_index: []const u8,
    php_fastcgi: ?[]const u8,
    php_info_page: bool,
    php_front_controller: bool,
    upstream: ?UpstreamPoolConfig,
    upstream_policy: UpstreamPoolPolicy,
    tls_enabled: bool,
    tls_cert: ?[]const u8,
    tls_key: ?[]const u8,
    tls_material: ?tls_pem.ConfiguredTlsMaterial,
    tls_auto: bool,
    letsencrypt_email: ?[]const u8,
    letsencrypt_domains: ?[]const u8,
    letsencrypt_webroot: []const u8,
    letsencrypt_certbot: []const u8,
    letsencrypt_staging: bool,
    letsencrypt_renew: bool,
    letsencrypt_renew_interval_ms: u32,
    http_redirect_enabled: bool,
    http_redirect_port: u16,
    http_redirect_https_port: u16,
    http_redirect_status: u16,
    h2_upstream: ?UpstreamConfig,
    http3_enabled: bool,
    http3_port: u16,
    admin_enabled: bool,
    admin_socket_path: ?[]const u8,
    admin_ui_enabled: bool,
    admin_ui_path: []const u8,
    admin_credentials_path: []const u8,
    access_log_enabled: bool,
    access_log_path: []const u8,
    compression_enabled: bool,
    gzip_enabled: bool,
    compression_min_bytes: usize,
    compression_max_bytes: usize,
    response_headers: std.ArrayList(ResponseHeaderRule),
    redirects: std.ArrayList(RedirectRule),
    routes: std.ArrayList(RouteConfig),
    domains: std.ArrayList(DomainConfig),
    domain_config_dir: ?[]const u8,
    max_request_bytes: usize,
    max_body_bytes: usize,
    max_static_file_bytes: usize,
    max_requests_per_connection: usize,
    max_concurrent_connections: usize,
    worker_stack_size: usize,
    read_header_timeout_ms: u32,
    read_body_timeout_ms: u32,
    idle_timeout_ms: u32,
    write_timeout_ms: u32,
    upstream_timeout_ms: u32,
    upstream_retries: usize,
    upstream_max_failures: usize,
    upstream_fail_timeout_ms: u32,
    upstream_keepalive_enabled: bool,
    upstream_keepalive_max_idle: usize,
    upstream_keepalive_idle_timeout_ms: u32,
    upstream_keepalive_max_requests: usize,
    fastcgi_keepalive_enabled: bool,
    fastcgi_keepalive_max_idle: usize,
    fastcgi_keepalive_idle_timeout_ms: u32,
    fastcgi_keepalive_max_requests: usize,
    upstream_health_check_enabled: bool,
    upstream_health_check_path: []const u8,
    upstream_health_check_interval_ms: u32,
    upstream_health_check_timeout_ms: u32,
    upstream_circuit_breaker_enabled: bool,
    upstream_circuit_half_open_max: usize,
    upstream_slow_start_ms: u32,
    graceful_shutdown_timeout_ms: u32,
    cloudflare_auto_deploy: bool,
    max_php_output_bytes: usize,
    cloudflare_api_base: []const u8,
    cloudflare_token: ?[]const u8,
    cloudflare_zone_id: ?[]const u8,
    cloudflare_zone_name: ?[]const u8,
    cloudflare_record_name: ?[]const u8,
    cloudflare_record_type: []const u8,
    cloudflare_record_content: ?[]const u8,
    cloudflare_record_ttl: u32,
    cloudflare_record_proxied: bool,
    cloudflare_record_comment: ?[]const u8,
};

pub fn defaultServerConfig() ServerConfig {
    return .{
        .config_path = DEFAULT_CONFIG_PATH,
        .host = "127.0.0.1",
        .port = 8080,
        .static_dir = "public",
        .serve_static_root = false,
        .index_file = "index.html",
        .php_root = "public",
        .php_binary = "php-cgi",
        .php_index = DEFAULT_PHP_INDEX,
        .php_fastcgi = null,
        .php_info_page = false,
        .php_front_controller = false,
        .tls_enabled = false,
        .tls_auto = false,
        .letsencrypt_email = null,
        .letsencrypt_domains = null,
        .letsencrypt_webroot = "public",
        .letsencrypt_certbot = "certbot",
        .letsencrypt_staging = false,
        .letsencrypt_renew = true,
        .letsencrypt_renew_interval_ms = DEFAULT_LETSENCRYPT_RENEW_INTERVAL_MS,
        .http_redirect_enabled = false,
        .http_redirect_port = 80,
        .http_redirect_https_port = 443,
        .http_redirect_status = 308,
        .cloudflare_auto_deploy = false,
        .cloudflare_api_base = "https://api.cloudflare.com/client/v4",
        .cloudflare_token = null,
        .cloudflare_zone_id = null,
        .cloudflare_zone_name = null,
        .cloudflare_record_name = null,
        .cloudflare_record_type = "A",
        .cloudflare_record_content = null,
        .cloudflare_record_ttl = 300,
        .cloudflare_record_proxied = false,
        .cloudflare_record_comment = null,
        .upstream = null,
        .upstream_policy = .round_robin,
        .tls_cert = null,
        .tls_key = null,
        .tls_material = null,
        .h2_upstream = null,
        .http3_enabled = false,
        .http3_port = 8443,
        .admin_enabled = false,
        .admin_socket_path = DEFAULT_ADMIN_SOCKET_PATH,
        .admin_ui_enabled = false,
        .admin_ui_path = DEFAULT_ADMIN_UI_PATH,
        .admin_credentials_path = DEFAULT_ADMIN_CREDENTIALS_PATH,
        .access_log_enabled = false,
        .access_log_path = DEFAULT_ACCESS_LOG_PATH,
        .compression_enabled = false,
        .gzip_enabled = true,
        .compression_min_bytes = DEFAULT_COMPRESSION_MIN_BYTES,
        .compression_max_bytes = DEFAULT_COMPRESSION_MAX_BYTES,
        .response_headers = .empty,
        .redirects = .empty,
        .routes = .empty,
        .domains = .empty,
        .domain_config_dir = null,
        .max_request_bytes = DEFAULT_MAX_REQUEST_BYTES,
        .max_body_bytes = DEFAULT_MAX_BODY_BYTES,
        .max_static_file_bytes = DEFAULT_MAX_STATIC_FILE_BYTES,
        .max_requests_per_connection = DEFAULT_MAX_REQUESTS_PER_CONNECTION,
        .max_concurrent_connections = DEFAULT_MAX_CONCURRENT_CONNECTIONS,
        .worker_stack_size = DEFAULT_WORKER_STACK_BYTES,
        .read_header_timeout_ms = DEFAULT_READ_HEADER_TIMEOUT_MS,
        .read_body_timeout_ms = DEFAULT_READ_BODY_TIMEOUT_MS,
        .idle_timeout_ms = DEFAULT_IDLE_TIMEOUT_MS,
        .write_timeout_ms = DEFAULT_WRITE_TIMEOUT_MS,
        .upstream_timeout_ms = DEFAULT_UPSTREAM_TIMEOUT_MS,
        .upstream_retries = DEFAULT_UPSTREAM_RETRIES,
        .upstream_max_failures = DEFAULT_UPSTREAM_MAX_FAILURES,
        .upstream_fail_timeout_ms = DEFAULT_UPSTREAM_FAIL_TIMEOUT_MS,
        .upstream_keepalive_enabled = true,
        .upstream_keepalive_max_idle = DEFAULT_UPSTREAM_KEEPALIVE_MAX_IDLE,
        .upstream_keepalive_idle_timeout_ms = DEFAULT_UPSTREAM_KEEPALIVE_IDLE_TIMEOUT_MS,
        .upstream_keepalive_max_requests = DEFAULT_UPSTREAM_KEEPALIVE_MAX_REQUESTS,
        .fastcgi_keepalive_enabled = true,
        .fastcgi_keepalive_max_idle = DEFAULT_FASTCGI_KEEPALIVE_MAX_IDLE,
        .fastcgi_keepalive_idle_timeout_ms = DEFAULT_FASTCGI_KEEPALIVE_IDLE_TIMEOUT_MS,
        .fastcgi_keepalive_max_requests = DEFAULT_FASTCGI_KEEPALIVE_MAX_REQUESTS,
        .upstream_health_check_enabled = false,
        .upstream_health_check_path = DEFAULT_UPSTREAM_HEALTH_CHECK_PATH,
        .upstream_health_check_interval_ms = DEFAULT_UPSTREAM_HEALTH_CHECK_INTERVAL_MS,
        .upstream_health_check_timeout_ms = DEFAULT_UPSTREAM_HEALTH_CHECK_TIMEOUT_MS,
        .upstream_circuit_breaker_enabled = true,
        .upstream_circuit_half_open_max = DEFAULT_UPSTREAM_CIRCUIT_HALF_OPEN_MAX,
        .upstream_slow_start_ms = DEFAULT_UPSTREAM_SLOW_START_MS,
        .graceful_shutdown_timeout_ms = DEFAULT_GRACEFUL_SHUTDOWN_TIMEOUT_MS,
        .max_php_output_bytes = DEFAULT_MAX_PHP_OUTPUT_BYTES,
    };
}

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

pub fn buildResponseHeaderContext(allocator: std.mem.Allocator, cfg: *const ServerConfig, domain: ?*const DomainConfig, route: ?*const RouteConfig) !ResponseHeaderContext {
    const domain_headers = if (domain) |d| d.response_headers.items else &.{};
    const route_headers = if (route) |r| r.response_headers.items else &.{};
    const count = cfg.response_headers.items.len + domain_headers.len + route_headers.len;
    if (count == 0) return .{ .items = &.{} };

    const owned = try allocator.alloc(ResponseHeaderRule, count);
    var cursor: usize = 0;
    appendResponseHeaderSlice(owned, &cursor, cfg.response_headers.items);
    appendResponseHeaderSlice(owned, &cursor, domain_headers);
    appendResponseHeaderSlice(owned, &cursor, route_headers);
    return .{ .items = owned, .owned = owned };
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

pub fn responseHeaderRulesContain(headers: []const ResponseHeaderRule, name: []const u8) bool {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return true;
    }
    return false;
}

// Parse scheme/host/port/path strings from a proxy URL into normalized fields.
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

fn isCompressionEnabledKey(key: []const u8) bool {
    return std.mem.eql(u8, key, "compression") or
        std.mem.eql(u8, key, "compress") or
        std.mem.eql(u8, key, "encode");
}

fn isGzipEnabledKey(key: []const u8) bool {
    return std.mem.eql(u8, key, "gzip") or
        std.mem.eql(u8, key, "gzip_enabled");
}

fn isCompressionMinBytesKey(key: []const u8) bool {
    return std.mem.eql(u8, key, "compression_min_bytes") or
        std.mem.eql(u8, key, "gzip_min_bytes");
}

fn isCompressionMaxBytesKey(key: []const u8) bool {
    return std.mem.eql(u8, key, "compression_max_bytes") or
        std.mem.eql(u8, key, "gzip_max_bytes");
}

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
    if (parsed == 0) return error.InvalidConfigValue;
    switch (field) {
        .upstream_timeout_ms => route.upstream_timeout_ms = parsed,
    }
}

pub fn setRouteBoolProperty(routes: *std.ArrayList(RouteConfig), route_name: []const u8, value: []const u8, field: RouteBoolProperty) !void {
    const route = findRouteConfigMutable(routes, route_name) orelse return error.UnknownConfigRoute;
    const parsed = try parseConfigBool(value);
    switch (field) {
        .php_info_page => route.php_info_page = parsed,
        .php_front_controller => route.php_front_controller = parsed,
        .strip_prefix => route.strip_prefix = parsed,
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

pub fn isDomainConfigNameValid(name: []const u8) bool {
    return isRouteNameValid(name);
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
    }
}

pub fn setDomainBoolProperty(cfg: *ServerConfig, domain_name: []const u8, value: []const u8, field: DomainBoolProperty) !void {
    const domain = findDomainConfigMutable(cfg, domain_name) orelse return error.UnknownConfigDomain;
    const parsed = try parseConfigBool(value);
    switch (field) {
        .serve_static_root => domain.serve_static_root = parsed,
        .php_info_page => domain.php_info_page = parsed,
        .php_front_controller => domain.php_front_controller = parsed,
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
    if (parsed == 0) return error.InvalidConfigValue;
    switch (field) {
        .upstream_timeout_ms => domain.upstream_timeout_ms = parsed,
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

// Map one config file line to fields. Config files are strict so typos do not
// silently change server behavior.
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
    } else if (findRoutePropertyName(k, "server_redirect.")) |name| {
        const domain = findDomainConfigMutable(cfg, name) orelse return error.UnknownConfigDomain;
        if (v.len > 0) try domain.redirects.append(allocator, try parseRedirectRule(allocator, v));
    } else if (findRoutePropertyName(k, "server_route.")) |name| {
        try setDomainRouteLine(cfg, allocator, name, v);
    } else if (findRoutePropertyName(k, "server_route_dir.")) |name| {
        try setDomainRouteStringProperty(cfg, allocator, name, v, .static_dir);
    } else if (findRoutePropertyName(k, "server_route_static_dir.")) |name| {
        try setDomainRouteStringProperty(cfg, allocator, name, v, .static_dir);
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

// Load and apply file-based config, skipping comments and empty lines.
pub fn loadConfig(io: std.Io, allocator: std.mem.Allocator, cfg: *ServerConfig, path: []const u8) !void {
    const content = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(MAX_CONFIG_BYTES));
    defer allocator.free(content);

    var lines = std.mem.splitSequence(u8, content, "\n");
    var line_number: usize = 0;
    while (lines.next()) |raw_line| {
        line_number += 1;
        var line = trimValue(raw_line);
        if (line.len == 0) continue;

        if (std.mem.indexOfScalar(u8, line, '#')) |comment_start| {
            if (comment_start == 0) continue;
            line = trimValue(line[0..comment_start]);
        }
        if (line.len == 0) continue;

        const eq = std.mem.indexOfScalar(u8, line, '=') orelse {
            std.debug.print("Config error in {s}:{d}: expected key = value\n", .{ path, line_number });
            return error.MalformedConfigLine;
        };
        const key = line[0..eq];
        const value = if (eq + 1 < line.len) line[eq + 1 ..] else "";
        applyConfigLine(cfg, allocator, key, value) catch |err| {
            std.debug.print("Config error in {s}:{d}: {s}: {}\n", .{ path, line_number, trimValue(key), err });
            return err;
        };
    }
}

pub fn isDomainConfigFileName(name: []const u8) bool {
    return name.len > 0 and name[0] != '.' and std.mem.endsWith(u8, name, ".conf");
}

pub fn domainConfigNameFromPath(allocator: std.mem.Allocator, path: []const u8) ![]const u8 {
    const slash = std.mem.lastIndexOfAny(u8, path, "/\\");
    const base = if (slash) |pos| path[pos + 1 ..] else path;
    const stem = if (std.mem.endsWith(u8, base, ".conf")) base[0 .. base.len - ".conf".len] else base;
    if (stem.len == 0) return error.InvalidConfigValue;

    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    for (stem) |c| {
        if (std.ascii.isAlphanumeric(c) or c == '_' or c == '-') {
            try out.append(allocator, c);
        } else {
            try out.append(allocator, '-');
        }
    }
    return try out.toOwnedSlice(allocator);
}

pub fn stringLessThan(_: void, lhs: []const u8, rhs: []const u8) bool {
    return std.mem.order(u8, lhs, rhs) == .lt;
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
    }
}

pub fn setDomainBoolPropertyDirect(domain: *DomainConfig, value: []const u8, field: DomainBoolProperty) !void {
    const parsed = try parseConfigBool(value);
    switch (field) {
        .serve_static_root => domain.serve_static_root = parsed,
        .php_info_page => domain.php_info_page = parsed,
        .php_front_controller => domain.php_front_controller = parsed,
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
    if (parsed == 0) return error.InvalidConfigValue;
    switch (field) {
        .upstream_timeout_ms => domain.upstream_timeout_ms = parsed,
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
    } else if (isCompressionEnabledKey(k)) {
        try setDomainCompressionBoolPropertyDirect(domain, v, .enabled);
    } else if (isGzipEnabledKey(k)) {
        try setDomainCompressionBoolPropertyDirect(domain, v, .gzip_enabled);
    } else if (isCompressionMinBytesKey(k)) {
        try setDomainCompressionSizePropertyDirect(domain, v, .min_bytes);
    } else if (isCompressionMaxBytesKey(k)) {
        try setDomainCompressionSizePropertyDirect(domain, v, .max_bytes);
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

pub fn loadDomainConfigFile(io: std.Io, allocator: std.mem.Allocator, cfg: *ServerConfig, path: []const u8) !void {
    const default_name = try domainConfigNameFromPath(allocator, path);
    var domain = try initDomainConfig(allocator, default_name);

    const content = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(MAX_CONFIG_BYTES));
    defer allocator.free(content);

    var lines = std.mem.splitSequence(u8, content, "\n");
    var line_number: usize = 0;
    while (lines.next()) |raw_line| {
        line_number += 1;
        var line = trimValue(raw_line);
        if (line.len == 0) continue;

        if (std.mem.indexOfScalar(u8, line, '#')) |comment_start| {
            if (comment_start == 0) continue;
            line = trimValue(line[0..comment_start]);
        }
        if (line.len == 0) continue;

        const eq = std.mem.indexOfScalar(u8, line, '=') orelse {
            std.debug.print("Domain config error in {s}:{d}: expected key = value\n", .{ path, line_number });
            return error.MalformedConfigLine;
        };
        const key = line[0..eq];
        const value = if (eq + 1 < line.len) line[eq + 1 ..] else "";
        applyDomainConfigLine(&domain, allocator, key, value) catch |err| {
            std.debug.print("Domain config error in {s}:{d}: {s}: {}\n", .{ path, line_number, trimValue(key), err });
            return err;
        };
    }

    if (findDomainConfigMutable(cfg, domain.name) != null) return error.DuplicateConfigDomain;
    try cfg.domains.append(allocator, domain);
}

pub fn loadDomainConfigDir(io: std.Io, allocator: std.mem.Allocator, cfg: *ServerConfig, dir_path: []const u8) !void {
    var dir = try std.Io.Dir.cwd().openDir(io, dir_path, .{ .iterate = true });
    defer dir.close(io);

    var paths = std.ArrayList([]const u8).empty;
    defer paths.deinit(allocator);

    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        if (!isDomainConfigFileName(entry.name)) continue;
        const full_path = try std.fs.path.join(allocator, &.{ dir_path, entry.name });
        try paths.append(allocator, full_path);
    }

    std.sort.insertion([]const u8, paths.items, {}, stringLessThan);
    for (paths.items) |path| {
        try loadDomainConfigFile(io, allocator, cfg, path);
    }
}

pub fn loadConfiguredDomainConfigs(io: std.Io, allocator: std.mem.Allocator, cfg: *ServerConfig) !void {
    if (cfg.domain_config_dir) |dir_path| {
        try loadDomainConfigDir(io, allocator, cfg, dir_path);
    }
}

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
        try validateDomainCompressionOverrides(domain);
        try validateCompressionPolicy(compressionPolicyFor(cfg, domain, null));

        const fallback_upstream = if (domain.upstream) |upstream| upstream else cfg.upstream;
        for (domain.routes.items) |*route| {
            try validateRouteConfig(route, fallback_upstream);
            try validateCompressionPolicy(compressionPolicyFor(cfg, domain, route));
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
