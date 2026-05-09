const std = @import("std");
const tls_pem = @import("../tls_pem.zig");

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
pub const DEFAULT_RESPONSE_CACHE_MAX_BYTES = 16 * 1024 * 1024;
pub const DEFAULT_RESPONSE_CACHE_MAX_ENTRY_BYTES = 256 * 1024;
pub const DEFAULT_RESPONSE_CACHE_TTL_MS = 60 * 1000;
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
    sticky_cookie,
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
    upstream_health_check_path,
};

pub const RouteBoolProperty = enum {
    php_info_page,
    php_front_controller,
    strip_prefix,
    upstream_health_check_enabled,
    upstream_circuit_breaker_enabled,
};

pub const RouteU32Property = enum {
    upstream_timeout_ms,
    upstream_fail_timeout_ms,
    upstream_health_check_interval_ms,
    upstream_health_check_timeout_ms,
    upstream_slow_start_ms,
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

pub const SecurityHeaderPreset = enum {
    off,
    basic,
    strict,
};

pub const ResponseCacheBoolProperty = enum {
    enabled,
};

pub const ResponseCacheSizeProperty = enum {
    max_bytes,
    max_entry_bytes,
};

pub const ResponseCacheU32Property = enum {
    ttl_ms,
};

pub const UpstreamUsizeProperty = enum {
    retries,
    max_failures,
    circuit_half_open_max,
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
    upstream_health_check_path,
};

pub const DomainBoolProperty = enum {
    serve_static_root,
    php_info_page,
    php_front_controller,
    upstream_health_check_enabled,
    upstream_circuit_breaker_enabled,
};

pub const DomainU32Property = enum {
    upstream_timeout_ms,
    upstream_fail_timeout_ms,
    upstream_health_check_interval_ms,
    upstream_health_check_timeout_ms,
    upstream_slow_start_ms,
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
    response_cache_enabled: ?bool,
    response_cache_max_bytes: ?usize,
    response_cache_max_entry_bytes: ?usize,
    response_cache_ttl_ms: ?u32,
    security_headers: ?SecurityHeaderPreset,
    max_static_file_bytes: ?usize,
    upstream_retries: ?usize,
    upstream_max_failures: ?usize,
    upstream_fail_timeout_ms: ?u32,
    upstream_health_check_enabled: ?bool,
    upstream_health_check_path: ?[]const u8,
    upstream_health_check_interval_ms: ?u32,
    upstream_health_check_timeout_ms: ?u32,
    upstream_circuit_breaker_enabled: ?bool,
    upstream_circuit_half_open_max: ?usize,
    upstream_slow_start_ms: ?u32,
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
    response_cache_enabled: ?bool,
    response_cache_max_bytes: ?usize,
    response_cache_max_entry_bytes: ?usize,
    response_cache_ttl_ms: ?u32,
    security_headers: ?SecurityHeaderPreset,
    max_static_file_bytes: ?usize,
    upstream_retries: ?usize,
    upstream_max_failures: ?usize,
    upstream_fail_timeout_ms: ?u32,
    upstream_health_check_enabled: ?bool,
    upstream_health_check_path: ?[]const u8,
    upstream_health_check_interval_ms: ?u32,
    upstream_health_check_timeout_ms: ?u32,
    upstream_circuit_breaker_enabled: ?bool,
    upstream_circuit_half_open_max: ?usize,
    upstream_slow_start_ms: ?u32,
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
    response_cache_enabled: bool,
    response_cache_max_bytes: usize,
    response_cache_max_entry_bytes: usize,
    response_cache_ttl_ms: u32,
    security_headers: SecurityHeaderPreset,
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
        .response_cache_enabled = false,
        .response_cache_max_bytes = DEFAULT_RESPONSE_CACHE_MAX_BYTES,
        .response_cache_max_entry_bytes = DEFAULT_RESPONSE_CACHE_MAX_ENTRY_BYTES,
        .response_cache_ttl_ms = DEFAULT_RESPONSE_CACHE_TTL_MS,
        .security_headers = .off,
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
