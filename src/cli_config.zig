const std = @import("std");

const config_loader = @import("config_loader.zig");
const config_mod = @import("config.zig");

const ServerConfig = config_mod.ServerConfig;
const DEFAULT_CONFIG_PATH = config_mod.DEFAULT_CONFIG_PATH;
const disablesOptionalUrl = config_mod.disablesOptionalUrl;
const loadConfig = config_loader.loadConfig;
const loadConfiguredDomainConfigs = config_loader.loadConfiguredDomainConfigs;
const normalizeConfig = config_mod.normalizeConfig;
const parseBool = config_mod.parseBool;
const parseSecurityHeaderPreset = config_mod.parseSecurityHeaderPreset;
const parseUpstream = config_mod.parseUpstream;
const parseUpstreamPool = config_mod.parseUpstreamPool;
const parseUpstreamPoolPolicy = config_mod.parseUpstreamPoolPolicy;
const validateConfig = config_mod.validateConfig;
const validateFastcgiEndpoint = config_mod.validateFastcgiEndpoint;

pub const Callbacks = struct {
    usage: *const fn () void,
    dump_routes: *const fn (*const ServerConfig) void,
    dump_certs: *const fn (*const ServerConfig) void,
    doctor: *const fn (std.Io, *const ServerConfig) usize,
    admin_command: *const fn (std.Io, std.mem.Allocator, *const ServerConfig, []const u8) anyerror!void,
};

pub fn prepare(init: std.process.Init, allocator: std.mem.Allocator, cfg: *ServerConfig, callbacks: Callbacks) !bool {
    var args_for_config = std.process.Args.iterate(init.minimal.args);
    _ = args_for_config.next();
    var config_explicitly_set = false;
    while (args_for_config.next()) |arg| {
        if (std.mem.eql(u8, arg, "--config")) {
            config_explicitly_set = true;
            if (args_for_config.next()) |path| {
                loadConfig(init.io, allocator, cfg, path) catch |err| {
                    std.debug.print("Failed to load config file: {s}\n", .{path});
                    return err;
                };
                cfg.config_path = path;
            } else {
                callbacks.usage();
                return false;
            }
        }
    }

    if (!config_explicitly_set) {
        if (std.Io.Dir.cwd().statFile(init.io, DEFAULT_CONFIG_PATH, .{})) |_| {
            loadConfig(init.io, allocator, cfg, DEFAULT_CONFIG_PATH) catch |err| {
                std.debug.print("Failed to load default config file: {s}\n", .{DEFAULT_CONFIG_PATH});
                return err;
            };
        } else |_| {}
    }

    var args = std.process.Args.iterate(init.minimal.args);
    _ = args.next();
    var validate_only = false;
    var dump_routes = false;
    var dump_certs = false;
    var doctor = false;
    var admin_command: ?[]const u8 = null;
    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            callbacks.usage();
            return false;
        } else if (std.mem.eql(u8, arg, "--config")) {
            _ = args.next();
        } else if (std.mem.eql(u8, arg, "--domain-config-dir") or std.mem.eql(u8, arg, "--domains-dir") or std.mem.eql(u8, arg, "--sites-enabled")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.domain_config_dir = if (value.len == 0) null else value;
        } else if (std.mem.eql(u8, arg, "--validate-config") or std.mem.eql(u8, arg, "--check-config")) {
            validate_only = true;
        } else if (std.mem.eql(u8, arg, "--dump-routes") or std.mem.eql(u8, arg, "--routes")) {
            dump_routes = true;
        } else if (std.mem.eql(u8, arg, "--dump-certs") or std.mem.eql(u8, arg, "--certs") or std.mem.eql(u8, arg, "--certificates")) {
            dump_certs = true;
        } else if (std.mem.eql(u8, arg, "--doctor")) {
            doctor = true;
        } else if (std.mem.eql(u8, arg, "--admin-command") or std.mem.eql(u8, arg, "--admin-cmd")) {
            admin_command = args.next() orelse {
                callbacks.usage();
                return false;
            };
        } else if (std.mem.eql(u8, arg, "--reload")) {
            admin_command = "reload";
        } else if (std.mem.eql(u8, arg, "--restart")) {
            admin_command = "restart";
        } else if (std.mem.eql(u8, arg, "--runtime-status")) {
            admin_command = "status";
        } else if (std.mem.eql(u8, arg, "--runtime-validate")) {
            admin_command = "validate-runtime";
        } else if (std.mem.eql(u8, arg, "--tls")) {
            if (args.next()) |value| {
                cfg.tls_enabled = parseBool(value) orelse cfg.tls_enabled;
            } else {
                callbacks.usage();
                return false;
            }
        } else if (std.mem.eql(u8, arg, "--tls-auto")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.tls_auto = parseBool(value) orelse cfg.tls_auto;
        } else if (std.mem.eql(u8, arg, "--letsencrypt-email")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            if (value.len == 0) {
                cfg.letsencrypt_email = null;
            } else {
                cfg.letsencrypt_email = value;
            }
        } else if (std.mem.eql(u8, arg, "--letsencrypt-domains")) {
            cfg.letsencrypt_domains = args.next() orelse {
                callbacks.usage();
                return false;
            };
        } else if (std.mem.eql(u8, arg, "--letsencrypt-webroot")) {
            cfg.letsencrypt_webroot = args.next() orelse {
                callbacks.usage();
                return false;
            };
        } else if (std.mem.eql(u8, arg, "--letsencrypt-certbot")) {
            cfg.letsencrypt_certbot = args.next() orelse {
                callbacks.usage();
                return false;
            };
        } else if (std.mem.eql(u8, arg, "--letsencrypt-staging")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.letsencrypt_staging = parseBool(value) orelse cfg.letsencrypt_staging;
        } else if (std.mem.eql(u8, arg, "--letsencrypt-renew") or std.mem.eql(u8, arg, "--tls-renew") or std.mem.eql(u8, arg, "--acme-renew")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.letsencrypt_renew = parseBool(value) orelse cfg.letsencrypt_renew;
        } else if (std.mem.eql(u8, arg, "--letsencrypt-renew-interval-ms") or std.mem.eql(u8, arg, "--tls-renew-interval-ms") or std.mem.eql(u8, arg, "--acme-renew-interval-ms")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.letsencrypt_renew_interval_ms = std.fmt.parseInt(u32, value, 10) catch cfg.letsencrypt_renew_interval_ms;
        } else if (std.mem.eql(u8, arg, "--http-redirect") or std.mem.eql(u8, arg, "--http-to-https")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.http_redirect_enabled = parseBool(value) orelse cfg.http_redirect_enabled;
        } else if (std.mem.eql(u8, arg, "--http-redirect-port") or std.mem.eql(u8, arg, "--http-to-https-port")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.http_redirect_port = std.fmt.parseInt(u16, value, 10) catch cfg.http_redirect_port;
        } else if (std.mem.eql(u8, arg, "--http-redirect-https-port") or std.mem.eql(u8, arg, "--https-port")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.http_redirect_https_port = std.fmt.parseInt(u16, value, 10) catch cfg.http_redirect_https_port;
        } else if (std.mem.eql(u8, arg, "--http-redirect-status") or std.mem.eql(u8, arg, "--http-to-https-status")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.http_redirect_status = std.fmt.parseInt(u16, value, 10) catch cfg.http_redirect_status;
        } else if (std.mem.eql(u8, arg, "--tls-cert")) {
            cfg.tls_cert = args.next() orelse {
                callbacks.usage();
                return false;
            };
        } else if (std.mem.eql(u8, arg, "--tls-key")) {
            cfg.tls_key = args.next() orelse {
                callbacks.usage();
                return false;
            };
        } else if (std.mem.eql(u8, arg, "--index")) {
            cfg.index_file = args.next() orelse {
                callbacks.usage();
                return false;
            };
        } else if (std.mem.eql(u8, arg, "--serve-static")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.serve_static_root = parseBool(value) orelse cfg.serve_static_root;
        } else if (std.mem.eql(u8, arg, "--host") or std.mem.eql(u8, arg, "-H")) {
            cfg.host = args.next() orelse {
                callbacks.usage();
                return false;
            };
        } else if (std.mem.eql(u8, arg, "--port") or std.mem.eql(u8, arg, "-p")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.port = std.fmt.parseInt(u16, value, 10) catch 80;
        } else if (std.mem.eql(u8, arg, "--dir") or std.mem.eql(u8, arg, "-d")) {
            cfg.static_dir = args.next() orelse {
                callbacks.usage();
                return false;
            };
        } else if (std.mem.eql(u8, arg, "--php-root") or std.mem.eql(u8, arg, "-r")) {
            cfg.php_root = args.next() orelse {
                callbacks.usage();
                return false;
            };
        } else if (std.mem.eql(u8, arg, "--php-bin") or std.mem.eql(u8, arg, "-P")) {
            cfg.php_binary = args.next() orelse {
                callbacks.usage();
                return false;
            };
        } else if (std.mem.eql(u8, arg, "--php-fastcgi") or std.mem.eql(u8, arg, "--php-fpm") or std.mem.eql(u8, arg, "--fastcgi")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            if (disablesOptionalUrl(value)) {
                cfg.php_fastcgi = null;
            } else {
                validateFastcgiEndpoint(value) catch {
                    std.debug.print("Failed to parse php_fastcgi endpoint: {s}\n", .{value});
                    return false;
                };
                cfg.php_fastcgi = value;
            }
        } else if (std.mem.eql(u8, arg, "--php-index") or std.mem.eql(u8, arg, "--php-index-file")) {
            cfg.php_index = args.next() orelse {
                callbacks.usage();
                return false;
            };
        } else if (std.mem.eql(u8, arg, "--php-info-page") or std.mem.eql(u8, arg, "--phpinfo-page")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.php_info_page = parseBool(value) orelse cfg.php_info_page;
        } else if (std.mem.eql(u8, arg, "--php-front-controller")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.php_front_controller = parseBool(value) orelse cfg.php_front_controller;
        } else if (std.mem.eql(u8, arg, "--proxy") or std.mem.eql(u8, arg, "-x")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.upstream = if (disablesOptionalUrl(value)) null else parseUpstreamPool(allocator, value) catch null;
        } else if (std.mem.eql(u8, arg, "--upstream-policy") or std.mem.eql(u8, arg, "--proxy-policy") or std.mem.eql(u8, arg, "--load-balance")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.upstream_policy = parseUpstreamPoolPolicy(value) catch {
                std.debug.print("Failed to parse upstream policy: {s}\n", .{value});
                return false;
            };
        } else if (std.mem.eql(u8, arg, "--h2-upstream") or std.mem.eql(u8, arg, "--http2-upstream")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            if (disablesOptionalUrl(value)) {
                cfg.h2_upstream = null;
                continue;
            }
            cfg.h2_upstream = parseUpstream(allocator, value) catch {
                std.debug.print("Failed to parse h2-upstream URL: {s}\n", .{value});
                return false;
            };
        } else if (std.mem.eql(u8, arg, "--http3")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.http3_enabled = parseBool(value) orelse cfg.http3_enabled;
        } else if (std.mem.eql(u8, arg, "--http3-port")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.http3_port = std.fmt.parseInt(u16, value, 10) catch cfg.http3_port;
        } else if (std.mem.eql(u8, arg, "--admin")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.admin_enabled = parseBool(value) orelse cfg.admin_enabled;
        } else if (std.mem.eql(u8, arg, "--admin-socket") or std.mem.eql(u8, arg, "--admin-socket-path")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            if (disablesOptionalUrl(value)) {
                cfg.admin_enabled = false;
                cfg.admin_socket_path = null;
            } else {
                cfg.admin_enabled = true;
                cfg.admin_socket_path = value;
            }
        } else if (std.mem.eql(u8, arg, "--admin-ui") or std.mem.eql(u8, arg, "--admin-ui-enabled")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.admin_ui_enabled = parseBool(value) orelse cfg.admin_ui_enabled;
        } else if (std.mem.eql(u8, arg, "--admin-ui-path")) {
            cfg.admin_ui_path = args.next() orelse {
                callbacks.usage();
                return false;
            };
        } else if (std.mem.eql(u8, arg, "--admin-credentials-path") or std.mem.eql(u8, arg, "--admin-state-path")) {
            cfg.admin_credentials_path = args.next() orelse {
                callbacks.usage();
                return false;
            };
        } else if (std.mem.eql(u8, arg, "--access-log")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            if (disablesOptionalUrl(value)) {
                cfg.access_log_enabled = false;
            } else if (std.ascii.eqlIgnoreCase(value, "true") or std.ascii.eqlIgnoreCase(value, "on") or std.ascii.eqlIgnoreCase(value, "yes") or std.mem.eql(u8, value, "1")) {
                cfg.access_log_enabled = true;
            } else {
                cfg.access_log_enabled = true;
                cfg.access_log_path = value;
            }
        } else if (std.mem.eql(u8, arg, "--access-log-path")) {
            cfg.access_log_enabled = true;
            cfg.access_log_path = args.next() orelse {
                callbacks.usage();
                return false;
            };
        } else if (std.mem.eql(u8, arg, "--compression") or std.mem.eql(u8, arg, "--compress") or std.mem.eql(u8, arg, "--encode")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.compression_enabled = parseBool(value) orelse cfg.compression_enabled;
        } else if (std.mem.eql(u8, arg, "--gzip")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.gzip_enabled = parseBool(value) orelse cfg.gzip_enabled;
        } else if (std.mem.eql(u8, arg, "--compression-min-bytes") or std.mem.eql(u8, arg, "--gzip-min-bytes")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.compression_min_bytes = std.fmt.parseInt(usize, value, 10) catch cfg.compression_min_bytes;
        } else if (std.mem.eql(u8, arg, "--compression-max-bytes") or std.mem.eql(u8, arg, "--gzip-max-bytes")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.compression_max_bytes = std.fmt.parseInt(usize, value, 10) catch cfg.compression_max_bytes;
        } else if (std.mem.eql(u8, arg, "--security-headers") or std.mem.eql(u8, arg, "--security-header-preset")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.security_headers = parseSecurityHeaderPreset(value) catch cfg.security_headers;
        } else if (std.mem.eql(u8, arg, "--response-cache") or std.mem.eql(u8, arg, "--static-response-cache")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.response_cache_enabled = parseBool(value) orelse cfg.response_cache_enabled;
        } else if (std.mem.eql(u8, arg, "--response-cache-max-bytes")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.response_cache_max_bytes = std.fmt.parseInt(usize, value, 10) catch cfg.response_cache_max_bytes;
        } else if (std.mem.eql(u8, arg, "--response-cache-max-entry-bytes")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.response_cache_max_entry_bytes = std.fmt.parseInt(usize, value, 10) catch cfg.response_cache_max_entry_bytes;
        } else if (std.mem.eql(u8, arg, "--response-cache-ttl-ms")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.response_cache_ttl_ms = std.fmt.parseInt(u32, value, 10) catch cfg.response_cache_ttl_ms;
        } else if (std.mem.eql(u8, arg, "--max-request-bytes")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.max_request_bytes = std.fmt.parseInt(usize, value, 10) catch cfg.max_request_bytes;
        } else if (std.mem.eql(u8, arg, "--max-body-bytes")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.max_body_bytes = std.fmt.parseInt(usize, value, 10) catch cfg.max_body_bytes;
        } else if (std.mem.eql(u8, arg, "--max-static-bytes")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.max_static_file_bytes = std.fmt.parseInt(usize, value, 10) catch cfg.max_static_file_bytes;
        } else if (std.mem.eql(u8, arg, "--max-requests-per-connection")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.max_requests_per_connection = std.fmt.parseInt(usize, value, 10) catch cfg.max_requests_per_connection;
        } else if (std.mem.eql(u8, arg, "--max-php-output-bytes")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.max_php_output_bytes = std.fmt.parseInt(usize, value, 10) catch cfg.max_php_output_bytes;
        } else if (std.mem.eql(u8, arg, "--worker-stack-size")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.worker_stack_size = std.fmt.parseInt(usize, value, 10) catch cfg.worker_stack_size;
        } else if (std.mem.eql(u8, arg, "--read-header-timeout-ms")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.read_header_timeout_ms = std.fmt.parseInt(u32, value, 10) catch cfg.read_header_timeout_ms;
        } else if (std.mem.eql(u8, arg, "--read-body-timeout-ms")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.read_body_timeout_ms = std.fmt.parseInt(u32, value, 10) catch cfg.read_body_timeout_ms;
        } else if (std.mem.eql(u8, arg, "--idle-timeout-ms")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.idle_timeout_ms = std.fmt.parseInt(u32, value, 10) catch cfg.idle_timeout_ms;
        } else if (std.mem.eql(u8, arg, "--write-timeout-ms")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.write_timeout_ms = std.fmt.parseInt(u32, value, 10) catch cfg.write_timeout_ms;
        } else if (std.mem.eql(u8, arg, "--upstream-timeout-ms")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.upstream_timeout_ms = std.fmt.parseInt(u32, value, 10) catch cfg.upstream_timeout_ms;
        } else if (std.mem.eql(u8, arg, "--upstream-retries")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.upstream_retries = std.fmt.parseInt(usize, value, 10) catch cfg.upstream_retries;
        } else if (std.mem.eql(u8, arg, "--upstream-max-failures") or std.mem.eql(u8, arg, "--upstream-max-fails") or std.mem.eql(u8, arg, "--proxy-max-fails")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.upstream_max_failures = std.fmt.parseInt(usize, value, 10) catch cfg.upstream_max_failures;
        } else if (std.mem.eql(u8, arg, "--upstream-fail-timeout-ms") or std.mem.eql(u8, arg, "--proxy-fail-timeout-ms")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.upstream_fail_timeout_ms = std.fmt.parseInt(u32, value, 10) catch cfg.upstream_fail_timeout_ms;
        } else if (std.mem.eql(u8, arg, "--upstream-keepalive") or std.mem.eql(u8, arg, "--proxy-keepalive")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.upstream_keepalive_enabled = parseBool(value) orelse cfg.upstream_keepalive_enabled;
        } else if (std.mem.eql(u8, arg, "--upstream-keepalive-max-idle") or std.mem.eql(u8, arg, "--proxy-keepalive-max-idle")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.upstream_keepalive_max_idle = std.fmt.parseInt(usize, value, 10) catch cfg.upstream_keepalive_max_idle;
        } else if (std.mem.eql(u8, arg, "--upstream-keepalive-idle-timeout-ms") or std.mem.eql(u8, arg, "--proxy-keepalive-idle-timeout-ms")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.upstream_keepalive_idle_timeout_ms = std.fmt.parseInt(u32, value, 10) catch cfg.upstream_keepalive_idle_timeout_ms;
        } else if (std.mem.eql(u8, arg, "--upstream-keepalive-max-requests") or std.mem.eql(u8, arg, "--proxy-keepalive-max-requests")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.upstream_keepalive_max_requests = std.fmt.parseInt(usize, value, 10) catch cfg.upstream_keepalive_max_requests;
        } else if (std.mem.eql(u8, arg, "--fastcgi-keepalive") or std.mem.eql(u8, arg, "--php-fastcgi-keepalive") or std.mem.eql(u8, arg, "--fastcgi-keep-conn")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.fastcgi_keepalive_enabled = parseBool(value) orelse cfg.fastcgi_keepalive_enabled;
        } else if (std.mem.eql(u8, arg, "--fastcgi-keepalive-max-idle") or std.mem.eql(u8, arg, "--php-fastcgi-keepalive-max-idle")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.fastcgi_keepalive_max_idle = std.fmt.parseInt(usize, value, 10) catch cfg.fastcgi_keepalive_max_idle;
        } else if (std.mem.eql(u8, arg, "--fastcgi-keepalive-idle-timeout-ms") or std.mem.eql(u8, arg, "--php-fastcgi-keepalive-idle-timeout-ms")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.fastcgi_keepalive_idle_timeout_ms = std.fmt.parseInt(u32, value, 10) catch cfg.fastcgi_keepalive_idle_timeout_ms;
        } else if (std.mem.eql(u8, arg, "--fastcgi-keepalive-max-requests") or std.mem.eql(u8, arg, "--php-fastcgi-keepalive-max-requests")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.fastcgi_keepalive_max_requests = std.fmt.parseInt(usize, value, 10) catch cfg.fastcgi_keepalive_max_requests;
        } else if (std.mem.eql(u8, arg, "--upstream-health-check") or std.mem.eql(u8, arg, "--proxy-health-check")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.upstream_health_check_enabled = parseBool(value) orelse cfg.upstream_health_check_enabled;
        } else if (std.mem.eql(u8, arg, "--upstream-health-path") or std.mem.eql(u8, arg, "--upstream-health-check-path") or std.mem.eql(u8, arg, "--proxy-health-path")) {
            cfg.upstream_health_check_path = args.next() orelse {
                callbacks.usage();
                return false;
            };
        } else if (std.mem.eql(u8, arg, "--upstream-health-interval-ms") or std.mem.eql(u8, arg, "--upstream-health-check-interval-ms") or std.mem.eql(u8, arg, "--proxy-health-interval-ms")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.upstream_health_check_interval_ms = std.fmt.parseInt(u32, value, 10) catch cfg.upstream_health_check_interval_ms;
        } else if (std.mem.eql(u8, arg, "--upstream-health-timeout-ms") or std.mem.eql(u8, arg, "--upstream-health-check-timeout-ms") or std.mem.eql(u8, arg, "--proxy-health-timeout-ms")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.upstream_health_check_timeout_ms = std.fmt.parseInt(u32, value, 10) catch cfg.upstream_health_check_timeout_ms;
        } else if (std.mem.eql(u8, arg, "--upstream-circuit-breaker") or std.mem.eql(u8, arg, "--proxy-circuit-breaker")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.upstream_circuit_breaker_enabled = parseBool(value) orelse cfg.upstream_circuit_breaker_enabled;
        } else if (std.mem.eql(u8, arg, "--upstream-circuit-half-open-max") or std.mem.eql(u8, arg, "--proxy-circuit-half-open-max")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.upstream_circuit_half_open_max = std.fmt.parseInt(usize, value, 10) catch cfg.upstream_circuit_half_open_max;
        } else if (std.mem.eql(u8, arg, "--upstream-slow-start-ms") or std.mem.eql(u8, arg, "--proxy-slow-start-ms")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.upstream_slow_start_ms = std.fmt.parseInt(u32, value, 10) catch cfg.upstream_slow_start_ms;
        } else if (std.mem.eql(u8, arg, "--graceful-shutdown-timeout-ms")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.graceful_shutdown_timeout_ms = std.fmt.parseInt(u32, value, 10) catch cfg.graceful_shutdown_timeout_ms;
        } else if (std.mem.eql(u8, arg, "--max-concurrent-connections")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.max_concurrent_connections = std.fmt.parseInt(usize, value, 10) catch cfg.max_concurrent_connections;
        } else if (std.mem.eql(u8, arg, "--cf-auto-deploy")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.cloudflare_auto_deploy = parseBool(value) orelse cfg.cloudflare_auto_deploy;
        } else if (std.mem.eql(u8, arg, "--cf-api-base")) {
            cfg.cloudflare_api_base = args.next() orelse {
                callbacks.usage();
                return false;
            };
        } else if (std.mem.eql(u8, arg, "--cf-token")) {
            cfg.cloudflare_token = args.next() orelse {
                callbacks.usage();
                return false;
            };
        } else if (std.mem.eql(u8, arg, "--cf-zone-id")) {
            cfg.cloudflare_zone_id = args.next() orelse {
                callbacks.usage();
                return false;
            };
        } else if (std.mem.eql(u8, arg, "--cf-zone-name")) {
            cfg.cloudflare_zone_name = args.next() orelse {
                callbacks.usage();
                return false;
            };
        } else if (std.mem.eql(u8, arg, "--cf-record-name")) {
            cfg.cloudflare_record_name = args.next() orelse {
                callbacks.usage();
                return false;
            };
        } else if (std.mem.eql(u8, arg, "--cf-record-type")) {
            cfg.cloudflare_record_type = args.next() orelse {
                callbacks.usage();
                return false;
            };
        } else if (std.mem.eql(u8, arg, "--cf-record-content")) {
            cfg.cloudflare_record_content = args.next() orelse {
                callbacks.usage();
                return false;
            };
        } else if (std.mem.eql(u8, arg, "--cf-record-ttl")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.cloudflare_record_ttl = std.fmt.parseInt(u32, value, 10) catch cfg.cloudflare_record_ttl;
        } else if (std.mem.eql(u8, arg, "--cf-record-proxied")) {
            const value = args.next() orelse {
                callbacks.usage();
                return false;
            };
            cfg.cloudflare_record_proxied = parseBool(value) orelse cfg.cloudflare_record_proxied;
        } else if (std.mem.eql(u8, arg, "--cf-record-comment")) {
            cfg.cloudflare_record_comment = args.next() orelse {
                callbacks.usage();
                return false;
            };
        } else {
            std.debug.print("Unknown argument: {s}\n", .{arg});
            callbacks.usage();
            return error.InvalidCommandLine;
        }
    }

    loadConfiguredDomainConfigs(init.io, allocator, cfg) catch |err| {
        std.debug.print("Failed to load domain config dir: {}\n", .{err});
        return err;
    };

    normalizeConfig(cfg);
    validateConfig(cfg) catch |err| {
        std.debug.print("Invalid Layerline configuration: {}\n", .{err});
        return err;
    };

    if (validate_only) {
        std.debug.print("Layerline config OK: {s}:{d}\n", .{ cfg.host, cfg.port });
    }
    if (dump_routes) {
        callbacks.dump_routes(cfg);
    }
    if (dump_certs) {
        callbacks.dump_certs(cfg);
    }
    if (doctor) {
        const failures = callbacks.doctor(init.io, cfg);
        if (failures > 0) return error.DoctorFailed;
    }
    if (admin_command) |command| {
        try callbacks.admin_command(init.io, allocator, cfg, command);
    }
    if (validate_only or dump_routes or dump_certs or doctor or admin_command != null) {
        return false;
    }

    return true;
}
