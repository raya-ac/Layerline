const std = @import("std");
const config_mod = @import("config.zig");
const routing_mod = @import("routing.zig");
const upstream_mod = @import("upstream.zig");

const ServerConfig = config_mod.ServerConfig;

pub fn dumpRoutes(cfg: *const ServerConfig) void {
    if (cfg.routes.items.len == 0 and cfg.domains.items.len == 0) {
        std.debug.print("Layerline routes: no named routes configured; built-in routes remain active.\n", .{});
        return;
    }

    if (cfg.routes.items.len == 0) {
        std.debug.print("Layerline routes: no global named routes configured.\n", .{});
    } else {
        std.debug.print("Layerline routes ({d}):\n", .{cfg.routes.items.len});
    }
    for (cfg.routes.items) |route| {
        std.debug.print(
            "  {s}: {s} {s} -> {s}",
            .{ route.name, config_mod.routeMatchName(route.match_kind), route.pattern, config_mod.routeHandlerName(route.handler) },
        );
        switch (route.handler) {
            .static => {
                std.debug.print(" dir={s} index={s}", .{ route.static_dir orelse cfg.static_dir, route.index_file orelse cfg.index_file });
            },
            .php => {
                std.debug.print(" php_root={s} php_bin={s} php_index={s}", .{ route.php_root orelse cfg.php_root, route.php_binary orelse cfg.php_binary, route.php_index orelse cfg.php_index });
                if (routing_mod.routePhpFastcgi(cfg, null, &route)) |endpoint| std.debug.print(" fastcgi={s}", .{endpoint});
                if (route.upstream_timeout_ms) |timeout_ms| std.debug.print(" timeout_ms={d}", .{timeout_ms});
                if (route.php_front_controller orelse cfg.php_front_controller) std.debug.print(" front_controller=true", .{});
            },
            .proxy => {
                const maybe_upstream = if (route.upstream) |pool| pool else cfg.upstream;
                if (maybe_upstream) |pool| {
                    upstream_mod.printUpstreamPool(route.upstream_policy orelse cfg.upstream_policy, pool);
                } else {
                    std.debug.print(" upstream=<unset>", .{});
                }
                if (route.upstream_timeout_ms) |timeout_ms| std.debug.print(" timeout_ms={d}", .{timeout_ms});
            },
        }
        if (!route.strip_prefix) std.debug.print(" strip_prefix=false", .{});
        if (route.response_headers.items.len > 0) std.debug.print(" response_headers={d}", .{route.response_headers.items.len});
        const route_cache = config_mod.responseCachePolicyFor(cfg, null, &route);
        const route_upstream = config_mod.upstreamRuntimePolicyFor(cfg, null, &route);
        std.debug.print(" security={s} response_cache={} max_static_bytes={d} upstream_retries={d} upstream_health={}", .{
            config_mod.securityHeaderPresetName(config_mod.securityHeaderPresetFor(cfg, null, &route)),
            route_cache.enabled,
            config_mod.maxStaticFileBytesFor(cfg, null, &route),
            route_upstream.retries,
            route_upstream.health_check_enabled,
        });
        std.debug.print("\n", .{});
    }

    if (cfg.domains.items.len > 0) {
        std.debug.print("Layerline domains ({d}):\n", .{cfg.domains.items.len});
    }
    for (cfg.domains.items) |*domain| {
        std.debug.print("  server {s}: server_name", .{domain.name});
        for (domain.server_names.items) |server_name| {
            std.debug.print(" {s}", .{server_name});
        }
        std.debug.print(" root={s} index={s}", .{ routing_mod.domainStaticDir(cfg, domain), routing_mod.domainIndexFile(cfg, domain) });
        if (routing_mod.domainServeStaticRoot(cfg, domain)) std.debug.print(" serve_static_root=true", .{});
        if (domain.upstream) |pool| upstream_mod.printUpstreamPool(routing_mod.domainUpstreamPolicy(cfg, domain), pool);
        if (domain.upstream_timeout_ms) |timeout_ms| std.debug.print(" timeout_ms={d}", .{timeout_ms});
        if (domain.response_headers.items.len > 0) std.debug.print(" response_headers={d}", .{domain.response_headers.items.len});
        const domain_cache = config_mod.responseCachePolicyFor(cfg, domain, null);
        const domain_upstream = config_mod.upstreamRuntimePolicyFor(cfg, domain, null);
        std.debug.print(" security={s} response_cache={} max_static_bytes={d} upstream_retries={d} upstream_health={}", .{
            config_mod.securityHeaderPresetName(config_mod.securityHeaderPresetFor(cfg, domain, null)),
            domain_cache.enabled,
            config_mod.maxStaticFileBytesFor(cfg, domain, null),
            domain_upstream.retries,
            domain_upstream.health_check_enabled,
        });
        std.debug.print("\n", .{});

        for (domain.routes.items) |route| {
            std.debug.print(
                "    {s}: {s} {s} -> {s}",
                .{ route.name, config_mod.routeMatchName(route.match_kind), route.pattern, config_mod.routeHandlerName(route.handler) },
            );
            switch (route.handler) {
                .static => {
                    std.debug.print(" dir={s} index={s}", .{ route.static_dir orelse routing_mod.domainStaticDir(cfg, domain), route.index_file orelse routing_mod.domainIndexFile(cfg, domain) });
                },
                .php => {
                    std.debug.print(" php_root={s} php_bin={s} php_index={s}", .{ route.php_root orelse routing_mod.domainPhpRoot(cfg, domain), route.php_binary orelse routing_mod.domainPhpBinary(cfg, domain), routing_mod.routePhpIndex(cfg, domain, &route) });
                    if (routing_mod.routePhpFastcgi(cfg, domain, &route)) |endpoint| std.debug.print(" fastcgi={s}", .{endpoint});
                    if (route.upstream_timeout_ms) |timeout_ms| std.debug.print(" timeout_ms={d}", .{timeout_ms});
                    if (routing_mod.routePhpFrontController(cfg, domain, &route)) std.debug.print(" front_controller=true", .{});
                },
                .proxy => {
                    const maybe_upstream = if (route.upstream) |pool| pool else routing_mod.domainUpstream(cfg, domain);
                    if (maybe_upstream) |pool| {
                        upstream_mod.printUpstreamPool(routing_mod.routeUpstreamPolicy(cfg, domain, &route), pool);
                    } else {
                        std.debug.print(" upstream=<unset>", .{});
                    }
                    if (route.upstream_timeout_ms) |timeout_ms| std.debug.print(" timeout_ms={d}", .{timeout_ms});
                },
            }
            if (!route.strip_prefix) std.debug.print(" strip_prefix=false", .{});
            if (route.response_headers.items.len > 0) std.debug.print(" response_headers={d}", .{route.response_headers.items.len});
            const route_cache = config_mod.responseCachePolicyFor(cfg, domain, &route);
            const route_upstream = config_mod.upstreamRuntimePolicyFor(cfg, domain, &route);
            std.debug.print(" security={s} response_cache={} max_static_bytes={d} upstream_retries={d} upstream_health={}", .{
                config_mod.securityHeaderPresetName(config_mod.securityHeaderPresetFor(cfg, domain, &route)),
                route_cache.enabled,
                config_mod.maxStaticFileBytesFor(cfg, domain, &route),
                route_upstream.retries,
                route_upstream.health_check_enabled,
            });
            std.debug.print("\n", .{});
        }
    }
}

pub fn usage() void {
    std.debug.print(
        "Layerline HTTP server\n\n" ++
            "Usage:\n" ++
            "  zig build run -- [--config server.conf] [--validate-config] [--dump-routes] [--host 127.0.0.1] [--port PORT] [--dir STATIC_DIR] " ++
            "[--index INDEX.html] [--serve-static true|false] [--php-root PHP_ROOT] [--php-bin /usr/bin/php-cgi] [--php-fastcgi 127.0.0.1:9000|unix:/run/php.sock] [--php-index index.php] [--php-front-controller true|false] [--php-info-page true|false] " ++
            "[--domain-config-dir domains-enabled] " ++
            "[--proxy http://HOST:PORT[/path][,http://HOST:PORT[/path]]] [--upstream-policy round_robin|random|least_connections|weighted|consistent_hash|sticky_cookie] [--h2-upstream http://HOST:PORT[/path]] " ++
            "[--http3 true|false] [--http3-port PORT] [--admin true|false] [--admin-socket /run/layerline/admin.sock] [--admin-ui true|false] [--admin-ui-path /_layerline/admin] [--admin-credentials-path .layerline-admin] [--access-log off|stderr|PATH] [--compression true|false] [--compression-min-bytes N] [--compression-max-bytes N] [--security-headers off|basic|strict] [--response-cache true|false] [--response-cache-max-bytes N] [--response-cache-max-entry-bytes N] [--response-cache-ttl-ms N] [--tls true|false] [--tls-cert path] [--tls-key path] " ++
            "[--tls-auto true|false] [--letsencrypt-email EMAIL] [--letsencrypt-domains example.com,www.example.com] " ++
            "[--letsencrypt-webroot /var/www/html] [--letsencrypt-certbot /usr/bin/certbot] [--letsencrypt-staging true|false] [--letsencrypt-renew true|false] [--letsencrypt-renew-interval-ms N] " ++
            "[--http-redirect true|false] [--http-redirect-port 80] [--http-redirect-https-port 443] [--http-redirect-status 308] " ++
            "[--cf-auto-deploy true|false] [--cf-zone-name example.com] [--cf-zone-id ZONE_ID] [--cf-record-name www.example.com] " ++
            "[--cf-record-type A|AAAA|CNAME|TXT] [--cf-record-content 203.0.113.10] [--cf-record-ttl 300] [--cf-record-proxied true|false] " ++
            "[--max-request-bytes N] [--max-body-bytes N] [--max-static-bytes N] [--max-concurrent-connections N] " ++
            "[--max-requests-per-connection N] [--max-php-output-bytes N] [--worker-stack-size N] [--read-header-timeout-ms N] " ++
            "[--read-body-timeout-ms N] [--idle-timeout-ms N] [--write-timeout-ms N] [--upstream-timeout-ms N] [--upstream-retries N] [--upstream-max-failures N] [--upstream-fail-timeout-ms N] " ++
            "[--upstream-keepalive true|false] [--upstream-keepalive-max-idle N] [--upstream-keepalive-idle-timeout-ms N] [--upstream-keepalive-max-requests N] " ++
            "[--fastcgi-keepalive true|false] [--fastcgi-keepalive-max-idle N] [--fastcgi-keepalive-idle-timeout-ms N] [--fastcgi-keepalive-max-requests N] " ++
            "[--upstream-health-check true|false] [--upstream-health-path /health] [--upstream-health-interval-ms N] [--upstream-health-timeout-ms N] " ++
            "[--upstream-circuit-breaker true|false] [--upstream-circuit-half-open-max N] [--upstream-slow-start-ms N] " ++
            "[--graceful-shutdown-timeout-ms N]\n" ++
            "  Supported config keys: host, port, static_dir/dir, index_file/index, serve_static_root, " ++
            "php_root, php_binary/php_bin, php_fastcgi/php_fpm/fastcgi, php_index/php_index_file, php_front_controller, php_info_page/phpinfo_page, proxy, upstream_policy/proxy_policy, h2_upstream, http3, http3_port, admin, admin_socket/admin_socket_path, admin_ui/admin_ui_enabled, admin_ui_path, admin_credentials_path, access_log, access_log_path, compression/compress/encode, gzip, compression_min_bytes, compression_max_bytes, security_headers/security_header_preset, response_cache, response_cache_max_bytes, response_cache_max_entry_bytes, response_cache_ttl_ms, domain_config_dir/domains_dir/sites_enabled, header/response_header/add_header, cache_control, redirect/redir, tls, tls_cert, tls_key, max_request_bytes, " ++
            "tls_auto, letsencrypt_email, letsencrypt_domains, letsencrypt_webroot, letsencrypt_certbot, letsencrypt_staging, letsencrypt_renew, letsencrypt_renew_interval_ms, http_redirect, http_redirect_port, http_redirect_https_port, http_redirect_status, " ++
            "max_body_bytes, max_static_file_bytes, max_requests_per_connection, max_php_output_bytes, max_concurrent_connections, worker_stack_size, " ++
            "read_header_timeout_ms, read_body_timeout_ms, idle_timeout_ms, write_timeout_ms, upstream_timeout_ms, upstream_retries, upstream_max_failures, upstream_fail_timeout_ms, upstream_keepalive, upstream_keepalive_max_idle, upstream_keepalive_idle_timeout_ms, upstream_keepalive_max_requests, fastcgi_keepalive, fastcgi_keepalive_max_idle, fastcgi_keepalive_idle_timeout_ms, fastcgi_keepalive_max_requests, upstream_health_check, upstream_health_check_path, upstream_health_check_interval_ms, upstream_health_check_timeout_ms, upstream_circuit_breaker, upstream_circuit_half_open_max, upstream_slow_start_ms, graceful_shutdown_timeout_ms, " ++
            "cf_auto_deploy, cf_api_base, cf_token, cf_zone_id, cf_zone_name, cf_record_name, cf_record_type, cf_record_content, " ++
            "cf_record_ttl, cf_record_proxied, cf_record_comment, route, route_dir.NAME, route_index.NAME, route_max_static_file_bytes.NAME, route_php_root.NAME, " ++
            "route_php_bin.NAME, route_php_fastcgi.NAME, route_php_index.NAME, route_php_front_controller.NAME, route_php_info_page.NAME, route_proxy.NAME, route_upstream_policy.NAME, route_upstream_timeout_ms.NAME, route_upstream_retries.NAME, route_upstream_max_failures.NAME, route_upstream_health_check.NAME, route_strip_prefix.NAME, route_header.NAME, route_cache_control.NAME, route_response_cache.NAME, route_security_headers.NAME, server/domain/vhost, " ++
            "server_name.NAME, server_root.NAME, server_index.NAME, server_serve_static_root.NAME, server_header.NAME, server_cache_control.NAME, server_response_cache.NAME, server_security_headers.NAME, server_proxy.NAME, " ++
            "server_upstream_policy.NAME, server_upstream_timeout_ms.NAME, server_upstream_retries.NAME, server_upstream_max_failures.NAME, server_upstream_health_check.NAME, server_php_fastcgi.NAME, server_php_index.NAME, server_php_front_controller.NAME, server_tls_cert.NAME, server_tls_key.NAME, server_redirect.NAME, server_route.NAME, server_route_dir.DOMAIN.ROUTE, server_route_max_static_file_bytes.DOMAIN.ROUTE, server_route_header.DOMAIN.ROUTE, server_route_cache_control.DOMAIN.ROUTE, server_route_response_cache.DOMAIN.ROUTE, server_route_security_headers.DOMAIN.ROUTE, server_route_php_fastcgi.DOMAIN.ROUTE, server_route_php_index.DOMAIN.ROUTE, server_route_php_front_controller.DOMAIN.ROUTE, server_route_proxy.DOMAIN.ROUTE, server_route_upstream_policy.DOMAIN.ROUTE, server_route_upstream_timeout_ms.DOMAIN.ROUTE, server_route_upstream_retries.DOMAIN.ROUTE, server_route_upstream_health_check.DOMAIN.ROUTE\n" ++
            "  HTTP/1 is served directly. HTTP/2 cleartext can be passed through with --h2-upstream. " ++
            "Native HTTP/3 serves static, health, redirect, and fallback page responses over QUIC on --http3-port.\n\n" ++
            "Examples:\n" ++
            "  zig build run\n" ++
            "  zig build run -- --validate-config\n" ++
            "  zig build run -- --dump-routes\n" ++
            "  zig build run -- --port 4000\n" ++
            "  zig build run -- --index index.php --serve-static true\n" ++
            "  zig build run -- --php-root public --php-bin php-cgi\n" ++
            "  zig build run -- --php-root public --php-fastcgi 127.0.0.1:9000\n" ++
            "  zig build run -- --php-front-controller true --php-index index.php\n" ++
            "  zig build run -- --config server.conf\n" ++
            "  zig build run -- --domain-config-dir domains-enabled --dump-routes\n" ++
            "  zig build run -- --proxy http://127.0.0.1:9000,http://127.0.0.1:9001\n" ++
            "  zig build run -- --proxy http://127.0.0.1:9000,http://127.0.0.1:9001 --upstream-policy random\n" ++
            "  zig build run -- --proxy http://127.0.0.1:9000 --upstream-keepalive true --upstream-keepalive-max-idle 32\n" ++
            "  zig build run -- --proxy http://127.0.0.1:9000,http://127.0.0.1:9001 --upstream-health-check true\n" ++
            "  zig build run -- --proxy http://127.0.0.1:9000,http://127.0.0.1:9001 --upstream-circuit-breaker true --upstream-slow-start-ms 10000\n" ++
            "  zig build run -- --proxy off\n" ++
            "  zig build run -- --admin-ui true --admin-ui-path /_layerline/admin\n" ++
            "  zig build run -- --access-log /var/log/layerline/access.log\n" ++
            "  zig build run -- --tls-auto true --letsencrypt-email admin@example.com --letsencrypt-domains example.com\n" ++
            "  zig build run -- --cf-auto-deploy true --cf-token xxxxx --cf-zone-name example.com --cf-record-name www.example.com\n" ++
            "  zig build run -- --h2-upstream http://127.0.0.1:9001\n\n" ++
            "Notes:\n" ++
            "  HTTP/1 client handling is still thread-per-connection. Upstream keep-alive pooling\n" ++
            "  removes backend reconnect churn, but very high fan-in still needs strict timeout\n" ++
            "  and connection management policies.\n" ++
            "  Native HTTP/3 currently covers static, health, redirect, and fallback page paths, with proxy/PHP\n" ++
            "  and certificate trust/automation still kept separate from the HTTP/1 surface.\n",
        .{},
    );
}
