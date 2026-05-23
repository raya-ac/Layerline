const std = @import("std");

const acme_mod = @import("acme.zig");
const admin_upstreams = @import("admin_upstreams.zig");
const config_diff = @import("config_diff.zig");
const config_mod = @import("config.zig");
const fastcgi = @import("fastcgi.zig");
const h2_server = @import("http2_server.zig");
const h2_support = @import("http2_support.zig");
const proxy_utils = @import("proxy_utils.zig");
const request_mod = @import("request.zig");
const redirects = @import("redirects.zig");
const response_body = @import("response_body.zig");
const routing_mod = @import("routing.zig");
const static_cache = @import("static_cache.zig");
const static_files = @import("static_files.zig");
const upstream_mod = @import("upstream.zig");
const upstream_runtime = @import("upstream_runtime.zig");

const appendFastcgiParam = fastcgi.appendParam;
const acceptsContentCoding = static_files.acceptsContentCoding;
const applyConfigLine = config_mod.applyConfigLine;
const applyDomainConfigLine = config_mod.applyDomainConfigLine;
const applyLetsEncryptDefaultCertPaths = acme_mod.applyLetsEncryptDefaultCertPaths;
const appendServerNames = config_mod.appendServerNames;
const buildAcmeChallengeFilePath = acme_mod.buildAcmeChallengeFilePath;
const buildResponseHeaderContext = config_mod.buildResponseHeaderContext;
const certbotWebrootFromAcmeConfig = acme_mod.certbotWebrootFromAcmeConfig;
const ChunkedBodyScanner = proxy_utils.ChunkedBodyScanner;
const compressionPolicyFor = config_mod.compressionPolicyFor;
const DEFAULT_COMPRESSION_WORKER_STACK_BYTES = config_mod.DEFAULT_COMPRESSION_WORKER_STACK_BYTES;
const DEFAULT_PHP_INDEX = config_mod.DEFAULT_PHP_INDEX;
const defaultServerConfig = config_mod.defaultServerConfig;
const domainUpstreamMutable = routing_mod.domainUpstreamMutable;
const domainUpstreamTimeoutMs = routing_mod.domainUpstreamTimeoutMs;
const findDomainConfigMutable = config_mod.findDomainConfigMutable;
const findDomainForHost = routing_mod.findDomainForHost;
const findDomainRoute = routing_mod.findDomainRoute;
const findNamedRoute = routing_mod.findNamedRoute;
const findNamedRouteMutable = routing_mod.findNamedRouteMutable;
const initDomainConfig = config_mod.initDomainConfig;
const makePhpFrontControllerTarget = fastcgi.makePhpFrontControllerTarget;
const makeStaticBaseHeaders = static_files.makeStaticBaseHeaders;
const normalizeConfig = config_mod.normalizeConfig;
const parseFastcgiEndpoint = config_mod.parseFastcgiEndpoint;
const parseHttpStatusCode = proxy_utils.parseHttpStatusCode;
const parseOptionalUpstreamPoolPolicy = config_mod.parseOptionalUpstreamPoolPolicy;
const parseUpstream = config_mod.parseUpstream;
const parseUpstreamPool = config_mod.parseUpstreamPool;
const parseUpstreamPoolPolicy = config_mod.parseUpstreamPoolPolicy;
const parseUpstreamResponseFraming = proxy_utils.parseUpstreamResponseFraming;
const routeFileRelativePath = routing_mod.routeFileRelativePath;
const RouteConfig = config_mod.RouteConfig;
const routeUpstreamPolicy = routing_mod.routeUpstreamPolicy;
const routeUpstreamTimeoutMs = routing_mod.routeUpstreamTimeoutMs;
const setDomainLine = config_mod.setDomainLine;
const setDomainRouteLine = config_mod.setDomainRouteLine;
const setRouteLine = config_mod.setRouteLine;
const setRouteLineFor = config_mod.setRouteLineFor;
const UpstreamHealthTransition = upstream_runtime.HealthTransition;
const upstreamAtAttempt = upstream_mod.upstreamAtAttempt;
const upstreamAttemptLimit = upstream_mod.upstreamAttemptLimit;
const upstreamBeginAttempt = upstream_mod.upstreamBeginAttempt;
const upstreamEffectiveWeight = upstream_mod.upstreamEffectiveWeight;
const upstreamEndAttempt = upstream_mod.upstreamEndAttempt;
const upstreamInSlowStart = upstream_mod.upstreamInSlowStart;
const stickyCookieIndex = upstream_mod.stickyCookieIndex;
const UpstreamPoolPolicy = config_mod.UpstreamPoolPolicy;
const selectUpstream = upstream_mod.selectUpstream;
const upstreamRecordActiveHealthResult = upstream_runtime.recordActiveHealthResult;
const upstreamRecordFailure = upstream_mod.upstreamRecordFailure;
const upstreamRecordSuccess = upstream_mod.upstreamRecordSuccess;
const upstreamIsEjected = upstream_mod.upstreamIsEjected;
const upstreamStartTicket = upstream_mod.upstreamStartTicket;
const upstreamRuntimePolicyFromConfig = config_mod.upstreamRuntimePolicyFromConfig;
const upstreamRuntimePolicyFor = config_mod.upstreamRuntimePolicyFor;
const HttpRequest = request_mod.HttpRequest;

test "parses FastCGI tcp and unix endpoints" {
    const tcp = try parseFastcgiEndpoint("tcp://127.0.0.1:9000");
    try std.testing.expectEqualStrings("127.0.0.1", tcp.tcp.host);
    try std.testing.expectEqual(@as(u16, 9000), tcp.tcp.port);

    const shorthand = try parseFastcgiEndpoint("localhost:9001");
    try std.testing.expectEqualStrings("localhost", shorthand.tcp.host);
    try std.testing.expectEqual(@as(u16, 9001), shorthand.tcp.port);

    const unix_endpoint = try parseFastcgiEndpoint("unix:///tmp/layerline.sock");
    try std.testing.expectEqualStrings("/tmp/layerline.sock", unix_endpoint.unix);

    try std.testing.expectError(error.InvalidConfigValue, parseFastcgiEndpoint("localhost"));
    try std.testing.expectError(error.InvalidConfigValue, parseFastcgiEndpoint("false"));
}

test "encodes FastCGI name value pairs" {
    var out = std.ArrayList(u8).empty;
    defer out.deinit(std.testing.allocator);

    try appendFastcgiParam(&out, std.testing.allocator, "A", "B");
    try std.testing.expectEqualSlices(u8, &.{ 1, 1, 'A', 'B' }, out.items);

    out.clearRetainingCapacity();
    const long_name = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    try appendFastcgiParam(&out, std.testing.allocator, long_name, "x");
    try std.testing.expectEqual(@as(u8, 0x80), out.items[0]);
    try std.testing.expectEqual(@as(u8, 0x00), out.items[1]);
    try std.testing.expectEqual(@as(u8, 0x00), out.items[2]);
    try std.testing.expectEqual(@as(u8, 0x80), out.items[3]);
    try std.testing.expectEqual(@as(u8, 1), out.items[4]);
}

test "named routes prefer exact and longest prefix matches" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var cfg = defaultServerConfig();

    try setRouteLine(&cfg, allocator, "assets /assets/* static");
    try setRouteLine(&cfg, allocator, "private /assets/private/* static");
    try setRouteLine(&cfg, allocator, "health /health proxy");
    try applyConfigLine(&cfg, allocator, "upstream_policy", "random");
    try applyConfigLine(&cfg, allocator, "upstream_max_failures", "3");
    try applyConfigLine(&cfg, allocator, "upstream_fail_timeout_ms", "1500");
    try applyConfigLine(&cfg, allocator, "upstream_keepalive", "true");
    try applyConfigLine(&cfg, allocator, "upstream_keepalive_max_idle", "24");
    try applyConfigLine(&cfg, allocator, "upstream_keepalive_idle_timeout_ms", "45000");
    try applyConfigLine(&cfg, allocator, "upstream_keepalive_max_requests", "250");
    try applyConfigLine(&cfg, allocator, "fastcgi_keepalive", "true");
    try applyConfigLine(&cfg, allocator, "fastcgi_keepalive_max_idle", "12");
    try applyConfigLine(&cfg, allocator, "fastcgi_keepalive_idle_timeout_ms", "35000");
    try applyConfigLine(&cfg, allocator, "fastcgi_keepalive_max_requests", "125");
    try applyConfigLine(&cfg, allocator, "compression", "true");
    try applyConfigLine(&cfg, allocator, "compression_min_bytes", "128");
    try applyConfigLine(&cfg, allocator, "compression_max_bytes", "4096");
    try applyConfigLine(&cfg, allocator, "route_compression.assets", "false");
    try applyConfigLine(&cfg, allocator, "route_gzip_min_bytes.assets", "256");
    try applyConfigLine(&cfg, allocator, "route_gzip_max_bytes.assets", "8192");
    try applyConfigLine(&cfg, allocator, "admin_socket", "/tmp/layerline-test-admin.sock");
    try applyConfigLine(&cfg, allocator, "admin_ui", "true");
    try applyConfigLine(&cfg, allocator, "admin_ui_path", "/_test/admin");
    try applyConfigLine(&cfg, allocator, "admin_credentials_path", "/tmp/layerline-test-admin.creds");
    try applyConfigLine(&cfg, allocator, "access_log", "/tmp/layerline-access.log");
    try applyConfigLine(&cfg, allocator, "letsencrypt_renew", "false");
    try applyConfigLine(&cfg, allocator, "letsencrypt_renew_interval_ms", "7200000");
    try applyConfigLine(&cfg, allocator, "http_redirect", "true");
    try applyConfigLine(&cfg, allocator, "http_redirect_port", "18080");
    try applyConfigLine(&cfg, allocator, "http_redirect_https_port", "18443");
    try applyConfigLine(&cfg, allocator, "http_redirect_status", "308");
    try applyConfigLine(&cfg, allocator, "upstream_health_check", "true");
    try applyConfigLine(&cfg, allocator, "upstream_health_check_path", "/ready");
    try applyConfigLine(&cfg, allocator, "upstream_health_check_interval_ms", "2500");
    try applyConfigLine(&cfg, allocator, "upstream_health_check_timeout_ms", "750");
    try applyConfigLine(&cfg, allocator, "upstream_circuit_half_open_max", "2");
    try applyConfigLine(&cfg, allocator, "upstream_slow_start_ms", "6000");
    try applyConfigLine(&cfg, allocator, "header", "X-Global-Policy: one");
    try applyConfigLine(&cfg, allocator, "cache_control", "public, max-age=60");
    try applyConfigLine(&cfg, allocator, "route_header.assets", "X-Route-Policy: assets");
    try applyConfigLine(&cfg, allocator, "route_cache_control.assets", "public, max-age=31536000, immutable");
    try applyConfigLine(&cfg, allocator, "route_proxy_policy.health", "round-robin");
    try applyConfigLine(&cfg, allocator, "route_proxy_timeout_ms.health", "1250");

    try std.testing.expectEqualStrings("health", findNamedRoute(&cfg, "/health").?.name);
    try std.testing.expectEqualStrings("private", findNamedRoute(&cfg, "/assets/private/a.txt").?.name);
    try std.testing.expectEqualStrings("assets", findNamedRoute(&cfg, "/assets/hello.txt").?.name);
    try std.testing.expect(findNamedRoute(&cfg, "/missing") == null);
    try std.testing.expectEqual(UpstreamPoolPolicy.random, cfg.upstream_policy);
    try std.testing.expectEqual(@as(usize, 3), cfg.upstream_max_failures);
    try std.testing.expectEqual(@as(u32, 1500), cfg.upstream_fail_timeout_ms);
    try std.testing.expect(cfg.upstream_keepalive_enabled);
    try std.testing.expectEqual(@as(usize, 24), cfg.upstream_keepalive_max_idle);
    try std.testing.expectEqual(@as(u32, 45000), cfg.upstream_keepalive_idle_timeout_ms);
    try std.testing.expectEqual(@as(usize, 250), cfg.upstream_keepalive_max_requests);
    try std.testing.expect(cfg.fastcgi_keepalive_enabled);
    try std.testing.expectEqual(@as(usize, 12), cfg.fastcgi_keepalive_max_idle);
    try std.testing.expectEqual(@as(u32, 35000), cfg.fastcgi_keepalive_idle_timeout_ms);
    try std.testing.expectEqual(@as(usize, 125), cfg.fastcgi_keepalive_max_requests);
    try std.testing.expect(cfg.compression_enabled);
    try std.testing.expect(cfg.gzip_enabled);
    try std.testing.expectEqual(@as(usize, 128), cfg.compression_min_bytes);
    try std.testing.expectEqual(@as(usize, 4096), cfg.compression_max_bytes);
    const assets_compression = compressionPolicyFor(&cfg, null, findNamedRoute(&cfg, "/assets/hello.txt").?);
    try std.testing.expect(!assets_compression.enabled);
    try std.testing.expectEqual(@as(usize, 256), assets_compression.min_bytes);
    try std.testing.expectEqual(@as(usize, 8192), assets_compression.max_bytes);
    try std.testing.expect(cfg.admin_enabled);
    try std.testing.expectEqualStrings("/tmp/layerline-test-admin.sock", cfg.admin_socket_path.?);
    try std.testing.expect(cfg.admin_ui_enabled);
    try std.testing.expectEqualStrings("/_test/admin", cfg.admin_ui_path);
    try std.testing.expectEqualStrings("/tmp/layerline-test-admin.creds", cfg.admin_credentials_path);
    try std.testing.expect(cfg.access_log_enabled);
    try std.testing.expectEqualStrings("/tmp/layerline-access.log", cfg.access_log_path);
    try std.testing.expect(!cfg.letsencrypt_renew);
    try std.testing.expectEqual(@as(u32, 7200000), cfg.letsencrypt_renew_interval_ms);
    try std.testing.expect(cfg.http_redirect_enabled);
    try std.testing.expectEqual(@as(u16, 18080), cfg.http_redirect_port);
    try std.testing.expectEqual(@as(u16, 18443), cfg.http_redirect_https_port);
    try std.testing.expectEqual(@as(u16, 308), cfg.http_redirect_status);
    try std.testing.expectEqualStrings("public", certbotWebrootFromAcmeConfig("public/.well-known/acme-challenge"));
    const acme_path = try buildAcmeChallengeFilePath(allocator, "public", "token-123");
    try std.testing.expectEqualStrings("public/.well-known/acme-challenge/token-123", acme_path);

    var acme_cfg = defaultServerConfig();
    acme_cfg.tls_auto = true;
    acme_cfg.letsencrypt_domains = "example.com,www.example.com";
    try applyLetsEncryptDefaultCertPaths(allocator, &acme_cfg);
    try std.testing.expectEqualStrings("/etc/letsencrypt/live/example.com/fullchain.pem", acme_cfg.tls_cert.?);
    try std.testing.expectEqualStrings("/etc/letsencrypt/live/example.com/privkey.pem", acme_cfg.tls_key.?);

    const redirect_req = HttpRequest{
        .method = "GET",
        .path = "/docs",
        .query = "q=1",
        .headers = "Host: example.com:18080\r\n",
        .version = "HTTP/1.1",
        .body = "",
        .close_connection = true,
    };
    const redirect_location = try redirects.buildHttpsLocation(allocator, &cfg, redirect_req);
    try std.testing.expectEqualStrings("https://example.com:18443/docs?q=1", redirect_location);
    const bad_redirect_req = HttpRequest{
        .method = "GET",
        .path = "/docs",
        .query = "",
        .headers = "Host: example.com:bad\r\n",
        .version = "HTTP/1.1",
        .body = "",
        .close_connection = true,
    };
    try std.testing.expectError(error.InvalidRedirectHost, redirects.buildHttpsLocation(allocator, &cfg, bad_redirect_req));
    normalizeConfig(&cfg);
    try std.testing.expectEqual(@as(usize, DEFAULT_COMPRESSION_WORKER_STACK_BYTES), cfg.worker_stack_size);
    try std.testing.expect(cfg.upstream_health_check_enabled);
    try std.testing.expectEqualStrings("/ready", cfg.upstream_health_check_path);
    try std.testing.expectEqual(@as(u32, 2500), cfg.upstream_health_check_interval_ms);
    try std.testing.expectEqual(@as(u32, 750), cfg.upstream_health_check_timeout_ms);
    try std.testing.expect(cfg.upstream_circuit_breaker_enabled);
    try std.testing.expectEqual(@as(usize, 2), cfg.upstream_circuit_half_open_max);
    try std.testing.expectEqual(@as(u32, 6000), cfg.upstream_slow_start_ms);
    try std.testing.expectEqual(@as(usize, 2), cfg.response_headers.items.len);
    try std.testing.expectEqual(@as(usize, 2), findNamedRoute(&cfg, "/assets/hello.txt").?.response_headers.items.len);
    try std.testing.expectEqual(UpstreamPoolPolicy.round_robin, routeUpstreamPolicy(&cfg, null, findNamedRoute(&cfg, "/health").?));
    try std.testing.expectEqual(@as(u32, 1250), routeUpstreamTimeoutMs(&cfg, null, findNamedRoute(&cfg, "/health").?));

    cfg.upstream = try parseUpstreamPool(allocator, "http://127.0.0.1:9100");
    const fallback_pool = domainUpstreamMutable(&cfg, null).?;
    try std.testing.expect(!upstreamRecordFailure(&fallback_pool.targets.items[0], 1_000, 2, 500));
    try std.testing.expectEqual(@as(usize, 1), domainUpstreamMutable(&cfg, null).?.targets.items[0].passive_failures.load(.monotonic));

    var breaker_target = try parseUpstream(allocator, "http://127.0.0.1:9200");
    breaker_target.weight = 5;
    const runtime_policy = upstreamRuntimePolicyFromConfig(&cfg);
    try std.testing.expect(upstreamRecordFailure(&breaker_target, 10_000, 1, 500));
    try std.testing.expect(upstreamIsEjected(&breaker_target, 10_250));
    try std.testing.expect(upstreamBeginAttempt(&breaker_target, 10_250, &runtime_policy) == null);
    const half_open_1 = upstreamBeginAttempt(&breaker_target, 10_500, &runtime_policy) orelse return error.TestUnexpectedResult;
    const half_open_2 = upstreamBeginAttempt(&breaker_target, 10_500, &runtime_policy) orelse return error.TestUnexpectedResult;
    try std.testing.expect(half_open_1.half_open);
    try std.testing.expect(half_open_2.half_open);
    try std.testing.expect(upstreamBeginAttempt(&breaker_target, 10_500, &runtime_policy) == null);
    upstreamEndAttempt(&breaker_target, half_open_2);
    upstreamEndAttempt(&breaker_target, half_open_1);
    upstreamRecordSuccess(&breaker_target, 10_550, cfg.upstream_slow_start_ms);
    try std.testing.expect(!upstreamIsEjected(&breaker_target, 10_551));
    try std.testing.expect(upstreamInSlowStart(&breaker_target, 10_551, &runtime_policy));
    try std.testing.expectEqual(@as(usize, 1), upstreamEffectiveWeight(&breaker_target, 10_551, &runtime_policy));
    try std.testing.expectEqual(@as(usize, 5), upstreamEffectiveWeight(&breaker_target, 16_550, &runtime_policy));

    try applyConfigLine(&cfg, allocator, "route_proxy.health", "http://127.0.0.1:9101");
    const health_route = findNamedRouteMutable(&cfg, "/health").?;
    if (health_route.upstream) |*route_pool| {
        try std.testing.expect(!upstreamRecordFailure(&route_pool.targets.items[0], 1_000, 2, 500));
    } else {
        return error.TestUnexpectedResult;
    }
    if (findNamedRouteMutable(&cfg, "/health").?.upstream) |*route_pool| {
        try std.testing.expectEqual(@as(usize, 1), route_pool.targets.items[0].passive_failures.load(.monotonic));
    } else {
        return error.TestUnexpectedResult;
    }

    const rel = try routeFileRelativePath(allocator, findNamedRoute(&cfg, "/assets/hello.txt").?, "/assets/hello.txt", "index.html");
    try std.testing.expectEqualStrings("hello.txt", rel);

    try setDomainLine(&cfg, allocator, "site");
    try appendServerNames(allocator, findDomainConfigMutable(&cfg, "site").?, "example.test *.example.test");
    try applyConfigLine(&cfg, allocator, "server_tls_cert.site", "/certs/site/fullchain.pem");
    try applyConfigLine(&cfg, allocator, "server_tls_key.site", "/certs/site/privkey.pem");
    try applyConfigLine(&cfg, allocator, "server_header.site", "X-Site-Policy: site");
    try applyConfigLine(&cfg, allocator, "server_cache_control.site", "private, max-age=30");
    try applyConfigLine(&cfg, allocator, "server_compression.site", "false");
    try setDomainRouteLine(&cfg, allocator, "site", "site-assets /assets/* static");
    try setDomainRouteLine(&cfg, allocator, "site", "site-api /api/* proxy");
    try applyConfigLine(&cfg, allocator, "server_route_header.site.site-api", "X-Api-Policy: route");
    try applyConfigLine(&cfg, allocator, "server_route_cache_control.site.site-api", "no-store");
    try applyConfigLine(&cfg, allocator, "server_route_compression.site.site-api", "true");
    try applyConfigLine(&cfg, allocator, "server_route_gzip_min_bytes.site.site-api", "64");
    try applyConfigLine(&cfg, allocator, "server_route_gzip_max_bytes.site.site-api", "2048");
    try applyConfigLine(&cfg, allocator, "server_proxy_policy.site", "random");
    try applyConfigLine(&cfg, allocator, "server_proxy_timeout_ms.site", "4200");
    try applyConfigLine(&cfg, allocator, "server_route_proxy_policy.site.site-api", "inherit");
    try applyConfigLine(&cfg, allocator, "server_route_proxy_timeout_ms.site.site-api", "900");

    try setDomainLine(&cfg, allocator, "fallback");
    try appendServerNames(allocator, findDomainConfigMutable(&cfg, "fallback").?, "_");

    try std.testing.expectEqualStrings("site", findDomainForHost(&cfg, "example.test:8080").?.name);
    try std.testing.expectEqualStrings("site", findDomainForHost(&cfg, "www.example.test").?.name);
    try std.testing.expectEqualStrings("fallback", findDomainForHost(&cfg, "other.test").?.name);
    try std.testing.expectEqualStrings("/certs/site/fullchain.pem", findDomainForHost(&cfg, "example.test").?.tls_cert.?);
    try std.testing.expectEqualStrings("/certs/site/privkey.pem", findDomainForHost(&cfg, "example.test").?.tls_key.?);
    try std.testing.expectEqualStrings("site-assets", findDomainRoute(findDomainForHost(&cfg, "example.test"), "/assets/domain.txt").?.name);
    try std.testing.expectEqualStrings("assets", findNamedRoute(&cfg, "/assets/global.txt").?.name);
    try std.testing.expectEqual(UpstreamPoolPolicy.random, routeUpstreamPolicy(&cfg, findDomainForHost(&cfg, "example.test"), findDomainRoute(findDomainForHost(&cfg, "example.test"), "/api/status").?));
    try std.testing.expectEqual(@as(u32, 900), routeUpstreamTimeoutMs(&cfg, findDomainForHost(&cfg, "example.test"), findDomainRoute(findDomainForHost(&cfg, "example.test"), "/api/status").?));
    try std.testing.expectEqual(@as(u32, 4200), domainUpstreamTimeoutMs(&cfg, findDomainForHost(&cfg, "example.test")));
    const site_domain = findDomainForHost(&cfg, "example.test").?;
    const site_api_route = findDomainRoute(site_domain, "/api/status").?;
    const site_compression = compressionPolicyFor(&cfg, site_domain, null);
    try std.testing.expect(!site_compression.enabled);
    const site_api_compression = compressionPolicyFor(&cfg, site_domain, site_api_route);
    try std.testing.expect(site_api_compression.enabled);
    try std.testing.expectEqual(@as(usize, 64), site_api_compression.min_bytes);
    try std.testing.expectEqual(@as(usize, 2048), site_api_compression.max_bytes);
    const response_header_context = try buildResponseHeaderContext(allocator, &cfg, site_domain, site_api_route);
    defer response_header_context.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 6), response_header_context.items.len);
    try std.testing.expectEqualStrings("X-Global-Policy", response_header_context.items[0].name);
    try std.testing.expectEqualStrings("Cache-Control", response_header_context.items[1].name);
    try std.testing.expectEqualStrings("X-Site-Policy", response_header_context.items[2].name);
    try std.testing.expectEqualStrings("Cache-Control", response_header_context.items[3].name);
    try std.testing.expectEqualStrings("X-Api-Policy", response_header_context.items[4].name);
    try std.testing.expectEqualStrings("Cache-Control", response_header_context.items[5].name);

    var file_domain = try initDomainConfig(allocator, "file-site");
    try applyDomainConfigLine(&file_domain, allocator, "compression", "true");
    try applyDomainConfigLine(&file_domain, allocator, "gzip_min_bytes", "32");
    try applyDomainConfigLine(&file_domain, allocator, "route", "file-assets /assets/* static");
    try applyDomainConfigLine(&file_domain, allocator, "route_compression.file-assets", "false");
    try applyDomainConfigLine(&file_domain, allocator, "add_header", "X-File-Policy: file");
    try applyDomainConfigLine(&file_domain, allocator, "cache_control", "public, max-age=120");
    try applyDomainConfigLine(&file_domain, allocator, "ssl_certificate", "/certs/file/fullchain.pem");
    try applyDomainConfigLine(&file_domain, allocator, "ssl_certificate_key", "/certs/file/privkey.pem");
    try std.testing.expectEqual(@as(usize, 2), file_domain.response_headers.items.len);
    try std.testing.expectEqualStrings("/certs/file/fullchain.pem", file_domain.tls_cert.?);
    try std.testing.expectEqualStrings("/certs/file/privkey.pem", file_domain.tls_key.?);
    try std.testing.expect(file_domain.compression_enabled.?);
    try std.testing.expectEqual(@as(usize, 32), file_domain.compression_min_bytes.?);
    try std.testing.expect(!file_domain.routes.items[0].compression_enabled.?);
}

test "activation config diff reports global and route changes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var active = defaultServerConfig();
    var candidate = defaultServerConfig();
    try applyConfigLine(&candidate, allocator, "compression", "true");
    try setRouteLine(&candidate, allocator, "api /api/* proxy");
    try applyConfigLine(&candidate, allocator, "route_proxy.api", "http://127.0.0.1:9000");

    const diff = try config_diff.render(std.testing.allocator, &active, &candidate);
    defer std.testing.allocator.free(diff);
    try std.testing.expect(std.mem.indexOf(u8, diff, "~ global.compression: false -> true") != null);
    try std.testing.expect(std.mem.indexOf(u8, diff, "+ route.api: prefix /api/ -> proxy") != null);
}

fn headersContainRule(headers: []const config_mod.ResponseHeaderRule, name: []const u8, value: []const u8) bool {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name) and std.mem.eql(u8, header.value, value)) return true;
    }
    return false;
}

test "cache stale shortcuts inherit through domain and route scopes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var cfg = defaultServerConfig();
    try applyConfigLine(&cfg, allocator, "stale_while_revalidate", "30");
    try applyConfigLine(&cfg, allocator, "route", "assets /assets/* static");
    try applyConfigLine(&cfg, allocator, "route_stale_if_error.assets", "600");

    try setDomainLine(&cfg, allocator, "site");
    try appendServerNames(allocator, findDomainConfigMutable(&cfg, "site").?, "example.test");
    try applyConfigLine(&cfg, allocator, "server_stale_if_error.site", "120");
    try setDomainRouteLine(&cfg, allocator, "site", "app /app/* proxy");
    try applyConfigLine(&cfg, allocator, "server_route_stale_while_revalidate.site.app", "15");

    const route_context = try buildResponseHeaderContext(allocator, &cfg, null, findNamedRoute(&cfg, "/assets/app.css").?);
    defer route_context.deinit(allocator);
    try std.testing.expect(headersContainRule(route_context.items, "Cache-Control", "stale-while-revalidate=30"));
    try std.testing.expect(headersContainRule(route_context.items, "Cache-Control", "stale-if-error=600"));

    const site = findDomainForHost(&cfg, "example.test").?;
    const app_route = findDomainRoute(site, "/app/status").?;
    const domain_route_context = try buildResponseHeaderContext(allocator, &cfg, site, app_route);
    defer domain_route_context.deinit(allocator);
    try std.testing.expect(headersContainRule(domain_route_context.items, "Cache-Control", "stale-while-revalidate=30"));
    try std.testing.expect(headersContainRule(domain_route_context.items, "Cache-Control", "stale-if-error=120"));
    try std.testing.expect(headersContainRule(domain_route_context.items, "Cache-Control", "stale-while-revalidate=15"));

    try std.testing.expectError(error.InvalidConfigValue, applyConfigLine(&cfg, allocator, "route_stale_if_error.assets", "0"));
}

test "route-local policy overrides cache security and upstream health settings" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var cfg = defaultServerConfig();
    try applyConfigLine(&cfg, allocator, "response_cache", "true");
    try applyConfigLine(&cfg, allocator, "response_cache_ttl_ms", "60000");
    try applyConfigLine(&cfg, allocator, "security_headers", "basic");
    try applyConfigLine(&cfg, allocator, "route", "assets /assets/* static");
    try applyConfigLine(&cfg, allocator, "route_response_cache.assets", "false");
    try applyConfigLine(&cfg, allocator, "route_security_headers.assets", "strict");
    try applyConfigLine(&cfg, allocator, "route_max_static_file_bytes.assets", "2048");
    try applyConfigLine(&cfg, allocator, "route", "api /api/* proxy");
    try applyConfigLine(&cfg, allocator, "route_proxy.api", "http://127.0.0.1:9100");
    try applyConfigLine(&cfg, allocator, "route_upstream_retries.api", "3");
    try applyConfigLine(&cfg, allocator, "route_upstream_max_failures.api", "4");
    try applyConfigLine(&cfg, allocator, "route_upstream_fail_timeout_ms.api", "250");
    try applyConfigLine(&cfg, allocator, "route_upstream_health_check.api", "true");
    try applyConfigLine(&cfg, allocator, "route_upstream_health_check_path.api", "/ready");
    try applyConfigLine(&cfg, allocator, "route_upstream_health_check_interval_ms.api", "1500");
    try applyConfigLine(&cfg, allocator, "route_upstream_health_check_timeout_ms.api", "300");
    try applyConfigLine(&cfg, allocator, "route_upstream_circuit_breaker.api", "false");
    try applyConfigLine(&cfg, allocator, "route_upstream_slow_start_ms.api", "0");

    const assets_route = findNamedRoute(&cfg, "/assets/app.css").?;
    const cache_policy = static_cache.policyForConfig(&cfg, null, assets_route);
    try std.testing.expect(!cache_policy.enabled);
    try std.testing.expectEqual(@as(usize, 2048), config_mod.maxStaticFileBytesFor(&cfg, null, assets_route));

    const headers = try buildResponseHeaderContext(allocator, &cfg, null, assets_route);
    defer headers.deinit(allocator);
    try std.testing.expect(headersContainRule(headers.items, "Content-Security-Policy", "default-src 'self'; base-uri 'self'; frame-ancestors 'none'"));

    const api_route = findNamedRoute(&cfg, "/api/status").?;
    const upstream_policy = upstreamRuntimePolicyFor(&cfg, null, api_route);
    try std.testing.expectEqual(@as(u32, config_mod.DEFAULT_UPSTREAM_TIMEOUT_MS), upstream_policy.timeout_ms);
    try std.testing.expectEqual(@as(usize, 3), upstream_policy.retries);
    try std.testing.expectEqual(@as(usize, 4), upstream_policy.max_failures);
    try std.testing.expectEqual(@as(u32, 250), upstream_policy.fail_timeout_ms);
    try std.testing.expect(upstream_policy.health_check_enabled);
    try std.testing.expectEqualStrings("/ready", upstream_policy.health_check_path);
    try std.testing.expectEqual(@as(u32, 1500), upstream_policy.health_check_interval_ms);
    try std.testing.expectEqual(@as(u32, 300), upstream_policy.health_check_timeout_ms);
    try std.testing.expect(!upstream_policy.circuit_breaker_enabled);
    try std.testing.expectEqual(@as(u32, 0), upstream_policy.slow_start_ms);
    try std.testing.expect(config_mod.configCanRunHealthChecks(&cfg));
}

test "php front controller target keeps script and path info separate" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var global_target = try makePhpFrontControllerTarget(allocator, null, "/orders/42", DEFAULT_PHP_INDEX);
    defer global_target.deinit(allocator);
    try std.testing.expectEqualStrings("index.php", global_target.script_rel_path);
    try std.testing.expectEqualStrings("/index.php", global_target.script_name);
    try std.testing.expectEqualStrings("/orders/42", global_target.path_info);

    var routes = std.ArrayList(RouteConfig).empty;
    try setRouteLineFor(&routes, allocator, "app /app/* php");
    const route = &routes.items[0];
    var route_target = try makePhpFrontControllerTarget(allocator, route, "/app/users/7", DEFAULT_PHP_INDEX);
    defer route_target.deinit(allocator);
    try std.testing.expectEqualStrings("index.php", route_target.script_rel_path);
    try std.testing.expectEqualStrings("/app/index.php", route_target.script_name);
    try std.testing.expectEqualStrings("/users/7", route_target.path_info);
}

test "upstream pools parse multiple targets and rotate selection" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var pool = try parseUpstreamPool(allocator, "http://127.0.0.1:9000/api, http://127.0.0.1:9001");

    try std.testing.expectEqual(@as(usize, 2), pool.targets.items.len);
    try std.testing.expectEqualStrings("127.0.0.1", pool.targets.items[0].host);
    try std.testing.expectEqual(@as(u16, 9000), pool.targets.items[0].port);
    try std.testing.expectEqualStrings("/api", pool.targets.items[0].base_path);
    try std.testing.expectEqual(@as(u16, 9001), pool.targets.items[1].port);

    const first = selectUpstream(&pool).?;
    const second = selectUpstream(&pool).?;
    try std.testing.expect(first.port != second.port);
}

test "upstream retry budget is capped to configured targets" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var pool = try parseUpstreamPool(allocator, "http://127.0.0.1:9000, http://127.0.0.1:9001, http://127.0.0.1:9002");

    try std.testing.expectEqual(@as(usize, 1), upstreamAttemptLimit(&pool, 0));
    try std.testing.expectEqual(@as(usize, 2), upstreamAttemptLimit(&pool, 1));
    try std.testing.expectEqual(@as(usize, 3), upstreamAttemptLimit(&pool, 99));
    try std.testing.expectEqual(@as(u16, 9001), upstreamAtAttempt(&pool, 4, 0).port);
    try std.testing.expectEqual(@as(u16, 9002), upstreamAtAttempt(&pool, 4, 1).port);
    try std.testing.expectEqual(@as(u16, 9000), upstreamAtAttempt(&pool, 4, 2).port);
}

test "upstream policy parser accepts configured policy names" {
    try std.testing.expectEqual(UpstreamPoolPolicy.round_robin, try parseUpstreamPoolPolicy("round_robin"));
    try std.testing.expectEqual(UpstreamPoolPolicy.round_robin, try parseUpstreamPoolPolicy("round-robin"));
    try std.testing.expectEqual(UpstreamPoolPolicy.random, try parseUpstreamPoolPolicy("random"));
    try std.testing.expectEqual(UpstreamPoolPolicy.least_connections, try parseUpstreamPoolPolicy("least_connections"));
    try std.testing.expectEqual(UpstreamPoolPolicy.least_connections, try parseUpstreamPoolPolicy("least-connections"));
    try std.testing.expectEqual(UpstreamPoolPolicy.least_connections, try parseUpstreamPoolPolicy("leastconn"));
    try std.testing.expectEqual(UpstreamPoolPolicy.weighted, try parseUpstreamPoolPolicy("weighted"));
    try std.testing.expectEqual(UpstreamPoolPolicy.weighted, try parseUpstreamPoolPolicy("weighted-round-robin"));
    try std.testing.expectEqual(UpstreamPoolPolicy.weighted, try parseUpstreamPoolPolicy("wrr"));
    try std.testing.expectEqual(UpstreamPoolPolicy.consistent_hash, try parseUpstreamPoolPolicy("consistent_hash"));
    try std.testing.expectEqual(UpstreamPoolPolicy.consistent_hash, try parseUpstreamPoolPolicy("consistent-hash"));
    try std.testing.expectEqual(UpstreamPoolPolicy.consistent_hash, try parseUpstreamPoolPolicy("uri_hash"));
    try std.testing.expectEqual(UpstreamPoolPolicy.sticky_cookie, try parseUpstreamPoolPolicy("sticky_cookie"));
    try std.testing.expectEqual(UpstreamPoolPolicy.sticky_cookie, try parseUpstreamPoolPolicy("sticky"));
    try std.testing.expectEqual(UpstreamPoolPolicy.sticky_cookie, try parseUpstreamPoolPolicy("cookie"));
    try std.testing.expectEqual(@as(?UpstreamPoolPolicy, null), try parseOptionalUpstreamPoolPolicy("inherit"));
}

test "upstream pools parse target weights" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const pool = try parseUpstreamPool(allocator, "http://127.0.0.1:9000 weight=3, http://127.0.0.1:9001 w=1");

    try std.testing.expectEqual(@as(usize, 2), pool.targets.items.len);
    try std.testing.expectEqual(@as(usize, 3), pool.targets.items[0].weight);
    try std.testing.expectEqual(@as(usize, 1), pool.targets.items[1].weight);
    try std.testing.expectError(error.InvalidUpstream, parseUpstreamPool(allocator, "weight=3 http://127.0.0.1:9000"));
    try std.testing.expectError(error.InvalidUpstream, parseUpstreamPool(allocator, "http://127.0.0.1:9000 weight=0"));
}

test "least-connections policy chooses the quietest healthy upstream" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var pool = try parseUpstreamPool(allocator, "http://127.0.0.1:9000, http://127.0.0.1:9001, http://127.0.0.1:9002");

    pool.targets.items[0].active_requests.store(5, .monotonic);
    pool.targets.items[1].active_requests.store(1, .monotonic);
    pool.targets.items[2].active_requests.store(3, .monotonic);
    try std.testing.expectEqual(@as(usize, 1), upstreamStartTicket(&pool, .least_connections, 1_000, null, null));

    pool.targets.items[1].ejected_until_ms.store(2_000, .monotonic);
    try std.testing.expectEqual(@as(usize, 2), upstreamStartTicket(&pool, .least_connections, 1_000, null, null));
}

test "weighted policy honors target weights and passive ejection" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var pool = try parseUpstreamPool(allocator, "http://127.0.0.1:9000 weight=3, http://127.0.0.1:9001 weight=1");

    upstream_mod.round_robin_cursor.store(0, .monotonic);
    try std.testing.expectEqual(@as(usize, 0), upstreamStartTicket(&pool, .weighted, 1_000, null, null));
    try std.testing.expectEqual(@as(usize, 0), upstreamStartTicket(&pool, .weighted, 1_000, null, null));
    try std.testing.expectEqual(@as(usize, 0), upstreamStartTicket(&pool, .weighted, 1_000, null, null));
    try std.testing.expectEqual(@as(usize, 1), upstreamStartTicket(&pool, .weighted, 1_000, null, null));

    upstream_mod.round_robin_cursor.store(0, .monotonic);
    pool.targets.items[0].ejected_until_ms.store(2_000, .monotonic);
    try std.testing.expectEqual(@as(usize, 1), upstreamStartTicket(&pool, .weighted, 1_000, null, null));
}

test "consistent hash policy keeps a stable healthy target" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var pool = try parseUpstreamPool(allocator, "http://127.0.0.1:9000, http://127.0.0.1:9001, http://127.0.0.1:9002");
    const req = HttpRequest{
        .method = "GET",
        .path = "/api/users",
        .query = "page=1",
        .headers = "Host: example.test\r\nX-Forwarded-For: 203.0.113.10, 10.0.0.1\r\n",
        .version = "HTTP/1.1",
        .body = "",
        .close_connection = false,
    };

    const first = upstreamStartTicket(&pool, .consistent_hash, 1_000, request_mod.upstreamHashInput(req), null);
    try std.testing.expectEqual(first, upstreamStartTicket(&pool, .consistent_hash, 1_000, request_mod.upstreamHashInput(req), null));

    pool.targets.items[first].ejected_until_ms.store(2_000, .monotonic);
    const replacement = upstreamStartTicket(&pool, .consistent_hash, 1_000, request_mod.upstreamHashInput(req), null);
    try std.testing.expect(replacement != first);
    try std.testing.expect(replacement < pool.targets.items.len);
}

test "sticky cookie policy pins valid cookies and falls back when unhealthy" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var pool = try parseUpstreamPool(allocator, "http://127.0.0.1:9000, http://127.0.0.1:9001, http://127.0.0.1:9002");
    const req = HttpRequest{
        .method = "GET",
        .path = "/dashboard",
        .query = "",
        .headers = "Host: example.test\r\nCookie: session=abc; ll_upstream=2\r\n",
        .version = "HTTP/1.1",
        .body = "",
        .close_connection = false,
    };

    try std.testing.expectEqual(@as(?usize, 2), stickyCookieIndex(req.headers, pool.targets.items.len));
    try std.testing.expectEqual(@as(usize, 2), upstreamStartTicket(&pool, .sticky_cookie, 1_000, request_mod.upstreamHashInput(req), null));

    upstream_mod.round_robin_cursor.store(0, .monotonic);
    pool.targets.items[2].ejected_until_ms.store(2_000, .monotonic);
    try std.testing.expectEqual(@as(usize, 0), upstreamStartTicket(&pool, .sticky_cookie, 1_000, request_mod.upstreamHashInput(req), null));
}

test "active health result transitions update upstream availability" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var upstream = try parseUpstream(allocator, "http://127.0.0.1:9000");

    try std.testing.expectEqual(UpstreamHealthTransition.ejected, upstreamRecordActiveHealthResult(&upstream, false, 1_000, 500, 0));
    try std.testing.expect(upstreamIsEjected(&upstream, 1_250));
    try std.testing.expectEqual(@as(i64, 1_500), upstream.ejected_until_ms.load(.monotonic));
    try std.testing.expectEqual(UpstreamHealthTransition.unchanged, upstreamRecordActiveHealthResult(&upstream, false, 1_300, 500, 0));
    try std.testing.expectEqual(UpstreamHealthTransition.recovered, upstreamRecordActiveHealthResult(&upstream, true, 1_350, 500, 0));
    try std.testing.expect(!upstreamIsEjected(&upstream, 1_351));
}

test "health check status parser accepts normal HTTP status lines" {
    try std.testing.expectEqual(@as(?u16, 200), parseHttpStatusCode("HTTP/1.1 200 OK\r\nServer: test\r\n\r\n"));
    try std.testing.expectEqual(@as(?u16, 503), parseHttpStatusCode("HTTP/1.0 503 Service Unavailable\r\n\r\n"));
    try std.testing.expectEqual(@as(?u16, null), parseHttpStatusCode("not-http\r\n\r\n"));
}

test "accept encoding q values control gzip negotiation" {
    try std.testing.expect(acceptsContentCoding("Accept-Encoding: br, gzip\r\n", "gzip"));
    try std.testing.expect(acceptsContentCoding("Accept-Encoding: *;q=0.5\r\n", "gzip"));
    try std.testing.expect(!acceptsContentCoding("Accept-Encoding: gzip;q=0, br\r\n", "gzip"));
    try std.testing.expect(!acceptsContentCoding("Accept-Encoding: *;q=1, gzip;q=0\r\n", "gzip"));
    try std.testing.expect(!acceptsContentCoding("Accept-Encoding: gzip;q=0.0\r\n", "gzip"));
}

test "gzip response preparation compresses eligible text bodies" {
    var body: [2048]u8 = undefined;
    @memset(&body, 'a');

    const prepared = try response_body.prepare(std.testing.allocator, .{
        .status_code = 200,
        .content_type = "text/plain; charset=utf-8",
        .body = &body,
        .is_head = false,
        .request_headers = "Accept-Encoding: gzip\r\n",
        .response_headers = &.{},
        .compression_policy = .{ .enabled = true, .gzip_enabled = true, .min_bytes = 1, .max_bytes = 4096 },
        .compression_work_buffer_bytes = std.compress.flate.max_window_len,
    });
    defer prepared.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("gzip", prepared.encoding.?);
    try std.testing.expect(prepared.body.len < body.len);
    try std.testing.expectEqual(@as(u8, 0x1f), prepared.body[0]);
    try std.testing.expectEqual(@as(u8, 0x8b), prepared.body[1]);
}

test "http2 goaway payload masks reserved stream bit" {
    const payload = h2_support.makeGoawayPayload(0xffff_ffff, h2_server.ERROR_NO_ERROR);
    try std.testing.expectEqual(@as(u32, 0x7fff_ffff), std.mem.readInt(u32, payload[0..4], .big));
    try std.testing.expectEqual(@as(u32, h2_server.ERROR_NO_ERROR), std.mem.readInt(u32, payload[4..8], .big));
}

test "static cache headers include cache status detail" {
    const plain_status = try static_cache.cacheStatusStatic(std.testing.allocator, null);
    defer std.testing.allocator.free(plain_status);
    const plain = try makeStaticBaseHeaders(std.testing.allocator, "\"etag\"", "Sun, 06 Nov 1994 08:49:37 GMT", null, plain_status);
    defer std.testing.allocator.free(plain);
    try std.testing.expect(std.mem.indexOf(u8, plain, "Last-Modified: Sun, 06 Nov 1994 08:49:37 GMT\r\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, plain, "Cache-Status: Layerline; fwd=uri-miss; detail=\"static-file\"\r\n") != null);

    const encoded_status = try static_cache.cacheStatusStatic(std.testing.allocator, "br");
    defer std.testing.allocator.free(encoded_status);
    const encoded = try makeStaticBaseHeaders(std.testing.allocator, "\"etag\"", "Sun, 06 Nov 1994 08:49:37 GMT", "br", encoded_status);
    defer std.testing.allocator.free(encoded);
    try std.testing.expect(std.mem.indexOf(u8, encoded, "Cache-Status: Layerline; fwd=uri-miss; detail=\"precompressed-static\"\r\n") != null);
}

test "static HTTP dates use IMF fixdate format" {
    const timestamp = std.Io.Timestamp.fromNanoseconds(@as(i96, 784111777) * std.time.ns_per_s);
    const rendered = try static_files.makeHttpDate(std.testing.allocator, timestamp);
    defer std.testing.allocator.free(rendered);

    try std.testing.expectEqualStrings("Sun, 06 Nov 1994 08:49:37 GMT", rendered);
    try std.testing.expectEqual(@as(i64, 784111777), static_files.parseHttpDate(rendered).?);
    try std.testing.expect(static_files.parseHttpDate("not a date") == null);
}

test "chunked upstream body scanner detects trailers and terminator" {
    var scanner = ChunkedBodyScanner{};
    var completed = false;
    for ("4;ext=1\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Upstream: yes\r\n\r\n") |byte| {
        completed = try scanner.consume(byte);
    }
    try std.testing.expect(completed);
}

test "upstream response framing parser keeps keep-alive candidates explicit" {
    const head =
        "HTTP/1.1 200 OK\r\n" ++
        "Content-Length: 12\r\n" ++
        "Connection: keep-alive\r\n" ++
        "\r\n";
    const headers = head["HTTP/1.1 200 OK\r\n".len .. head.len - 4];
    const framing = try parseUpstreamResponseFraming(head, headers);
    try std.testing.expectEqual(@as(?u16, 200), framing.status_code);
    try std.testing.expectEqual(@as(?usize, 12), framing.content_length);
    try std.testing.expect(!framing.connection_close);
    try std.testing.expect(!framing.transfer_chunked);
}

test "passive upstream health ejects and recovers targets" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var upstream = try parseUpstream(allocator, "http://127.0.0.1:9000");
    try std.testing.expect(!upstreamIsEjected(&upstream, 1_000));
    try std.testing.expect(!upstreamRecordFailure(&upstream, 1_000, 2, 250));
    try std.testing.expect(upstreamRecordFailure(&upstream, 1_010, 2, 250));
    try std.testing.expect(upstreamIsEjected(&upstream, 1_100));
    try std.testing.expect(!upstreamIsEjected(&upstream, 1_300));
    try std.testing.expectEqual(@as(usize, 2), upstream.passive_failures.load(.monotonic));
    upstreamRecordSuccess(&upstream, 1_301, 0);
    try std.testing.expectEqual(@as(usize, 0), upstream.passive_failures.load(.monotonic));

    try std.testing.expect(!upstreamRecordFailure(&upstream, 1_400, 0, 250));
    try std.testing.expect(!upstreamIsEjected(&upstream, 1_401));
}
