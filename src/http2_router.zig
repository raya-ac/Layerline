const std = @import("std");

const buffered_cache = @import("buffered_cache.zig");
const config_mod = @import("config.zig");
const fastcgi = @import("fastcgi.zig");
const h2_native = @import("h2_native.zig");
const h2_support = @import("http2_support.zig");
const metrics_mod = @import("metrics.zig");
const php_runtime = @import("php_runtime.zig");
const request_mod = @import("request.zig");
const routing_mod = @import("routing.zig");
const server_assets = @import("server_assets.zig");
const static_cache = @import("static_cache.zig");

const CompressionPolicy = config_mod.CompressionPolicy;
const DomainConfig = config_mod.DomainConfig;
const H2BufferedResponse = h2_support.BufferedResponse;
const HttpRequest = request_mod.HttpRequest;
const ResponseHeaderRule = config_mod.ResponseHeaderRule;
const RouteConfig = config_mod.RouteConfig;
const ServerConfig = config_mod.ServerConfig;
const UpstreamPoolConfig = config_mod.UpstreamPoolConfig;
const UpstreamPoolPolicy = config_mod.UpstreamPoolPolicy;
const UpstreamRuntimePolicy = config_mod.UpstreamRuntimePolicy;

pub const Callbacks = struct {
    access_log_set_handler: *const fn ([]const u8) void,
    custom_not_found_response: *const fn (std.Io, std.mem.Allocator, *const ServerConfig, ?*const DomainConfig) anyerror!?H2BufferedResponse,
    error_response: *const fn (std.mem.Allocator, u16, []const u8, []const u8) anyerror!H2BufferedResponse,
    fetch_upstream_pool_response: *const fn (std.mem.Allocator, *UpstreamPoolConfig, UpstreamPoolPolicy, UpstreamRuntimePolicy, HttpRequest, *const ServerConfig) anyerror!H2BufferedResponse,
    buffered_cache: *buffered_cache.Store,
    metrics: *metrics_mod.ServerMetrics,
    php_callbacks: php_runtime.Callbacks,
    read_acme_challenge: *const fn (std.Io, std.mem.Allocator, *const ServerConfig, []const u8) anyerror!H2BufferedResponse,
    read_static_file: *const fn (std.Io, std.mem.Allocator, []const u8, []const u8, usize, static_cache.Policy) anyerror!H2BufferedResponse,
    redirect_response: *const fn (std.mem.Allocator, config_mod.RedirectRule, HttpRequest) anyerror!H2BufferedResponse,
    set_compression_policy: *const fn (CompressionPolicy) void,
    set_response_headers: *const fn ([]const ResponseHeaderRule) void,
};

fn fetchBufferedMicrocache(
    io: std.Io,
    allocator: std.mem.Allocator,
    cfg: *const ServerConfig,
    domain: ?*const DomainConfig,
    route: ?*const RouteConfig,
    scope: []const u8,
    req: HttpRequest,
    callbacks: Callbacks,
) !?H2BufferedResponse {
    const policy = static_cache.policyForConfig(cfg, domain, route);
    if (!buffered_cache.requestCanUse(req, policy)) return null;

    const key = try buffered_cache.makeKey(allocator, scope, req);
    defer allocator.free(key);
    const now_ms = std.Io.Timestamp.now(io, .awake).toMilliseconds();
    if (try callbacks.buffered_cache.fetch(allocator, key, now_ms, policy)) |cached| {
        callbacks.metrics.responseCacheHit(cached.body.len);
        return cached;
    }
    callbacks.metrics.responseCacheMiss();
    return null;
}

fn storeBufferedMicrocache(
    io: std.Io,
    allocator: std.mem.Allocator,
    cfg: *const ServerConfig,
    domain: ?*const DomainConfig,
    route: ?*const RouteConfig,
    scope: []const u8,
    req: HttpRequest,
    response: H2BufferedResponse,
    callbacks: Callbacks,
) !H2BufferedResponse {
    const policy = static_cache.policyForConfig(cfg, domain, route);
    if (!buffered_cache.requestCanUse(req, policy)) return response;

    const key = try buffered_cache.makeKey(allocator, scope, req);
    defer allocator.free(key);
    const now_ms = std.Io.Timestamp.now(io, .awake).toMilliseconds();
    const outcome = try callbacks.buffered_cache.store(key, response, now_ms, policy);
    if (outcome.result != .stored) return response;

    callbacks.metrics.responseCacheStore();
    var eviction_index: usize = 0;
    while (eviction_index < outcome.evictions) : (eviction_index += 1) callbacks.metrics.responseCacheEviction();

    const cache_status = try buffered_cache.cacheStatusStored(allocator, policy);
    return buffered_cache.withCacheStatus(allocator, response, cache_status);
}

pub fn buildResponseForRequest(
    io: std.Io,
    allocator: std.mem.Allocator,
    cfg: *ServerConfig,
    req: HttpRequest,
    process_env: *const std.process.Environ.Map,
    callbacks: Callbacks,
) !H2BufferedResponse {
    _ = process_env;
    const is_head = std.mem.eql(u8, req.method, "HEAD");
    const domain = routing_mod.findDomainForRequestMutable(cfg, req.headers);
    callbacks.set_compression_policy(config_mod.compressionPolicyFor(cfg, domain, null));
    const base_header_context = try config_mod.buildResponseHeaderContext(allocator, cfg, domain, null);
    callbacks.set_response_headers(base_header_context.items);

    if (routing_mod.findDomainRedirectRule(domain, req.path)) |redirect| {
        callbacks.access_log_set_handler("domain_redirect");
        return callbacks.redirect_response(allocator, redirect, req);
    }
    if (routing_mod.findRedirectRule(cfg, req.path)) |redirect| {
        callbacks.access_log_set_handler("redirect");
        return callbacks.redirect_response(allocator, redirect, req);
    }

    if (routing_mod.findDomainRouteMutable(domain, req.path)) |route| {
        const route_header_context = try config_mod.buildResponseHeaderContext(allocator, cfg, domain, route);
        callbacks.set_response_headers(route_header_context.items);
        callbacks.set_compression_policy(config_mod.compressionPolicyFor(cfg, domain, route));
        return buildRouteResponse(io, allocator, cfg, domain, route, req, callbacks);
    }
    if (routing_mod.findNamedRouteMutable(cfg, req.path)) |route| {
        const route_header_context = try config_mod.buildResponseHeaderContext(allocator, cfg, domain, route);
        callbacks.set_response_headers(route_header_context.items);
        callbacks.set_compression_policy(config_mod.compressionPolicyFor(cfg, domain, route));
        return buildRouteResponse(io, allocator, cfg, domain, route, req, callbacks);
    }

    if ((std.mem.eql(u8, req.method, "GET") or is_head) and std.mem.startsWith(u8, req.path, "/.well-known/acme-challenge/")) {
        callbacks.access_log_set_handler("acme_challenge");
        return callbacks.read_acme_challenge(io, allocator, cfg, req.path["/.well-known/acme-challenge/".len..]);
    }

    if (domain != null) {
        if (routing_mod.domainUpstreamMutable(cfg, domain)) |pool| {
            if (try fetchBufferedMicrocache(io, allocator, cfg, domain, null, "domain_proxy", req, callbacks)) |cached| {
                callbacks.access_log_set_handler("domain_proxy_cache");
                return cached;
            }
            callbacks.access_log_set_handler("domain_proxy");
            const response = try callbacks.fetch_upstream_pool_response(allocator, pool, routing_mod.domainUpstreamPolicy(cfg, domain), config_mod.upstreamRuntimePolicyFor(cfg, domain, null), req, cfg);
            return storeBufferedMicrocache(io, allocator, cfg, domain, null, "domain_proxy", req, response, callbacks);
        }
    }

    if (std.mem.eql(u8, req.method, "GET") or is_head) {
        if (std.mem.eql(u8, req.path, "/favicon.svg") or std.mem.eql(u8, req.path, "/icon.svg")) {
            callbacks.access_log_set_handler("builtin_asset");
            return h2_support.textResponse(200, "image/svg+xml", server_assets.SERVER_ICON_SVG);
        }
        if (std.mem.eql(u8, req.path, "/") and routing_mod.domainServeStaticRoot(cfg, domain)) {
            callbacks.access_log_set_handler("static_root");
            return callbacks.read_static_file(io, allocator, routing_mod.domainStaticDir(cfg, domain), routing_mod.domainIndexFile(cfg, domain), config_mod.maxStaticFileBytesFor(cfg, domain, null), static_cache.policyForConfig(cfg, domain, null));
        }
        if (std.mem.eql(u8, req.path, "/")) {
            callbacks.access_log_set_handler("builtin_root");
            return h2_support.textResponse(200, "text/html; charset=utf-8", server_assets.H2_DEFAULT_PAGE);
        }
        if (std.mem.eql(u8, req.path, "/health")) {
            callbacks.access_log_set_handler("health");
            return h2_support.textResponse(200, "text/plain; charset=utf-8", "ok\n");
        }
        if (std.mem.eql(u8, req.path, "/metrics")) {
            callbacks.access_log_set_handler("metrics");
            return .{ .status_code = 200, .content_type = "text/plain; version=0.0.4; charset=utf-8", .body = try metrics_mod.render(allocator, callbacks.metrics) };
        }
        if (std.mem.eql(u8, req.path, "/time")) {
            callbacks.access_log_set_handler("time");
            return .{ .status_code = 200, .content_type = "application/json; charset=utf-8", .body = try std.fmt.allocPrint(allocator, "{{\"time\":{}}}\n", .{std.Io.Timestamp.now(io, .real).toSeconds()}) };
        }
        if (std.mem.eql(u8, req.path, "/api/echo")) {
            callbacks.access_log_set_handler("api_echo");
            if (try fetchBufferedMicrocache(io, allocator, cfg, domain, null, "builtin:api_echo", req, callbacks)) |cached| {
                callbacks.access_log_set_handler("api_echo_cache");
                return cached;
            }
            const response = if (request_mod.findQueryValue(req.query, "msg")) |msg|
                H2BufferedResponse{ .status_code = 200, .content_type = "application/json; charset=utf-8", .body = try std.fmt.allocPrint(allocator, "{{\"msg\":\"{s}\"}}\n", .{msg}) }
            else
                h2_support.textResponse(200, "text/plain; charset=utf-8", "try /api/echo?msg=your-text\n");
            return storeBufferedMicrocache(io, allocator, cfg, domain, null, "builtin:api_echo", req, response, callbacks);
        }
        if (std.mem.startsWith(u8, req.path, "/static/")) {
            callbacks.access_log_set_handler("static");
            return callbacks.read_static_file(io, allocator, routing_mod.domainStaticDir(cfg, domain), req.path["/static/".len..], config_mod.maxStaticFileBytesFor(cfg, domain, null), static_cache.policyForConfig(cfg, domain, null));
        }
        if (routing_mod.domainServeStaticRoot(cfg, domain) and
            !std.mem.startsWith(u8, req.path, "/api/") and
            !std.mem.startsWith(u8, req.path, "/php/") and
            !std.mem.eql(u8, req.path, "/health") and
            !std.mem.eql(u8, req.path, "/time") and
            !std.mem.eql(u8, req.path, "/"))
        {
            const rel = try routing_mod.makeStaticPathFromRequest(allocator, req.path, routing_mod.domainIndexFile(cfg, domain));
            callbacks.access_log_set_handler("static_root");
            const response = try callbacks.read_static_file(io, allocator, routing_mod.domainStaticDir(cfg, domain), rel, config_mod.maxStaticFileBytesFor(cfg, domain, null), static_cache.policyForConfig(cfg, domain, null));
            if (response.status_code == 404) {
                if (try callbacks.custom_not_found_response(io, allocator, cfg, domain)) |custom| return custom;
            }
            return response;
        }
        if (routing_mod.domainUpstreamMutable(cfg, domain)) |pool| {
            if (try fetchBufferedMicrocache(io, allocator, cfg, domain, null, "domain_proxy", req, callbacks)) |cached| {
                callbacks.access_log_set_handler("domain_proxy_cache");
                return cached;
            }
            callbacks.access_log_set_handler("domain_proxy");
            const response = try callbacks.fetch_upstream_pool_response(allocator, pool, routing_mod.domainUpstreamPolicy(cfg, domain), config_mod.upstreamRuntimePolicyFor(cfg, domain, null), req, cfg);
            return storeBufferedMicrocache(io, allocator, cfg, domain, null, "domain_proxy", req, response, callbacks);
        }
        callbacks.access_log_set_handler("not_found");
        if (try callbacks.custom_not_found_response(io, allocator, cfg, domain)) |custom| return custom;
        return callbacks.error_response(allocator, 404, "Not Found", "The requested resource was not found on this server.");
    }

    if (std.mem.eql(u8, req.method, "POST") and std.mem.eql(u8, req.path, "/api/echo")) {
        callbacks.access_log_set_handler("api_echo");
        return .{ .status_code = 200, .content_type = "text/plain; charset=utf-8", .body = req.body };
    }
    if (std.mem.eql(u8, req.method, "OPTIONS")) {
        callbacks.access_log_set_handler("options");
        const headers = try allocator.alloc(h2_native.Header, 1);
        headers[0] = .{ .name = "allow", .value = "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS" };
        return .{ .status_code = 204, .content_type = "text/plain; charset=utf-8", .body = "", .headers = headers };
    }
    if (routing_mod.domainUpstreamMutable(cfg, domain)) |pool| {
        callbacks.access_log_set_handler("domain_proxy");
        return callbacks.fetch_upstream_pool_response(allocator, pool, routing_mod.domainUpstreamPolicy(cfg, domain), config_mod.upstreamRuntimePolicyFor(cfg, domain, null), req, cfg);
    }
    callbacks.access_log_set_handler("not_implemented");
    return callbacks.error_response(allocator, 501, "Not Implemented", "This server has not implemented that HTTP/2 behavior yet.");
}

fn buildRouteResponse(
    io: std.Io,
    allocator: std.mem.Allocator,
    cfg: *ServerConfig,
    domain: ?*DomainConfig,
    route: *RouteConfig,
    req: HttpRequest,
    callbacks: Callbacks,
) !H2BufferedResponse {
    const is_head = std.mem.eql(u8, req.method, "HEAD");
    switch (route.handler) {
        .static => {
            callbacks.access_log_set_handler("route_static");
            if (std.mem.eql(u8, req.method, "OPTIONS")) {
                const headers = try allocator.alloc(h2_native.Header, 1);
                headers[0] = .{ .name = "allow", .value = "GET,HEAD,OPTIONS" };
                return .{ .status_code = 204, .content_type = "text/plain; charset=utf-8", .body = "", .headers = headers };
            }
            if (!(std.mem.eql(u8, req.method, "GET") or is_head)) {
                const headers = try allocator.alloc(h2_native.Header, 1);
                headers[0] = .{ .name = "allow", .value = "GET,HEAD,OPTIONS" };
                var response = try callbacks.error_response(allocator, 405, "Method Not Allowed", "That method is not supported for this endpoint.");
                response.headers = headers;
                return response;
            }
            const rel = try routing_mod.routeFileRelativePath(allocator, route, req.path, route.index_file orelse routing_mod.domainIndexFile(cfg, domain));
            return callbacks.read_static_file(io, allocator, route.static_dir orelse routing_mod.domainStaticDir(cfg, domain), rel, config_mod.maxStaticFileBytesFor(cfg, domain, route), static_cache.policyForConfig(cfg, domain, route));
        },
        .proxy => {
            callbacks.access_log_set_handler("route_proxy");
            const scope = try std.fmt.allocPrint(allocator, "route_proxy:{s}", .{route.name});
            defer allocator.free(scope);
            if (try fetchBufferedMicrocache(io, allocator, cfg, domain, route, scope, req, callbacks)) |cached| {
                callbacks.access_log_set_handler("route_proxy_cache");
                return cached;
            }
            const pool = if (route.upstream) |*route_pool|
                route_pool
            else
                routing_mod.domainUpstreamMutable(cfg, domain) orelse return callbacks.error_response(allocator, 502, "Bad Gateway", "Route proxy upstream is not configured.");
            const response = try callbacks.fetch_upstream_pool_response(allocator, pool, routing_mod.routeUpstreamPolicy(cfg, domain, route), config_mod.upstreamRuntimePolicyFor(cfg, domain, route), req, cfg);
            return storeBufferedMicrocache(io, allocator, cfg, domain, route, scope, req, response, callbacks);
        },
        .php => {
            callbacks.access_log_set_handler("route_php");
            if (std.mem.eql(u8, req.method, "OPTIONS")) {
                const headers = try allocator.alloc(h2_native.Header, 1);
                headers[0] = .{ .name = "allow", .value = "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS" };
                return .{ .status_code = 204, .content_type = "text/plain; charset=utf-8", .body = "", .headers = headers };
            }
            if (std.mem.eql(u8, req.path, "/test.php") and !(route.php_info_page orelse routing_mod.domainPhpInfoPage(cfg, domain))) {
                return callbacks.error_response(allocator, 404, "Not Found", "The requested resource was not found on this server.");
            }
            if (routing_mod.routePhpFrontController(cfg, domain, route)) {
                const target = try fastcgi.makePhpFrontControllerTarget(allocator, route, req.path, routing_mod.routePhpIndex(cfg, domain, route));
                defer target.deinit(allocator);
                return php_runtime.buildHttp2FastcgiResponse(io, allocator, cfg, req, route.php_root orelse routing_mod.domainPhpRoot(cfg, domain), routing_mod.routePhpFastcgi(cfg, domain, route), target.script_rel_path, target.script_name, target.path_info, routing_mod.routeUpstreamTimeoutMs(cfg, domain, route), callbacks.php_callbacks);
            }
            const script_rel = try routing_mod.routeFileRelativePath(allocator, route, req.path, route.index_file orelse routing_mod.domainIndexFile(cfg, domain));
            defer allocator.free(script_rel);
            return php_runtime.buildHttp2FastcgiResponse(io, allocator, cfg, req, route.php_root orelse routing_mod.domainPhpRoot(cfg, domain), routing_mod.routePhpFastcgi(cfg, domain, route), script_rel, req.path, "", routing_mod.routeUpstreamTimeoutMs(cfg, domain, route), callbacks.php_callbacks);
        },
    }
}
