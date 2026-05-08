const std = @import("std");
const admin_support = @import("admin_support.zig");
const config_mod = @import("config.zig");
const php_runtime = @import("php_runtime.zig");
const request_mod = @import("request.zig");
const routing_mod = @import("routing.zig");
const server_assets = @import("server_assets.zig");
const static_cache = @import("static_cache.zig");

const CompressionPolicy = config_mod.CompressionPolicy;
const DomainConfig = config_mod.DomainConfig;
const HttpRequest = request_mod.HttpRequest;
const RedirectRule = config_mod.RedirectRule;
const ResponseHeaderRule = config_mod.ResponseHeaderRule;
const RouteConfig = config_mod.RouteConfig;
const ServerConfig = config_mod.ServerConfig;
const UpstreamPoolConfig = config_mod.UpstreamPoolConfig;
const UpstreamPoolPolicy = config_mod.UpstreamPoolPolicy;
const UpstreamRuntimePolicy = config_mod.UpstreamRuntimePolicy;

pub const Callbacks = struct {
    access_log_set_handler: *const fn ([]const u8) void,
    clear_request_context: *const fn () void,
    clear_response_headers: *const fn () void,
    forward_to_upstream_pool: *const fn (
        std.Io.net.Stream,
        std.mem.Allocator,
        *UpstreamPoolConfig,
        UpstreamPoolPolicy,
        UpstreamRuntimePolicy,
        HttpRequest,
        *const ServerConfig,
    ) anyerror!void,
    handle_admin_ui: *const fn (std.Io, std.Io.net.Stream, std.mem.Allocator, *ServerConfig, HttpRequest, bool, bool) anyerror!void,
    handle_named_route: *const fn (
        std.Io,
        std.Io.net.Stream,
        std.mem.Allocator,
        *ServerConfig,
        ?*DomainConfig,
        *RouteConfig,
        HttpRequest,
        bool,
        bool,
        *const std.process.Environ.Map,
    ) anyerror!void,
    php_callbacks: php_runtime.Callbacks,
    send_configured_redirect: *const fn (std.Io.net.Stream, std.mem.Allocator, RedirectRule, HttpRequest, bool, bool) anyerror!void,
    send_domain_custom_not_found: *const fn (std.Io, std.Io.net.Stream, std.mem.Allocator, *const ServerConfig, ?*DomainConfig, bool, bool) anyerror!void,
    send_method_not_allowed: *const fn (std.Io.net.Stream, std.mem.Allocator, []const u8, bool, bool) anyerror!void,
    send_metrics: *const fn (std.Io.net.Stream, std.mem.Allocator, bool, bool) anyerror!void,
    send_not_found_for_method: *const fn (std.mem.Allocator, std.Io.net.Stream, bool, bool) anyerror!void,
    send_not_found_with_connection: *const fn (std.mem.Allocator, std.Io.net.Stream, bool) anyerror!void,
    send_not_implemented: *const fn (std.Io.net.Stream, std.mem.Allocator, bool) anyerror!void,
    send_response: *const fn (std.Io.net.Stream, u16, []const u8, []const u8, []const u8, bool) anyerror!void,
    send_response_for_method: *const fn (std.Io.net.Stream, u16, []const u8, []const u8, []const u8, bool, bool) anyerror!void,
    send_response_no_body_headers: *const fn (std.Io.net.Stream, u16, []const u8, []const u8, usize, bool, ?[]const u8) anyerror!void,
    send_server_icon: *const fn (std.Io.net.Stream, bool, bool) anyerror!void,
    serve_acme_challenge: *const fn (std.Io, std.Io.net.Stream, std.mem.Allocator, []const u8, []const u8, bool, bool) anyerror!void,
    serve_static: *const fn (std.Io, std.Io.net.Stream, std.mem.Allocator, []const u8, []const u8, []const u8, bool, bool, usize, static_cache.Policy) anyerror!void,
    set_request_context: *const fn ([]const u8, CompressionPolicy) void,
    set_response_headers: *const fn ([]const ResponseHeaderRule) void,
};

fn findQueryValue(query: []const u8, key: []const u8) ?[]const u8 {
    if (query.len == 0) return null;

    var parts = std.mem.splitScalar(u8, query, '&');
    while (parts.next()) |part| {
        const eq = std.mem.indexOfScalar(u8, part, '=') orelse part.len;
        if (std.mem.eql(u8, part[0..eq], key)) {
            if (eq == part.len) return "";
            return part[eq + 1 ..];
        }
    }
    return null;
}

pub fn route(
    io: std.Io,
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    cfg: *ServerConfig,
    req: HttpRequest,
    process_env: *const std.process.Environ.Map,
    callbacks: Callbacks,
) !void {
    const should_close = req.close_connection;
    const method = req.method;
    const is_head = std.mem.eql(u8, method, "HEAD");
    const domain = routing_mod.findDomainForRequestMutable(cfg, req.headers);
    callbacks.set_request_context(req.headers, config_mod.compressionPolicyFor(cfg, domain, null));
    defer callbacks.clear_request_context();

    const base_header_context = try config_mod.buildResponseHeaderContext(allocator, cfg, domain, null);
    defer base_header_context.deinit(allocator);
    callbacks.set_response_headers(base_header_context.items);
    defer callbacks.clear_response_headers();

    if (cfg.admin_ui_enabled and admin_support.adminPathMatches(cfg.admin_ui_path, req.path)) {
        callbacks.access_log_set_handler("admin_ui");
        try callbacks.handle_admin_ui(io, stream, allocator, cfg, req, should_close, is_head);
        return;
    }

    if (routing_mod.findDomainRedirectRule(domain, req.path)) |redirect| {
        callbacks.access_log_set_handler("domain_redirect");
        try callbacks.send_configured_redirect(stream, allocator, redirect, req, should_close, is_head);
        return;
    }

    if (routing_mod.findRedirectRule(cfg, req.path)) |redirect| {
        callbacks.access_log_set_handler("redirect");
        try callbacks.send_configured_redirect(stream, allocator, redirect, req, should_close, is_head);
        return;
    }

    if (routing_mod.findDomainRouteMutable(domain, req.path)) |route_config| {
        const route_header_context = try config_mod.buildResponseHeaderContext(allocator, cfg, domain, route_config);
        defer route_header_context.deinit(allocator);
        callbacks.set_response_headers(route_header_context.items);
        callbacks.set_request_context(req.headers, config_mod.compressionPolicyFor(cfg, domain, route_config));
        try callbacks.handle_named_route(io, stream, allocator, cfg, domain, route_config, req, should_close, is_head, process_env);
        return;
    }

    if (routing_mod.findNamedRouteMutable(cfg, req.path)) |route_config| {
        const route_header_context = try config_mod.buildResponseHeaderContext(allocator, cfg, domain, route_config);
        defer route_header_context.deinit(allocator);
        callbacks.set_response_headers(route_header_context.items);
        callbacks.set_request_context(req.headers, config_mod.compressionPolicyFor(cfg, domain, route_config));
        try callbacks.handle_named_route(io, stream, allocator, cfg, domain, route_config, req, should_close, is_head, process_env);
        return;
    }

    if ((std.mem.eql(u8, method, "GET") or is_head) and std.mem.startsWith(u8, req.path, "/.well-known/acme-challenge/")) {
        callbacks.access_log_set_handler("acme_challenge");
        const token = req.path["/.well-known/acme-challenge/".len..];
        try callbacks.serve_acme_challenge(io, stream, allocator, cfg.letsencrypt_webroot, token, should_close, is_head);
        return;
    }

    // A domain-level proxy is the virtual host's fallback owner. Keep the
    // built-in Layerline pages for direct/default hosts, not for proxied apps.
    if (domain != null) {
        if (routing_mod.domainUpstreamMutable(cfg, domain)) |pool| {
            callbacks.access_log_set_handler("domain_proxy");
            try callbacks.forward_to_upstream_pool(stream, allocator, pool, routing_mod.domainUpstreamPolicy(cfg, domain), config_mod.upstreamRuntimePolicyFor(cfg, domain, null), req, cfg);
            return;
        }
    }

    if (std.mem.eql(u8, method, "GET") or is_head) {
        if (std.mem.eql(u8, req.path, "/favicon.svg") or std.mem.eql(u8, req.path, "/icon.svg")) {
            callbacks.access_log_set_handler("builtin_asset");
            try callbacks.send_server_icon(stream, should_close, is_head);
            return;
        }

        if (std.mem.eql(u8, req.path, "/") and routing_mod.domainPhpFrontController(cfg, domain)) {
            callbacks.access_log_set_handler("php_front_controller");
            try php_runtime.handleFrontController(io, stream, allocator, cfg, req, null, routing_mod.domainPhpRoot(cfg, domain), routing_mod.domainPhpBinary(cfg, domain), routing_mod.domainPhpFastcgi(cfg, domain), routing_mod.domainUpstreamTimeoutMs(cfg, domain), routing_mod.domainPhpIndex(cfg, domain), should_close, is_head, process_env, callbacks.php_callbacks);
            return;
        }

        if (std.mem.eql(u8, req.path, "/") and routing_mod.domainServeStaticRoot(cfg, domain)) {
            callbacks.access_log_set_handler("static_root");
            try callbacks.serve_static(io, stream, allocator, routing_mod.domainStaticDir(cfg, domain), routing_mod.domainIndexFile(cfg, domain), req.headers, should_close, is_head, config_mod.maxStaticFileBytesFor(cfg, domain, null), static_cache.policyForConfig(cfg, domain, null));
            return;
        }

        if (std.mem.eql(u8, req.path, "/")) {
            callbacks.access_log_set_handler("builtin_root");
            try callbacks.send_response_for_method(stream, 200, "OK", "text/html; charset=utf-8", server_assets.H3_DEFAULT_PAGE, should_close, is_head);
            return;
        }

        if (std.mem.eql(u8, req.path, "/health")) {
            callbacks.access_log_set_handler("health");
            try callbacks.send_response_for_method(stream, 200, "OK", "text/plain; charset=utf-8", "ok\n", should_close, is_head);
            return;
        }

        if (std.mem.eql(u8, req.path, "/metrics")) {
            callbacks.access_log_set_handler("metrics");
            try callbacks.send_metrics(stream, allocator, should_close, is_head);
            return;
        }

        if (std.mem.eql(u8, req.path, "/time")) {
            callbacks.access_log_set_handler("time");
            var ts_buf: [64]u8 = undefined;
            const ts = try std.fmt.bufPrint(&ts_buf, "{{\"time\":{}}}\n", .{std.Io.Timestamp.now(io, .real).toSeconds()});
            try callbacks.send_response_for_method(stream, 200, "OK", "application/json; charset=utf-8", ts, should_close, is_head);
            return;
        }

        if (std.mem.eql(u8, req.path, "/api/echo")) {
            callbacks.access_log_set_handler("api_echo");
            if (findQueryValue(req.query, "msg")) |msg| {
                const payload = try std.fmt.allocPrint(allocator, "{{\"msg\":\"{s}\"}}\n", .{msg});
                defer allocator.free(payload);
                try callbacks.send_response_for_method(stream, 200, "OK", "application/json; charset=utf-8", payload, should_close, is_head);
            } else {
                try callbacks.send_response_for_method(stream, 200, "OK", "text/plain; charset=utf-8", "try /api/echo?msg=your-text\n", should_close, is_head);
            }
            return;
        }

        if (std.mem.eql(u8, req.path, "/test.php") and !routing_mod.domainPhpInfoPage(cfg, domain)) {
            try callbacks.send_not_found_for_method(allocator, stream, should_close, is_head);
            return;
        }

        if (std.mem.endsWith(u8, req.path, ".php") or std.mem.startsWith(u8, req.path, "/php/")) {
            callbacks.access_log_set_handler("php");
            const rel_path = if (req.path.len > 0 and req.path[0] == '/') req.path[1..] else req.path;
            try php_runtime.handleScript(io, stream, allocator, cfg, req, routing_mod.domainPhpRoot(cfg, domain), routing_mod.domainPhpBinary(cfg, domain), routing_mod.domainPhpFastcgi(cfg, domain), routing_mod.domainUpstreamTimeoutMs(cfg, domain), rel_path, req.path, "", should_close, is_head, process_env, callbacks.php_callbacks);
            return;
        }

        if (std.mem.startsWith(u8, req.path, "/static/")) {
            callbacks.access_log_set_handler("static");
            const rel = req.path["/static/".len..];
            try callbacks.serve_static(io, stream, allocator, routing_mod.domainStaticDir(cfg, domain), rel, req.headers, should_close, is_head, config_mod.maxStaticFileBytesFor(cfg, domain, null), static_cache.policyForConfig(cfg, domain, null));
            return;
        }

        if (routing_mod.domainServeStaticRoot(cfg, domain) and
            !std.mem.startsWith(u8, req.path, "/api/") and
            !std.mem.startsWith(u8, req.path, "/php/") and
            !std.mem.eql(u8, req.path, "/health") and
            !std.mem.eql(u8, req.path, "/time") and
            !std.mem.eql(u8, req.path, "/"))
        {
            const static_dir = routing_mod.domainStaticDir(cfg, domain);
            const rel = try routing_mod.makeStaticPathFromRequest(allocator, req.path, routing_mod.domainIndexFile(cfg, domain));
            defer allocator.free(rel);

            const candidate_path = try std.fs.path.join(allocator, &.{ static_dir, rel });
            defer allocator.free(candidate_path);

            var file_exists = false;
            if (std.Io.Dir.cwd().statFile(io, candidate_path, .{})) |stat| {
                if (stat.kind == .file) {
                    file_exists = true;
                }
            } else |_| {}

            if (file_exists) {
                callbacks.access_log_set_handler("static_root");
                try callbacks.serve_static(io, stream, allocator, static_dir, rel, req.headers, should_close, is_head, config_mod.maxStaticFileBytesFor(cfg, domain, null), static_cache.policyForConfig(cfg, domain, null));
                return;
            }
        }

        if (routing_mod.domainPhpFrontController(cfg, domain)) {
            callbacks.access_log_set_handler("php_front_controller");
            try php_runtime.handleFrontController(io, stream, allocator, cfg, req, null, routing_mod.domainPhpRoot(cfg, domain), routing_mod.domainPhpBinary(cfg, domain), routing_mod.domainPhpFastcgi(cfg, domain), routing_mod.domainUpstreamTimeoutMs(cfg, domain), routing_mod.domainPhpIndex(cfg, domain), should_close, is_head, process_env, callbacks.php_callbacks);
            return;
        }

        if (routing_mod.domainUpstreamMutable(cfg, domain)) |pool| {
            callbacks.access_log_set_handler("domain_proxy");
            try callbacks.forward_to_upstream_pool(stream, allocator, pool, routing_mod.domainUpstreamPolicy(cfg, domain), config_mod.upstreamRuntimePolicyFor(cfg, domain, null), req, cfg);
            return;
        }

        callbacks.access_log_set_handler("not_found");
        try callbacks.send_domain_custom_not_found(io, stream, allocator, cfg, domain, should_close, is_head);
        return;
    }

    if (std.mem.eql(u8, method, "POST")) {
        if (std.mem.eql(u8, req.path, "/test.php") and !routing_mod.domainPhpInfoPage(cfg, domain)) {
            try callbacks.send_not_found_with_connection(allocator, stream, should_close);
            return;
        }

        if (std.mem.endsWith(u8, req.path, ".php")) {
            callbacks.access_log_set_handler("php");
            const rel_path = if (req.path.len > 0 and req.path[0] == '/') req.path[1..] else req.path;
            try php_runtime.handleScript(io, stream, allocator, cfg, req, routing_mod.domainPhpRoot(cfg, domain), routing_mod.domainPhpBinary(cfg, domain), routing_mod.domainPhpFastcgi(cfg, domain), routing_mod.domainUpstreamTimeoutMs(cfg, domain), rel_path, req.path, "", should_close, false, process_env, callbacks.php_callbacks);
            return;
        }

        if (std.mem.eql(u8, req.path, "/api/echo")) {
            callbacks.access_log_set_handler("api_echo");
            try callbacks.send_response(stream, 200, "OK", "text/plain; charset=utf-8", req.body, should_close);
            return;
        }

        if (routing_mod.domainPhpFrontController(cfg, domain)) {
            callbacks.access_log_set_handler("php_front_controller");
            try php_runtime.handleFrontController(io, stream, allocator, cfg, req, null, routing_mod.domainPhpRoot(cfg, domain), routing_mod.domainPhpBinary(cfg, domain), routing_mod.domainPhpFastcgi(cfg, domain), routing_mod.domainUpstreamTimeoutMs(cfg, domain), routing_mod.domainPhpIndex(cfg, domain), should_close, false, process_env, callbacks.php_callbacks);
            return;
        }

        if (routing_mod.domainUpstreamMutable(cfg, domain)) |pool| {
            callbacks.access_log_set_handler("domain_proxy");
            try callbacks.forward_to_upstream_pool(stream, allocator, pool, routing_mod.domainUpstreamPolicy(cfg, domain), config_mod.upstreamRuntimePolicyFor(cfg, domain, null), req, cfg);
            return;
        }

        callbacks.access_log_set_handler("not_found");
        try callbacks.send_not_found_with_connection(allocator, stream, should_close);
        return;
    }

    if (std.mem.eql(u8, method, "OPTIONS")) {
        callbacks.access_log_set_handler("options");
        const allow = "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS";
        const allow_header = try std.fmt.allocPrint(allocator, "Allow: {s}\r\n", .{allow});
        defer allocator.free(allow_header);
        try callbacks.send_response_no_body_headers(stream, 204, "No Content", "text/plain; charset=utf-8", 0, should_close, allow_header);
        return;
    }

    if (std.mem.eql(u8, method, "PUT") or std.mem.eql(u8, method, "PATCH") or std.mem.eql(u8, method, "DELETE")) {
        if (routing_mod.domainPhpFrontController(cfg, domain)) {
            callbacks.access_log_set_handler("php_front_controller");
            try php_runtime.handleFrontController(io, stream, allocator, cfg, req, null, routing_mod.domainPhpRoot(cfg, domain), routing_mod.domainPhpBinary(cfg, domain), routing_mod.domainPhpFastcgi(cfg, domain), routing_mod.domainUpstreamTimeoutMs(cfg, domain), routing_mod.domainPhpIndex(cfg, domain), should_close, false, process_env, callbacks.php_callbacks);
            return;
        }

        if (routing_mod.domainUpstreamMutable(cfg, domain)) |pool| {
            callbacks.access_log_set_handler("domain_proxy");
            try callbacks.forward_to_upstream_pool(stream, allocator, pool, routing_mod.domainUpstreamPolicy(cfg, domain), config_mod.upstreamRuntimePolicyFor(cfg, domain, null), req, cfg);
            return;
        }
        callbacks.access_log_set_handler("method_not_allowed");
        try callbacks.send_method_not_allowed(stream, allocator, "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS", should_close, false);
        return;
    }

    callbacks.access_log_set_handler("not_implemented");
    try callbacks.send_not_implemented(stream, allocator, should_close);
}
