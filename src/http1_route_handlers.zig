const std = @import("std");

const config_mod = @import("config.zig");
const request_mod = @import("request.zig");
const routing_mod = @import("routing.zig");

const DomainConfig = config_mod.DomainConfig;
const HttpRequest = request_mod.HttpRequest;
const RouteConfig = config_mod.RouteConfig;
const ServerConfig = config_mod.ServerConfig;
const UpstreamPoolConfig = config_mod.UpstreamPoolConfig;
const UpstreamPoolPolicy = config_mod.UpstreamPoolPolicy;

pub const MethodNotAllowedCallbacks = struct {
    send_cool_error: *const fn (std.Io.net.Stream, std.mem.Allocator, u16, []const u8, []const u8, bool, bool, ?[]const u8) anyerror!void,
};

pub const NamedRouteCallbacks = struct {
    access_log_set_handler: *const fn ([]const u8) void,
    forward_to_upstream_pool: *const fn (
        std.Io.net.Stream,
        std.mem.Allocator,
        *UpstreamPoolConfig,
        UpstreamPoolPolicy,
        u32,
        HttpRequest,
        *const ServerConfig,
    ) anyerror!void,
    handle_php_front_controller: *const fn (
        std.Io,
        std.Io.net.Stream,
        std.mem.Allocator,
        *const ServerConfig,
        HttpRequest,
        ?*const RouteConfig,
        []const u8,
        []const u8,
        ?[]const u8,
        u32,
        []const u8,
        bool,
        bool,
        *const std.process.Environ.Map,
    ) anyerror!void,
    handle_php_script: *const fn (
        std.Io,
        std.Io.net.Stream,
        std.mem.Allocator,
        *const ServerConfig,
        HttpRequest,
        []const u8,
        []const u8,
        ?[]const u8,
        u32,
        []const u8,
        []const u8,
        []const u8,
        bool,
        bool,
        *const std.process.Environ.Map,
    ) anyerror!void,
    send_cool_error: *const fn (std.Io.net.Stream, std.mem.Allocator, u16, []const u8, []const u8, bool, bool, ?[]const u8) anyerror!void,
    send_method_not_allowed: *const fn (std.Io.net.Stream, std.mem.Allocator, []const u8, bool, bool) anyerror!void,
    send_not_found_for_method: *const fn (std.mem.Allocator, std.Io.net.Stream, bool, bool) anyerror!void,
    send_response_no_body_headers: *const fn (std.Io.net.Stream, u16, []const u8, []const u8, usize, bool, ?[]const u8) anyerror!void,
    serve_static: *const fn (std.Io, std.Io.net.Stream, std.mem.Allocator, []const u8, []const u8, []const u8, bool, bool, usize) anyerror!void,
};

pub fn sendMethodNotAllowedWithAllow(
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    allowed_methods: []const u8,
    close_connection: bool,
    is_head: bool,
    callbacks: MethodNotAllowedCallbacks,
) !void {
    const allow_header = try std.fmt.allocPrint(allocator, "Allow: {s}\r\n", .{allowed_methods});
    defer allocator.free(allow_header);
    try callbacks.send_cool_error(stream, allocator, 405, "Method Not Allowed", "That method is not supported for this endpoint.", close_connection, is_head, allow_header);
}

pub fn handleNamedRoute(
    io: std.Io,
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    cfg: *ServerConfig,
    domain: ?*DomainConfig,
    route: *RouteConfig,
    req: HttpRequest,
    close_connection: bool,
    is_head: bool,
    process_env: *const std.process.Environ.Map,
    callbacks: NamedRouteCallbacks,
) !void {
    if (std.mem.eql(u8, req.method, "OPTIONS")) {
        const allow = switch (route.handler) {
            .static => "GET,HEAD,OPTIONS",
            .php => "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS",
            .proxy => "GET,HEAD,POST,PUT,PATCH,DELETE,OPTIONS",
        };
        const allow_header = try std.fmt.allocPrint(allocator, "Allow: {s}\r\n", .{allow});
        defer allocator.free(allow_header);
        try callbacks.send_response_no_body_headers(stream, 204, "No Content", "text/plain; charset=utf-8", 0, close_connection, allow_header);
        return;
    }

    switch (route.handler) {
        .static => {
            callbacks.access_log_set_handler("route_static");
            if (!(std.mem.eql(u8, req.method, "GET") or is_head)) {
                try callbacks.send_method_not_allowed(stream, allocator, "GET,HEAD,OPTIONS", close_connection, is_head);
                return;
            }
            const static_dir = route.static_dir orelse routing_mod.domainStaticDir(cfg, domain);
            const index_file = route.index_file orelse routing_mod.domainIndexFile(cfg, domain);
            const rel = try routing_mod.routeFileRelativePath(allocator, route, req.path, index_file);
            defer allocator.free(rel);
            try callbacks.serve_static(io, stream, allocator, static_dir, rel, req.headers, close_connection, is_head, cfg.max_static_file_bytes);
            return;
        },
        .php => {
            callbacks.access_log_set_handler("route_php");
            if (std.mem.eql(u8, req.path, "/test.php") and !(route.php_info_page orelse routing_mod.domainPhpInfoPage(cfg, domain))) {
                try callbacks.send_not_found_for_method(allocator, stream, close_connection, is_head);
                return;
            }
            const php_root = route.php_root orelse routing_mod.domainPhpRoot(cfg, domain);
            const php_binary = route.php_binary orelse routing_mod.domainPhpBinary(cfg, domain);
            const php_fastcgi = routing_mod.routePhpFastcgi(cfg, domain, route);
            if (routing_mod.routePhpFrontController(cfg, domain, route)) {
                try callbacks.handle_php_front_controller(io, stream, allocator, cfg, req, route, php_root, php_binary, php_fastcgi, routing_mod.routeUpstreamTimeoutMs(cfg, domain, route), routing_mod.routePhpIndex(cfg, domain, route), close_connection, is_head, process_env);
                return;
            }
            const script_rel = try routing_mod.routeFileRelativePath(allocator, route, req.path, route.index_file orelse routing_mod.domainIndexFile(cfg, domain));
            defer allocator.free(script_rel);
            try callbacks.handle_php_script(io, stream, allocator, cfg, req, php_root, php_binary, php_fastcgi, routing_mod.routeUpstreamTimeoutMs(cfg, domain, route), script_rel, req.path, "", close_connection, is_head, process_env);
            return;
        },
        .proxy => {
            callbacks.access_log_set_handler("route_proxy");
            const pool = if (route.upstream) |*route_pool|
                route_pool
            else
                routing_mod.domainUpstreamMutable(cfg, domain) orelse {
                    try callbacks.send_cool_error(stream, allocator, 502, "Bad Gateway", "Route proxy upstream is not configured.", close_connection, is_head, null);
                    return;
                };
            try callbacks.forward_to_upstream_pool(stream, allocator, pool, routing_mod.routeUpstreamPolicy(cfg, domain, route), routing_mod.routeUpstreamTimeoutMs(cfg, domain, route), req, cfg);
            return;
        },
    }
}
