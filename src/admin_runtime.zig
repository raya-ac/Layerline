const std = @import("std");
const builtin = @import("builtin");
const admin_pages = @import("admin_pages.zig");
const admin_support = @import("admin_support.zig");
const admin_upstreams = @import("admin_upstreams.zig");
const config_loader = @import("config_loader.zig");
const config_mod = @import("config.zig");
const http_headers = @import("http_headers.zig");
const request_mod = @import("request.zig");

const AdminConfigSetting = admin_support.AdminConfigSetting;
const AdminCredentials = admin_support.AdminCredentials;
const HttpRequest = request_mod.HttpRequest;
const ServerConfig = config_mod.ServerConfig;
const isDomainConfigFileName = config_loader.isDomainConfigFileName;
const trimValue = http_headers.trimValue;

pub const Callbacks = struct {
    active_config: *const fn () *ServerConfig,
    active_io: *const fn () std.Io,
    bind_thread_io: *const fn (std.Io) void,
    close_stream: *const fn (std.Io.net.Stream) void,
    read_stream: *const fn (std.Io.net.Stream, []u8) anyerror!usize,
    purge_caches: *const fn ([]const u8) usize,
    reload_config: *const fn (std.Io, std.mem.Allocator, *const ServerConfig) anyerror!void,
    render_config_diff: *const fn (std.Io, std.mem.Allocator, *const ServerConfig) anyerror![]const u8,
    renew_certs: *const fn (std.Io, std.mem.Allocator, *const ServerConfig) anyerror!void,
    render_metrics: *const fn (std.mem.Allocator) anyerror![]const u8,
    request_restart: *const fn () void,
    runtime_view: *const fn () admin_pages.RuntimeView,
    send_dashboard_page: *const fn (
        std.Io,
        std.Io.net.Stream,
        std.mem.Allocator,
        *const ServerConfig,
        AdminCredentials,
        ?[]const u8,
        ?[]const u8,
        u16,
        []const u8,
        bool,
        bool,
    ) anyerror!void,
    send_login_page: *const fn (std.Io.net.Stream, std.mem.Allocator, *const ServerConfig, ?[]const u8, u16, []const u8, bool, bool) anyerror!void,
    send_method_not_allowed: *const fn (std.Io.net.Stream, std.mem.Allocator, []const u8, bool, bool) anyerror!void,
    send_redirect: *const fn (std.Io.net.Stream, std.mem.Allocator, *const ServerConfig, ?[]const u8, bool, bool) anyerror!void,
    send_response: *const fn (std.Io.net.Stream, u16, []const u8, []const u8, []const u8, bool) anyerror!void,
    send_response_no_body: *const fn (std.Io.net.Stream, u16, []const u8, []const u8, usize, bool, ?[]const u8) anyerror!void,
    send_setup_page: *const fn (std.Io.net.Stream, std.mem.Allocator, *const ServerConfig, ?[]const u8, u16, []const u8, bool, bool) anyerror!void,
    set_stream_timeouts: *const fn (std.Io.net.Stream, u32, u32) anyerror!void,
    shutdown_requested: *std.atomic.Value(bool),
    validate_activation: *const fn (std.Io, std.mem.Allocator, *const ServerConfig) anyerror!void,
    validate_runtime: *const fn (*const ServerConfig) anyerror!void,
    write_all: *const fn (std.Io.net.Stream, []const u8) anyerror!void,
};

pub const SocketContext = struct {
    io: std.Io,
    cfg: *ServerConfig,
    socket_path: []const u8,
    callbacks: Callbacks,
};

fn handleSetupPost(io: std.Io, stream: std.Io.net.Stream, allocator: std.mem.Allocator, cfg: *const ServerConfig, req: HttpRequest, close_connection: bool, callbacks: Callbacks) !void {
    var fields = admin_support.parseUrlEncodedForm(allocator, req.body) catch {
        try callbacks.send_setup_page(stream, allocator, cfg, "The setup form could not be parsed.", 400, "Bad Request", close_connection, false);
        return;
    };
    defer admin_support.freeFormFields(allocator, &fields);

    const username = admin_support.formValue(fields.items, "username") orelse "";
    const password = admin_support.formValue(fields.items, "password") orelse "";
    const password_confirm = admin_support.formValue(fields.items, "password_confirm") orelse "";
    const credentials = admin_support.createAdminCredentials(io, allocator, cfg, username, password, password_confirm) catch |err| {
        const message = switch (err) {
            error.InvalidAdminUsername => "Use 2-64 characters: letters, numbers, dot, underscore, dash, or @.",
            error.AdminPasswordTooShort => "Use a password with at least 8 characters.",
            error.AdminPasswordMismatch => "The password confirmation did not match.",
            error.PathAlreadyExists => "Admin access is already configured. Sign in instead.",
            else => "Layerline could not create the admin credentials file.",
        };
        try callbacks.send_setup_page(stream, allocator, cfg, message, 400, "Bad Request", close_connection, false);
        return;
    };
    const cookie = try admin_support.makeAdminSessionCookie(allocator, cfg, credentials);
    defer allocator.free(cookie);
    try callbacks.send_redirect(stream, allocator, cfg, cookie, close_connection, false);
}

fn handleLoginPost(stream: std.Io.net.Stream, allocator: std.mem.Allocator, cfg: *const ServerConfig, credentials: AdminCredentials, req: HttpRequest, close_connection: bool, callbacks: Callbacks) !void {
    var fields = admin_support.parseUrlEncodedForm(allocator, req.body) catch {
        try callbacks.send_login_page(stream, allocator, cfg, "The login form could not be parsed.", 400, "Bad Request", close_connection, false);
        return;
    };
    defer admin_support.freeFormFields(allocator, &fields);

    const username = admin_support.formValue(fields.items, "username") orelse "";
    const password = admin_support.formValue(fields.items, "password") orelse "";
    if (!std.mem.eql(u8, username, credentials.username) or !(try admin_support.verifyAdminPassword(credentials, password))) {
        try callbacks.send_login_page(stream, allocator, cfg, "The username or password was not accepted.", 401, "Unauthorized", close_connection, false);
        return;
    }

    const cookie = try admin_support.makeAdminSessionCookie(allocator, cfg, credentials);
    defer allocator.free(cookie);
    try callbacks.send_redirect(stream, allocator, cfg, cookie, close_connection, false);
}

fn handleValidatePost(io: std.Io, stream: std.Io.net.Stream, allocator: std.mem.Allocator, cfg: *const ServerConfig, credentials: AdminCredentials, close_connection: bool, callbacks: Callbacks) !void {
    callbacks.validate_activation(io, allocator, cfg) catch |err| {
        const message = try std.fmt.allocPrint(allocator, "Activation config is invalid: {}", .{err});
        defer allocator.free(message);
        try callbacks.send_dashboard_page(io, stream, allocator, cfg, credentials, null, message, 400, "Bad Request", close_connection, false);
        return;
    };
    try callbacks.send_dashboard_page(io, stream, allocator, cfg, credentials, "Activation config is valid. A managed restart can apply staged writes.", null, 200, "OK", close_connection, false);
}

fn handleRestartPost(io: std.Io, stream: std.Io.net.Stream, allocator: std.mem.Allocator, cfg: *const ServerConfig, credentials: AdminCredentials, close_connection: bool, callbacks: Callbacks) !void {
    callbacks.validate_activation(io, allocator, cfg) catch |err| {
        const message = try std.fmt.allocPrint(allocator, "Restart blocked because activation config is invalid: {}", .{err});
        defer allocator.free(message);
        try callbacks.send_dashboard_page(io, stream, allocator, cfg, credentials, null, message, 400, "Bad Request", close_connection, false);
        return;
    };

    callbacks.request_restart();
    try callbacks.send_dashboard_page(io, stream, allocator, cfg, credentials, "Graceful restart requested after activation config preflight passed.", null, 202, "Accepted", close_connection, false);
}

fn handleReloadPost(io: std.Io, stream: std.Io.net.Stream, allocator: std.mem.Allocator, cfg: *const ServerConfig, credentials: AdminCredentials, close_connection: bool, callbacks: Callbacks) !void {
    callbacks.reload_config(io, allocator, cfg) catch |err| {
        const message = try std.fmt.allocPrint(allocator, "Reload blocked: {}", .{err});
        defer allocator.free(message);
        try callbacks.send_dashboard_page(io, stream, allocator, cfg, credentials, null, message, 400, "Bad Request", close_connection, false);
        return;
    };

    const active_cfg = callbacks.active_config();
    try callbacks.send_dashboard_page(io, stream, allocator, active_cfg, credentials, "Config reloaded in memory for new connections.", null, 200, "OK", close_connection, false);
}

fn handleCertRenewPost(io: std.Io, stream: std.Io.net.Stream, allocator: std.mem.Allocator, cfg: *const ServerConfig, credentials: AdminCredentials, close_connection: bool, callbacks: Callbacks) !void {
    callbacks.renew_certs(io, allocator, cfg) catch |err| {
        const message = switch (err) {
            error.AcmeRenewalDisabled => "Certificate renewal is not enabled. Configure tls_auto, letsencrypt_domains, letsencrypt_webroot, and letsencrypt_renew first.",
            else => try std.fmt.allocPrint(allocator, "Certificate renewal failed: {}", .{err}),
        };
        const allocated = err != error.AcmeRenewalDisabled;
        defer if (allocated) allocator.free(message);
        try callbacks.send_dashboard_page(io, stream, allocator, cfg, credentials, null, message, 400, "Bad Request", close_connection, false);
        return;
    };

    try callbacks.send_dashboard_page(io, stream, allocator, callbacks.active_config(), credentials, "Certificate renewal completed and TLS material was reloaded for new connections.", null, 200, "OK", close_connection, false);
}

fn handleCachePurgePost(io: std.Io, stream: std.Io.net.Stream, allocator: std.mem.Allocator, cfg: *const ServerConfig, credentials: AdminCredentials, req: HttpRequest, close_connection: bool, callbacks: Callbacks) !void {
    var fields = admin_support.parseUrlEncodedForm(allocator, req.body) catch {
        try callbacks.send_dashboard_page(io, stream, allocator, cfg, credentials, null, "The cache purge form could not be parsed.", 400, "Bad Request", close_connection, false);
        return;
    };
    defer admin_support.freeFormFields(allocator, &fields);

    const raw_target = admin_support.adminTrimmedField(fields.items, "target");
    const target = if (std.ascii.eqlIgnoreCase(raw_target, "all")) "" else raw_target;
    const removed = callbacks.purge_caches(target);
    const message = if (target.len == 0)
        try std.fmt.allocPrint(allocator, "Purged {d} cache entries.", .{removed})
    else
        try std.fmt.allocPrint(allocator, "Purged {d} cache entries matching {s}.", .{ removed, target });
    defer allocator.free(message);

    try callbacks.send_dashboard_page(io, stream, allocator, callbacks.active_config(), credentials, message, null, 200, "OK", close_connection, false);
}

fn appendJsonString(out: *std.ArrayList(u8), allocator: std.mem.Allocator, value: []const u8) !void {
    try out.append(allocator, '"');
    for (value) |byte| {
        switch (byte) {
            '"' => try out.appendSlice(allocator, "\\\""),
            '\\' => try out.appendSlice(allocator, "\\\\"),
            '\n' => try out.appendSlice(allocator, "\\n"),
            '\r' => try out.appendSlice(allocator, "\\r"),
            '\t' => try out.appendSlice(allocator, "\\t"),
            0...0x08, 0x0b...0x0c, 0x0e...0x1f => try out.print(allocator, "\\u{x:0>4}", .{byte}),
            else => try out.append(allocator, byte),
        }
    }
    try out.append(allocator, '"');
}

fn cachePurgeTargetFromRequest(allocator: std.mem.Allocator, req: HttpRequest) ![]const u8 {
    if (req.body.len == 0) return "";
    var fields = try admin_support.parseUrlEncodedForm(allocator, req.body);
    defer admin_support.freeFormFields(allocator, &fields);
    const raw_target = admin_support.adminTrimmedField(fields.items, "target");
    if (raw_target.len == 0) return "";
    if (std.ascii.eqlIgnoreCase(raw_target, "all")) return "";
    return try allocator.dupe(u8, raw_target);
}

fn handleCachePurgeApiPost(stream: std.Io.net.Stream, allocator: std.mem.Allocator, req: HttpRequest, close_connection: bool, callbacks: Callbacks) !void {
    const target = cachePurgeTargetFromRequest(allocator, req) catch {
        try callbacks.send_response(stream, 400, "Bad Request", "application/json; charset=utf-8", "{\"ok\":false,\"error\":\"invalid_form\"}\n", close_connection);
        return;
    };
    defer if (target.len > 0) allocator.free(target);

    const removed = callbacks.purge_caches(target);
    var body = std.ArrayList(u8).empty;
    defer body.deinit(allocator);
    try body.print(allocator, "{{\"ok\":true,\"removed\":{d},\"target\":", .{removed});
    try appendJsonString(&body, allocator, if (target.len == 0) "all" else target);
    try body.appendSlice(allocator, "}\n");

    try callbacks.send_response(stream, 200, "OK", "application/json; charset=utf-8", body.items, close_connection);
}

fn handleAddSitePost(io: std.Io, stream: std.Io.net.Stream, allocator: std.mem.Allocator, cfg: *const ServerConfig, credentials: AdminCredentials, req: HttpRequest, close_connection: bool, callbacks: Callbacks) !void {
    var fields = admin_support.parseUrlEncodedForm(allocator, req.body) catch {
        try callbacks.send_dashboard_page(io, stream, allocator, cfg, credentials, null, "The site form could not be parsed.", 400, "Bad Request", close_connection, false);
        return;
    };
    defer admin_support.freeFormFields(allocator, &fields);

    const name = admin_support.adminTrimmedField(fields.items, "name");
    const server_names = admin_support.adminTrimmedField(fields.items, "server_names");
    const root = admin_support.adminTrimmedField(fields.items, "root");
    const index = admin_support.adminTrimmedField(fields.items, "index");
    const proxy = admin_support.adminTrimmedField(fields.items, "proxy");
    const upstream_policy = admin_support.adminTrimmedField(fields.items, "upstream_policy");
    const php_fastcgi = admin_support.adminTrimmedField(fields.items, "php_fastcgi");
    const tls_cert = admin_support.adminTrimmedField(fields.items, "tls_cert");
    const tls_key = admin_support.adminTrimmedField(fields.items, "tls_key");
    const route_name = admin_support.adminTrimmedField(fields.items, "route_name");
    const route_pattern = admin_support.adminTrimmedField(fields.items, "route_pattern");
    const route_handler = admin_support.adminTrimmedField(fields.items, "route_handler");
    const route_static_dir = admin_support.adminTrimmedField(fields.items, "route_static_dir");
    const route_proxy = admin_support.adminTrimmedField(fields.items, "route_proxy");
    const route_php_fastcgi = admin_support.adminTrimmedField(fields.items, "route_php_fastcgi");

    const site_config = admin_support.buildAdminSiteConfig(
        allocator,
        name,
        server_names,
        if (root.len > 0) root else "public",
        if (index.len > 0) index else "index.html",
        admin_support.adminCheckboxEnabled(fields.items, "serve_static_root"),
        proxy,
        upstream_policy,
        php_fastcgi,
        admin_support.adminCheckboxEnabled(fields.items, "php_front_controller"),
        tls_cert,
        tls_key,
        route_name,
        route_pattern,
        route_handler,
        route_static_dir,
        route_proxy,
        route_php_fastcgi,
        admin_support.adminCheckboxEnabled(fields.items, "route_php_front_controller"),
    ) catch |err| {
        const message = switch (err) {
            error.InvalidUpstream => "The proxy field must be one or more http:// or https:// upstream URLs.",
            error.InvalidConfigValue => "The site values are invalid. Use a simple name, server names, safe paths, and complete route fields when adding a route.",
            else => "Layerline could not build that site config.",
        };
        try callbacks.send_dashboard_page(io, stream, allocator, cfg, credentials, null, message, 400, "Bad Request", close_connection, false);
        return;
    };
    defer allocator.free(site_config);

    const path = admin_support.writeAdminSiteConfigFile(io, allocator, cfg, name, site_config) catch |err| {
        const message = switch (err) {
            error.AdminDomainConfigDirMissing => "Set domain_config_dir before adding sites.",
            error.PathAlreadyExists => "A site config with that internal name already exists.",
            else => "Layerline could not write the site config file.",
        };
        try callbacks.send_dashboard_page(io, stream, allocator, cfg, credentials, null, message, 400, "Bad Request", close_connection, false);
        return;
    };
    defer allocator.free(path);

    const message = try std.fmt.allocPrint(allocator, "Created {s}. Restart Layerline for the new site to become active.", .{path});
    defer allocator.free(message);
    try callbacks.send_dashboard_page(io, stream, allocator, cfg, credentials, message, null, 201, "Created", close_connection, false);
}

fn handleSettingsPost(io: std.Io, stream: std.Io.net.Stream, allocator: std.mem.Allocator, cfg: *const ServerConfig, credentials: AdminCredentials, req: HttpRequest, close_connection: bool, callbacks: Callbacks) !void {
    var fields = admin_support.parseUrlEncodedForm(allocator, req.body) catch {
        try callbacks.send_dashboard_page(io, stream, allocator, cfg, credentials, null, "The settings form could not be parsed.", 400, "Bad Request", close_connection, false);
        return;
    };
    defer admin_support.freeFormFields(allocator, &fields);

    const host = admin_support.adminTrimmedField(fields.items, "host");
    const port = admin_support.adminTrimmedField(fields.items, "port");
    const static_dir = admin_support.adminTrimmedField(fields.items, "static_dir");
    const index_file = admin_support.adminTrimmedField(fields.items, "index_file");
    const domain_config_dir = admin_support.adminTrimmedField(fields.items, "domain_config_dir");
    const serve_static_root = admin_support.adminTrimmedField(fields.items, "serve_static_root");
    const compression = admin_support.adminTrimmedField(fields.items, "compression");
    const gzip = admin_support.adminTrimmedField(fields.items, "gzip");
    const security_headers = admin_support.adminTrimmedField(fields.items, "security_headers");
    const response_cache = admin_support.adminTrimmedField(fields.items, "response_cache");
    const response_cache_max_bytes = admin_support.adminTrimmedField(fields.items, "response_cache_max_bytes");
    const response_cache_max_entry_bytes = admin_support.adminTrimmedField(fields.items, "response_cache_max_entry_bytes");
    const response_cache_ttl_ms = admin_support.adminTrimmedField(fields.items, "response_cache_ttl_ms");
    const php_root = admin_support.adminTrimmedField(fields.items, "php_root");
    const php_binary = admin_support.adminTrimmedField(fields.items, "php_binary");
    const php_fastcgi = admin_support.adminTrimmedField(fields.items, "php_fastcgi");
    const php_front_controller = admin_support.adminTrimmedField(fields.items, "php_front_controller");
    const proxy = admin_support.adminTrimmedField(fields.items, "proxy");
    const upstream_policy = admin_support.adminTrimmedField(fields.items, "upstream_policy");
    const upstream_timeout_ms = admin_support.adminTrimmedField(fields.items, "upstream_timeout_ms");
    const upstream_retries = admin_support.adminTrimmedField(fields.items, "upstream_retries");
    const upstream_keepalive = admin_support.adminTrimmedField(fields.items, "upstream_keepalive");
    const fastcgi_keepalive = admin_support.adminTrimmedField(fields.items, "fastcgi_keepalive");
    const tls = admin_support.adminTrimmedField(fields.items, "tls");
    const tls_cert = admin_support.adminTrimmedField(fields.items, "tls_cert");
    const tls_key = admin_support.adminTrimmedField(fields.items, "tls_key");
    const http_redirect = admin_support.adminTrimmedField(fields.items, "http_redirect");
    const http_redirect_port = admin_support.adminTrimmedField(fields.items, "http_redirect_port");
    const http_redirect_https_port = admin_support.adminTrimmedField(fields.items, "http_redirect_https_port");
    const http3 = admin_support.adminTrimmedField(fields.items, "http3");
    const http3_port = admin_support.adminTrimmedField(fields.items, "http3_port");
    const admin_socket = admin_support.adminTrimmedField(fields.items, "admin_socket");
    const admin_ui = admin_support.adminTrimmedField(fields.items, "admin_ui");
    const admin_ui_path = admin_support.adminTrimmedField(fields.items, "admin_ui_path");
    const admin_credentials_path = admin_support.adminTrimmedField(fields.items, "admin_credentials_path");
    const access_log = admin_support.adminTrimmedField(fields.items, "access_log");
    const max_concurrent_connections = admin_support.adminTrimmedField(fields.items, "max_concurrent_connections");
    const max_request_bytes = admin_support.adminTrimmedField(fields.items, "max_request_bytes");
    const read_header_timeout_ms = admin_support.adminTrimmedField(fields.items, "read_header_timeout_ms");
    const idle_timeout_ms = admin_support.adminTrimmedField(fields.items, "idle_timeout_ms");
    const worker_stack_size = admin_support.adminTrimmedField(fields.items, "worker_stack_size");

    const settings = [_]AdminConfigSetting{
        .{ .key = "host", .value = host },
        .{ .key = "port", .value = port },
        .{ .key = "static_dir", .value = static_dir },
        .{ .key = "index_file", .value = index_file },
        .{ .key = "domain_config_dir", .value = domain_config_dir, .emit = domain_config_dir.len > 0 },
        .{ .key = "serve_static_root", .value = serve_static_root },
        .{ .key = "compression", .value = compression },
        .{ .key = "gzip", .value = gzip },
        .{ .key = "security_headers", .value = security_headers },
        .{ .key = "response_cache", .value = response_cache },
        .{ .key = "response_cache_max_bytes", .value = response_cache_max_bytes },
        .{ .key = "response_cache_max_entry_bytes", .value = response_cache_max_entry_bytes },
        .{ .key = "response_cache_ttl_ms", .value = response_cache_ttl_ms },
        .{ .key = "php_root", .value = php_root },
        .{ .key = "php_binary", .value = php_binary },
        .{ .key = "php_fastcgi", .value = if (php_fastcgi.len > 0) php_fastcgi else "off" },
        .{ .key = "php_front_controller", .value = php_front_controller },
        .{ .key = "proxy", .value = if (proxy.len > 0) proxy else "off" },
        .{ .key = "upstream_policy", .value = upstream_policy },
        .{ .key = "upstream_timeout_ms", .value = upstream_timeout_ms },
        .{ .key = "upstream_retries", .value = upstream_retries },
        .{ .key = "upstream_keepalive", .value = upstream_keepalive },
        .{ .key = "fastcgi_keepalive", .value = fastcgi_keepalive },
        .{ .key = "tls", .value = tls },
        .{ .key = "tls_cert", .value = tls_cert, .emit = tls_cert.len > 0 },
        .{ .key = "tls_key", .value = tls_key, .emit = tls_key.len > 0 },
        .{ .key = "http_redirect", .value = http_redirect },
        .{ .key = "http_redirect_port", .value = http_redirect_port },
        .{ .key = "http_redirect_https_port", .value = http_redirect_https_port },
        .{ .key = "http3", .value = http3 },
        .{ .key = "http3_port", .value = http3_port },
        .{ .key = "admin_socket", .value = if (admin_socket.len > 0) admin_socket else "off" },
        .{ .key = "admin_ui", .value = admin_ui },
        .{ .key = "admin_ui_path", .value = admin_ui_path },
        .{ .key = "admin_credentials_path", .value = admin_credentials_path },
        .{ .key = "access_log", .value = if (access_log.len > 0) access_log else "off" },
        .{ .key = "max_concurrent_connections", .value = max_concurrent_connections },
        .{ .key = "max_request_bytes", .value = max_request_bytes },
        .{ .key = "read_header_timeout_ms", .value = read_header_timeout_ms },
        .{ .key = "idle_timeout_ms", .value = idle_timeout_ms },
        .{ .key = "worker_stack_size", .value = worker_stack_size },
    };

    admin_support.validateAdminSettingsPatch(allocator, cfg, settings[0..], tls_cert, tls_key) catch |err| {
        const message = switch (err) {
            error.InvalidConfigValue => "The settings are invalid. Check ports, booleans, paths, TLS cert/key pairs, and upstream URLs.",
            error.InvalidUpstream => "The proxy field must be one or more http:// or https:// upstream URLs.",
            else => "Layerline could not validate those settings.",
        };
        try callbacks.send_dashboard_page(io, stream, allocator, cfg, credentials, null, message, 400, "Bad Request", close_connection, false);
        return;
    };

    const path = admin_support.writeAdminMainConfigFile(io, allocator, cfg, settings[0..]) catch |err| {
        const message = switch (err) {
            error.InvalidConfigValue => "The generated main config was too large or contained unsafe values.",
            else => "Layerline could not write the main config file.",
        };
        try callbacks.send_dashboard_page(io, stream, allocator, cfg, credentials, null, message, 400, "Bad Request", close_connection, false);
        return;
    };
    defer allocator.free(path);

    const message = try std.fmt.allocPrint(allocator, "Saved settings to {s}. A backup was written when the file already existed. Restart Layerline for these changes to become active.", .{path});
    defer allocator.free(message);
    try callbacks.send_dashboard_page(io, stream, allocator, cfg, credentials, message, null, 200, "OK", close_connection, false);
}

fn parseAdminUsize(value: []const u8) !usize {
    if (value.len == 0) return error.InvalidConfigValue;
    return std.fmt.parseInt(usize, value, 10) catch error.InvalidConfigValue;
}

fn parseAdminU32OrDefault(value: []const u8, default_value: u32) !u32 {
    if (value.len == 0) return default_value;
    return std.fmt.parseInt(u32, value, 10) catch error.InvalidConfigValue;
}

fn upstreamControlMessage(allocator: std.mem.Allocator, action: admin_upstreams.ControlAction, address: admin_upstreams.TargetAddress) ![]const u8 {
    const verb = switch (action) {
        .eject => "Ejected",
        .recover => "Recovered",
    };
    if (std.mem.eql(u8, address.scope, "global")) {
        return std.fmt.allocPrint(allocator, "{s} global upstream target {d}.", .{ verb, address.index });
    }
    if (std.mem.eql(u8, address.scope, "route")) {
        return std.fmt.allocPrint(allocator, "{s} route {s} upstream target {d}.", .{ verb, address.route, address.index });
    }
    if (std.mem.eql(u8, address.scope, "domain")) {
        return std.fmt.allocPrint(allocator, "{s} domain {s} upstream target {d}.", .{ verb, address.domain, address.index });
    }
    return std.fmt.allocPrint(allocator, "{s} domain {s} route {s} upstream target {d}.", .{ verb, address.domain, address.route, address.index });
}

fn handleUpstreamControlPost(io: std.Io, stream: std.Io.net.Stream, allocator: std.mem.Allocator, cfg: *ServerConfig, credentials: AdminCredentials, req: HttpRequest, action: admin_upstreams.ControlAction, close_connection: bool, callbacks: Callbacks) !void {
    var fields = admin_support.parseUrlEncodedForm(allocator, req.body) catch {
        try callbacks.send_dashboard_page(io, stream, allocator, cfg, credentials, null, "The upstream control form could not be parsed.", 400, "Bad Request", close_connection, false);
        return;
    };
    defer admin_support.freeFormFields(allocator, &fields);

    const address = admin_upstreams.TargetAddress{
        .scope = admin_support.adminTrimmedField(fields.items, "scope"),
        .domain = admin_support.adminTrimmedField(fields.items, "domain"),
        .route = admin_support.adminTrimmedField(fields.items, "route"),
        .index = parseAdminUsize(admin_support.adminTrimmedField(fields.items, "index")) catch {
            try callbacks.send_dashboard_page(io, stream, allocator, cfg, credentials, null, "The upstream target index is invalid.", 400, "Bad Request", close_connection, false);
            return;
        },
    };
    const duration_ms = parseAdminU32OrDefault(admin_support.adminTrimmedField(fields.items, "duration_ms"), admin_upstreams.DEFAULT_MANUAL_EJECT_MS) catch {
        try callbacks.send_dashboard_page(io, stream, allocator, cfg, credentials, null, "The upstream ejection duration is invalid.", 400, "Bad Request", close_connection, false);
        return;
    };

    admin_upstreams.applyControl(io, cfg, action, address, duration_ms) catch |err| {
        const message = try std.fmt.allocPrint(allocator, "Upstream control failed: {}", .{err});
        defer allocator.free(message);
        try callbacks.send_dashboard_page(io, stream, allocator, cfg, credentials, null, message, 400, "Bad Request", close_connection, false);
        return;
    };

    const message = try upstreamControlMessage(allocator, action, address);
    defer allocator.free(message);
    try callbacks.send_dashboard_page(io, stream, allocator, cfg, credentials, message, null, 200, "OK", close_connection, false);
}

pub fn handleUi(
    io: std.Io,
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    cfg: *ServerConfig,
    req: HttpRequest,
    close_connection: bool,
    is_head: bool,
    callbacks: Callbacks,
) !void {
    const method = req.method;
    if (std.mem.eql(u8, method, "OPTIONS")) {
        const allow_header = "Allow: GET,HEAD,POST,OPTIONS\r\nCache-Control: no-store\r\n";
        try callbacks.send_response_no_body(stream, 204, "No Content", "text/plain; charset=utf-8", 0, close_connection, allow_header);
        return;
    }
    if (!(std.mem.eql(u8, method, "GET") or is_head or std.mem.eql(u8, method, "POST"))) {
        try callbacks.send_method_not_allowed(stream, allocator, "GET,HEAD,POST,OPTIONS", close_connection, is_head);
        return;
    }

    const sub_path = admin_support.adminSubPath(cfg.admin_ui_path, req.path);
    const maybe_credentials = try admin_support.loadAdminCredentials(io, allocator, cfg.admin_credentials_path);
    if (maybe_credentials == null) {
        if (std.mem.eql(u8, method, "POST") and std.mem.eql(u8, sub_path, "/setup")) {
            try handleSetupPost(io, stream, allocator, cfg, req, close_connection, callbacks);
            return;
        }
        if (std.mem.eql(u8, method, "GET") or is_head) {
            try callbacks.send_setup_page(stream, allocator, cfg, null, 200, "OK", close_connection, is_head);
            return;
        }
        try callbacks.send_method_not_allowed(stream, allocator, "GET,HEAD,POST,OPTIONS", close_connection, is_head);
        return;
    }

    const credentials = maybe_credentials.?;
    if (std.mem.eql(u8, method, "POST") and std.mem.eql(u8, sub_path, "/login")) {
        try handleLoginPost(stream, allocator, cfg, credentials, req, close_connection, callbacks);
        return;
    }
    if (std.mem.eql(u8, method, "POST") and std.mem.eql(u8, sub_path, "/logout")) {
        const cookie = try admin_support.makeAdminClearCookie(allocator, cfg);
        defer allocator.free(cookie);
        try callbacks.send_redirect(stream, allocator, cfg, cookie, close_connection, false);
        return;
    }

    if (!admin_support.adminSessionCookieValid(req.headers, credentials)) {
        if (std.mem.eql(u8, method, "GET") or is_head) {
            try callbacks.send_login_page(stream, allocator, cfg, null, 200, "OK", close_connection, is_head);
            return;
        }
        try callbacks.send_login_page(stream, allocator, cfg, "Sign in before using the admin dashboard.", 401, "Unauthorized", close_connection, false);
        return;
    }

    if (std.mem.eql(u8, method, "POST") and std.mem.eql(u8, sub_path, "/validate")) {
        try handleValidatePost(io, stream, allocator, cfg, credentials, close_connection, callbacks);
        return;
    }
    if (std.mem.eql(u8, method, "POST") and std.mem.eql(u8, sub_path, "/restart")) {
        try handleRestartPost(io, stream, allocator, cfg, credentials, close_connection, callbacks);
        return;
    }
    if (std.mem.eql(u8, method, "POST") and std.mem.eql(u8, sub_path, "/reload")) {
        try handleReloadPost(io, stream, allocator, cfg, credentials, close_connection, callbacks);
        return;
    }
    if (std.mem.eql(u8, method, "POST") and std.mem.eql(u8, sub_path, "/certs/renew")) {
        try handleCertRenewPost(io, stream, allocator, cfg, credentials, close_connection, callbacks);
        return;
    }
    if (std.mem.eql(u8, method, "POST") and std.mem.eql(u8, sub_path, "/cache/purge")) {
        try handleCachePurgePost(io, stream, allocator, cfg, credentials, req, close_connection, callbacks);
        return;
    }
    if (std.mem.eql(u8, method, "POST") and std.mem.eql(u8, sub_path, "/api/cache/purge")) {
        try handleCachePurgeApiPost(stream, allocator, req, close_connection, callbacks);
        return;
    }
    if (std.mem.eql(u8, method, "POST") and std.mem.eql(u8, sub_path, "/upstreams/eject")) {
        try handleUpstreamControlPost(io, stream, allocator, cfg, credentials, req, .eject, close_connection, callbacks);
        return;
    }
    if (std.mem.eql(u8, method, "POST") and std.mem.eql(u8, sub_path, "/upstreams/recover")) {
        try handleUpstreamControlPost(io, stream, allocator, cfg, credentials, req, .recover, close_connection, callbacks);
        return;
    }
    if (std.mem.eql(u8, method, "POST") and std.mem.eql(u8, sub_path, "/sites/add")) {
        try handleAddSitePost(io, stream, allocator, cfg, credentials, req, close_connection, callbacks);
        return;
    }
    if (std.mem.eql(u8, method, "POST") and std.mem.eql(u8, sub_path, "/settings/save")) {
        try handleSettingsPost(io, stream, allocator, cfg, credentials, req, close_connection, callbacks);
        return;
    }

    if (std.mem.eql(u8, method, "GET") or is_head) {
        try callbacks.send_dashboard_page(io, stream, allocator, cfg, credentials, null, null, 200, "OK", close_connection, is_head);
        return;
    }

    try callbacks.send_method_not_allowed(stream, allocator, "GET,HEAD,POST,OPTIONS", close_connection, is_head);
}

fn sendText(stream: std.Io.net.Stream, bytes: []const u8, callbacks: Callbacks) !void {
    try callbacks.write_all(stream, bytes);
    if (bytes.len == 0 or bytes[bytes.len - 1] != '\n') try callbacks.write_all(stream, "\n");
}

fn parseSocketUpstreamAddress(command: []const u8) !admin_upstreams.TargetAddress {
    var tokens = std.mem.tokenizeAny(u8, command, " \t\r\n");
    _ = tokens.next() orelse return error.InvalidUpstreamCommand;
    const scope = tokens.next() orelse return error.InvalidUpstreamCommand;

    if (std.mem.eql(u8, scope, "global")) {
        const index = parseAdminUsize(tokens.next() orelse return error.InvalidUpstreamCommand) catch return error.InvalidUpstreamCommand;
        return .{ .scope = "global", .index = index };
    }
    if (std.mem.eql(u8, scope, "route")) {
        const route = tokens.next() orelse return error.InvalidUpstreamCommand;
        const index = parseAdminUsize(tokens.next() orelse return error.InvalidUpstreamCommand) catch return error.InvalidUpstreamCommand;
        return .{ .scope = "route", .route = route, .index = index };
    }
    if (std.mem.eql(u8, scope, "domain")) {
        const domain = tokens.next() orelse return error.InvalidUpstreamCommand;
        const index = parseAdminUsize(tokens.next() orelse return error.InvalidUpstreamCommand) catch return error.InvalidUpstreamCommand;
        return .{ .scope = "domain", .domain = domain, .index = index };
    }
    if (std.mem.eql(u8, scope, "domain-route")) {
        const domain = tokens.next() orelse return error.InvalidUpstreamCommand;
        const route = tokens.next() orelse return error.InvalidUpstreamCommand;
        const index = parseAdminUsize(tokens.next() orelse return error.InvalidUpstreamCommand) catch return error.InvalidUpstreamCommand;
        return .{ .scope = "domain-route", .domain = domain, .route = route, .index = index };
    }

    return error.InvalidUpstreamCommand;
}

fn parseSocketUpstreamDuration(command: []const u8, address: admin_upstreams.TargetAddress) !u32 {
    var tokens = std.mem.tokenizeAny(u8, command, " \t\r\n");
    _ = tokens.next() orelse return admin_upstreams.DEFAULT_MANUAL_EJECT_MS;
    _ = tokens.next() orelse return admin_upstreams.DEFAULT_MANUAL_EJECT_MS;
    if (std.mem.eql(u8, address.scope, "global")) {
        _ = tokens.next() orelse return admin_upstreams.DEFAULT_MANUAL_EJECT_MS;
    } else if (std.mem.eql(u8, address.scope, "route")) {
        _ = tokens.next() orelse return admin_upstreams.DEFAULT_MANUAL_EJECT_MS;
        _ = tokens.next() orelse return admin_upstreams.DEFAULT_MANUAL_EJECT_MS;
    } else if (std.mem.eql(u8, address.scope, "domain")) {
        _ = tokens.next() orelse return admin_upstreams.DEFAULT_MANUAL_EJECT_MS;
        _ = tokens.next() orelse return admin_upstreams.DEFAULT_MANUAL_EJECT_MS;
    } else if (std.mem.eql(u8, address.scope, "domain-route")) {
        _ = tokens.next() orelse return admin_upstreams.DEFAULT_MANUAL_EJECT_MS;
        _ = tokens.next() orelse return admin_upstreams.DEFAULT_MANUAL_EJECT_MS;
        _ = tokens.next() orelse return admin_upstreams.DEFAULT_MANUAL_EJECT_MS;
    }
    return parseAdminU32OrDefault(tokens.next() orelse "", admin_upstreams.DEFAULT_MANUAL_EJECT_MS) catch error.InvalidUpstreamCommand;
}

fn handleUpstreamControlCommand(stream: std.Io.net.Stream, allocator: std.mem.Allocator, cfg: *ServerConfig, command: []const u8, action: admin_upstreams.ControlAction, callbacks: Callbacks) !void {
    const address = parseSocketUpstreamAddress(command) catch {
        try sendText(stream, "ERROR usage: upstream-eject global <index> [ms] | upstream-eject route <name> <index> [ms] | upstream-eject domain <name> <index> [ms] | upstream-eject domain-route <domain> <route> <index> [ms]\n", callbacks);
        return;
    };
    const duration_ms = parseSocketUpstreamDuration(command, address) catch {
        try sendText(stream, "ERROR upstream duration must be an unsigned millisecond value\n", callbacks);
        return;
    };

    admin_upstreams.applyControl(callbacks.active_io(), cfg, action, address, duration_ms) catch |err| {
        const body = try std.fmt.allocPrint(allocator, "ERROR upstream control failed: {}\n", .{err});
        defer allocator.free(body);
        try sendText(stream, body, callbacks);
        return;
    };

    const message = try upstreamControlMessage(allocator, action, address);
    defer allocator.free(message);
    const body = try std.fmt.allocPrint(allocator, "OK {s}\n", .{message});
    defer allocator.free(body);
    try sendText(stream, body, callbacks);
}

fn appendRedactedConfigFile(io: std.Io, out: *std.ArrayList(u8), allocator: std.mem.Allocator, label: []const u8, path: []const u8, max_bytes: usize) !void {
    try out.print(allocator, "\n--- {s}: {s} ---\n", .{ label, path });
    const content = std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(max_bytes)) catch |err| switch (err) {
        error.FileNotFound => {
            try out.appendSlice(allocator, "missing\n");
            return;
        },
        error.FileTooBig => {
            try out.appendSlice(allocator, "too large to preview\n");
            return;
        },
        else => return err,
    };
    defer allocator.free(content);

    try admin_support.appendRedactedConfigPlain(out, allocator, content);
    if (content.len == 0 or content[content.len - 1] != '\n') try out.append(allocator, '\n');
}

fn appendDomainConfigPreviews(io: std.Io, out: *std.ArrayList(u8), allocator: std.mem.Allocator, cfg: *const ServerConfig) !void {
    const dir_path = cfg.domain_config_dir orelse {
        try out.appendSlice(allocator, "domain_config_dir = <not configured>\n");
        return;
    };
    try out.print(allocator, "domain_config_dir = {s}\n", .{dir_path});

    var dir = std.Io.Dir.cwd().openDir(io, dir_path, .{ .iterate = true }) catch |err| switch (err) {
        error.FileNotFound, error.NotDir => {
            try out.appendSlice(allocator, "domain_config_dir_status = missing\n");
            return;
        },
        else => return err,
    };
    defer dir.close(io);

    var found = false;
    var count: usize = 0;
    var it = dir.iterate();
    while (try it.next(io)) |entry| {
        if (!isDomainConfigFileName(entry.name)) continue;
        found = true;
        const path = try std.fs.path.join(allocator, &.{ dir_path, entry.name });
        defer allocator.free(path);
        try appendRedactedConfigFile(io, out, allocator, "domain", path, admin_support.ADMIN_SITE_CONFIG_MAX_BYTES);
        count += 1;
        if (count >= 64) {
            try out.appendSlice(allocator, "domain_config_status = truncated after 64 files\n");
            break;
        }
    }
    if (!found) try out.appendSlice(allocator, "domain_files = <none>\n");
}

fn renderRedactedConfig(io: std.Io, allocator: std.mem.Allocator, cfg: *const ServerConfig) ![]const u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);

    try out.appendSlice(allocator, "Layerline redacted config\n");
    try out.print(allocator, "main_config = {s}\n", .{cfg.config_path});
    try appendDomainConfigPreviews(io, &out, allocator, cfg);
    try appendRedactedConfigFile(io, &out, allocator, "main", cfg.config_path, admin_support.ADMIN_MAIN_CONFIG_MAX_BYTES);

    return out.toOwnedSlice(allocator);
}

fn handleCommand(stream: std.Io.net.Stream, allocator: std.mem.Allocator, cfg: *ServerConfig, command_raw: []const u8, callbacks: Callbacks) !void {
    const command = trimValue(command_raw);
    var token_it = std.mem.tokenizeAny(u8, command, " \t\r\n");
    const verb = token_it.next() orelse "";
    if (command.len == 0 or std.mem.eql(u8, verb, "help")) {
        try sendText(stream, "commands: status, validate, validate-runtime, diff, config, cache-purge, reload, restart, routes, upstreams, upstream-eject, upstream-recover, certs, cert-renew, metrics, help\n", callbacks);
        return;
    }

    if (std.mem.eql(u8, verb, "status")) {
        const body = try admin_pages.renderStatus(allocator, cfg, callbacks.runtime_view());
        defer allocator.free(body);
        try sendText(stream, body, callbacks);
        return;
    }

    if (std.mem.eql(u8, verb, "validate") or std.mem.eql(u8, verb, "validate-config")) {
        callbacks.validate_activation(callbacks.active_io(), allocator, cfg) catch |err| {
            const body = try std.fmt.allocPrint(allocator, "ERROR config invalid: {}\n", .{err});
            defer allocator.free(body);
            try sendText(stream, body, callbacks);
            return;
        };
        try sendText(stream, "OK activation config\n", callbacks);
        return;
    }

    if (std.mem.eql(u8, verb, "validate-runtime")) {
        callbacks.validate_runtime(cfg) catch |err| {
            const body = try std.fmt.allocPrint(allocator, "ERROR runtime config invalid: {}\n", .{err});
            defer allocator.free(body);
            try sendText(stream, body, callbacks);
            return;
        };
        try sendText(stream, "OK runtime config\n", callbacks);
        return;
    }

    if (std.mem.eql(u8, verb, "config") or std.mem.eql(u8, verb, "config-redacted") or std.mem.eql(u8, verb, "redacted-config") or std.mem.eql(u8, verb, "main-config")) {
        const body = renderRedactedConfig(callbacks.active_io(), allocator, cfg) catch |err| {
            const error_body = try std.fmt.allocPrint(allocator, "ERROR config unavailable: {}\n", .{err});
            defer allocator.free(error_body);
            try sendText(stream, error_body, callbacks);
            return;
        };
        defer allocator.free(body);
        try sendText(stream, body, callbacks);
        return;
    }

    if (std.mem.eql(u8, verb, "diff") or std.mem.eql(u8, verb, "config-diff") or std.mem.eql(u8, verb, "activation-diff")) {
        const body = callbacks.render_config_diff(callbacks.active_io(), allocator, cfg) catch |err| {
            const error_body = try std.fmt.allocPrint(allocator, "ERROR config diff unavailable: {}\n", .{err});
            defer allocator.free(error_body);
            try sendText(stream, error_body, callbacks);
            return;
        };
        defer allocator.free(body);
        try sendText(stream, body, callbacks);
        return;
    }

    if (std.mem.eql(u8, verb, "restart") or std.mem.eql(u8, verb, "graceful-restart")) {
        callbacks.validate_activation(callbacks.active_io(), allocator, cfg) catch |err| {
            const body = try std.fmt.allocPrint(allocator, "ERROR restart blocked: {}\n", .{err});
            defer allocator.free(body);
            try sendText(stream, body, callbacks);
            return;
        };
        try sendText(stream, "OK graceful restart requested\n", callbacks);
        callbacks.request_restart();
        return;
    }

    if (std.mem.eql(u8, verb, "reload")) {
        callbacks.reload_config(callbacks.active_io(), allocator, cfg) catch |err| {
            const body = try std.fmt.allocPrint(allocator, "ERROR reload blocked: {}\n", .{err});
            defer allocator.free(body);
            try sendText(stream, body, callbacks);
            return;
        };
        try sendText(stream, "OK config reloaded\n", callbacks);
        return;
    }

    if (std.mem.eql(u8, verb, "cache-purge") or std.mem.eql(u8, verb, "purge-cache") or std.mem.eql(u8, verb, "purge-caches")) {
        const raw_target = token_it.next() orelse "";
        const target = if (std.ascii.eqlIgnoreCase(raw_target, "all")) "" else raw_target;
        const removed = callbacks.purge_caches(target);
        const body = if (target.len == 0)
            try std.fmt.allocPrint(allocator, "OK purged {d} cache entries\n", .{removed})
        else
            try std.fmt.allocPrint(allocator, "OK purged {d} cache entries matching {s}\n", .{ removed, target });
        defer allocator.free(body);
        try sendText(stream, body, callbacks);
        return;
    }

    if (std.mem.eql(u8, verb, "routes")) {
        const body = try admin_pages.renderRoutes(allocator, cfg);
        defer allocator.free(body);
        try sendText(stream, body, callbacks);
        return;
    }

    if (std.mem.eql(u8, verb, "upstreams")) {
        const body = try admin_upstreams.renderReport(callbacks.active_io(), allocator, cfg);
        defer allocator.free(body);
        try sendText(stream, body, callbacks);
        return;
    }

    if (std.mem.eql(u8, verb, "upstream-eject") or std.mem.eql(u8, verb, "upstream-drain")) {
        try handleUpstreamControlCommand(stream, allocator, cfg, command, .eject, callbacks);
        return;
    }

    if (std.mem.eql(u8, verb, "upstream-recover")) {
        try handleUpstreamControlCommand(stream, allocator, cfg, command, .recover, callbacks);
        return;
    }

    if (std.mem.eql(u8, verb, "certs") or std.mem.eql(u8, verb, "certificates")) {
        const body = try admin_pages.renderCerts(allocator, cfg, callbacks.runtime_view());
        defer allocator.free(body);
        try sendText(stream, body, callbacks);
        return;
    }

    if (std.mem.eql(u8, verb, "cert-renew") or std.mem.eql(u8, verb, "renew-certs") or std.mem.eql(u8, verb, "acme-renew")) {
        callbacks.renew_certs(callbacks.active_io(), allocator, cfg) catch |err| {
            const body = try std.fmt.allocPrint(allocator, "ERROR certificate renewal failed: {}\n", .{err});
            defer allocator.free(body);
            try sendText(stream, body, callbacks);
            return;
        };
        try sendText(stream, "OK certificate renewal completed and TLS material reloaded\n", callbacks);
        return;
    }

    if (std.mem.eql(u8, verb, "metrics")) {
        const body = try callbacks.render_metrics(allocator);
        defer allocator.free(body);
        try sendText(stream, body, callbacks);
        return;
    }

    try sendText(stream, "ERROR unknown command\n", callbacks);
}

fn handleConnection(stream: std.Io.net.Stream, allocator: std.mem.Allocator, cfg: *ServerConfig, callbacks: Callbacks) !void {
    callbacks.set_stream_timeouts(stream, 1_000, 1_000) catch {};
    var buffer: [1024]u8 = undefined;
    const n = try callbacks.read_stream(stream, &buffer);
    if (n == 0) return;
    _ = cfg;
    try handleCommand(stream, allocator, callbacks.active_config(), buffer[0..n], callbacks);
}

pub fn unlinkUnixSocket(path: []const u8, callbacks: Callbacks) void {
    if (builtin.os.tag == .windows) return;
    std.Io.Dir.deleteFileAbsolute(callbacks.active_io(), path) catch {};
}

pub fn serveSocketTask(ctx: SocketContext) void {
    ctx.callbacks.bind_thread_io(ctx.io);
    unlinkUnixSocket(ctx.socket_path, ctx.callbacks);

    const address = std.Io.net.UnixAddress.init(ctx.socket_path) catch |err| {
        std.debug.print("Admin socket path invalid: {s}: {}\n", .{ ctx.socket_path, err });
        return;
    };
    var server = address.listen(ctx.io, .{ .kernel_backlog = 16 }) catch |err| {
        std.debug.print("Admin socket listen failed: {s}: {}\n", .{ ctx.socket_path, err });
        return;
    };
    defer {
        server.deinit(ctx.io);
        unlinkUnixSocket(ctx.socket_path, ctx.callbacks);
    }

    std.debug.print("Admin socket: {s}\n", .{ctx.socket_path});
    while (!ctx.callbacks.shutdown_requested.load(.acquire)) {
        const conn = server.accept(ctx.io) catch |err| {
            if (ctx.callbacks.shutdown_requested.load(.acquire)) break;
            std.debug.print("Admin socket accept failed: {}\n", .{err});
            ctx.io.sleep(.fromMilliseconds(50), .awake) catch {};
            continue;
        };
        handleConnection(conn, std.heap.page_allocator, ctx.cfg, ctx.callbacks) catch |err| {
            std.debug.print("Admin command failed: {}\n", .{err});
        };
        ctx.callbacks.close_stream(conn);
    }
}
