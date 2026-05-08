const std = @import("std");
const cgi_headers = @import("cgi_headers.zig");
const config_mod = @import("config.zig");
const fastcgi = @import("fastcgi.zig");
const h2_native = @import("h2_native.zig");
const h2_support = @import("http2_support.zig");
const http_headers = @import("http_headers.zig");
const http_response = @import("http_response.zig");
const metrics_mod = @import("metrics.zig");
const request_mod = @import("request.zig");

const FastcgiIdleConnection = config_mod.FastcgiIdleConnection;
const FastcgiKeepAlivePool = config_mod.FastcgiKeepAlivePool;
const H2BufferedResponse = h2_support.BufferedResponse;
const HttpRequest = request_mod.HttpRequest;
const PhpFastcgiEndpoint = config_mod.PhpFastcgiEndpoint;
const RouteConfig = config_mod.RouteConfig;
const ServerConfig = config_mod.ServerConfig;

pub const Callbacks = struct {
    active_io: *const fn () std.Io,
    connect_fastcgi_endpoint: *const fn (std.mem.Allocator, PhpFastcgiEndpoint) anyerror!std.Io.net.Stream,
    current_request_id: *const fn () []const u8,
    fastcgi_pool: *FastcgiKeepAlivePool,
    h2_error_response: *const fn (std.mem.Allocator, u16, []const u8, []const u8) anyerror!H2BufferedResponse,
    metrics: *metrics_mod.ServerMetrics,
    now_ms: *const fn () i64,
    send_cool_error: *const fn (std.Io.net.Stream, std.mem.Allocator, u16, []const u8, []const u8, bool, bool, ?[]const u8) anyerror!void,
    send_not_found_for_method: *const fn (std.mem.Allocator, std.Io.net.Stream, bool, bool) anyerror!void,
    send_response: *const fn (std.Io.net.Stream, u16, []const u8, []const u8, []const u8, bool) anyerror!void,
    send_response_headers: *const fn (std.Io.net.Stream, u16, []const u8, []const u8, []const u8, bool, ?[]const u8) anyerror!void,
    send_response_no_body: *const fn (std.Io.net.Stream, u16, []const u8, []const u8, usize, bool) anyerror!void,
    send_response_no_body_headers: *const fn (std.Io.net.Stream, u16, []const u8, []const u8, usize, bool, ?[]const u8) anyerror!void,
    server_header: []const u8,
    set_stream_timeouts: *const fn (std.Io.net.Stream, u32, u32) anyerror!void,
    stderr_limit: usize,
    stream_close: *const fn (std.Io.net.Stream) void,
    stream_read: *const fn (std.Io.net.Stream, []u8) anyerror!usize,
    stream_write_all: *const fn (std.Io.net.Stream, []const u8) anyerror!void,
};

const FastcgiConnectionLease = struct {
    stream: std.Io.net.Stream,
    requests_served: usize,
};

fn fastcgiKeepaliveConfigured(cfg: *const ServerConfig) bool {
    return cfg.fastcgi_keepalive_enabled and cfg.fastcgi_keepalive_max_idle > 0;
}

fn closeIdleFastcgiConnection(conn: FastcgiIdleConnection, callbacks: Callbacks) void {
    callbacks.stream_close(conn.stream);
    callbacks.metrics.fastcgiConnectionDiscarded();
}

fn fastcgiAcquireConnection(allocator: std.mem.Allocator, endpoint_name: []const u8, endpoint: PhpFastcgiEndpoint, cfg: *const ServerConfig, timeout_ms: u32, now_ms: i64, callbacks: Callbacks) !FastcgiConnectionLease {
    if (fastcgiKeepaliveConfigured(cfg)) {
        const io = callbacks.active_io();
        callbacks.fastcgi_pool.mutex.lockUncancelable(io);
        defer callbacks.fastcgi_pool.mutex.unlock(io);

        var index: usize = 0;
        while (index < callbacks.fastcgi_pool.idle.items.len) {
            const conn = callbacks.fastcgi_pool.idle.items[index];
            if (conn.expires_at_ms <= now_ms or conn.requests_served >= cfg.fastcgi_keepalive_max_requests) {
                closeIdleFastcgiConnection(callbacks.fastcgi_pool.idle.orderedRemove(index), callbacks);
                continue;
            }
            if (std.mem.eql(u8, conn.endpoint_name, endpoint_name)) {
                const reused = callbacks.fastcgi_pool.idle.orderedRemove(index);
                callbacks.set_stream_timeouts(reused.stream, timeout_ms, timeout_ms) catch |err| {
                    closeIdleFastcgiConnection(reused, callbacks);
                    return err;
                };
                callbacks.metrics.fastcgiConnectionReused();
                return .{
                    .stream = reused.stream,
                    .requests_served = reused.requests_served,
                };
            }
            index += 1;
        }
    }

    const conn = try callbacks.connect_fastcgi_endpoint(allocator, endpoint);
    try callbacks.set_stream_timeouts(conn, timeout_ms, timeout_ms);
    callbacks.metrics.fastcgiConnectionOpened();
    return .{
        .stream = conn,
        .requests_served = 0,
    };
}

fn fastcgiReleaseConnection(endpoint_name: []const u8, cfg: *const ServerConfig, lease: FastcgiConnectionLease, reusable: bool, now_ms: i64, callbacks: Callbacks) void {
    if (!reusable or !fastcgiKeepaliveConfigured(cfg)) {
        callbacks.stream_close(lease.stream);
        callbacks.metrics.fastcgiConnectionDiscarded();
        return;
    }

    const served = lease.requests_served + 1;
    if (served >= cfg.fastcgi_keepalive_max_requests) {
        callbacks.stream_close(lease.stream);
        callbacks.metrics.fastcgiConnectionDiscarded();
        return;
    }

    const idle_conn = FastcgiIdleConnection{
        .stream = lease.stream,
        .endpoint_name = endpoint_name,
        .expires_at_ms = now_ms + @as(i64, @intCast(cfg.fastcgi_keepalive_idle_timeout_ms)),
        .requests_served = served,
    };

    const io = callbacks.active_io();
    callbacks.fastcgi_pool.mutex.lockUncancelable(io);
    defer callbacks.fastcgi_pool.mutex.unlock(io);

    while (callbacks.fastcgi_pool.idle.items.len >= cfg.fastcgi_keepalive_max_idle) {
        closeIdleFastcgiConnection(callbacks.fastcgi_pool.idle.orderedRemove(0), callbacks);
    }

    callbacks.fastcgi_pool.idle.append(std.heap.page_allocator, idle_conn) catch {
        callbacks.stream_close(idle_conn.stream);
        callbacks.metrics.fastcgiConnectionDiscarded();
        return;
    };
    callbacks.metrics.fastcgiConnectionPooled();
}

fn sendPhpOutput(stream: std.Io.net.Stream, allocator: std.mem.Allocator, output: []const u8, close_connection: bool, is_head: bool, callbacks: Callbacks) !void {
    const split = cgi_headers.splitHeaderBlock(output) orelse {
        if (is_head) {
            try callbacks.send_response_no_body(stream, 200, "OK", "text/plain; charset=utf-8", output.len, close_connection);
        } else {
            try callbacks.send_response(stream, 200, "OK", "text/plain; charset=utf-8", output, close_connection);
        }
        return;
    };

    const headers = split.headers;
    const body = split.body;

    const status = cgi_headers.parseStatus(headers);
    const ctype_out = cgi_headers.findHeaderValue(headers, "Content-Type") orelse "text/plain; charset=utf-8";
    const extra_headers = try cgi_headers.buildExtraHeaders(allocator, headers);
    defer if (extra_headers) |h| allocator.free(h);

    if (http_response.canSendBody(status.code, is_head)) {
        try callbacks.send_response_headers(stream, status.code, status.text, ctype_out, body, close_connection, extra_headers);
    } else {
        const declared_len = if (is_head) body.len else 0;
        try callbacks.send_response_no_body_headers(stream, status.code, status.text, ctype_out, declared_len, close_connection, extra_headers);
    }
}

fn collectCgiHttp2Headers(allocator: std.mem.Allocator, headers: []const u8) ![]h2_native.Header {
    var out = std.ArrayList(h2_native.Header).empty;
    errdefer out.deinit(allocator);

    var lines = std.mem.splitScalar(u8, headers, '\n');
    while (lines.next()) |line| {
        const trimmed = http_headers.trimValue(line);
        if (trimmed.len == 0) continue;
        if (std.mem.indexOfScalar(u8, trimmed, ':')) |colon| {
            const name = http_headers.trimValue(trimmed[0..colon]);
            const value = http_headers.trimValue(trimmed[colon + 1 ..]);
            if (name.len == 0 or value.len == 0 or cgi_headers.isSkippedResponseHeader(name) or h2_support.isSkippedResponseHeader(name)) continue;
            try out.append(allocator, .{
                .name = try allocator.dupe(u8, name),
                .value = try allocator.dupe(u8, value),
            });
        }
    }

    return out.toOwnedSlice(allocator);
}

fn h2PhpOutputResponse(allocator: std.mem.Allocator, output: []const u8) !H2BufferedResponse {
    const split = cgi_headers.splitHeaderBlock(output) orelse {
        return .{
            .status_code = 200,
            .content_type = "text/plain; charset=utf-8",
            .body = try allocator.dupe(u8, output),
        };
    };

    const status = cgi_headers.parseStatus(split.headers);
    const content_type = if (cgi_headers.findHeaderValue(split.headers, "Content-Type")) |ctype|
        try allocator.dupe(u8, http_headers.trimValue(ctype))
    else
        "text/plain; charset=utf-8";
    const headers = try collectCgiHttp2Headers(allocator, split.headers);

    return .{
        .status_code = status.code,
        .content_type = content_type,
        .body = try allocator.dupe(u8, split.body),
        .headers = headers,
    };
}

fn runFastcgiRequest(
    allocator: std.mem.Allocator,
    cfg: *const ServerConfig,
    req: HttpRequest,
    php_root: []const u8,
    php_fastcgi: []const u8,
    script_path: []const u8,
    script_name: []const u8,
    path_info: []const u8,
    timeout_ms: u32,
    callbacks: Callbacks,
) !fastcgi.RunResult {
    const endpoint = config_mod.parseFastcgiEndpoint(php_fastcgi) catch return error.InvalidFastcgiEndpoint;

    const lease = fastcgiAcquireConnection(allocator, php_fastcgi, endpoint, cfg, timeout_ms, callbacks.now_ms(), callbacks) catch return error.FastcgiConnectFailed;
    const conn = lease.stream;
    var reusable_fastcgi_conn = false;
    defer fastcgiReleaseConnection(php_fastcgi, cfg, lease, reusable_fastcgi_conn, callbacks.now_ms(), callbacks);

    const request_id: u16 = 1;
    const begin_body = [_]u8{ 0, @intCast(fastcgi.RESPONDER), if (fastcgiKeepaliveConfigured(cfg)) fastcgi.KEEP_CONN else 0, 0, 0, 0, 0, 0 };
    try fastcgi.writeRecord(conn, fastcgi.BEGIN_REQUEST, request_id, &begin_body, callbacks.stream_write_all);

    const params = try fastcgi.buildParams(allocator, .{
        .server_header = callbacks.server_header,
        .current_request_id = callbacks.current_request_id(),
        .server_host = cfg.host,
        .server_port = cfg.port,
        .method = req.method,
        .path = req.path,
        .query = req.query,
        .version = req.version,
        .headers = req.headers,
        .body_len = req.body.len,
    }, php_root, script_path, script_name, path_info);
    defer allocator.free(params);
    try fastcgi.writeRecord(conn, fastcgi.PARAMS, request_id, params, callbacks.stream_write_all);
    try fastcgi.writeRecord(conn, fastcgi.PARAMS, request_id, "", callbacks.stream_write_all);
    if (req.body.len > 0) try fastcgi.writeRecord(conn, fastcgi.STDIN, request_id, req.body, callbacks.stream_write_all);
    try fastcgi.writeRecord(conn, fastcgi.STDIN, request_id, "", callbacks.stream_write_all);

    const result = try fastcgi.readResponse(allocator, conn, request_id, cfg.max_php_output_bytes, callbacks.stderr_limit, callbacks.stream_read);
    errdefer result.deinit(allocator);

    if (result.protocol_status != fastcgi.REQUEST_COMPLETE) return error.FastcgiProtocolFailed;
    if (result.app_status != 0) return error.FastcgiAppFailed;

    reusable_fastcgi_conn = fastcgiKeepaliveConfigured(cfg);
    return result;
}

fn handleFastcgi(
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    cfg: *const ServerConfig,
    req: HttpRequest,
    php_root: []const u8,
    php_fastcgi: []const u8,
    script_path: []const u8,
    script_name: []const u8,
    path_info: []const u8,
    timeout_ms: u32,
    close_connection: bool,
    is_head: bool,
    callbacks: Callbacks,
) !void {
    const result = runFastcgiRequest(allocator, cfg, req, php_root, php_fastcgi, script_path, script_name, path_info, timeout_ms, callbacks) catch |err| switch (err) {
        error.InvalidFastcgiEndpoint => {
            try callbacks.send_cool_error(stream, allocator, 500, "Server Error", "PHP FastCGI endpoint is invalid.", close_connection, is_head, null);
            return;
        },
        error.FastcgiConnectFailed => {
            std.debug.print("PHP FastCGI connect failed for {s}\n", .{php_fastcgi});
            try callbacks.send_cool_error(stream, allocator, 502, "Bad Gateway", "PHP FastCGI worker could not be reached.", close_connection, is_head, null);
            return;
        },
        error.StreamTooLong => {
            try callbacks.send_cool_error(stream, allocator, 502, "Bad Gateway", "PHP FastCGI response exceeded max_php_output_bytes.", close_connection, is_head, null);
            return;
        },
        error.FastcgiProtocolFailed => {
            try callbacks.send_cool_error(stream, allocator, 502, "Bad Gateway", "PHP FastCGI request did not complete cleanly.", close_connection, is_head, null);
            return;
        },
        error.FastcgiAppFailed => {
            try callbacks.send_cool_error(stream, allocator, 502, "Bad Gateway", "PHP FastCGI app returned a non-zero status.", close_connection, is_head, null);
            return;
        },
        else => |e| return e,
    };
    defer result.deinit(allocator);

    if (result.stderr.len > 0) {
        std.debug.print("PHP FastCGI stderr: {s}\n", .{result.stderr});
    }

    try sendPhpOutput(stream, allocator, result.stdout, close_connection, is_head, callbacks);
}

pub fn buildHttp2FastcgiResponse(
    io: std.Io,
    allocator: std.mem.Allocator,
    cfg: *const ServerConfig,
    req: HttpRequest,
    php_root: []const u8,
    php_fastcgi: ?[]const u8,
    script_rel_path: []const u8,
    script_name: []const u8,
    path_info: []const u8,
    timeout_ms: u32,
    callbacks: Callbacks,
) !H2BufferedResponse {
    const endpoint = php_fastcgi orelse return callbacks.h2_error_response(allocator, 501, "Not Implemented", "Native HTTP/2 PHP routing currently requires FastCGI.");
    if (config_mod.disablesOptionalUrl(endpoint)) return callbacks.h2_error_response(allocator, 501, "Not Implemented", "Native HTTP/2 PHP routing currently requires FastCGI.");

    const rel_path = script_rel_path;
    if (rel_path.len == 0 or std.mem.indexOf(u8, rel_path, "..") != null) {
        return callbacks.h2_error_response(allocator, 404, "Not Found", "The requested resource was not found on this server.");
    }

    const script_path = try std.fs.path.join(allocator, &.{ php_root, rel_path });
    defer allocator.free(script_path);

    const script_stat = std.Io.Dir.cwd().statFile(io, script_path, .{}) catch {
        return callbacks.h2_error_response(allocator, 404, "Not Found", "The requested resource was not found on this server.");
    };
    if (script_stat.kind != .file) {
        return callbacks.h2_error_response(allocator, 404, "Not Found", "The requested resource was not found on this server.");
    }

    const result = runFastcgiRequest(allocator, cfg, req, php_root, endpoint, script_path, script_name, path_info, timeout_ms, callbacks) catch |err| switch (err) {
        error.InvalidFastcgiEndpoint => return callbacks.h2_error_response(allocator, 500, "Server Error", "PHP FastCGI endpoint is invalid."),
        error.FastcgiConnectFailed => return callbacks.h2_error_response(allocator, 502, "Bad Gateway", "PHP FastCGI worker could not be reached."),
        error.StreamTooLong => return callbacks.h2_error_response(allocator, 502, "Bad Gateway", "PHP FastCGI response exceeded max_php_output_bytes."),
        error.FastcgiProtocolFailed => return callbacks.h2_error_response(allocator, 502, "Bad Gateway", "PHP FastCGI request did not complete cleanly."),
        error.FastcgiAppFailed => return callbacks.h2_error_response(allocator, 502, "Bad Gateway", "PHP FastCGI app returned a non-zero status."),
        else => |e| return e,
    };
    defer result.deinit(allocator);

    if (result.stderr.len > 0) {
        std.debug.print("PHP FastCGI stderr: {s}\n", .{result.stderr});
    }

    return h2PhpOutputResponse(allocator, result.stdout);
}

pub fn handleFrontController(
    io: std.Io,
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    cfg: *const ServerConfig,
    req: HttpRequest,
    route_config: ?*const RouteConfig,
    php_root: []const u8,
    php_binary: []const u8,
    php_fastcgi: ?[]const u8,
    timeout_ms: u32,
    php_index: []const u8,
    close_connection: bool,
    is_head: bool,
    process_env: *const std.process.Environ.Map,
    callbacks: Callbacks,
) !void {
    const target = try fastcgi.makePhpFrontControllerTarget(allocator, route_config, req.path, php_index);
    defer target.deinit(allocator);
    try handleScript(io, stream, allocator, cfg, req, php_root, php_binary, php_fastcgi, timeout_ms, target.script_rel_path, target.script_name, target.path_info, close_connection, is_head, process_env, callbacks);
}

pub fn handleScript(
    io: std.Io,
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    cfg: *const ServerConfig,
    req: HttpRequest,
    php_root: []const u8,
    php_binary: []const u8,
    php_fastcgi: ?[]const u8,
    timeout_ms: u32,
    script_rel_path: []const u8,
    script_name: []const u8,
    path_info: []const u8,
    close_connection: bool,
    is_head: bool,
    process_env: *const std.process.Environ.Map,
    callbacks: Callbacks,
) !void {
    const rel_path = script_rel_path;
    if (rel_path.len == 0 or std.mem.indexOf(u8, rel_path, "..") != null) {
        try callbacks.send_not_found_for_method(allocator, stream, close_connection, is_head);
        return;
    }

    const script_path = try std.fs.path.join(allocator, &.{ php_root, rel_path });
    defer allocator.free(script_path);

    const script_stat = std.Io.Dir.cwd().statFile(io, script_path, .{}) catch {
        try callbacks.send_not_found_for_method(allocator, stream, close_connection, is_head);
        return;
    };
    if (script_stat.kind != .file) {
        try callbacks.send_not_found_for_method(allocator, stream, close_connection, is_head);
        return;
    }

    if (php_fastcgi) |endpoint| {
        if (!config_mod.disablesOptionalUrl(endpoint)) {
            try handleFastcgi(stream, allocator, cfg, req, php_root, endpoint, script_path, script_name, path_info, timeout_ms, close_connection, is_head, callbacks);
            return;
        }
    }

    if (php_binary.len == 0) {
        try callbacks.send_cool_error(stream, allocator, 500, "Server Error", "PHP support is not configured for this server.", close_connection, is_head, null);
        return;
    }

    var argv = std.ArrayList([]const u8).empty;
    defer argv.deinit(allocator);

    try argv.append(allocator, php_binary);
    if (!cgi_headers.isPhpCgiBinary(php_binary)) {
        try argv.append(allocator, "-f");
        try argv.append(allocator, script_path);
    }

    var child_env = try process_env.clone(allocator);
    defer child_env.deinit();

    const request_uri = try std.fmt.allocPrint(allocator, "{s}{s}{s}", .{
        req.path,
        if (req.query.len > 0) "?" else "",
        req.query,
    });
    defer allocator.free(request_uri);

    const content_length = try std.fmt.allocPrint(allocator, "{d}", .{req.body.len});
    defer allocator.free(content_length);

    const server_port = try std.fmt.allocPrint(allocator, "{d}", .{cfg.port});
    defer allocator.free(server_port);

    try child_env.put("GATEWAY_INTERFACE", "CGI/1.1");
    try child_env.put("SERVER_SOFTWARE", callbacks.server_header);
    try child_env.put("SERVER_NAME", cfg.host);
    try child_env.put("SERVER_PORT", server_port);
    try child_env.put("SERVER_PROTOCOL", req.version);
    try child_env.put("REQUEST_METHOD", req.method);
    try child_env.put("REQUEST_URI", request_uri);
    const path_translated = if (path_info.len > 0 and path_info[0] == '/') blk: {
        const translated_rel = path_info[1..];
        break :blk try std.fs.path.join(allocator, &.{ php_root, translated_rel });
    } else try allocator.dupe(u8, script_path);
    defer allocator.free(path_translated);

    try child_env.put("SCRIPT_NAME", script_name);
    try child_env.put("SCRIPT_FILENAME", script_path);
    try child_env.put("PHP_SELF", script_name);
    try child_env.put("PATH_TRANSLATED", path_translated);
    try child_env.put("PATH_INFO", path_info);
    try child_env.put("QUERY_STRING", req.query);
    try child_env.put("DOCUMENT_ROOT", php_root);
    try child_env.put("REQUEST_SCHEME", "http");
    try child_env.put("HTTPS", "off");
    try child_env.put("REDIRECT_STATUS", "200");
    try child_env.put("CONTENT_LENGTH", content_length);
    try child_env.put("CONTENT_TYPE", http_headers.findHeaderValue(req.headers, "Content-Type") orelse "");
    try cgi_headers.putRequestHeaders(allocator, &child_env, req.headers);
    if (callbacks.current_request_id().len > 0) try child_env.put("HTTP_X_REQUEST_ID", callbacks.current_request_id());

    // PHP-CGI wants the script in the CGI environment. Plain `php` gets a
    // script argument as a fallback for local development setups.
    var child = std.process.spawn(io, .{
        .argv = argv.items,
        .environ_map = &child_env,
        .stdin = .pipe,
        .stdout = .pipe,
        .stderr = .inherit,
    }) catch |err| {
        std.debug.print("PHP spawn failed for {s}: {}\n", .{ php_binary, err });
        try callbacks.send_cool_error(
            stream,
            allocator,
            502,
            "Bad Gateway",
            "PHP worker could not be started. Check php_bin and make sure php-cgi is installed or configured with an absolute path.",
            close_connection,
            is_head,
            null,
        );
        return;
    };
    defer child.kill(io);

    if (child.stdin) |in_pipe| {
        var in_writer = in_pipe.writer(io, &.{});
        if (req.body.len > 0) {
            try in_writer.interface.writeAll(req.body);
        }
        in_pipe.close(io);
    }

    const max_output = cfg.max_php_output_bytes;
    const output = if (child.stdout) |out_pipe| blk: {
        var out_reader = out_pipe.reader(io, &.{});
        const captured_output = out_reader.interface.allocRemaining(allocator, .limited(max_output)) catch |err| switch (err) {
            error.StreamTooLong => {
                try callbacks.send_cool_error(
                    stream,
                    allocator,
                    502,
                    "Bad Gateway",
                    "PHP response exceeded max_php_output_bytes.",
                    close_connection,
                    is_head,
                    null,
                );
                return;
            },
            else => |e| return e,
        };
        break :blk captured_output;
    } else return error.InternalServerError;
    defer allocator.free(output);
    if (child.stdout) |out_pipe| out_pipe.close(io);

    const term = try child.wait(io);
    switch (term) {
        .exited => |code| {
            if (code != 0) {
                try callbacks.send_cool_error(
                    stream,
                    allocator,
                    502,
                    "Bad Gateway",
                    "PHP process exited with a non-zero status.",
                    close_connection,
                    is_head,
                    null,
                );
                return;
            }
        },
        .signal, .stopped, .unknown => {
            try callbacks.send_cool_error(
                stream,
                allocator,
                502,
                "Bad Gateway",
                "PHP process terminated abnormally.",
                close_connection,
                is_head,
                null,
            );
            return;
        },
    }

    try sendPhpOutput(stream, allocator, output, close_connection, is_head, callbacks);
}
