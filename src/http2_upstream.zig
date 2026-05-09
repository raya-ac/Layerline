const std = @import("std");

const config_mod = @import("config.zig");
const h2_native = @import("h2_native.zig");
const h2_support = @import("http2_support.zig");
const http_headers = @import("http_headers.zig");
const metrics_mod = @import("metrics.zig");
const proxy_utils = @import("proxy_utils.zig");
const request_mod = @import("request.zig");
const upstream_mod = @import("upstream.zig");

const H2BufferedResponse = h2_support.BufferedResponse;
const ServerConfig = config_mod.ServerConfig;
const ServerMetrics = metrics_mod.ServerMetrics;
const UpstreamConfig = config_mod.UpstreamConfig;
const UpstreamPoolConfig = config_mod.UpstreamPoolConfig;
const UpstreamPoolPolicy = config_mod.UpstreamPoolPolicy;
const UpstreamRuntimePolicy = config_mod.UpstreamRuntimePolicy;

const DEFAULT_MAX_REQUEST_BYTES = 16 * 1024;

pub const Callbacks = struct {
    access_log_set_upstream: *const fn ([]const u8) void,
    connect_tcp_host: *const fn (std.mem.Allocator, []const u8, u16) anyerror!std.Io.net.Stream,
    current_request_id: *const fn () []const u8,
    error_response: *const fn (std.mem.Allocator, u16, []const u8, []const u8) anyerror!H2BufferedResponse,
    metrics: *ServerMetrics,
    set_stream_timeouts: *const fn (std.Io.net.Stream, u32, u32) anyerror!void,
    stream_close: *const fn (std.Io.net.Stream) void,
    stream_read: *const fn (std.Io.net.Stream, []u8) anyerror!usize,
    stream_write_all: *const fn (std.Io.net.Stream, []const u8) anyerror!void,
    upstream_now_ms: *const fn () i64,
};

fn appendForwardedRequestHeaders(
    allocator: std.mem.Allocator,
    out: *std.ArrayList(u8),
    req: request_mod.HttpRequest,
    upstream: *const UpstreamConfig,
    cfg: *const ServerConfig,
    callbacks: Callbacks,
) !void {
    const forwarded_host = http_headers.findHeaderValue(req.headers, "Host") orelse upstream.host;
    const forwarded_proto = if (http_headers.findHeaderValue(req.headers, "X-Forwarded-Proto")) |proto|
        http_headers.trimValue(proto)
    else if (cfg.tls_enabled)
        "https"
    else
        "http";

    try out.print(allocator, "Host: {s}\r\nConnection: close\r\n", .{http_headers.trimValue(forwarded_host)});

    var saw_forwarded_host = false;
    var saw_forwarded_proto = false;
    var headers = std.mem.splitSequence(u8, req.headers, "\r\n");
    while (headers.next()) |line| {
        const trimmed = http_headers.trimValue(line);
        if (trimmed.len == 0) continue;
        if (std.mem.indexOfScalar(u8, trimmed, ':')) |colon| {
            const name = http_headers.trimValue(trimmed[0..colon]);
            if (proxy_utils.isSkippedProxyHeader(name)) continue;
            const value = http_headers.trimValue(trimmed[colon + 1 ..]);
            if (value.len == 0) continue;
            if (std.ascii.eqlIgnoreCase(name, "X-Forwarded-Host")) saw_forwarded_host = true;
            if (std.ascii.eqlIgnoreCase(name, "X-Forwarded-Proto")) saw_forwarded_proto = true;
            try out.print(allocator, "{s}: {s}\r\n", .{ name, value });
        }
    }
    if (!saw_forwarded_host) try out.print(allocator, "X-Forwarded-Host: {s}\r\n", .{http_headers.trimValue(forwarded_host)});
    if (!saw_forwarded_proto) try out.print(allocator, "X-Forwarded-Proto: {s}\r\n", .{forwarded_proto});
    const request_id = callbacks.current_request_id();
    if (request_id.len > 0) try out.print(allocator, "X-Request-Id: {s}\r\n", .{request_id});
}

fn readHttp1ResponseToBuffer(allocator: std.mem.Allocator, upstream_conn: std.Io.net.Stream, max_bytes: usize, callbacks: Callbacks) ![]u8 {
    var raw = std.ArrayList(u8).empty;
    errdefer raw.deinit(allocator);

    var buf: [8192]u8 = undefined;
    while (true) {
        const n = try callbacks.stream_read(upstream_conn, &buf);
        if (n == 0) break;
        if (raw.items.len + n > max_bytes) return error.PayloadTooLarge;
        try raw.appendSlice(allocator, buf[0..n]);
    }
    return raw.toOwnedSlice(allocator);
}

fn fetchResponse(allocator: std.mem.Allocator, upstream: *UpstreamConfig, req: request_mod.HttpRequest, cfg: *const ServerConfig, runtime_policy: UpstreamRuntimePolicy, callbacks: Callbacks) !H2BufferedResponse {
    if (upstream.https) return error.UnsupportedUpstreamScheme;

    const upstream_label = try std.fmt.allocPrint(
        allocator,
        "{s}://{s}:{d}{s}",
        .{ if (upstream.https) "https" else "http", upstream.host, upstream.port, upstream.base_path },
    );
    callbacks.access_log_set_upstream(upstream_label);

    const upstream_conn = try callbacks.connect_tcp_host(allocator, upstream.host, upstream.port);
    defer callbacks.stream_close(upstream_conn);
    try callbacks.set_stream_timeouts(upstream_conn, runtime_policy.timeout_ms, runtime_policy.timeout_ms);

    const proxy_path = try proxy_utils.buildProxyPath(allocator, upstream.base_path, req.path, req.query);
    var request = std.ArrayList(u8).empty;
    defer request.deinit(allocator);
    try request.print(allocator, "{s} {s} HTTP/1.1\r\n", .{ req.method, proxy_path });
    try appendForwardedRequestHeaders(allocator, &request, req, upstream, cfg, callbacks);
    try request.print(allocator, "Content-Length: {d}\r\n\r\n", .{req.body.len});
    try request.appendSlice(allocator, req.body);
    try callbacks.stream_write_all(upstream_conn, request.items);

    const raw = try readHttp1ResponseToBuffer(allocator, upstream_conn, cfg.max_static_file_bytes + DEFAULT_MAX_REQUEST_BYTES, callbacks);
    const header_end = (std.mem.indexOf(u8, raw, "\r\n\r\n") orelse return error.BadGateway) + 4;
    const header_bytes = raw[0..header_end];
    const body_tail = raw[header_end..];
    const status_line_end = std.mem.indexOf(u8, header_bytes, "\r\n") orelse return error.BadGateway;
    const response_headers = header_bytes[status_line_end + 2 .. header_end - 4];
    const framing = try proxy_utils.parseUpstreamResponseFraming(header_bytes, response_headers);
    const status_code = framing.status_code orelse 502;

    const body = if (proxy_utils.responseHasNoBody(req.method, status_code))
        try allocator.dupe(u8, "")
    else if (framing.transfer_chunked)
        try h2_support.decodeChunkedBuffer(allocator, body_tail)
    else if (framing.content_length) |content_length| blk: {
        if (body_tail.len < content_length) return error.BadGateway;
        break :blk try allocator.dupe(u8, body_tail[0..content_length]);
    } else try allocator.dupe(u8, body_tail);

    const content_type = if (http_headers.findHeaderValue(response_headers, "Content-Type")) |ctype|
        try allocator.dupe(u8, http_headers.trimValue(ctype))
    else
        "application/octet-stream";
    const headers = try h2_support.collectUpstreamHeaders(allocator, response_headers);
    return .{ .status_code = status_code, .content_type = content_type, .body = body, .headers = headers };
}

pub fn fetchPoolResponse(
    allocator: std.mem.Allocator,
    pool: *UpstreamPoolConfig,
    policy: UpstreamPoolPolicy,
    runtime_policy: UpstreamRuntimePolicy,
    req: request_mod.HttpRequest,
    cfg: *const ServerConfig,
    callbacks: Callbacks,
) !H2BufferedResponse {
    if (pool.targets.items.len == 0) return callbacks.error_response(allocator, 502, "Bad Gateway", "Proxy upstream pool is empty.");

    const attempt_limit = upstream_mod.upstreamAttemptLimit(pool, runtime_policy.retries);
    const start_ms = callbacks.upstream_now_ms();
    const start_ticket = upstream_mod.upstreamStartTicket(pool, policy, start_ms, request_mod.upstreamHashInput(req), &runtime_policy);
    var considered: usize = 0;
    var attempts: usize = 0;
    var skipped_ejected: usize = 0;
    var last_error: ?anyerror = null;

    while (considered < pool.targets.items.len and attempts < attempt_limit) : (considered += 1) {
        const upstream_index = upstream_mod.upstreamAttemptIndex(pool, start_ticket, considered);
        const upstream = &pool.targets.items[upstream_index];
        const lease = upstream_mod.upstreamBeginAttempt(upstream, start_ms, &runtime_policy) orelse {
            skipped_ejected += 1;
            callbacks.metrics.upstreamEjectedSkip();
            continue;
        };

        if (attempts > 0) callbacks.metrics.upstreamRetried();
        attempts += 1;
        callbacks.metrics.upstreamRequestStarted();
        var response = fetchResponse(allocator, upstream, req, cfg, runtime_policy, callbacks) catch |err| {
            upstream_mod.upstreamEndAttempt(upstream, lease);
            last_error = err;
            callbacks.metrics.upstreamRequestFailed();
            if (upstream_mod.upstreamRecordFailure(upstream, callbacks.upstream_now_ms(), runtime_policy.max_failures, runtime_policy.fail_timeout_ms)) {
                callbacks.metrics.upstreamEjected();
            }
            continue;
        };
        if (policy == .sticky_cookie) {
            const cookie_value = try upstream_mod.stickyCookieValue(allocator, upstream_index);
            const headers = try allocator.alloc(h2_native.Header, response.headers.len + 1);
            if (response.headers.len > 0) @memcpy(headers[0..response.headers.len], response.headers);
            headers[response.headers.len] = .{ .name = "set-cookie", .value = cookie_value };
            response.headers = headers;
        }
        upstream_mod.upstreamEndAttempt(upstream, lease);
        upstream_mod.upstreamRecordSuccess(upstream, callbacks.upstream_now_ms(), runtime_policy.slow_start_ms);
        return response;
    }

    if (attempts == 0 and skipped_ejected > 0) {
        return callbacks.error_response(allocator, 503, "Service Unavailable", "All configured upstream targets are unavailable or limited by circuit breaker recovery.");
    }
    if (last_error) |err| switch (err) {
        error.RequestTimeout => return callbacks.error_response(allocator, 504, "Gateway Timeout", "All configured upstream attempts timed out."),
        error.UnsupportedUpstreamScheme => return callbacks.error_response(allocator, 501, "Not Implemented", "HTTPS upstream is not yet supported in this server path."),
        error.PayloadTooLarge => return callbacks.error_response(allocator, 502, "Bad Gateway", "Upstream response exceeds configured response buffer."),
        else => {},
    };
    return callbacks.error_response(allocator, 502, "Bad Gateway", "All configured upstream attempts failed.");
}
