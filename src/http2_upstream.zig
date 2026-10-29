const std = @import("std");
const php_version = @import("php_version.zig");

const config_mod = @import("config.zig");
const h2_native = @import("h2_native.zig");
const h2_support = @import("http2_support.zig");
const http_headers = @import("http_headers.zig");
const metrics_mod = @import("metrics.zig");
const proxy_utils = @import("proxy_utils.zig");
const request_mod = @import("request.zig");
const upstream_mod = @import("upstream.zig");
const backend_deadline = @import("backend_deadline.zig");
const upstream_reader = @import("upstream_reader.zig");

const H2BufferedResponse = h2_support.BufferedResponse;
const ServerConfig = config_mod.ServerConfig;
const ServerMetrics = metrics_mod.ServerMetrics;
const UpstreamConfig = config_mod.UpstreamConfig;
const UpstreamPoolConfig = config_mod.UpstreamPoolConfig;
const UpstreamPoolPolicy = config_mod.UpstreamPoolPolicy;
const UpstreamRuntimePolicy = config_mod.UpstreamRuntimePolicy;

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
    active_io: *const fn () std.Io,
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
    const client_proto = if (proxy_utils.isConnectionField(req.headers, "X-Forwarded-Proto")) null else http_headers.findHeaderValue(req.headers, "X-Forwarded-Proto");
    const forwarded_proto = if (client_proto) |proto|
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
            if (proxy_utils.skipRequestField(req.headers, name)) continue;
            const value = http_headers.trimValue(trimmed[colon + 1 ..]);
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

fn fetchResponse(allocator: std.mem.Allocator, upstream: *UpstreamConfig, req: request_mod.HttpRequest, cfg: *const ServerConfig, runtime_policy: UpstreamRuntimePolicy, callbacks: Callbacks) !H2BufferedResponse {
    if (upstream.https) return error.UnsupportedUpstreamScheme;
    var phase: enum { connect, configure, request, response_head, response_body } = .connect;
    errdefer |err| if (!@import("builtin").is_test and err == error.Unexpected) {
        std.debug.print("{{\"event\":\"server.upstream_failure_detail\",\"protocol\":\"h2\",\"phase\":\"{s}\",\"error\":\"{s}\"}}\n", .{ @tagName(phase), @errorName(err) });
    };
    const previous_backend = backend_deadline.push(callbacks.active_io(), runtime_policy.timeout_ms);
    defer backend_deadline.restore(previous_backend);

    const upstream_label = try std.fmt.allocPrint(
        allocator,
        "{s}://{s}:{d}{s}",
        .{ if (upstream.https) "https" else "http", upstream.host, upstream.port, upstream.base_path },
    );
    callbacks.access_log_set_upstream(upstream_label);

    const upstream_conn = try callbacks.connect_tcp_host(allocator, upstream.host, upstream.port);
    defer callbacks.stream_close(upstream_conn);
    phase = .configure;
    try backend_deadline.attach(upstream_conn);
    try callbacks.set_stream_timeouts(upstream_conn, runtime_policy.timeout_ms, runtime_policy.timeout_ms);

    const proxy_path = try proxy_utils.buildProxyPath(allocator, upstream.base_path, req.path, req.query);
    phase = .request;
    var request = std.ArrayList(u8).empty;
    defer request.deinit(allocator);
    try request.print(allocator, "{s} {s} HTTP/1.1\r\n", .{ req.method, proxy_path });
    try appendForwardedRequestHeaders(allocator, &request, req, upstream, cfg, callbacks);
    try request.print(allocator, "Content-Length: {d}\r\n\r\n", .{req.body.len});
    try request.appendSlice(allocator, req.body);
    try callbacks.stream_write_all(upstream_conn, request.items);

    const reader = try upstream_reader.Reader.create(allocator, upstream_conn, callbacks.stream_read);
    defer allocator.destroy(reader);
    var informational = std.ArrayList(h2_support.Informational).empty;
    defer informational.deinit(allocator);
    phase = .response_head;
    const head = final: while (true) {
        const head = try reader.nextHead();
        if (php_version.exposedHeaders(head.fields)) |version| {
            php_version.log(version);
            return .{ .status_code = 503, .content_type = "text/plain; charset=utf-8", .body = try php_version.updateMessage(allocator, version), .headers = &.{.{ .name = "cache-control", .value = "no-store" }} };
        }
        const status = head.framing.status_code.?;
        if (status == 101) return error.BadGateway;
        if (status >= 200) break :final head;
        // Layerline already handled the client's expectation and buffered its
        // body. Other informational replies belong to this response, not cache.
        if (status != 100) {
            const reply = h2_support.Informational{ .status_code = status, .headers = try h2_support.collectUpstreamHeaders(allocator, head.fields, head.fields) };
            if (h2_support.informational_sink) |sink| {
                try sink.emit(sink.context, reply);
            } else try informational.append(allocator, reply);
        }
    };
    try reader.beginBody(req.method, head.framing, cfg.max_static_file_bytes);
    phase = .response_body;
    var body = std.ArrayList(u8).empty;
    defer body.deinit(allocator);
    while (try reader.nextData()) |data| try body.appendSlice(allocator, data);
    const content_type = if (!proxy_utils.isConnectionField(head.fields, "Content-Type"))
        if (http_headers.findHeaderValue(head.fields, "Content-Type")) |value| try allocator.dupe(u8, value) else "application/octet-stream"
    else
        "application/octet-stream";
    return .{
        .status_code = head.framing.status_code.?,
        .content_type = content_type,
        .body = try body.toOwnedSlice(allocator),
        .headers = try h2_support.collectUpstreamHeaders(allocator, head.fields, head.fields),
        .trailers = try h2_support.collectUpstreamHeaders(allocator, reader.trailers(), head.fields),
        .informational = try informational.toOwnedSlice(allocator),
        .content_length = if (proxy_utils.responseHasNoBody(req.method, head.framing.status_code)) head.framing.content_length else null,
        .omit_content_length = std.mem.eql(u8, req.method, "HEAD") and head.framing.content_length == null,
    };
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

    const attempt_limit = upstream_mod.upstreamAttemptLimit(pool, upstream_mod.requestRetryBudget(req.method, runtime_policy.retries));
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
        defer upstream_mod.upstreamEndAttempt(upstream, lease);

        if (attempts > 0) callbacks.metrics.upstreamRetried();
        attempts += 1;
        callbacks.metrics.upstreamRequestStarted();
        var response = fetchResponse(allocator, upstream, req, cfg, runtime_policy, callbacks) catch |err| {
            if (err == error.Canceled or err == error.OutOfMemory or err == error.BackendCapacity) return err;
            if (!@import("builtin").is_test) std.debug.print("{{\"event\":\"server.upstream_failure\",\"protocol\":\"h2\",\"error\":\"{s}\"}}\n", .{@errorName(err)});
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

test "canceling a client or exhausting local memory never ejects an upstream" {
    const Fake = struct {
        threadlocal var failure: anyerror = error.Canceled;
        threadlocal var connects: usize = 0;
        fn connect(_: std.mem.Allocator, _: []const u8, _: u16) !std.Io.net.Stream {
            connects += 1;
            return failure;
        }
        fn label(_: []const u8) void {}
        fn requestId() []const u8 {
            return "";
        }
        fn errorResponse(_: std.mem.Allocator, _: u16, _: []const u8, _: []const u8) !H2BufferedResponse {
            return error.UnexpectedErrorPage;
        }
        fn timeout(_: std.Io.net.Stream, _: u32, _: u32) !void {}
        fn close(_: std.Io.net.Stream) void {}
        fn read(_: std.Io.net.Stream, _: []u8) !usize {
            return error.UnexpectedRead;
        }
        fn write(_: std.Io.net.Stream, _: []const u8) !void {
            return error.UnexpectedWrite;
        }
        fn now() i64 {
            return 1000;
        }
        fn io() std.Io {
            return std.testing.io;
        }
    };
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var cfg = config_mod.defaultServerConfig();
    cfg.upstream_max_failures = 1;
    var pool = try config_mod.parseUpstreamPool(allocator, "http://127.0.0.1:9000,http://127.0.0.1:9001");
    var metrics = ServerMetrics.init();
    const callbacks: Callbacks = .{
        .access_log_set_upstream = Fake.label,
        .connect_tcp_host = Fake.connect,
        .current_request_id = Fake.requestId,
        .error_response = Fake.errorResponse,
        .metrics = &metrics,
        .set_stream_timeouts = Fake.timeout,
        .stream_close = Fake.close,
        .stream_read = Fake.read,
        .stream_write_all = Fake.write,
        .upstream_now_ms = Fake.now,
        .active_io = Fake.io,
    };
    const req: request_mod.HttpRequest = .{ .method = "GET", .path = "/", .query = "", .headers = "Host: local", .body = "", .version = "HTTP/2.0", .close_connection = true };
    for ([_]anyerror{ error.Canceled, error.OutOfMemory, error.BackendCapacity }) |failure| {
        Fake.failure = failure;
        Fake.connects = 0;
        try std.testing.expectError(failure, fetchPoolResponse(allocator, &pool, .round_robin, config_mod.upstreamRuntimePolicyFromConfig(&cfg), req, &cfg, callbacks));
        try std.testing.expectEqual(1, Fake.connects);
        for (pool.targets.items) |target| {
            try std.testing.expectEqual(0, target.active_requests.load(.acquire));
            try std.testing.expectEqual(0, target.passive_failures.load(.acquire));
            try std.testing.expectEqual(0, target.ejected_until_ms.load(.acquire));
        }
    }
    try std.testing.expectEqual(0, metrics.upstream_failures_total.load(.acquire));
}
