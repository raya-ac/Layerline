const std = @import("std");

const access_log_mod = @import("access_log.zig");
const concurrency_mod = @import("concurrency.zig");
const config_mod = @import("config.zig");
const h2_support = @import("http2_support.zig");
const http_headers = @import("http_headers.zig");
const metrics_mod = @import("metrics.zig");
const native_tls = @import("native_tls_runtime.zig");
const request_mod = @import("request.zig");
const tls_client_hello = @import("tls_client_hello.zig");

const CompressionPolicy = config_mod.CompressionPolicy;
const ConcurrencyState = concurrency_mod.State;
const HttpRequest = request_mod.HttpRequest;
const ResponseHeaderRule = config_mod.ResponseHeaderRule;
const ServerConfig = config_mod.ServerConfig;
const ServerMetrics = metrics_mod.ServerMetrics;

const MAX_CHUNK_LINE_BYTES = 4096;

pub const Callbacks = struct {
    access_log_set_error: *const fn ([]const u8) void,
    access_log_set_handler: *const fn ([]const u8) void,
    active_config: *const fn () *ServerConfig,
    bind_thread_io: *const fn (std.Io) void,
    clear_access_context: *const fn () void,
    clear_request_context: *const fn () void,
    clear_response_headers: *const fn () void,
    emit_access_log: *const fn (u16, usize) void,
    handle_http2_preface: *const fn (std.Io, std.Io.net.Stream, std.mem.Allocator, *ServerConfig, []const u8, *const std.process.Environ.Map) anyerror!void,
    handle_http2_upgrade: *const fn (std.Io, std.Io.net.Stream, std.mem.Allocator, *ServerConfig, HttpRequest, *const std.process.Environ.Map) anyerror!void,
    handle_tls_client_hello_probe: *const fn (std.Io, std.Io.net.Stream, std.mem.Allocator, *ServerConfig, []const u8, *const std.process.Environ.Map) anyerror!void,
    metrics: *ServerMetrics,
    resolve_request_id: *const fn (std.Io, std.mem.Allocator, []const u8) anyerror![]const u8,
    route_request: *const fn (std.Io, std.Io.net.Stream, std.mem.Allocator, *ServerConfig, HttpRequest, *const std.process.Environ.Map) anyerror!void,
    send_bad_request: *const fn (std.mem.Allocator, std.Io.net.Stream, []const u8) anyerror!void,
    send_bad_request_for_method: *const fn (std.mem.Allocator, std.Io.net.Stream, []const u8, bool, bool) anyerror!void,
    send_cool_error: *const fn (std.Io.net.Stream, std.mem.Allocator, u16, []const u8, []const u8) anyerror!void,
    send_cool_error_with_connection: *const fn (std.Io.net.Stream, std.mem.Allocator, u16, []const u8, []const u8, bool, bool, ?[]const u8) anyerror!void,
    send_https_redirect: *const fn (std.Io.net.Stream, std.mem.Allocator, *const ServerConfig, HttpRequest, bool, bool) anyerror!void,
    serve_acme_challenge: *const fn (std.Io, std.Io.net.Stream, std.mem.Allocator, []const u8, []const u8, bool, bool) anyerror!void,
    set_access_context: *const fn (*access_log_mod.Context, []const u8) void,
    set_request_context: *const fn ([]const u8, CompressionPolicy) void,
    set_response_headers: *const fn ([]const ResponseHeaderRule) void,
    set_stream_read_timeout: *const fn (std.Io.net.Stream, u32) anyerror!void,
    set_stream_timeouts: *const fn (std.Io.net.Stream, u32, u32) anyerror!void,
    set_stream_write_timeout: *const fn (std.Io.net.Stream, u32) anyerror!void,
    shutdown_requested: *std.atomic.Value(bool),
    stream_close: *const fn (std.Io.net.Stream) void,
    stream_read: *const fn (std.Io.net.Stream, []u8) anyerror!usize,
    stream_write_all: *const fn (std.Io.net.Stream, []const u8) anyerror!void,
};

fn routeHttpRedirectRequest(
    io: std.Io,
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    cfg: *ServerConfig,
    req: HttpRequest,
    callbacks: Callbacks,
) !void {
    const is_head = std.mem.eql(u8, req.method, "HEAD");
    const close_connection = true;

    callbacks.set_request_context(req.headers, .disabled);
    callbacks.set_response_headers(&.{});
    defer {
        callbacks.clear_request_context();
        callbacks.clear_response_headers();
    }

    if ((std.mem.eql(u8, req.method, "GET") or is_head) and std.mem.startsWith(u8, req.path, "/.well-known/acme-challenge/")) {
        callbacks.access_log_set_handler("acme_challenge");
        const token = req.path["/.well-known/acme-challenge/".len..];
        try callbacks.serve_acme_challenge(io, stream, allocator, cfg.letsencrypt_webroot, token, close_connection, is_head);
        return;
    }

    callbacks.access_log_set_handler("http_to_https_redirect");
    callbacks.send_https_redirect(stream, allocator, cfg, req, close_connection, is_head) catch |err| switch (err) {
        error.MissingHostHeader => try callbacks.send_bad_request_for_method(allocator, stream, "Missing Host header.", close_connection, is_head),
        error.InvalidRedirectHost => try callbacks.send_bad_request_for_method(allocator, stream, "Invalid Host header.", close_connection, is_head),
        error.InvalidRedirectPath => try callbacks.send_bad_request_for_method(allocator, stream, "Invalid request path.", close_connection, is_head),
        else => return err,
    };
}

fn handleHttpRedirectConnection(
    io: std.Io,
    stream: std.Io.net.Stream,
    cfg: *ServerConfig,
    allocator: std.mem.Allocator,
    callbacks: Callbacks,
) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const req_alloc = arena.allocator();

    callbacks.set_stream_timeouts(stream, cfg.read_header_timeout_ms, cfg.write_timeout_ms) catch |err| {
        std.debug.print("HTTP redirect socket timeout setup failed: {}\n", .{err});
    };

    var prefill_buf: [64]u8 = undefined;
    const prefill_len = callbacks.stream_read(stream, &prefill_buf) catch |err| switch (err) {
        error.RequestTimeout => {
            try callbacks.send_cool_error_with_connection(
                stream,
                req_alloc,
                408,
                "Request Timeout",
                "No request bytes arrived before the redirect listener timeout.",
                true,
                false,
                null,
            );
            return;
        },
        else => |e| return e,
    };
    if (prefill_len == 0) return;
    const prefill = prefill_buf[0..prefill_len];

    if (h2_support.isLikelyPreface(prefill) or tls_client_hello.looksLikeTlsClientHello(prefill) or native_tls.isHttp3OverTcpProbe(prefill)) {
        try callbacks.send_cool_error_with_connection(
            stream,
            req_alloc,
            426,
            "Upgrade Required",
            "Use the HTTPS listener for TLS, HTTP/2, or HTTP/3. This socket only handles ACME HTTP-01 and HTTP-to-HTTPS redirects.",
            true,
            false,
            null,
        );
        return;
    }

    var req = request_mod.parseHeadersOnly(stream, req_alloc, cfg.max_request_bytes, prefill, .{
        .read = callbacks.stream_read,
        .write_all = callbacks.stream_write_all,
        .set_read_timeout = callbacks.set_stream_read_timeout,
    }) catch |err| {
        if (err != error.ConnectionClosed) callbacks.metrics.requestParseError();
        switch (err) {
            error.ConnectionClosed => return,
            error.RequestTimeout => {
                try callbacks.send_cool_error_with_connection(stream, req_alloc, 408, "Request Timeout", "The request took too long to read.", true, false, null);
                return;
            },
            error.RequestTooLarge => {
                try callbacks.send_cool_error_with_connection(stream, req_alloc, 413, "Payload Too Large", "Request headers are too large.", true, false, null);
                return;
            },
            error.PayloadTooLarge => {
                try callbacks.send_cool_error_with_connection(stream, req_alloc, 413, "Payload Too Large", "Request body exceeds configured limit.", true, false, null);
                return;
            },
            error.InvalidContentLength => {
                try callbacks.send_bad_request(req_alloc, stream, "Invalid Content-Length header.");
                return;
            },
            error.UnsupportedTransferEncoding => {
                try callbacks.send_cool_error_with_connection(stream, req_alloc, 501, "Not Implemented", "Only plain Content-Length and chunked request bodies are supported.", true, false, null);
                return;
            },
            error.ExpectationFailed => {
                try callbacks.send_cool_error_with_connection(stream, req_alloc, 417, "Expectation Failed", "Only Expect: 100-continue is supported.", true, false, null);
                return;
            },
            error.MalformedRequest => {
                try callbacks.send_bad_request(req_alloc, stream, "Malformed request.");
                return;
            },
            error.BadRequest => {
                try callbacks.send_bad_request(req_alloc, stream, "Bad request.");
                return;
            },
            error.MissingHostHeader => {
                try callbacks.send_bad_request(req_alloc, stream, "Missing Host header.");
                return;
            },
            error.UnsupportedHttpVersion => {
                try callbacks.send_cool_error_with_connection(stream, req_alloc, 505, "HTTP Version Not Supported", "The redirect listener only accepts HTTP/1.x before sending clients to HTTPS.", true, false, null);
                return;
            },
            else => {
                try callbacks.send_cool_error_with_connection(stream, req_alloc, 500, "Internal Server Error", "Internal server error while parsing request.", true, false, null);
                return;
            },
        }
    };
    req.close_connection = true;
    callbacks.metrics.requestStarted();
    const request_id = try callbacks.resolve_request_id(io, req_alloc, req.headers);

    var access_ctx = access_log_mod.Context{
        .enabled = cfg.access_log_enabled,
        .sink = cfg.access_log_path,
        .method = req.method,
        .path = req.path,
        .query = req.query,
        .protocol = req.version,
        .host = http_headers.findHeaderValue(req.headers, "Host") orelse "",
        .request_id = request_id,
        .start_ms = std.Io.Timestamp.now(io, .awake).toMilliseconds(),
    };
    callbacks.set_access_context(&access_ctx, request_id);
    defer callbacks.clear_access_context();

    routeHttpRedirectRequest(io, stream, req_alloc, cfg, req, callbacks) catch |err| {
        callbacks.access_log_set_error(@errorName(err));
        callbacks.emit_access_log(0, 0);
        callbacks.metrics.routeError();
        return err;
    };
    if (!access_ctx.logged) callbacks.emit_access_log(0, 0);
}

fn serveHttpRedirectConnectionTask(
    io: std.Io,
    stream: std.Io.net.Stream,
    cfg: *ServerConfig,
    allocator: std.mem.Allocator,
    state: *ConcurrencyState,
    callbacks: Callbacks,
) void {
    callbacks.bind_thread_io(io);
    defer {
        state.release();
        callbacks.stream_close(stream);
    }

    handleHttpRedirectConnection(io, stream, cfg, allocator, callbacks) catch |err| {
        std.debug.print("HTTP redirect handler error: {}\n", .{err});
    };
}

pub const HttpRedirectListenerContext = struct {
    io: std.Io,
    server: *std.Io.net.Server,
    cfg: *ServerConfig,
    allocator: std.mem.Allocator,
    state: *ConcurrencyState,
    callbacks: Callbacks,
};

pub fn serveHttpRedirectListenerTask(ctx: HttpRedirectListenerContext) void {
    ctx.callbacks.bind_thread_io(ctx.io);

    while (!ctx.callbacks.shutdown_requested.load(.acquire)) {
        const conn = ctx.server.accept(ctx.io) catch |err| {
            if (ctx.callbacks.shutdown_requested.load(.acquire)) break;
            std.debug.print("HTTP redirect accept failed: {}. Continuing to accept.\n", .{err});
            ctx.io.sleep(.fromMilliseconds(25), .awake) catch {};
            continue;
        };
        if (ctx.callbacks.shutdown_requested.load(.acquire)) {
            ctx.callbacks.stream_close(conn);
            break;
        }

        const active_cfg = ctx.callbacks.active_config();
        if (!ctx.state.tryAcquire(active_cfg.max_concurrent_connections)) {
            ctx.callbacks.metrics.connectionRejected();
            ctx.callbacks.send_cool_error(
                conn,
                ctx.allocator,
                503,
                "Service Unavailable",
                "Maximum concurrent connections reached. Try again in a moment.",
            ) catch {};
            ctx.callbacks.stream_close(conn);
            continue;
        }

        const worker = std.Thread.spawn(
            .{ .stack_size = active_cfg.worker_stack_size },
            serveHttpRedirectConnectionTask,
            .{ ctx.io, conn, active_cfg, ctx.allocator, ctx.state, ctx.callbacks },
        ) catch |err| {
            std.debug.print("Failed to start HTTP redirect worker: {}\n", .{err});
            ctx.state.release();
            ctx.callbacks.stream_close(conn);
            continue;
        };
        worker.detach();
    }
}

pub fn handleConnection(
    io: std.Io,
    stream: std.Io.net.Stream,
    cfg: *ServerConfig,
    allocator: std.mem.Allocator,
    process_env: *const std.process.Environ.Map,
    callbacks: Callbacks,
) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    var handled_requests: usize = 0;
    callbacks.set_stream_write_timeout(stream, cfg.write_timeout_ms) catch |err| {
        std.debug.print("Socket write timeout setup failed: {}\n", .{err});
    };

    // Keep one connection worker alive across keep-alive requests.
    // Each request still gets a hard cap before the socket is closed.
    while (true) {
        if (cfg.max_requests_per_connection > 0 and handled_requests >= cfg.max_requests_per_connection) {
            return;
        }

        _ = arena.reset(.retain_capacity);
        const req_alloc = arena.allocator();
        const next_read_timeout = if (handled_requests == 0) cfg.read_header_timeout_ms else cfg.idle_timeout_ms;
        callbacks.set_stream_read_timeout(stream, next_read_timeout) catch |err| {
            std.debug.print("Socket read timeout setup failed: {}\n", .{err});
        };
        var prefill_buf: [64]u8 = undefined;
        const prefill_len = callbacks.stream_read(stream, &prefill_buf) catch |err| switch (err) {
            error.RequestTimeout => {
                if (handled_requests > 0) return;
                try callbacks.send_cool_error_with_connection(
                    stream,
                    req_alloc,
                    408,
                    "Request Timeout",
                    "No request bytes arrived before the header timeout.",
                    true,
                    false,
                    null,
                );
                return;
            },
            else => |e| return e,
        };
        if (prefill_len == 0) return;
        const prefill = prefill_buf[0..prefill_len];

        if (h2_support.isLikelyPreface(prefill)) {
            try callbacks.handle_http2_preface(io, stream, req_alloc, cfg, prefill, process_env);
            return;
        }

        if (tls_client_hello.looksLikeTlsClientHello(prefill)) {
            try callbacks.handle_tls_client_hello_probe(io, stream, allocator, cfg, prefill, process_env);
            return;
        }

        if (native_tls.isHttp3OverTcpProbe(prefill)) {
            try callbacks.send_cool_error_with_connection(
                stream,
                req_alloc,
                426,
                "Upgrade Required",
                "HTTP/3 is a QUIC transport and cannot be served directly over this TCP socket.",
                true,
                false,
                null,
            );
            return;
        }

        callbacks.set_stream_read_timeout(stream, cfg.read_header_timeout_ms) catch |err| {
            std.debug.print("Socket header timeout setup failed: {}\n", .{err});
        };
        var req = request_mod.parse(stream, req_alloc, cfg.max_request_bytes, cfg.max_body_bytes, cfg.read_body_timeout_ms, MAX_CHUNK_LINE_BYTES, prefill, .{
            .read = callbacks.stream_read,
            .write_all = callbacks.stream_write_all,
            .set_read_timeout = callbacks.set_stream_read_timeout,
        }) catch |err| {
            if (err != error.ConnectionClosed) callbacks.metrics.requestParseError();
            switch (err) {
                error.ConnectionClosed => return,
                error.RequestTimeout => {
                    try callbacks.send_cool_error_with_connection(
                        stream,
                        req_alloc,
                        408,
                        "Request Timeout",
                        "The request took too long to read.",
                        true,
                        false,
                        null,
                    );
                    return;
                },
                error.RequestTooLarge => {
                    try callbacks.send_cool_error_with_connection(
                        stream,
                        req_alloc,
                        413,
                        "Payload Too Large",
                        "Request headers are too large.",
                        true,
                        false,
                        null,
                    );
                    return;
                },
                error.PayloadTooLarge => {
                    try callbacks.send_cool_error_with_connection(
                        stream,
                        req_alloc,
                        413,
                        "Payload Too Large",
                        "Request body exceeds configured limit.",
                        true,
                        false,
                        null,
                    );
                    return;
                },
                error.InvalidContentLength => {
                    try callbacks.send_bad_request(req_alloc, stream, "Invalid Content-Length header.");
                    return;
                },
                error.UnsupportedTransferEncoding => {
                    try callbacks.send_cool_error_with_connection(
                        stream,
                        req_alloc,
                        501,
                        "Not Implemented",
                        "Only plain Content-Length and chunked request bodies are supported.",
                        true,
                        false,
                        null,
                    );
                    return;
                },
                error.ExpectationFailed => {
                    try callbacks.send_cool_error_with_connection(
                        stream,
                        req_alloc,
                        417,
                        "Expectation Failed",
                        "Only Expect: 100-continue is supported.",
                        true,
                        false,
                        null,
                    );
                    return;
                },
                error.MalformedRequest => {
                    try callbacks.send_bad_request(req_alloc, stream, "Malformed request.");
                    return;
                },
                error.BadRequest => {
                    try callbacks.send_bad_request(req_alloc, stream, "Bad request.");
                    return;
                },
                error.MissingHostHeader => {
                    try callbacks.send_bad_request(req_alloc, stream, "Missing Host header.");
                    return;
                },
                error.UnsupportedHttpVersion => {
                    try callbacks.send_cool_error_with_connection(
                        stream,
                        req_alloc,
                        505,
                        "HTTP Version Not Supported",
                        "This process only serves HTTP/1.x requests directly. Configure TLS reverse proxy fronting for h2/h3 and set --h2-upstream for HTTP/2 cleartext passthrough.",
                        true,
                        false,
                        null,
                    );
                    return;
                },
                else => {
                    try callbacks.send_cool_error_with_connection(
                        stream,
                        req_alloc,
                        500,
                        "Internal Server Error",
                        "Internal server error while parsing request.",
                        true,
                        false,
                        null,
                    );
                    return;
                },
            }
        };
        handled_requests += 1;
        callbacks.metrics.requestStarted();

        {
            const request_id = try callbacks.resolve_request_id(io, req_alloc, req.headers);
            var access_ctx = access_log_mod.Context{
                .enabled = cfg.access_log_enabled,
                .sink = cfg.access_log_path,
                .method = req.method,
                .path = req.path,
                .query = req.query,
                .protocol = req.version,
                .host = http_headers.findHeaderValue(req.headers, "Host") orelse "",
                .request_id = request_id,
                .start_ms = std.Io.Timestamp.now(io, .awake).toMilliseconds(),
            };
            callbacks.set_access_context(&access_ctx, request_id);
            defer callbacks.clear_access_context();

            if (req.h2c_upgrade_tail.len > 0 or request_mod.isH2cUpgradeHeaders(req.headers)) {
                callbacks.access_log_set_handler("h2c_upgrade");
                try callbacks.handle_http2_upgrade(io, stream, req_alloc, cfg, req, process_env);
                return;
            }

            if (cfg.max_requests_per_connection > 0 and handled_requests >= cfg.max_requests_per_connection) {
                req.close_connection = true;
            }

            callbacks.route_request(io, stream, req_alloc, cfg, req, process_env) catch |err| switch (err) {
                error.CloseConnection => break,
                else => {
                    callbacks.access_log_set_error(@errorName(err));
                    callbacks.emit_access_log(0, 0);
                    callbacks.metrics.routeError();
                    return err;
                },
            };

            if (!access_ctx.logged) callbacks.emit_access_log(0, 0);
        }

        if (req.close_connection) break;
    }
}

pub fn serveConnectionTask(
    io: std.Io,
    stream: std.Io.net.Stream,
    cfg: *ServerConfig,
    allocator: std.mem.Allocator,
    state: *ConcurrencyState,
    process_env: *const std.process.Environ.Map,
    callbacks: Callbacks,
) void {
    callbacks.bind_thread_io(io);

    // One worker thread owns one stream; always release the slot and close stream.
    defer {
        state.release();
        callbacks.stream_close(stream);
    }

    handleConnection(io, stream, cfg, allocator, process_env, callbacks) catch |err| {
        std.debug.print("Connection handler error: {}\n", .{err});
    };
}
