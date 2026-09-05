const std = @import("std");

const access_log_mod = @import("access_log.zig");
const config_mod = @import("config.zig");
const h2_native = @import("h2_native.zig");
const h2_server = @import("http2_server.zig");
const h2_support = @import("http2_support.zig");
const http_headers = @import("http_headers.zig");
const http_response = @import("http_response.zig");
const http2_content = @import("http2_content.zig");
const metrics_mod = @import("metrics.zig");
const request_mod = @import("request.zig");
const response_body = @import("response_body.zig");

const CompressionPolicy = config_mod.CompressionPolicy;
const H2BufferedResponse = h2_support.BufferedResponse;
const H2PendingReader = h2_support.PendingReader;
const HttpRequest = request_mod.HttpRequest;
const ResponseHeaderRule = config_mod.ResponseHeaderRule;
const ServerConfig = config_mod.ServerConfig;

pub const SendContext = struct {
    server_header: []const u8,
    request_id: []const u8,
    request_headers: []const u8,
    response_headers: []const ResponseHeaderRule,
    compression_policy: CompressionPolicy,
    compression_work_buffer_bytes: usize,
    metrics: *metrics_mod.ServerMetrics,
    stream_write_all: *const fn (std.Io.net.Stream, []const u8) anyerror!void,
    record_response_sent: *const fn (u16, usize) void,
};

pub const CompleteContext = struct {
    metrics: *metrics_mod.ServerMetrics,
    resolve_request_id: *const fn (std.Io, std.mem.Allocator, []const u8) anyerror![]const u8,
    set_request_context: *const fn ([]const u8, []const u8, CompressionPolicy) void,
    clear_request_context: *const fn () void,
    set_access_context: *const fn (*access_log_mod.Context, []const u8) void,
    clear_access_context: *const fn () void,
    access_log_set_handler: *const fn ([]const u8) void,
    access_log_set_error: *const fn ([]const u8) void,
    emit_access_log: *const fn (u16, usize) void,
    build_response_for_request: *const fn (std.Io, std.mem.Allocator, *ServerConfig, HttpRequest, *const std.process.Environ.Map) anyerror!H2BufferedResponse,
    cool_error_response: *const fn (std.mem.Allocator, u16, []const u8, []const u8) anyerror!H2BufferedResponse,
    send_response: *const fn (std.Io.net.Stream, std.mem.Allocator, u32, H2BufferedResponse, bool) anyerror!void,
};

pub const ConnectionContext = struct {
    server_header: []const u8,
    stream_read: *const fn (std.Io.net.Stream, []u8) anyerror!usize,
    stream_write_all: *const fn (std.Io.net.Stream, []const u8) anyerror!void,
    write_request_id_header: *const fn (std.Io.net.Stream) anyerror!void,
    record_response_sent: *const fn (u16, usize) void,
    send_cool_error_with_connection: *const fn (std.Io.net.Stream, std.mem.Allocator, u16, []const u8, []const u8, bool, bool, ?[]const u8) anyerror!void,
    build_response_for_request: *const fn (std.Io, std.mem.Allocator, *ServerConfig, HttpRequest, *const std.process.Environ.Map) anyerror!H2BufferedResponse,
    cool_error_response: *const fn (std.mem.Allocator, u16, []const u8, []const u8) anyerror!H2BufferedResponse,
    send_response: *const fn (std.Io.net.Stream, std.mem.Allocator, u32, H2BufferedResponse, bool) anyerror!void,
    frame_callbacks: h2_server.Callbacks,
};

pub fn sendResponse(
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    stream_id: u32,
    response: H2BufferedResponse,
    is_head: bool,
    ctx: SendContext,
) !void {
    var header_block = std.ArrayList(u8).empty;
    defer header_block.deinit(allocator);

    const prepared = try response_body.prepare(allocator, .{
        .status_code = response.status_code,
        .content_type = response.content_type,
        .body = response.body,
        .is_head = is_head,
        .h2_headers = response.headers,
        .request_headers = ctx.request_headers,
        .response_headers = ctx.response_headers,
        .compression_policy = ctx.compression_policy,
        .compression_work_buffer_bytes = ctx.compression_work_buffer_bytes,
        .metrics = ctx.metrics,
    });
    defer prepared.deinit(allocator);

    try h2_native.appendStatus(allocator, &header_block, response.status_code);
    try h2_native.appendHeaderIndexedName(allocator, &header_block, 54, ctx.server_header);
    try h2_native.appendHeaderIndexedName(allocator, &header_block, 31, response.content_type);

    var len_buf: [32]u8 = undefined;
    const body_len = if (http_response.canSendBody(response.status_code, is_head)) prepared.body.len else 0;
    if (http_response.canSendBody(response.status_code, false)) {
        const len_text = try std.fmt.bufPrint(&len_buf, "{d}", .{prepared.body.len});
        try h2_native.appendHeaderIndexedName(allocator, &header_block, 28, len_text);
    }
    if (ctx.request_id.len > 0) {
        try h2_support.appendHeader(allocator, &header_block, "x-request-id", ctx.request_id);
    }

    for (response.headers) |header| {
        if (h2_support.isSkippedResponseHeader(header.name)) continue;
        try h2_support.appendHeader(allocator, &header_block, header.name, header.value);
    }
    if (prepared.encoding) |encoding| {
        try h2_support.appendHeader(allocator, &header_block, "content-encoding", encoding);
        try h2_support.appendHeader(allocator, &header_block, "vary", "Accept-Encoding");
    }
    for (ctx.response_headers) |header| {
        if (h2_support.isSkippedResponseHeader(header.name)) continue;
        if (std.ascii.eqlIgnoreCase(header.name, "x-request-id")) continue;
        try h2_support.appendHeader(allocator, &header_block, header.name, header.value);
    }

    const header_flags = h2_native.FLAG_END_HEADERS | if (body_len == 0) h2_native.FLAG_END_STREAM else @as(u8, 0);
    try h2_support.sendFrame(stream, h2_native.FRAME_HEADERS, header_flags, stream_id, header_block.items, ctx.stream_write_all);

    if (body_len > 0) {
        var sent: usize = 0;
        while (sent < body_len) {
            const chunk_len = @min(@as(usize, 16 * 1024), body_len - sent);
            const flags = if (sent + chunk_len == body_len) h2_native.FLAG_END_STREAM else @as(u8, 0);
            try h2_support.sendFrame(stream, h2_native.FRAME_DATA, flags, stream_id, prepared.body[sent .. sent + chunk_len], ctx.stream_write_all);
            sent += chunk_len;
        }
    }

    ctx.record_response_sent(response.status_code, body_len);
}

pub fn coolErrorResponse(
    allocator: std.mem.Allocator,
    server_name: []const u8,
    server_tagline: []const u8,
    status_code: u16,
    status_text: []const u8,
    detail: []const u8,
) !H2BufferedResponse {
    return http2_content.coolErrorResponse(allocator, server_name, server_tagline, status_code, status_text, detail);
}

pub fn completeRequest(
    io: std.Io,
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    cfg: *ServerConfig,
    process_env: *const std.process.Environ.Map,
    stream_id: u32,
    req: HttpRequest,
    ctx: CompleteContext,
) !void {
    const request_id = try ctx.resolve_request_id(io, allocator, req.headers);
    ctx.set_request_context(req.headers, request_id, config_mod.compressionPolicyFromConfig(cfg));
    defer ctx.clear_request_context();

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
    ctx.set_access_context(&access_ctx, request_id);
    defer ctx.clear_access_context();

    ctx.metrics.requestStarted();
    ctx.access_log_set_handler("h2");
    const response = ctx.build_response_for_request(io, allocator, cfg, req, process_env) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => blk: {
            ctx.access_log_set_error(@errorName(err));
            break :blk try ctx.cool_error_response(allocator, 500, "Internal Server Error", "Internal server error while routing HTTP/2 request.");
        },
    };
    try ctx.send_response(stream, allocator, stream_id, response, std.mem.eql(u8, req.method, "HEAD"));
    if (!access_ctx.logged) ctx.emit_access_log(0, 0);
}

pub fn handlePreface(
    io: std.Io,
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    cfg: *ServerConfig,
    prefill: []const u8,
    process_env: *const std.process.Environ.Map,
    ctx: ConnectionContext,
) !void {
    var reader = H2PendingReader{
        .stream = stream,
        .pending = prefill,
        .read = ctx.stream_read,
    };
    h2_support.readClientPreface(&reader) catch {
        try ctx.send_cool_error_with_connection(stream, allocator, 400, "Bad Request", "Invalid HTTP/2 connection preface.", true, false, null);
        return;
    };

    try h2_support.sendFrame(stream, h2_native.FRAME_SETTINGS, 0, 0, "", ctx.stream_write_all);
    std.debug.print("HTTP/2 native h2c connection accepted\n", .{});
    try h2_server.runFrameLoop(io, stream, allocator, cfg, &reader, process_env, ctx.frame_callbacks);
}

pub fn handleUpgrade(
    io: std.Io,
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    cfg: *ServerConfig,
    req: HttpRequest,
    process_env: *const std.process.Environ.Map,
    ctx: ConnectionContext,
) !void {
    try ctx.stream_write_all(
        stream,
        "HTTP/1.1 101 Switching Protocols\r\n" ++
            "Server: ",
    );
    try ctx.stream_write_all(stream, ctx.server_header);
    try ctx.stream_write_all(
        stream,
        "\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Upgrade: h2c\r\n",
    );
    try ctx.write_request_id_header(stream);
    try ctx.stream_write_all(stream, "\r\n");
    ctx.record_response_sent(101, 0);

    try h2_support.sendFrame(stream, h2_native.FRAME_SETTINGS, 0, 0, "", ctx.stream_write_all);

    var reader = H2PendingReader{
        .stream = stream,
        .pending = req.h2c_upgrade_tail,
        .read = ctx.stream_read,
    };
    h2_support.readClientPreface(&reader) catch {
        try h2_support.sendFrame(stream, h2_native.FRAME_GOAWAY, 0, 0, "\x00\x00\x00\x00\x00\x00\x00\x01", ctx.stream_write_all);
        return;
    };

    var h2_req = req;
    h2_req.version = "HTTP/2.0";
    h2_req.close_connection = true;
    std.debug.print("HTTP/2 h2c upgrade {s} {s}\n", .{ h2_req.method, h2_req.path });
    const response = ctx.build_response_for_request(io, allocator, cfg, h2_req, process_env) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => try ctx.cool_error_response(allocator, 500, "Internal Server Error", "Internal server error while routing HTTP/2 upgrade request."),
    };
    try ctx.send_response(stream, allocator, 1, response, std.mem.eql(u8, h2_req.method, "HEAD"));
    try h2_server.runFrameLoop(io, stream, allocator, cfg, &reader, process_env, ctx.frame_callbacks);
}
