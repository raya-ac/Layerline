const std = @import("std");

const config_mod = @import("config.zig");
const error_pages = @import("error_pages.zig");
const http_response = @import("http_response.zig");
const metrics_mod = @import("metrics.zig");
const redirects = @import("redirects.zig");
const request_mod = @import("request.zig");
const response_body = @import("response_body.zig");

const CompressionPolicy = config_mod.CompressionPolicy;
const RedirectRule = config_mod.RedirectRule;
const ResponseHeaderRule = config_mod.ResponseHeaderRule;
const ServerConfig = config_mod.ServerConfig;

pub const Context = struct {
    server_name: []const u8,
    server_tagline: []const u8,
    server_header: []const u8,
    request_headers: []const u8,
    request_id: []const u8,
    response_headers: []const ResponseHeaderRule,
    compression_policy: CompressionPolicy,
    compression_work_buffer_bytes: usize,
    metrics: *metrics_mod.ServerMetrics,
    emit_access_log: *const fn (u16, usize) void,
    stream_write_all: *const fn (std.Io.net.Stream, []const u8) anyerror!void,
};

fn writeFmt(stream: std.Io.net.Stream, ctx: Context, comptime fmt: []const u8, args: anytype) !void {
    var stack_buffer: [4096]u8 = undefined;
    const rendered = try std.fmt.bufPrint(&stack_buffer, fmt, args);
    try ctx.stream_write_all(stream, rendered);
}

fn recordResponseSent(ctx: Context, status_code: u16, body_bytes: usize) void {
    ctx.metrics.responseSent(status_code, body_bytes);
    ctx.emit_access_log(status_code, body_bytes);
}

pub fn writeRequestIdHeader(stream: std.Io.net.Stream, ctx: Context) !void {
    if (ctx.request_id.len == 0) return;
    try writeFmt(stream, ctx, "X-Request-Id: {s}\r\n", .{ctx.request_id});
}

pub fn writeConfiguredResponseHeaders(stream: std.Io.net.Stream, ctx: Context) !void {
    try writeRequestIdHeader(stream, ctx);
    for (ctx.response_headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, "X-Request-Id")) continue;
        try writeFmt(stream, ctx, "{s}: {s}\r\n", .{ header.name, header.value });
    }
}

pub fn sendCoolErrorWithConnection(
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    status_code: u16,
    status_text: []const u8,
    detail: []const u8,
    close_connection: bool,
    is_head: bool,
    extra_headers: ?[]const u8,
    ctx: Context,
) !void {
    const body = try error_pages.render(allocator, ctx.server_name, ctx.server_tagline, status_code, status_text, detail);
    defer allocator.free(body);

    if (is_head) {
        try sendResponseNoBodyWithConnectionAndHeaders(stream, status_code, status_text, "text/html; charset=utf-8", body.len, close_connection, extra_headers, ctx);
        return;
    }
    try sendResponseWithConnectionAndHeaders(stream, status_code, status_text, "text/html; charset=utf-8", body, close_connection, extra_headers, ctx);
}

pub fn sendCoolError(stream: std.Io.net.Stream, allocator: std.mem.Allocator, status_code: u16, status_text: []const u8, detail: []const u8, ctx: Context) !void {
    return sendCoolErrorWithConnection(stream, allocator, status_code, status_text, detail, true, false, null, ctx);
}

pub fn sendResponseWithConnectionAndHeaders(
    stream: std.Io.net.Stream,
    status_code: u16,
    status_text: []const u8,
    content_type: []const u8,
    body: []const u8,
    close_connection: bool,
    extra_headers: ?[]const u8,
    ctx: Context,
) !void {
    const prepared = try response_body.prepare(std.heap.page_allocator, .{
        .status_code = status_code,
        .content_type = content_type,
        .body = body,
        .is_head = false,
        .extra_headers = extra_headers,
        .request_headers = ctx.request_headers,
        .response_headers = ctx.response_headers,
        .compression_policy = ctx.compression_policy,
        .compression_work_buffer_bytes = ctx.compression_work_buffer_bytes,
        .metrics = ctx.metrics,
    });
    defer prepared.deinit(std.heap.page_allocator);

    const body_len = prepared.body.len;
    var header_buffer: [4096]u8 = undefined;
    const base_headers = try http_response.formatHttp1BaseHeaders(&header_buffer, .{
        .status_code = status_code,
        .status_text = status_text,
        .server = ctx.server_header,
        .content_type = content_type,
        .content_length = body_len,
        .close_connection = close_connection,
    });
    try ctx.stream_write_all(stream, base_headers);
    if (extra_headers) |headers| {
        try ctx.stream_write_all(stream, headers);
    }
    if (prepared.encoding) |encoding| {
        try writeFmt(stream, ctx, "Content-Encoding: {s}\r\nVary: Accept-Encoding\r\n", .{encoding});
    }
    try writeConfiguredResponseHeaders(stream, ctx);
    try ctx.stream_write_all(stream, "\r\n");

    if (body_len > 0) try ctx.stream_write_all(stream, prepared.body);
    recordResponseSent(ctx, status_code, body_len);
}

pub fn sendResponseWithConnection(stream: std.Io.net.Stream, status_code: u16, status_text: []const u8, content_type: []const u8, body: []const u8, close_connection: bool, ctx: Context) !void {
    try sendResponseWithConnectionAndHeaders(stream, status_code, status_text, content_type, body, close_connection, null, ctx);
}

pub fn sendResponse(stream: std.Io.net.Stream, status_code: u16, status_text: []const u8, content_type: []const u8, body: []const u8, ctx: Context) !void {
    try sendResponseWithConnectionAndHeaders(stream, status_code, status_text, content_type, body, true, null, ctx);
}

pub fn sendResponseNoBodyWithConnectionAndHeaders(
    stream: std.Io.net.Stream,
    status_code: u16,
    status_text: []const u8,
    content_type: []const u8,
    body_len: usize,
    close_connection: bool,
    extra_headers: ?[]const u8,
    ctx: Context,
) !void {
    var header_buffer: [4096]u8 = undefined;
    const base_headers = try http_response.formatHttp1BaseHeaders(&header_buffer, .{
        .status_code = status_code,
        .status_text = status_text,
        .server = ctx.server_header,
        .content_type = content_type,
        .content_length = body_len,
        .close_connection = close_connection,
    });
    try ctx.stream_write_all(stream, base_headers);
    if (extra_headers) |headers| {
        try ctx.stream_write_all(stream, headers);
    }
    try writeConfiguredResponseHeaders(stream, ctx);
    try ctx.stream_write_all(stream, "\r\n");
    recordResponseSent(ctx, status_code, 0);
}

pub fn sendResponseNoBodyWithConnection(stream: std.Io.net.Stream, status_code: u16, status_text: []const u8, content_type: []const u8, body_len: usize, close_connection: bool, ctx: Context) !void {
    try sendResponseNoBodyWithConnectionAndHeaders(stream, status_code, status_text, content_type, body_len, close_connection, null, ctx);
}

pub fn sendResponseNoBody(stream: std.Io.net.Stream, status_code: u16, status_text: []const u8, content_type: []const u8, body_len: usize, ctx: Context) !void {
    try sendResponseNoBodyWithConnection(stream, status_code, status_text, content_type, body_len, true, ctx);
}

pub fn sendResponseForMethod(stream: std.Io.net.Stream, status_code: u16, status_text: []const u8, content_type: []const u8, body: []const u8, close_connection: bool, is_head: bool, ctx: Context) !void {
    if (http_response.canSendBody(status_code, is_head)) {
        try sendResponseWithConnection(stream, status_code, status_text, content_type, body, close_connection, ctx);
        return;
    }

    const declared_len = if (is_head) body.len else 0;
    try sendResponseNoBodyWithConnection(stream, status_code, status_text, content_type, declared_len, close_connection, ctx);
}

pub fn sendConfiguredRedirect(stream: std.Io.net.Stream, allocator: std.mem.Allocator, rule: RedirectRule, req: request_mod.HttpRequest, close_connection: bool, is_head: bool, ctx: Context) !void {
    const location = try redirects.buildLocation(allocator, rule, req);
    defer allocator.free(location);

    const extra_headers = try std.fmt.allocPrint(allocator, "Location: {s}\r\n", .{location});
    defer allocator.free(extra_headers);

    const body = try std.fmt.allocPrint(allocator, "Redirecting to {s}\n", .{location});
    defer allocator.free(body);

    if (is_head) {
        try sendResponseNoBodyWithConnectionAndHeaders(stream, rule.status_code, redirects.statusText(rule.status_code), "text/plain; charset=utf-8", body.len, close_connection, extra_headers, ctx);
        return;
    }

    try sendResponseWithConnectionAndHeaders(stream, rule.status_code, redirects.statusText(rule.status_code), "text/plain; charset=utf-8", body, close_connection, extra_headers, ctx);
}

pub fn sendHttpsRedirect(stream: std.Io.net.Stream, allocator: std.mem.Allocator, cfg: *const ServerConfig, req: request_mod.HttpRequest, close_connection: bool, is_head: bool, ctx: Context) !void {
    const location = try redirects.buildHttpsLocation(allocator, cfg, req);
    defer allocator.free(location);

    const extra_headers = try std.fmt.allocPrint(allocator, "Location: {s}\r\n", .{location});
    defer allocator.free(extra_headers);

    const body = try std.fmt.allocPrint(allocator, "Redirecting to {s}\n", .{location});
    defer allocator.free(body);

    if (is_head) {
        try sendResponseNoBodyWithConnectionAndHeaders(stream, cfg.http_redirect_status, redirects.statusText(cfg.http_redirect_status), "text/plain; charset=utf-8", body.len, close_connection, extra_headers, ctx);
        return;
    }
    try sendResponseWithConnectionAndHeaders(stream, cfg.http_redirect_status, redirects.statusText(cfg.http_redirect_status), "text/plain; charset=utf-8", body, close_connection, extra_headers, ctx);
}
