const std = @import("std");

const config_mod = @import("config.zig");
const custom_errors = @import("custom_errors.zig");
const http1_responses = @import("http1_responses.zig");
const metrics_mod = @import("metrics.zig");
const request_mod = @import("request.zig");
const runtime_state = @import("runtime_state.zig");
const server_assets = @import("server_assets.zig");
const server_identity = @import("server_identity.zig");
const stream_runtime = @import("stream_runtime.zig");

const DomainConfig = config_mod.DomainConfig;
const HttpRequest = request_mod.HttpRequest;
const RedirectRule = config_mod.RedirectRule;
const ServerConfig = config_mod.ServerConfig;

pub const compression_work_buffer_bytes = std.compress.flate.max_window_len;

pub fn context() http1_responses.Context {
    return .{
        .server_name = server_identity.name,
        .server_tagline = server_identity.tagline,
        .server_header = server_identity.header,
        .request_headers = runtime_state.current_request_headers,
        .request_id = runtime_state.current_request_id,
        .response_headers = runtime_state.current_response_headers,
        .compression_policy = runtime_state.current_compression_policy,
        .compression_work_buffer_bytes = compression_work_buffer_bytes,
        .metrics = &runtime_state.server_metrics,
        .emit_access_log = emitAccessLog,
        .stream_write_all = stream_runtime.streamWriteAll,
    };
}

pub fn streamWriteRequestIdHeader(stream: std.Io.net.Stream) !void {
    try http1_responses.writeRequestIdHeader(stream, context());
}

pub fn streamWriteConfiguredResponseHeaders(stream: std.Io.net.Stream) !void {
    try http1_responses.writeConfiguredResponseHeaders(stream, context());
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
) !void {
    try http1_responses.sendCoolErrorWithConnection(stream, allocator, status_code, status_text, detail, close_connection, is_head, extra_headers, context());
}

pub fn sendCoolError(stream: std.Io.net.Stream, allocator: std.mem.Allocator, status_code: u16, status_text: []const u8, detail: []const u8) !void {
    try http1_responses.sendCoolError(stream, allocator, status_code, status_text, detail, context());
}

pub fn sendResponseWithConnectionAndHeaders(stream: std.Io.net.Stream, status_code: u16, status_text: []const u8, content_type: []const u8, body: []const u8, close_connection: bool, extra_headers: ?[]const u8) !void {
    try http1_responses.sendResponseWithConnectionAndHeaders(stream, status_code, status_text, content_type, body, close_connection, extra_headers, context());
}

pub fn sendResponseWithConnection(stream: std.Io.net.Stream, status_code: u16, status_text: []const u8, content_type: []const u8, body: []const u8, close_connection: bool) !void {
    try http1_responses.sendResponseWithConnection(stream, status_code, status_text, content_type, body, close_connection, context());
}

pub fn sendResponse(stream: std.Io.net.Stream, status_code: u16, status_text: []const u8, content_type: []const u8, body: []const u8) !void {
    try http1_responses.sendResponse(stream, status_code, status_text, content_type, body, context());
}

pub fn sendResponseNoBodyWithConnectionAndHeaders(stream: std.Io.net.Stream, status_code: u16, status_text: []const u8, content_type: []const u8, body_len: usize, close_connection: bool, extra_headers: ?[]const u8) !void {
    try http1_responses.sendResponseNoBodyWithConnectionAndHeaders(stream, status_code, status_text, content_type, body_len, close_connection, extra_headers, context());
}

pub fn sendResponseNoBodyWithConnection(stream: std.Io.net.Stream, status_code: u16, status_text: []const u8, content_type: []const u8, body_len: usize, close_connection: bool) !void {
    try http1_responses.sendResponseNoBodyWithConnection(stream, status_code, status_text, content_type, body_len, close_connection, context());
}

pub fn sendNotFoundWithConnection(allocator: std.mem.Allocator, stream: std.Io.net.Stream, close_connection: bool) !void {
    try sendNotFoundForMethod(allocator, stream, close_connection, false);
}

pub fn sendNotFoundForMethod(allocator: std.mem.Allocator, stream: std.Io.net.Stream, close_connection: bool, is_head: bool) !void {
    try sendCoolErrorWithConnection(stream, allocator, 404, "Not Found", "The requested resource was not found on this server.", close_connection, is_head, null);
}

pub fn sendDomainCustomNotFoundForMethod(
    io: std.Io,
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    cfg: *const ServerConfig,
    domain: ?*const DomainConfig,
    close_connection: bool,
    is_head: bool,
) !void {
    try custom_errors.sendHttp1DomainNotFound(io, stream, allocator, cfg, domain, close_connection, is_head, .{
        .send_not_found_for_method = sendNotFoundForMethod,
        .send_response_for_method = sendResponseForMethod,
    });
}

pub fn sendBadRequest(allocator: std.mem.Allocator, stream: std.Io.net.Stream, reason: []const u8) !void {
    try sendCoolError(stream, allocator, 400, "Bad Request", reason);
}

pub fn sendBadRequestForMethod(allocator: std.mem.Allocator, stream: std.Io.net.Stream, reason: []const u8, close_connection: bool, is_head: bool) !void {
    try sendCoolErrorWithConnection(stream, allocator, 400, "Bad Request", reason, close_connection, is_head, null);
}

pub fn sendNotImplemented(stream: std.Io.net.Stream, allocator: std.mem.Allocator, close_connection: bool) !void {
    try sendCoolErrorWithConnection(stream, allocator, 501, "Not Implemented", "This server has not implemented that behavior.", close_connection, false, null);
}

pub fn sendResponseForMethod(stream: std.Io.net.Stream, status_code: u16, status_text: []const u8, content_type: []const u8, body: []const u8, close_connection: bool, is_head: bool) !void {
    try http1_responses.sendResponseForMethod(stream, status_code, status_text, content_type, body, close_connection, is_head, context());
}

pub fn sendConfiguredRedirect(stream: std.Io.net.Stream, allocator: std.mem.Allocator, rule: RedirectRule, req: HttpRequest, close_connection: bool, is_head: bool) !void {
    try http1_responses.sendConfiguredRedirect(stream, allocator, rule, req, close_connection, is_head, context());
}

pub fn sendHttpsRedirect(stream: std.Io.net.Stream, allocator: std.mem.Allocator, cfg: *const ServerConfig, req: HttpRequest, close_connection: bool, is_head: bool) !void {
    try http1_responses.sendHttpsRedirect(stream, allocator, cfg, req, close_connection, is_head, context());
}

pub fn sendServerIcon(stream: std.Io.net.Stream, close_connection: bool, is_head: bool) !void {
    try sendResponseForMethod(stream, 200, "OK", "image/svg+xml", server_assets.SERVER_ICON_SVG, close_connection, is_head);
}

pub fn recordResponseSent(status_code: u16, body_bytes: usize) void {
    runtime_state.server_metrics.responseSent(status_code, body_bytes);
    emitAccessLog(status_code, body_bytes);
}

pub fn emitAccessLog(status_code: u16, body_bytes: usize) void {
    runtime_state.emitAccessLog(stream_runtime.activeIo(), server_identity.name, status_code, body_bytes);
}

pub fn sendMetrics(stream: std.Io.net.Stream, allocator: std.mem.Allocator, close_connection: bool, is_head: bool) !void {
    const body = try metrics_mod.render(allocator, &runtime_state.server_metrics);
    defer allocator.free(body);
    try sendResponseForMethod(stream, 200, "OK", "text/plain; version=0.0.4; charset=utf-8", body, close_connection, is_head);
}
