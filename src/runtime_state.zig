const std = @import("std");

const access_log_mod = @import("access_log.zig");
const config_mod = @import("config.zig");
const metrics_mod = @import("metrics.zig");
const request_trace = @import("request_trace.zig");

const CompressionPolicy = config_mod.CompressionPolicy;
const ResponseHeaderRule = config_mod.ResponseHeaderRule;

pub threadlocal var current_response_headers: []const ResponseHeaderRule = &.{};
pub threadlocal var current_request_headers: []const u8 = "";
pub threadlocal var current_request_id: []const u8 = "";
pub threadlocal var current_compression_policy: CompressionPolicy = .disabled;
pub threadlocal var current_access_log: ?*access_log_mod.Context = null;

pub var access_log_writer = access_log_mod.Writer{};
pub var request_id_generator = request_trace.Generator{};
pub var shutdown_requested = std.atomic.Value(bool).init(false);
pub var server_metrics = metrics_mod.ServerMetrics.init();
pub var fastcgi_keepalive_pool = config_mod.FastcgiKeepAlivePool.init();

pub fn currentRequestId() []const u8 {
    return current_request_id;
}

pub fn resolveRequestId(io: std.Io, allocator: std.mem.Allocator, headers: []const u8) ![]const u8 {
    return request_id_generator.resolve(io, allocator, headers);
}

pub fn setHttp1RequestContext(headers: []const u8, policy: CompressionPolicy) void {
    current_request_headers = headers;
    current_compression_policy = policy;
}

pub fn clearHttp1RequestContext() void {
    current_request_headers = "";
    current_compression_policy = .disabled;
}

pub fn setHttp2RequestContext(headers: []const u8, request_id: []const u8, policy: CompressionPolicy) void {
    current_request_headers = headers;
    current_request_id = request_id;
    current_compression_policy = policy;
}

pub fn clearHttp2RequestContext() void {
    current_request_headers = "";
    current_request_id = "";
    current_compression_policy = .disabled;
    current_response_headers = &.{};
}

pub fn setResponseHeaders(headers: []const ResponseHeaderRule) void {
    current_response_headers = headers;
}

pub fn setCompressionPolicy(policy: CompressionPolicy) void {
    current_compression_policy = policy;
}

pub fn clearResponseHeaders() void {
    current_response_headers = &.{};
}

pub fn setAccessLogContext(ctx: *access_log_mod.Context, request_id: []const u8) void {
    current_access_log = ctx;
    current_request_id = request_id;
}

pub fn clearAccessLogContext() void {
    current_access_log = null;
    current_request_id = "";
}

pub fn accessLogSetHandler(handler: []const u8) void {
    access_log_mod.setHandler(current_access_log, handler);
}

pub fn accessLogSetUpstream(upstream: []const u8) void {
    access_log_mod.setUpstream(current_access_log, upstream);
}

pub fn accessLogSetError(error_name: []const u8) void {
    access_log_mod.setError(current_access_log, error_name);
}

pub fn emitAccessLog(io: std.Io, server_name: []const u8, status_code: u16, body_bytes: usize) void {
    access_log_writer.emit(io, current_access_log, server_name, status_code, body_bytes);
}
