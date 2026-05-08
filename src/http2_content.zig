const std = @import("std");

const acme_mod = @import("acme.zig");
const config_mod = @import("config.zig");
const error_pages = @import("error_pages.zig");
const h2_native = @import("h2_native.zig");
const h2_support = @import("http2_support.zig");
const metrics_mod = @import("metrics.zig");
const redirects = @import("redirects.zig");
const request_mod = @import("request.zig");
const static_files = @import("static_files.zig");

const H2BufferedResponse = h2_support.BufferedResponse;
const RedirectRule = config_mod.RedirectRule;
const ServerMetrics = metrics_mod.ServerMetrics;

pub fn coolErrorResponse(
    allocator: std.mem.Allocator,
    server_name: []const u8,
    server_tagline: []const u8,
    status_code: u16,
    status_text: []const u8,
    detail: []const u8,
) !H2BufferedResponse {
    const body = try error_pages.render(allocator, server_name, server_tagline, status_code, status_text, detail);
    return .{ .status_code = status_code, .content_type = "text/html; charset=utf-8", .body = body };
}

pub fn readStaticFile(
    io: std.Io,
    allocator: std.mem.Allocator,
    static_dir: []const u8,
    rel_path: []const u8,
    max_file_bytes: usize,
    metrics: *ServerMetrics,
    server_name: []const u8,
    server_tagline: []const u8,
) !H2BufferedResponse {
    if (rel_path.len == 0 or std.mem.indexOf(u8, rel_path, "..") != null or std.mem.indexOfScalar(u8, rel_path, '\\') != null) {
        return coolErrorResponse(allocator, server_name, server_tagline, 400, "Bad Request", "Invalid static file path.");
    }

    const file_path = try std.fs.path.join(allocator, &.{ static_dir, rel_path });
    const stat = static_files.statRegularFile(io, file_path) catch |err| {
        if (err == error.NotDir or err == error.FileNotFound or err == error.NotFile) {
            return coolErrorResponse(allocator, server_name, server_tagline, 404, "Not Found", "The requested resource was not found on this server.");
        }
        return err;
    };
    if (stat.size > max_file_bytes) {
        return coolErrorResponse(allocator, server_name, server_tagline, 413, "Payload Too Large", "Static file is too large for configured limits.");
    }

    const data = std.Io.Dir.cwd().readFileAlloc(io, file_path, allocator, .limited(max_file_bytes)) catch |err| {
        if (err == error.StreamTooLong) {
            return coolErrorResponse(allocator, server_name, server_tagline, 413, "Payload Too Large", "Static file is too large for configured limits.");
        }
        return err;
    };
    const etag = try static_files.makeStaticEtag(allocator, stat);
    const headers = try allocator.alloc(h2_native.Header, 5);
    headers[0] = .{ .name = "accept-ranges", .value = "bytes" };
    headers[1] = .{ .name = "etag", .value = etag };
    headers[2] = .{ .name = "cache-control", .value = "public, max-age=60" };
    headers[3] = .{ .name = "cache-status", .value = "Layerline; hit; ttl=60; detail=\"static-file\"" };
    headers[4] = .{ .name = "vary", .value = "Accept-Encoding" };

    metrics.staticBodySent(data.len, .buffered);
    return .{ .status_code = 200, .content_type = static_files.contentTypeFromPath(rel_path), .body = data, .headers = headers };
}

pub fn readAcmeChallenge(
    io: std.Io,
    allocator: std.mem.Allocator,
    webroot: []const u8,
    token: []const u8,
    server_name: []const u8,
    server_tagline: []const u8,
) !H2BufferedResponse {
    if (token.len == 0 or std.mem.indexOf(u8, token, "..") != null or std.mem.indexOfScalar(u8, token, '\\') != null or std.mem.indexOfScalar(u8, token, '/') != null) {
        return coolErrorResponse(allocator, server_name, server_tagline, 400, "Bad Request", "Invalid ACME challenge path.");
    }

    const file_path = try acme_mod.buildAcmeChallengeFilePath(allocator, webroot, token);
    defer allocator.free(file_path);
    const data = std.Io.Dir.cwd().readFileAlloc(io, file_path, allocator, .limited(64 * 1024)) catch |err| {
        if (err == error.NotDir or err == error.FileNotFound) {
            return coolErrorResponse(allocator, server_name, server_tagline, 404, "Not Found", "The requested resource was not found on this server.");
        }
        if (err == error.StreamTooLong) {
            return coolErrorResponse(allocator, server_name, server_tagline, 413, "Payload Too Large", "ACME challenge file is too large.");
        }
        return err;
    };
    if (data.len > 0 and std.mem.indexOfScalar(u8, data, 0) != null) {
        return coolErrorResponse(allocator, server_name, server_tagline, 404, "Not Found", "The requested resource was not found on this server.");
    }
    return .{ .status_code = 200, .content_type = "text/plain; charset=utf-8", .body = data };
}

pub fn redirectResponse(allocator: std.mem.Allocator, rule: RedirectRule, req: request_mod.HttpRequest) !H2BufferedResponse {
    const location = try redirects.buildLocation(allocator, rule, req);
    const body = try std.fmt.allocPrint(allocator, "Redirecting to {s}\n", .{location});
    const headers = try allocator.alloc(h2_native.Header, 1);
    headers[0] = .{ .name = "location", .value = location };
    return .{ .status_code = rule.status_code, .content_type = "text/plain; charset=utf-8", .body = body, .headers = headers };
}
