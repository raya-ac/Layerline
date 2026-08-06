const std = @import("std");

const acme_mod = @import("acme.zig");
const config_mod = @import("config.zig");
const error_pages = @import("error_pages.zig");
const h2_native = @import("h2_native.zig");
const h2_support = @import("http2_support.zig");
const http_headers = @import("http_headers.zig");
const metrics_mod = @import("metrics.zig");
const redirects = @import("redirects.zig");
const request_mod = @import("request.zig");
const static_cache = @import("static_cache.zig");
const static_files = @import("static_files.zig");

const H2BufferedResponse = h2_support.BufferedResponse;
const RedirectRule = config_mod.RedirectRule;
const ServerMetrics = metrics_mod.ServerMetrics;

fn staticResponseHeaders(allocator: std.mem.Allocator, etag: []const u8, last_modified: []const u8, cache_status: []const u8) ![]h2_native.Header {
    const headers = try allocator.alloc(h2_native.Header, 6);
    headers[0] = .{ .name = "accept-ranges", .value = "bytes" };
    headers[1] = .{ .name = "etag", .value = etag };
    headers[2] = .{ .name = "last-modified", .value = last_modified };
    headers[3] = .{ .name = "cache-control", .value = "public, max-age=3600" };
    headers[4] = .{ .name = "cache-status", .value = cache_status };
    headers[5] = .{ .name = "vary", .value = "Accept-Encoding" };
    return headers;
}

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
    request_headers: []const u8,
    max_file_bytes: usize,
    metrics: *ServerMetrics,
    response_cache: *static_cache.Store,
    response_cache_policy: static_cache.Policy,
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

    const etag = try static_files.makeStaticEtag(allocator, stat);
    const last_modified = try static_files.makeHttpDate(allocator, stat.mtime);
    const file_len = std.math.cast(usize, stat.size) orelse return error.FileTooBig;
    const content_type = static_files.contentTypeFromPath(rel_path);

    if (http_headers.findHeaderValue(request_headers, "if-none-match")) |if_none_match| {
        if (static_files.etagMatches(if_none_match, etag)) {
            const cache_status = try static_cache.cacheStatusStatic(allocator, null);
            const headers = try staticResponseHeaders(allocator, etag, last_modified, cache_status);
            return .{ .status_code = 304, .content_type = content_type, .body = "", .headers = headers };
        }
    }
    if (http_headers.findHeaderValue(request_headers, "if-modified-since")) |if_modified_since| {
        if (static_files.notModifiedSince(stat, if_modified_since)) {
            const cache_status = try static_cache.cacheStatusStatic(allocator, null);
            const headers = try staticResponseHeaders(allocator, etag, last_modified, cache_status);
            return .{ .status_code = 304, .content_type = content_type, .body = "", .headers = headers };
        }
    }

    if (response_cache_policy.enabled and file_len <= response_cache_policy.max_entry_bytes) {
        const now_ms = std.Io.Timestamp.now(io, .awake).toMilliseconds();
        if (try response_cache.fetch(allocator, file_path, etag, now_ms)) |cached| {
            metrics.responseCacheHit(cached.len);
            const cache_status = try static_cache.cacheStatusHit(allocator, response_cache_policy);
            const headers = try staticResponseHeaders(allocator, etag, last_modified, cache_status);
            return .{ .status_code = 200, .content_type = content_type, .body = cached, .headers = headers };
        }

        metrics.responseCacheMiss();
        const data = std.Io.Dir.cwd().readFileAlloc(io, file_path, allocator, .limited(max_file_bytes)) catch |err| {
            if (err == error.StreamTooLong) {
                return coolErrorResponse(allocator, server_name, server_tagline, 413, "Payload Too Large", "Static file is too large for configured limits.");
            }
            return err;
        };
        const store_outcome = try response_cache.store(file_path, etag, data, now_ms, response_cache_policy);
        if (store_outcome.result == .stored) metrics.responseCacheStore();
        var eviction_index: usize = 0;
        while (eviction_index < store_outcome.evictions) : (eviction_index += 1) metrics.responseCacheEviction();
        const cache_status = if (store_outcome.result == .stored)
            try static_cache.cacheStatusStored(allocator, response_cache_policy)
        else
            try static_cache.cacheStatusStatic(allocator, null);
        const headers = try staticResponseHeaders(allocator, etag, last_modified, cache_status);

        metrics.staticBodySent(data.len, .buffered);
        return .{ .status_code = 200, .content_type = content_type, .body = data, .headers = headers };
    }

    const data = std.Io.Dir.cwd().readFileAlloc(io, file_path, allocator, .limited(max_file_bytes)) catch |err| {
        if (err == error.StreamTooLong) {
            return coolErrorResponse(allocator, server_name, server_tagline, 413, "Payload Too Large", "Static file is too large for configured limits.");
        }
        return err;
    };
    const cache_status = try static_cache.cacheStatusStatic(allocator, null);
    const headers = try staticResponseHeaders(allocator, etag, last_modified, cache_status);

    metrics.staticBodySent(data.len, .buffered);
    return .{ .status_code = 200, .content_type = content_type, .body = data, .headers = headers };
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
