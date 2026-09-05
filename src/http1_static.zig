const std = @import("std");

const acme = @import("acme.zig");
const metrics_mod = @import("metrics.zig");
const static_cache = @import("static_cache.zig");
const static_files = @import("static_files.zig");
const http_headers = @import("http_headers.zig");

pub const Callbacks = struct {
    metrics: *metrics_mod.ServerMetrics,
    response_cache: *static_cache.Store,
    send_bad_request_for_method: *const fn (std.mem.Allocator, std.Io.net.Stream, []const u8, bool, bool) anyerror!void,
    send_cool_error: *const fn (std.Io.net.Stream, std.mem.Allocator, u16, []const u8, []const u8, bool, bool, ?[]const u8) anyerror!void,
    send_not_found_for_method: *const fn (std.mem.Allocator, std.Io.net.Stream, bool, bool) anyerror!void,
    send_response: *const fn (std.Io.net.Stream, u16, []const u8, []const u8, []const u8, bool) anyerror!void,
    send_response_no_body: *const fn (std.Io.net.Stream, u16, []const u8, []const u8, usize, bool) anyerror!void,
    send_response_no_body_headers: *const fn (std.Io.net.Stream, u16, []const u8, []const u8, usize, bool, ?[]const u8) anyerror!void,
    write_all: *const fn (std.Io.net.Stream, []const u8) anyerror!void,
};

pub fn serveStatic(
    io: std.Io,
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    static_dir: []const u8,
    rel_path: []const u8,
    request_headers: []const u8,
    close_connection: bool,
    is_head: bool,
    max_file_bytes: usize,
    response_cache_policy: static_cache.Policy,
    callbacks: Callbacks,
) !void {
    // Static paths are deliberately boring: no parent hops, no backslashes, no
    // directory listings. If it is not a plain file, it is not served.
    if (rel_path.len == 0 or std.mem.indexOf(u8, rel_path, "..") != null or std.mem.indexOfScalar(u8, rel_path, '\\') != null) {
        try callbacks.send_bad_request_for_method(allocator, stream, "Invalid static file path.", close_connection, is_head);
        return;
    }

    const file_path = try std.fs.path.join(allocator, &.{ static_dir, rel_path });
    defer allocator.free(file_path);

    var stat = static_files.statRegularFile(io, file_path) catch |err| {
        if (err == error.NotDir or err == error.FileNotFound or err == error.NotFile) {
            try callbacks.send_not_found_for_method(allocator, stream, close_connection, is_head);
            return;
        }
        return err;
    };

    const raw_range_header = if (is_head) null else http_headers.findHeaderValue(request_headers, "Range");
    var selected_path = file_path;
    var encoded_path: ?[]const u8 = null;
    defer if (encoded_path) |path| allocator.free(path);
    var content_encoding: ?[]const u8 = null;

    // Serve precompressed assets when present. On-the-fly compression belongs
    // in a worker/offline build step, not on the hot request path.
    if (raw_range_header == null) {
        const candidates = [_]struct { coding: []const u8, suffix: []const u8 }{
            .{ .coding = "br", .suffix = ".br" },
            .{ .coding = "gzip", .suffix = ".gz" },
        };
        for (candidates) |candidate| {
            if (!static_files.acceptsContentCoding(request_headers, candidate.coding)) continue;
            const candidate_path = try std.fmt.allocPrint(allocator, "{s}{s}", .{ file_path, candidate.suffix });
            if (static_files.statRegularFile(io, candidate_path)) |candidate_stat| {
                selected_path = candidate_path;
                encoded_path = candidate_path;
                stat = candidate_stat;
                content_encoding = candidate.coding;
                break;
            } else |_| {
                allocator.free(candidate_path);
            }
        }
    }

    if (stat.size > max_file_bytes) {
        try callbacks.send_cool_error(stream, allocator, 413, "Payload Too Large", "Static file is too large for configured limits.", close_connection, is_head, null);
        return;
    }
    const file_len = std.math.cast(usize, stat.size) orelse return error.FileTooBig;

    const etag = try static_files.makeStaticEtag(allocator, stat);
    defer allocator.free(etag);
    const last_modified = try static_files.makeHttpDate(allocator, stat.mtime);
    defer allocator.free(last_modified);
    const content_type = static_files.contentTypeFromPath(rel_path);
    const range_header = if (raw_range_header) |range_value| blk: {
        if (http_headers.findHeaderValue(request_headers, "If-Range")) |if_range| {
            if (!static_files.ifRangeAllows(if_range, etag, stat)) break :blk null;
        }
        break :blk range_value;
    } else null;

    if (static_files.isNotModified(request_headers, etag, stat.mtime)) {
        const cache_status = try static_cache.cacheStatusStatic(allocator, content_encoding);
        defer allocator.free(cache_status);
        const base_headers = try static_files.makeStaticBaseHeaders(allocator, etag, last_modified, content_encoding, cache_status);
        defer allocator.free(base_headers);
        try callbacks.send_response_no_body_headers(stream, 304, "Not Modified", content_type, 0, close_connection, base_headers);
        return;
    }

    if (range_header) |range_value| {
        const cache_status = try static_cache.cacheStatusStatic(allocator, content_encoding);
        defer allocator.free(cache_status);
        const base_headers = try static_files.makeStaticBaseHeaders(allocator, etag, last_modified, content_encoding, cache_status);
        defer allocator.free(base_headers);
        const range = static_files.parseByteRange(range_value, file_len) catch |err| switch (err) {
            error.RangeNotSatisfiable => {
                const headers = try std.fmt.allocPrint(allocator, "{s}Content-Range: bytes */{d}\r\n", .{ base_headers, file_len });
                defer allocator.free(headers);
                try callbacks.send_cool_error(stream, allocator, 416, "Range Not Satisfiable", "Requested byte range cannot be served.", close_connection, is_head, headers);
                return;
            },
            error.BadRequest => {
                try callbacks.send_bad_request_for_method(allocator, stream, "Invalid Range header.", close_connection, is_head);
                return;
            },
        };

        const content_range = try std.fmt.allocPrint(allocator, "bytes {d}-{d}/{d}", .{ range.start, range.end, file_len });
        defer allocator.free(content_range);
        const headers = try std.fmt.allocPrint(allocator, "{s}Content-Range: {s}\r\n", .{ base_headers, content_range });
        defer allocator.free(headers);
        const body_len = range.end - range.start + 1;

        try callbacks.send_response_no_body_headers(stream, 206, "Partial Content", content_type, body_len, close_connection, headers);
        if (!is_head) {
            try static_files.streamRangeBody(io, stream, selected_path, range.start, body_len, .{ .metrics = callbacks.metrics, .write_all = callbacks.write_all });
        }
        return;
    }

    if (response_cache_policy.enabled and file_len <= response_cache_policy.max_entry_bytes) {
        const now_ms = std.Io.Timestamp.now(io, .awake).toMilliseconds();
        if (try callbacks.response_cache.fetch(allocator, selected_path, etag, now_ms)) |cached| {
            defer allocator.free(cached);
            callbacks.metrics.responseCacheHit(cached.len);
            const cache_status = try static_cache.cacheStatusHit(allocator, response_cache_policy);
            defer allocator.free(cache_status);
            const base_headers = try static_files.makeStaticBaseHeaders(allocator, etag, last_modified, content_encoding, cache_status);
            defer allocator.free(base_headers);
            try callbacks.send_response_no_body_headers(stream, 200, "OK", content_type, cached.len, close_connection, base_headers);
            if (!is_head and cached.len > 0) try callbacks.write_all(stream, cached);
            return;
        }

        callbacks.metrics.responseCacheMiss();
        const data = std.Io.Dir.cwd().readFileAlloc(io, selected_path, allocator, .limited(response_cache_policy.max_entry_bytes)) catch |err| {
            if (err == error.StreamTooLong) {
                try callbacks.send_cool_error(stream, allocator, 413, "Payload Too Large", "Static file is too large for configured cache limits.", close_connection, is_head, null);
                return;
            }
            return err;
        };
        defer allocator.free(data);

        const store_outcome = try callbacks.response_cache.store(selected_path, etag, data, now_ms, response_cache_policy);
        if (store_outcome.result == .stored) callbacks.metrics.responseCacheStore();
        var eviction_index: usize = 0;
        while (eviction_index < store_outcome.evictions) : (eviction_index += 1) callbacks.metrics.responseCacheEviction();
        const cache_status = if (store_outcome.result == .stored)
            try static_cache.cacheStatusStored(allocator, response_cache_policy)
        else
            try static_cache.cacheStatusStatic(allocator, content_encoding);
        defer allocator.free(cache_status);
        const base_headers = try static_files.makeStaticBaseHeaders(allocator, etag, last_modified, content_encoding, cache_status);
        defer allocator.free(base_headers);
        try callbacks.send_response_no_body_headers(stream, 200, "OK", content_type, data.len, close_connection, base_headers);
        if (!is_head and data.len > 0) try callbacks.write_all(stream, data);
        if (!is_head) callbacks.metrics.staticBodySent(data.len, .buffered);
        return;
    }

    const cache_status = try static_cache.cacheStatusStatic(allocator, content_encoding);
    defer allocator.free(cache_status);
    const base_headers = try static_files.makeStaticBaseHeaders(allocator, etag, last_modified, content_encoding, cache_status);
    defer allocator.free(base_headers);
    try callbacks.send_response_no_body_headers(stream, 200, "OK", content_type, file_len, close_connection, base_headers);
    if (!is_head) {
        try static_files.streamRangeBody(io, stream, selected_path, 0, file_len, .{ .metrics = callbacks.metrics, .write_all = callbacks.write_all });
    }
}

pub fn serveAcmeChallenge(
    io: std.Io,
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    webroot: []const u8,
    token: []const u8,
    close_connection: bool,
    is_head: bool,
    callbacks: Callbacks,
) !void {
    if (token.len == 0 or std.mem.indexOf(u8, token, "..") != null or std.mem.indexOfScalar(u8, token, '\\') != null or std.mem.indexOfScalar(u8, token, '/') != null) {
        try callbacks.send_bad_request_for_method(allocator, stream, "Invalid ACME challenge path.", close_connection, is_head);
        return;
    }

    const file_path = try acme.buildAcmeChallengeFilePath(allocator, webroot, token);
    defer allocator.free(file_path);

    const data = std.Io.Dir.cwd().readFileAlloc(io, file_path, allocator, .limited(64 * 1024)) catch |err| {
        if (err == error.StreamTooLong) {
            try callbacks.send_cool_error(stream, allocator, 413, "Payload Too Large", "ACME challenge file is too large.", close_connection, is_head, null);
            return;
        }
        if (err == error.NotDir or err == error.FileNotFound) {
            try callbacks.send_not_found_for_method(allocator, stream, close_connection, is_head);
            return;
        }
        return err;
    };
    defer allocator.free(data);

    if (data.len > 0 and std.mem.indexOfScalar(u8, data, 0) != null) {
        try callbacks.send_not_found_for_method(allocator, stream, close_connection, is_head);
        return;
    }

    if (is_head) {
        try callbacks.send_response_no_body(stream, 200, "OK", "text/plain; charset=utf-8", data.len, close_connection);
        return;
    }
    try callbacks.send_response(stream, 200, "OK", "text/plain; charset=utf-8", data, close_connection);
}
