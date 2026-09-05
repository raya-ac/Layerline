const std = @import("std");

const config_mod = @import("config.zig");
const h2_native = @import("h2_native.zig");
const http_headers = @import("http_headers.zig");
const http_response = @import("http_response.zig");
const metrics_mod = @import("metrics.zig");
const static_files = @import("static_files.zig");

pub const Prepared = struct {
    body: []const u8,
    encoding: ?[]const u8 = null,
    owned: ?[]u8 = null,

    pub fn deinit(self: Prepared, allocator: std.mem.Allocator) void {
        if (self.owned) |owned| allocator.free(owned);
    }
};

pub const PrepareOptions = struct {
    status_code: u16,
    content_type: []const u8,
    body: []const u8,
    is_head: bool,
    extra_headers: ?[]const u8 = null,
    h2_headers: []const h2_native.Header = &.{},
    request_headers: []const u8,
    response_headers: []const config_mod.ResponseHeaderRule,
    compression_policy: config_mod.CompressionPolicy,
    compression_work_buffer_bytes: usize,
    metrics: ?*metrics_mod.ServerMetrics = null,
};

fn headerBlockContainsHeader(headers: ?[]const u8, name: []const u8) bool {
    const raw_headers = headers orelse return false;
    var lines = std.mem.splitSequence(u8, raw_headers, "\r\n");
    while (lines.next()) |line| {
        const trimmed = http_headers.trimValue(line);
        if (trimmed.len == 0) continue;
        const colon = std.mem.indexOfScalar(u8, trimmed, ':') orelse continue;
        const header_name = http_headers.trimValue(trimmed[0..colon]);
        if (std.ascii.eqlIgnoreCase(header_name, name)) return true;
    }
    return false;
}

fn h2HeadersContain(headers: []const h2_native.Header, name: []const u8) bool {
    for (headers) |header| {
        if (std.ascii.eqlIgnoreCase(header.name, name)) return true;
    }
    return false;
}

fn isCompressibleContentType(content_type: []const u8) bool {
    const semicolon = std.mem.indexOfScalar(u8, content_type, ';') orelse content_type.len;
    const base = http_headers.trimValue(content_type[0..semicolon]);
    return std.mem.startsWith(u8, base, "text/") or
        std.ascii.eqlIgnoreCase(base, "application/javascript") or
        std.ascii.eqlIgnoreCase(base, "application/json") or
        std.ascii.eqlIgnoreCase(base, "application/xml") or
        std.ascii.eqlIgnoreCase(base, "application/wasm") or
        std.ascii.eqlIgnoreCase(base, "image/svg+xml");
}

fn gzipCompressAlloc(allocator: std.mem.Allocator, body: []const u8, work_buffer_bytes: usize) ![]u8 {
    var output = try std.Io.Writer.Allocating.initCapacity(allocator, @max(@as(usize, 64), body.len / 2));
    errdefer output.deinit();

    const work_buffer = try allocator.alloc(u8, work_buffer_bytes);
    defer allocator.free(work_buffer);

    const GzipCompressor = std.compress.flate.Compress;
    const gzip = try allocator.create(GzipCompressor);
    defer allocator.destroy(gzip);

    gzip.* = try GzipCompressor.init(&output.writer, work_buffer, .gzip, .fastest);
    try gzip.writer.writeAll(body);
    try gzip.finish();
    return output.toOwnedSlice();
}

pub fn prepare(allocator: std.mem.Allocator, options: PrepareOptions) !Prepared {
    const policy = options.compression_policy;
    if (!http_response.canSendBody(options.status_code, options.is_head) or
        options.status_code == 206 or
        !policy.enabled or
        !policy.gzip_enabled or
        options.body.len < policy.min_bytes or
        options.body.len > policy.max_bytes or
        !isCompressibleContentType(options.content_type) or
        !static_files.acceptsContentCoding(options.request_headers, "gzip") or
        headerBlockContainsHeader(options.extra_headers, "Content-Encoding") or
        h2HeadersContain(options.h2_headers, "content-encoding") or
        config_mod.responseHeaderRulesContain(options.response_headers, "Content-Encoding"))
    {
        return .{ .body = options.body };
    }

    const compressed = try gzipCompressAlloc(allocator, options.body, options.compression_work_buffer_bytes);
    if (compressed.len >= options.body.len) {
        allocator.free(compressed);
        return .{ .body = options.body };
    }

    if (options.metrics) |metrics| metrics.compressedResponseSent(compressed.len);
    return .{ .body = compressed, .encoding = "gzip", .owned = compressed };
}
