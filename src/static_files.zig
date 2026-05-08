const std = @import("std");

const http_headers = @import("http_headers.zig");

pub const ByteRange = struct {
    start: usize,
    end: usize,
};

pub fn contentTypeFromPath(path: []const u8) []const u8 {
    if (std.mem.endsWith(u8, path, ".html")) return "text/html; charset=utf-8";
    if (std.mem.endsWith(u8, path, ".txt")) return "text/plain; charset=utf-8";
    if (std.mem.endsWith(u8, path, ".css")) return "text/css; charset=utf-8";
    if (std.mem.endsWith(u8, path, ".js")) return "application/javascript; charset=utf-8";
    if (std.mem.endsWith(u8, path, ".json")) return "application/json; charset=utf-8";
    if (std.mem.endsWith(u8, path, ".xml")) return "application/xml; charset=utf-8";
    if (std.mem.endsWith(u8, path, ".svg")) return "image/svg+xml";
    if (std.mem.endsWith(u8, path, ".png")) return "image/png";
    if (std.mem.endsWith(u8, path, ".jpg") or std.mem.endsWith(u8, path, ".jpeg")) return "image/jpeg";
    if (std.mem.endsWith(u8, path, ".webp")) return "image/webp";
    if (std.mem.endsWith(u8, path, ".gif")) return "image/gif";
    if (std.mem.endsWith(u8, path, ".ico")) return "image/x-icon";
    if (std.mem.endsWith(u8, path, ".wasm")) return "application/wasm";
    return "text/plain; charset=utf-8";
}

// Single ranges cover the common browser/media case. Multi-range responses are
// MIME multipart work, so they stay rejected until there is a real need.
pub fn etagMatches(raw: []const u8, etag: []const u8) bool {
    var cursor = raw;
    while (cursor.len > 0) {
        const comma_pos = std.mem.indexOfScalar(u8, cursor, ',') orelse cursor.len;
        const item = http_headers.trimValue(cursor[0..comma_pos]);
        if (std.mem.eql(u8, item, "*") or std.mem.eql(u8, item, etag)) return true;
        if (comma_pos >= cursor.len) break;
        cursor = cursor[comma_pos + 1 ..];
    }
    return false;
}

pub fn parseByteRange(raw: []const u8, total_len: usize) !ByteRange {
    if (!std.mem.startsWith(u8, raw, "bytes=")) return error.BadRequest;
    if (total_len == 0) return error.RangeNotSatisfiable;

    const spec = http_headers.trimValue(raw["bytes=".len..]);
    if (std.mem.indexOfScalar(u8, spec, ',') != null) return error.BadRequest;

    const dash = std.mem.indexOfScalar(u8, spec, '-') orelse return error.BadRequest;
    const start_raw = http_headers.trimValue(spec[0..dash]);
    const end_raw = http_headers.trimValue(spec[dash + 1 ..]);

    if (start_raw.len == 0) {
        if (end_raw.len == 0) return error.BadRequest;
        const suffix_len = std.fmt.parseInt(usize, end_raw, 10) catch return error.BadRequest;
        if (suffix_len == 0) return error.RangeNotSatisfiable;
        const actual_len = @min(suffix_len, total_len);
        return .{ .start = total_len - actual_len, .end = total_len - 1 };
    }

    const start = std.fmt.parseInt(usize, start_raw, 10) catch return error.BadRequest;
    const end = if (end_raw.len == 0)
        total_len - 1
    else
        std.fmt.parseInt(usize, end_raw, 10) catch return error.BadRequest;

    if (start >= total_len or start > end) return error.RangeNotSatisfiable;
    return .{ .start = start, .end = @min(end, total_len - 1) };
}

pub fn makeStaticEtag(allocator: std.mem.Allocator, stat: std.Io.File.Stat) ![]const u8 {
    // Cheap validator, not a content hash. Good enough to catch ordinary local
    // edits without reading the file twice.
    return std.fmt.allocPrint(
        allocator,
        "\"{d}-{d}-{d}\"",
        .{ stat.inode, stat.size, stat.mtime.toNanoseconds() },
    );
}

pub fn makeStaticBaseHeaders(allocator: std.mem.Allocator, etag: []const u8, content_encoding: ?[]const u8) ![]const u8 {
    if (content_encoding) |encoding| {
        return std.fmt.allocPrint(
            allocator,
            "Accept-Ranges: bytes\r\n" ++
                "ETag: {s}\r\n" ++
                "Cache-Control: public, max-age=60\r\n" ++
                "Cache-Status: Layerline; hit; ttl=60; detail=\"precompressed-static\"\r\n" ++
                "Vary: Accept-Encoding\r\n" ++
                "Content-Encoding: {s}\r\n",
            .{ etag, encoding },
        );
    }

    return std.fmt.allocPrint(
        allocator,
        "Accept-Ranges: bytes\r\n" ++
            "ETag: {s}\r\n" ++
            "Cache-Control: public, max-age=60\r\n" ++
            "Cache-Status: Layerline; hit; ttl=60; detail=\"static-file\"\r\n" ++
            "Vary: Accept-Encoding\r\n",
        .{etag},
    );
}

fn contentCodingQAllows(item: []const u8) bool {
    var parts = std.mem.splitScalar(u8, item, ';');
    _ = parts.next();
    while (parts.next()) |part| {
        const param = http_headers.trimValue(part);
        const eq = std.mem.indexOfScalar(u8, param, '=') orelse continue;
        const name = http_headers.trimValue(param[0..eq]);
        if (!std.ascii.eqlIgnoreCase(name, "q")) continue;
        const value = http_headers.trimValue(param[eq + 1 ..]);
        const q = std.fmt.parseFloat(f64, value) catch return false;
        return q > 0.0;
    }
    return true;
}

pub fn acceptsContentCoding(request_headers: []const u8, coding: []const u8) bool {
    const raw = http_headers.findHeaderValue(request_headers, "Accept-Encoding") orelse return false;
    var wildcard_allowed: ?bool = null;
    var cursor = raw;
    while (cursor.len > 0) {
        const comma_pos = std.mem.indexOfScalar(u8, cursor, ',') orelse cursor.len;
        const item = http_headers.trimValue(cursor[0..comma_pos]);
        const semicolon_pos = std.mem.indexOfScalar(u8, item, ';') orelse item.len;
        const token = http_headers.trimValue(item[0..semicolon_pos]);
        if (std.ascii.eqlIgnoreCase(token, coding)) return contentCodingQAllows(item);
        if (std.mem.eql(u8, token, "*")) wildcard_allowed = contentCodingQAllows(item);
        if (comma_pos >= cursor.len) break;
        cursor = cursor[comma_pos + 1 ..];
    }
    return wildcard_allowed orelse false;
}

pub fn statRegularFile(io: std.Io, file_path: []const u8) !std.Io.File.Stat {
    const stat = try std.Io.Dir.cwd().statFile(io, file_path, .{});
    if (stat.kind != .file) return error.NotFile;
    return stat;
}
