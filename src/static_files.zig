const std = @import("std");
const builtin = @import("builtin");

const http_headers = @import("http_headers.zig");
const metrics_mod = @import("metrics.zig");

const HAS_DARWIN_SENDFILE = switch (builtin.os.tag) {
    .driverkit, .ios, .maccatalyst, .macos, .tvos, .visionos, .watchos => true,
    else => false,
};

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
    if (std.mem.endsWith(u8, path, ".zip")) return "application/zip";
    if (std.mem.endsWith(u8, path, ".tar")) return "application/x-tar";
    if (std.mem.endsWith(u8, path, ".tar.gz") or std.mem.endsWith(u8, path, ".tgz")) return "application/gzip";
    if (std.mem.endsWith(u8, path, ".gz")) return "application/gzip";
    if (std.mem.endsWith(u8, path, ".dmg")) return "application/x-apple-diskimage";
    if (std.mem.endsWith(u8, path, ".exe")) return "application/vnd.microsoft.portable-executable";
    if (std.mem.endsWith(u8, path, ".msi")) return "application/x-msi";
    return "text/plain; charset=utf-8";
}

test "contentTypeFromPath recognizes downloadable archives" {
    try std.testing.expectEqualStrings("application/zip", contentTypeFromPath("junkstep-windows.zip"));
    try std.testing.expectEqualStrings("application/gzip", contentTypeFromPath("junkstep-linux.tar.gz"));
    try std.testing.expectEqualStrings("application/gzip", contentTypeFromPath("junkstep-linux.tgz"));
    try std.testing.expectEqualStrings("application/x-tar", contentTypeFromPath("pack.tar"));
    try std.testing.expectEqualStrings("application/x-apple-diskimage", contentTypeFromPath("junkstep.dmg"));
    try std.testing.expectEqualStrings("application/vnd.microsoft.portable-executable", contentTypeFromPath("junkstep.exe"));
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

pub fn makeStaticBaseHeaders(allocator: std.mem.Allocator, etag: []const u8, content_encoding: ?[]const u8, cache_status: []const u8) ![]const u8 {
    if (content_encoding) |encoding| {
        return std.fmt.allocPrint(
            allocator,
            "Accept-Ranges: bytes\r\n" ++
                "ETag: {s}\r\n" ++
                "Cache-Control: public, max-age=60\r\n" ++
                "Cache-Status: {s}\r\n" ++
                "Vary: Accept-Encoding\r\n" ++
                "Content-Encoding: {s}\r\n",
            .{ etag, cache_status, encoding },
        );
    }

    return std.fmt.allocPrint(
        allocator,
        "Accept-Ranges: bytes\r\n" ++
            "ETag: {s}\r\n" ++
            "Cache-Control: public, max-age=60\r\n" ++
            "Cache-Status: {s}\r\n" ++
            "Vary: Accept-Encoding\r\n",
        .{ etag, cache_status },
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

pub const RangeBodyCallbacks = struct {
    metrics: *metrics_mod.ServerMetrics,
    write_all: *const fn (std.Io.net.Stream, []const u8) anyerror!void,
};

fn trySendfileRange(stream: std.Io.net.Stream, file: std.Io.File, start: usize, body_len: usize) !bool {
    if (comptime !HAS_DARWIN_SENDFILE) return false;
    if (body_len == 0) return true;

    var offset = std.math.cast(std.c.off_t, start) orelse return error.FileTooBig;
    var remaining = body_len;
    var sent_total: usize = 0;

    while (remaining > 0) {
        const chunk = @min(remaining, @as(usize, @intCast(std.math.maxInt(i32))));
        var len: std.c.off_t = @intCast(chunk);
        switch (std.c.errno(std.c.sendfile(file.handle, stream.socket.handle, offset, &len, null, 0))) {
            .SUCCESS => {},
            .INTR, .AGAIN => {
                if (len == 0) continue;
            },
            .OPNOTSUPP, .NOTSOCK, .NOSYS => {
                if (sent_total == 0) return false;
                return error.Unexpected;
            },
            .PIPE, .NOTCONN => return error.BrokenPipe,
            .IO => return error.InputOutput,
            else => return error.Unexpected,
        }

        if (len <= 0) return error.WriteZero;
        const sent: usize = @intCast(len);
        remaining -= sent;
        sent_total += sent;
        offset += len;
    }

    return true;
}

pub fn streamRangeBody(
    io: std.Io,
    stream: std.Io.net.Stream,
    file_path: []const u8,
    start: usize,
    body_len: usize,
    callbacks: RangeBodyCallbacks,
) !void {
    const file = try std.Io.Dir.cwd().openFile(io, file_path, .{ .mode = .read_only, .allow_directory = false });
    defer file.close(io);

    if (try trySendfileRange(stream, file, start, body_len)) {
        callbacks.metrics.staticBodySent(body_len, .sendfile);
        return;
    }

    var buffer: [8 * 1024]u8 = undefined;
    var sent: usize = 0;
    while (sent < body_len) {
        const chunk_len = @min(buffer.len, body_len - sent);
        var vec: [1][]u8 = .{buffer[0..chunk_len]};
        const read_n = try file.readPositional(io, &vec, start + sent);
        if (read_n == 0) return error.UnexpectedEndOfFile;
        try callbacks.write_all(stream, buffer[0..read_n]);
        sent += read_n;
    }

    callbacks.metrics.staticBodySent(body_len, .buffered);
}
