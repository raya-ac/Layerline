const std = @import("std");
const headers = @import("http_headers.zig");
const request = @import("request.zig");
const access_log = @import("access_log.zig");
const config = @import("config.zig");

var writer = access_log.Writer{};

pub fn log(io: std.Io, cfg: *const config.ServerConfig, req: request.HttpRequest, rule: Rule) void {
    // Security denials are logged even when ordinary access logging is disabled.
    writer.securityBlock(io, if (cfg.access_log_enabled) cfg.access_log_path else "stderr", req.method, req.version, req.path, @tagName(rule));
}

pub const reply = "Nice try. This is a web server, not a shell vending machine.\n";
pub const Rule = enum {
    php2shell_probe,
    php_runtime_override,
    php_upload_progress,
    multipart_encoding,
    multipart_boundary,
    multipart_headers,
    multipart_parts,
    multipart_nesting,
};

fn contains(text: []const u8, needle: []const u8) bool {
    if (text.len < needle.len) return false;
    for (0..text.len - needle.len + 1) |i|
        if (std.ascii.eqlIgnoreCase(text[i..][0..needle.len], needle)) return true;
    return false;
}

fn hex(byte: u8) ?u8 {
    return std.fmt.charToDigit(byte, 16) catch null;
}

fn decode(buffer: []u8) []u8 {
    var read: usize = 0;
    var written: usize = 0;
    while (read < buffer.len) {
        if (buffer[read] == '%' and read + 2 < buffer.len) {
            if (hex(buffer[read + 1])) |high| {
                if (hex(buffer[read + 2])) |low| {
                    buffer[written] = high * 16 + low;
                    written += 1;
                    read += 3;
                    continue;
                }
            }
        }
        buffer[written] = buffer[read];
        written += 1;
        read += 1;
    }
    return buffer[0..written];
}

fn probe(allocator: std.mem.Allocator, text: []const u8) !?Rule {
    // Each pass only shrinks the buffer. Bound decoding depth and never expand
    // attacker input or interpret PHP, shell, or serialized application data.
    const owned = try allocator.dupe(u8, text);
    defer allocator.free(owned);
    var view = owned;
    for (0..4) |_| {
        if (contains(view, "php2shell") or contains(view, "CVE-2026-109618") or contains(view, "CVE-2026-109619")) return .php2shell_probe;
        if (contains(view, "PHP_SESSION_UPLOAD_PROGRESS")) return .php_upload_progress;
        const next = decode(view);
        if (next.len == view.len) break;
        view = next;
    }
    return null;
}

fn multipart(content_type: []const u8, body: []const u8) ?Rule {
    var parameters = std.mem.splitScalar(u8, content_type, ';');
    _ = parameters.next();
    var boundary: ?[]const u8 = null;
    while (parameters.next()) |parameter| {
        const equal = std.mem.indexOfScalar(u8, parameter, '=') orelse return .multipart_boundary;
        const name = std.mem.trim(u8, parameter[0..equal], " \t");
        var value = std.mem.trim(u8, parameter[equal + 1 ..], " \t");
        if (!std.ascii.eqlIgnoreCase(name, "boundary") or boundary != null) return .multipart_boundary;
        if (value.len >= 2 and value[0] == '"' and value[value.len - 1] == '"') value = value[1 .. value.len - 1];
        if (value.len == 0 or value.len > 70) return .multipart_boundary;
        for (value) |byte| if (!std.ascii.isAlphanumeric(byte) and std.mem.indexOfScalar(u8, "'()+_,-./:=?", byte) == null) return .multipart_boundary;
        boundary = value;
    }
    const token = boundary orelse return .multipart_boundary;
    var delimiter_buffer: [74]u8 = undefined;
    const delimiter = std.fmt.bufPrint(&delimiter_buffer, "\r\n--{s}", .{token}) catch return .multipart_boundary;
    if (!std.mem.startsWith(u8, body, delimiter[2..])) return .multipart_boundary;
    var cursor = body[delimiter.len - 2 ..];
    var parts: usize = 0;
    while (true) {
        if (std.mem.eql(u8, cursor, "--") or std.mem.eql(u8, cursor, "--\r\n")) return null;
        if (!std.mem.startsWith(u8, cursor, "\r\n")) return .multipart_boundary;
        cursor = cursor[2..];
        parts += 1;
        if (parts > 128) return .multipart_parts;
        const end = std.mem.indexOf(u8, cursor, "\r\n\r\n") orelse return .multipart_headers;
        if (end > 8192) return .multipart_headers;
        var lines = std.mem.splitSequence(u8, cursor[0..end], "\r\n");
        var count: usize = 0;
        var disposition = false;
        while (lines.next()) |line| {
            count += 1;
            if (count > 32) return .multipart_headers;
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse return .multipart_headers;
            if (colon == 0) return .multipart_headers;
            for (line[0..colon]) |byte| if (!headers.isHeaderNameByte(byte)) return .multipart_headers;
            const value = headers.trimValue(line[colon + 1 ..]);
            if (!headers.validFieldValue(value)) return .multipart_headers;
            if (std.ascii.eqlIgnoreCase(line[0..colon], "Content-Type") and contains(value, "multipart/")) return .multipart_nesting;
            if (std.ascii.eqlIgnoreCase(line[0..colon], "Content-Disposition")) {
                if (disposition or value.len < 10 or !std.ascii.eqlIgnoreCase(value[0..10], "form-data;")) return .multipart_headers;
                disposition = true;
                // Count opening brackets even in empty file controls, which PHP
                // still turns into metadata arrays despite upload count limits.
                if (std.mem.count(u8, value, "[") > 8) return .multipart_nesting;
            }
        }
        if (!disposition) return .multipart_headers;
        cursor = cursor[end + 4 ..];
        const next = std.mem.indexOf(u8, cursor, delimiter) orelse return .multipart_boundary;
        cursor = cursor[next + delimiter.len ..];
    }
}

pub fn inspect(allocator: std.mem.Allocator, req: request.HttpRequest) !?Rule {
    for ([_][]const u8{ req.path, req.query, req.headers, req.body }) |part|
        if (try probe(allocator, part)) |rule| return rule;
    if (contains(req.query, "auto_prepend_file") or contains(req.query, "allow_url_include")) return .php_runtime_override;
    var lines = std.mem.splitSequence(u8, req.headers, "\r\n");
    var content_type: ?[]const u8 = null;
    var encoding: ?[]const u8 = null;
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const name = line[0..colon];
        const value = headers.trimValue(line[colon + 1 ..]);
        if (std.ascii.eqlIgnoreCase(name, "PHP_VALUE") or std.ascii.eqlIgnoreCase(name, "PHP_ADMIN_VALUE") or
            std.ascii.eqlIgnoreCase(name, "PHP-Value") or std.ascii.eqlIgnoreCase(name, "PHP-Admin-Value")) return .php_runtime_override;
        if (std.ascii.eqlIgnoreCase(name, "Content-Type")) {
            if (content_type != null) return .multipart_headers;
            content_type = value;
        }
        if (std.ascii.eqlIgnoreCase(name, "Content-Encoding")) encoding = value;
    }
    if (content_type) |value| {
        var pieces = std.mem.splitScalar(u8, value, ';');
        const media_type = std.mem.trim(u8, pieces.next().?, " \t");
        if (std.ascii.eqlIgnoreCase(media_type, "multipart/form-data")) {
            if (encoding) |coding| if (!std.ascii.eqlIgnoreCase(coding, "identity")) {
                return .multipart_encoding;
            };
            return multipart(value, req.body);
        }
    }
    return null;
}

test "guard detects encoded probes, override headers and abusive multipart" {
    var req = request.HttpRequest{ .method = "POST", .path = "/upload", .query = "", .headers = "", .body = "", .version = "HTTP/2.0", .close_connection = false };
    req.query = "%2570hp2%2573hell";
    try std.testing.expectEqual(Rule.php2shell_probe, (try inspect(std.testing.allocator, req)).?);
    req.query = "";
    req.headers = "PHP_ADMIN_VALUE: memory_limit=-1";
    try std.testing.expectEqual(Rule.php_runtime_override, (try inspect(std.testing.allocator, req)).?);
    req.headers = "Content-Type: multipart/form-data; boundary=boundary";
    req.body = "--boundary\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.txt\"\r\n\r\nnormal file\r\n--boundary--\r\n";
    try std.testing.expect(try inspect(std.testing.allocator, req) == null);
    req.body = "--boundary\r\nContent-Disposition: form-data; name=\"x[a][b][c][d][e][f][g][h][i]\"\r\n\r\nx\r\n--boundary--\r\n";
    try std.testing.expectEqual(Rule.multipart_nesting, (try inspect(std.testing.allocator, req)).?);
    req.body = "--boundary\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\nx";
    try std.testing.expectEqual(Rule.multipart_boundary, (try inspect(std.testing.allocator, req)).?);
}
