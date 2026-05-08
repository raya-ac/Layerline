const std = @import("std");
const http_headers = @import("http_headers.zig");

pub const HeaderSplit = struct {
    headers: []const u8,
    body: []const u8,
};

pub const Status = struct {
    code: u16,
    text: []const u8,
};

pub fn splitHeaderBlock(output: []const u8) ?HeaderSplit {
    if (std.mem.indexOf(u8, output, "\r\n\r\n")) |idx| {
        return .{ .headers = output[0..idx], .body = output[idx + 4 ..] };
    }
    if (std.mem.indexOf(u8, output, "\n\n")) |idx| {
        return .{ .headers = output[0..idx], .body = output[idx + 2 ..] };
    }
    return null;
}

pub fn findHeaderValue(headers: []const u8, target_name: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, headers, '\n');
    while (lines.next()) |line| {
        if (std.mem.indexOfScalar(u8, line, ':')) |colon| {
            const key = http_headers.trimValue(line[0..colon]);
            const value = http_headers.trimValue(line[colon + 1 ..]);
            if (std.ascii.eqlIgnoreCase(key, target_name)) return value;
        }
    }
    return null;
}

pub fn parseStatus(headers: []const u8) Status {
    const raw_status = findHeaderValue(headers, "Status") orelse return .{ .code = 200, .text = "OK" };
    const status_line = http_headers.trimValue(raw_status);
    if (status_line.len < 3) return .{ .code = 200, .text = "OK" };

    const code = std.fmt.parseInt(u16, status_line[0..@min(3, status_line.len)], 10) catch 200;
    if (code < 100 or code > 599) return .{ .code = 200, .text = "OK" };

    if (status_line.len > 3) {
        const reason = http_headers.trimValue(status_line[3..]);
        if (reason.len > 0) return .{ .code = code, .text = reason };
    }

    return .{ .code = code, .text = statusTextForCode(code) };
}

pub fn buildExtraHeaders(allocator: std.mem.Allocator, headers: []const u8) !?[]u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);

    var lines = std.mem.splitScalar(u8, headers, '\n');
    while (lines.next()) |line| {
        const trimmed = http_headers.trimValue(line);
        if (trimmed.len == 0) continue;
        if (std.mem.indexOfScalar(u8, trimmed, ':')) |colon| {
            const name = http_headers.trimValue(trimmed[0..colon]);
            const value = http_headers.trimValue(trimmed[colon + 1 ..]);
            if (name.len == 0 or value.len == 0 or isSkippedResponseHeader(name)) continue;
            try out.print(allocator, "{s}: {s}\r\n", .{ name, value });
        }
    }

    if (out.items.len == 0) {
        out.deinit(allocator);
        return null;
    }
    return try out.toOwnedSlice(allocator);
}

pub fn putRequestHeaders(
    allocator: std.mem.Allocator,
    env: *std.process.Environ.Map,
    request_headers: []const u8,
) !void {
    var lines = std.mem.splitSequence(u8, request_headers, "\r\n");
    while (lines.next()) |line| {
        if (std.mem.indexOfScalar(u8, line, ':')) |colon| {
            const name = http_headers.trimValue(line[0..colon]);
            const value = http_headers.trimValue(line[colon + 1 ..]);
            if (name.len == 0) continue;
            if (std.ascii.eqlIgnoreCase(name, "Content-Type") or std.ascii.eqlIgnoreCase(name, "Content-Length")) continue;
            if (std.ascii.eqlIgnoreCase(name, "X-Request-Id")) continue;

            var env_name = std.ArrayList(u8).empty;
            defer env_name.deinit(allocator);
            try env_name.appendSlice(allocator, "HTTP_");
            for (name) |c| {
                if (!isHeaderNameChar(c)) {
                    env_name.clearRetainingCapacity();
                    break;
                }
                try env_name.append(allocator, if (c == '-') '_' else std.ascii.toUpper(c));
            }
            if (env_name.items.len <= "HTTP_".len) continue;
            try env.put(env_name.items, value);
        }
    }
}

pub fn isPhpCgiBinary(path: []const u8) bool {
    const slash = std.mem.lastIndexOfScalar(u8, path, '/') orelse return std.mem.indexOf(u8, path, "php-cgi") != null;
    return std.mem.indexOf(u8, path[slash + 1 ..], "php-cgi") != null;
}

fn statusTextForCode(status_code: u16) []const u8 {
    return switch (status_code) {
        100 => "Continue",
        101 => "Switching Protocols",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        416 => "Range Not Satisfiable",
        417 => "Expectation Failed",
        426 => "Upgrade Required",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        else => if (status_code >= 500) "Internal Server Error" else if (status_code >= 400) "Bad Request" else "OK",
    };
}

pub fn isSkippedResponseHeader(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "Status") or
        std.ascii.eqlIgnoreCase(name, "Content-Type") or
        std.ascii.eqlIgnoreCase(name, "Content-Length") or
        std.ascii.eqlIgnoreCase(name, "Connection") or
        std.ascii.eqlIgnoreCase(name, "Keep-Alive") or
        std.ascii.eqlIgnoreCase(name, "Proxy-Authenticate") or
        std.ascii.eqlIgnoreCase(name, "Proxy-Authorization") or
        std.ascii.eqlIgnoreCase(name, "TE") or
        std.ascii.eqlIgnoreCase(name, "Trailer") or
        std.ascii.eqlIgnoreCase(name, "Trailers") or
        std.ascii.eqlIgnoreCase(name, "Transfer-Encoding") or
        std.ascii.eqlIgnoreCase(name, "Upgrade") or
        std.ascii.eqlIgnoreCase(name, "Server") or
        std.ascii.eqlIgnoreCase(name, "X-Request-Id");
}

pub fn isHeaderNameChar(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '-' or c == '_';
}

test "splits CGI output with CRLF or LF separators" {
    const crlf = splitHeaderBlock("Content-Type: text/plain\r\n\r\nbody").?;
    try std.testing.expectEqualStrings("Content-Type: text/plain", crlf.headers);
    try std.testing.expectEqualStrings("body", crlf.body);

    const lf = splitHeaderBlock("Content-Type: text/plain\n\nbody").?;
    try std.testing.expectEqualStrings("Content-Type: text/plain", lf.headers);
    try std.testing.expectEqualStrings("body", lf.body);
}

test "parses CGI status headers with reason text" {
    const status = parseStatus("Status: 404 Not Found\nContent-Type: text/plain");
    try std.testing.expectEqual(@as(u16, 404), status.code);
    try std.testing.expectEqualStrings("Not Found", status.text);

    const default_status = parseStatus("Content-Type: text/plain");
    try std.testing.expectEqual(@as(u16, 200), default_status.code);
    try std.testing.expectEqualStrings("OK", default_status.text);
}
