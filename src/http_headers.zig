const std = @import("std");

pub fn trimValue(value: []const u8) []const u8 {
    return std.mem.trim(u8, value, " \t\r\n");
}

pub fn parseContentLength(headers: []const u8) !usize {
    var lines = std.mem.splitSequence(u8, headers, "\r\n");
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        if (std.mem.indexOfScalar(u8, line, ':')) |colon| {
            const key = std.mem.trim(u8, line[0..colon], " \t");
            const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
            if (std.ascii.eqlIgnoreCase(key, "Content-Length")) {
                return std.fmt.parseInt(usize, value, 10) catch return error.InvalidContentLength;
            }
        }
    }

    return 0;
}

pub fn hasHeaderToken(headers: []const u8, name: []const u8, token: []const u8) bool {
    const value = findHeaderValue(headers, name) orelse return false;
    return hasConnectionToken(value, token);
}

pub fn hasConnectionToken(connection: []const u8, token: []const u8) bool {
    var cursor = connection;
    while (cursor.len > 0) {
        const comma_pos = std.mem.indexOfScalar(u8, cursor, ',') orelse cursor.len;
        const item = if (comma_pos > 0) trimValue(cursor[0..comma_pos]) else cursor;
        if (item.len > 0 and std.ascii.eqlIgnoreCase(item, token)) return true;
        if (comma_pos >= cursor.len) break;
        cursor = cursor[comma_pos + 1 ..];
    }
    return false;
}

pub fn parseConnectionClose(version: []const u8, headers: []const u8) bool {
    const connection = findHeaderValue(headers, "Connection") orelse "";
    const wants_close = hasConnectionToken(connection, "close");
    const wants_keep_alive = hasConnectionToken(connection, "keep-alive");

    const is_http11 = std.mem.startsWith(u8, version, "HTTP/1.1");
    const is_http10 = std.mem.startsWith(u8, version, "HTTP/1.0");

    if (wants_close) return true;
    if (is_http10) {
        return !wants_keep_alive;
    }
    if (is_http11) return false;
    return true;
}

pub fn transferEncodingIsChunkedOnly(headers: []const u8) !bool {
    const value = findHeaderValue(headers, "Transfer-Encoding") orelse return false;

    // This server understands normal fixed-length bodies and chunked bodies.
    // Anything stacked on top of chunked needs a real decoder, not optimism.
    var saw_chunked = false;
    var cursor = value;
    while (cursor.len > 0) {
        const comma_pos = std.mem.indexOfScalar(u8, cursor, ',') orelse cursor.len;
        const item = if (comma_pos > 0) trimValue(cursor[0..comma_pos]) else cursor;
        if (item.len > 0) {
            if (std.ascii.eqlIgnoreCase(item, "chunked")) {
                saw_chunked = true;
            } else {
                return error.UnsupportedTransferEncoding;
            }
        }
        if (comma_pos >= cursor.len) break;
        cursor = cursor[comma_pos + 1 ..];
    }

    return saw_chunked;
}

pub fn findHeaderValue(headers: []const u8, target_name: []const u8) ?[]const u8 {
    var lines = std.mem.splitSequence(u8, headers, "\r\n");
    while (lines.next()) |line| {
        if (std.mem.indexOfScalar(u8, line, ':')) |colon| {
            const key = std.mem.trim(u8, line[0..colon], " \t");
            const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
            if (std.ascii.eqlIgnoreCase(key, target_name)) return value;
        }
    }

    return null;
}

test "header lookup trims values and ignores case" {
    const headers = "Host: example.test\r\nx-request-id:  abc-123 \t\r\n";
    try std.testing.expectEqualStrings("example.test", findHeaderValue(headers, "host").?);
    try std.testing.expectEqualStrings("abc-123", findHeaderValue(headers, "X-Request-Id").?);
}

test "connection token parsing handles comma lists" {
    try std.testing.expect(hasConnectionToken("keep-alive, Upgrade", "upgrade"));
    try std.testing.expect(!hasConnectionToken("keep-alive", "close"));
    try std.testing.expect(!parseConnectionClose("HTTP/1.1", "Connection: keep-alive\r\n"));
    try std.testing.expect(parseConnectionClose("HTTP/1.0", ""));
}

test "transfer encoding parser only accepts bare chunked" {
    try std.testing.expect(try transferEncodingIsChunkedOnly("Transfer-Encoding: chunked\r\n"));
    try std.testing.expectError(error.UnsupportedTransferEncoding, transferEncodingIsChunkedOnly("Transfer-Encoding: gzip, chunked\r\n"));
}
