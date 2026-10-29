const std = @import("std");

const http_headers = @import("http_headers.zig");

const findHeaderValue = http_headers.findHeaderValue;
const trimValue = http_headers.trimValue;

// Build a target path for proxying while avoiding `//` and leading path glitches.
pub fn buildProxyPath(allocator: std.mem.Allocator, base_path: []const u8, request_path: []const u8, query: []const u8) ![]const u8 {
    var final_path = std.ArrayList(u8).empty;

    if (std.mem.eql(u8, base_path, "/")) {
        try final_path.appendSlice(allocator, request_path);
    } else {
        try final_path.appendSlice(allocator, base_path);
        if (!std.mem.endsWith(u8, base_path, "/") and request_path.len > 0 and request_path[0] != '/') {
            try final_path.append(allocator, '/');
        }
        if (!std.mem.startsWith(u8, request_path, "/")) {
            try final_path.appendSlice(allocator, request_path);
        } else {
            try final_path.appendSlice(allocator, request_path[1..]);
        }
    }

    if (final_path.items.len == 0) {
        try final_path.append(allocator, '/');
    }

    if (query.len > 0) {
        try final_path.append(allocator, '?');
        try final_path.appendSlice(allocator, query);
    }

    return try final_path.toOwnedSlice(allocator);
}

pub fn isSkippedProxyHeader(name: []const u8) bool {
    // Request bodies are already buffered and 100-continue was handled locally.
    if (std.ascii.eqlIgnoreCase(name, "Expect")) return true;
    return std.ascii.eqlIgnoreCase(name, "Connection") or
        std.ascii.eqlIgnoreCase(name, "Proxy-Connection") or
        std.ascii.eqlIgnoreCase(name, "Content-Length") or
        std.ascii.eqlIgnoreCase(name, "Keep-Alive") or
        std.ascii.eqlIgnoreCase(name, "Proxy-Authenticate") or
        std.ascii.eqlIgnoreCase(name, "Proxy-Authorization") or
        std.ascii.eqlIgnoreCase(name, "TE") or
        std.ascii.eqlIgnoreCase(name, "Trailers") or
        std.ascii.eqlIgnoreCase(name, "Trailer") or
        std.ascii.eqlIgnoreCase(name, "Transfer-Encoding") or
        std.ascii.eqlIgnoreCase(name, "Upgrade") or
        std.ascii.eqlIgnoreCase(name, "Host") or
        std.ascii.eqlIgnoreCase(name, "X-Request-Id");
}

test "buffered proxy requests do not forward an already handled expectation" {
    try std.testing.expect(isSkippedProxyHeader("Expect"));
    try std.testing.expect(isSkippedProxyHeader("expect"));
    try std.testing.expect(!isSkippedProxyHeader("X-Expect"));
}

pub fn isHttpUpgradeHeaders(headers: []const u8) bool {
    const upgrade = findHeaderValue(headers, "Upgrade") orelse return false;
    return trimValue(upgrade).len > 0 and http_headers.hasHeaderToken(headers, "Connection", "upgrade");
}

pub fn isSkippedProxyResponseHeader(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "Connection") or
        std.ascii.eqlIgnoreCase(name, "Proxy-Connection") or
        std.ascii.eqlIgnoreCase(name, "Content-Length") or
        std.ascii.eqlIgnoreCase(name, "Transfer-Encoding") or
        std.ascii.eqlIgnoreCase(name, "Keep-Alive") or
        std.ascii.eqlIgnoreCase(name, "Proxy-Authenticate") or
        std.ascii.eqlIgnoreCase(name, "Proxy-Authorization") or
        std.ascii.eqlIgnoreCase(name, "TE") or
        std.ascii.eqlIgnoreCase(name, "Trailers") or
        std.ascii.eqlIgnoreCase(name, "Trailer") or
        std.ascii.eqlIgnoreCase(name, "Upgrade") or
        std.ascii.eqlIgnoreCase(name, "X-Request-Id");
}

pub fn isConnectionField(fields: []const u8, name: []const u8) bool {
    return http_headers.hasHeaderToken(fields, "Connection", name);
}

pub fn skipRequestField(fields: []const u8, name: []const u8) bool {
    return isSkippedProxyHeader(name) or isConnectionField(fields, name);
}

pub fn skipResponseField(fields: []const u8, name: []const u8) bool {
    return isSkippedProxyResponseHeader(name) or isConnectionField(fields, name);
}

pub fn isForbiddenTrailer(name: []const u8) bool {
    if (isSkippedProxyHeader(name) or std.ascii.startsWithIgnoreCase(name, "if-")) return true;
    for ([_][]const u8{ "content-type", "content-encoding", "content-range", "authorization", "cookie", "set-cookie", "cache-control", "expires", "vary", "location", "range", "server", "x-powered-by" }) |forbidden| {
        if (std.ascii.eqlIgnoreCase(name, forbidden)) return true;
    }
    return false;
}

pub const UpstreamResponseForwardResult = struct {
    reusable: bool,
};

pub const UpstreamResponseFraming = struct {
    status_code: ?u16,
    content_length: ?usize,
    transfer_chunked: bool,
    connection_close: bool,
};

pub fn parseOptionalContentLength(headers: []const u8) !?usize {
    if (findHeaderValue(headers, "Content-Length")) |raw| {
        const value = trimValue(raw);
        if (value.len == 0) return error.BadGateway;
        return http_headers.parseDecimalLength(value) catch return error.BadGateway;
    }
    return null;
}

pub fn parseUpstreamResponseFraming(header_bytes: []const u8, response_headers: []const u8) !UpstreamResponseFraming {
    http_headers.validateHeaderBlock(response_headers) catch return error.BadGateway;
    http_headers.validateRequestFraming(response_headers) catch return error.BadGateway;
    const http10 = std.mem.startsWith(u8, header_bytes, "HTTP/1.0 ");
    if (!http10 and !std.mem.startsWith(u8, header_bytes, "HTTP/1.1 ")) return error.BadGateway;
    return .{
        .status_code = parseHttpStatusCode(header_bytes) orelse return error.BadGateway,
        .content_length = try parseOptionalContentLength(response_headers),
        .transfer_chunked = http_headers.hasHeaderToken(response_headers, "Transfer-Encoding", "chunked"),
        .connection_close = http_headers.hasHeaderToken(response_headers, "Connection", "close") or
            (http10 and !http_headers.hasHeaderToken(response_headers, "Connection", "keep-alive")),
    };
}

test "upstream HTTP10 closes by default and ambiguous framing is rejected" {
    try std.testing.expect((try parseUpstreamResponseFraming("HTTP/1.0 200 OK", "Content-Length: 1")).connection_close);
    try std.testing.expect(!(try parseUpstreamResponseFraming("HTTP/1.0 200 OK", "Content-Length: 1\r\nConnection: keep-alive")).connection_close);
    for ([_][]const u8{ "Content-Length: 1\r\nContent-Length: 2", "Content-Length: +1", "Content-Length: 1\r\nTransfer-Encoding: chunked", "Transfer-Encoding: chunked\r\nTransfer-Encoding: chunked" }) |fields|
        try std.testing.expectError(error.BadGateway, parseUpstreamResponseFraming("HTTP/1.1 200 OK", fields));
}

pub fn responseHasNoBody(method: []const u8, status_code: ?u16) bool {
    if (std.ascii.eqlIgnoreCase(method, "HEAD")) return true;
    const code = status_code orelse return false;
    return (code >= 100 and code < 200) or code == 204 or code == 304;
}

pub fn parseHttpStatusCode(response_head: []const u8) ?u16 {
    const first_line_end = std.mem.indexOf(u8, response_head, "\r\n") orelse response_head.len;
    const first_line = response_head[0..first_line_end];
    if (first_line.len < 13 or (!std.mem.startsWith(u8, first_line, "HTTP/1.1 ") and !std.mem.startsWith(u8, first_line, "HTTP/1.0 "))) return null;
    const code_raw = first_line[9..12];
    for (code_raw) |value| if (!std.ascii.isDigit(value)) return null;
    if (first_line[12] != ' ' or !http_headers.validFieldValue(first_line[13..])) return null;
    const code = std.fmt.parseInt(u16, code_raw, 10) catch return null;
    return if (code >= 100 and code <= 599) code else null;
}

test "connection nominations cover repeated fields without swallowing similarly named headers" {
    const fields = "Connection: keep-alive, X-Local\r\nconnection: x-other";
    try std.testing.expect(skipRequestField(fields, "X-LOCAL"));
    try std.testing.expect(skipResponseField(fields, "x-other"));
    try std.testing.expect(!skipResponseField(fields, "x-localized"));
    try std.testing.expect(isSkippedProxyHeader("Trailer"));
    try std.testing.expect(isSkippedProxyResponseHeader("proxy-connection"));
    for ([_][]const u8{ "HTTP/1.1 +20 OK", "HTTP/1.1 099 Odd", "HTTP/1.1 600 Odd", "HTTP/1.1 200x", "HTTP/1.1 200", "HTTP/1.1  200 OK", "HTTP/1.1 200 OK\x00" }) |line|
        try std.testing.expect(parseHttpStatusCode(line) == null);
    try std.testing.expectEqual(200, parseHttpStatusCode("HTTP/1.1 200 ").?);
}
