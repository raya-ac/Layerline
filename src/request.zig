const std = @import("std");

const http_headers = @import("http_headers.zig");
const request_body = @import("request_body.zig");
const upstream = @import("upstream.zig");

pub const HttpRequest = struct {
    method: []const u8,
    path: []const u8,
    query: []const u8,
    headers: []const u8,
    version: []const u8,
    body: []const u8,
    close_connection: bool,
    h2c_upgrade_tail: []const u8 = "",

    pub fn deinit(self: HttpRequest, allocator: std.mem.Allocator) void {
        allocator.free(self.method.ptr[0 .. self.headers.ptr + self.headers.len - self.method.ptr]);
    }
};

pub const StreamFns = struct {
    read: *const fn (std.Io.net.Stream, []u8) anyerror!usize,
    write_all: *const fn (std.Io.net.Stream, []const u8) anyerror!void,
    set_read_timeout: *const fn (std.Io.net.Stream, u32) anyerror!void,
};

pub fn upstreamHashInput(req: HttpRequest) upstream.RequestHashInput {
    return .{
        .path = req.path,
        .query = req.query,
        .headers = req.headers,
    };
}

pub fn findQueryValue(query: []const u8, key: []const u8) ?[]const u8 {
    if (query.len == 0) return null;

    var cursor = query;
    while (cursor.len > 0) {
        const token_end = std.mem.indexOfScalar(u8, cursor, '&') orelse cursor.len;
        const pair = cursor[0..token_end];

        if (std.mem.indexOfScalar(u8, pair, '=')) |eq| {
            const k = pair[0..eq];
            const v = pair[eq + 1 ..];
            if (std.mem.eql(u8, k, key)) return v;
        } else if (std.mem.eql(u8, pair, key)) {
            return "";
        }

        if (token_end == cursor.len) break;
        cursor = cursor[token_end + 1 ..];
    }

    return null;
}

fn http2SettingsDecodedLength(value: []const u8) ?usize {
    if (value.len == 0 or value.len % 4 != 0) return null;
    var decoded_len: usize = 0;
    var chunk_start: usize = 0;
    while (chunk_start < value.len) : (chunk_start += 4) {
        var padding: usize = 0;
        var chunk: [4]u8 = undefined;
        @memcpy(&chunk, value[chunk_start .. chunk_start + 4]);
        for (chunk) |c| {
            if (!(std.ascii.isAlphanumeric(c) or c == '-' or c == '_')) return null;
        }
        if (chunk[2] == '=') padding += 1;
        if (chunk[3] == '=') padding += 1;
        if (padding > 0 and chunk_start + 4 != value.len) return null;
        if (padding > 2) return null;
        decoded_len += 3 - padding;
    }
    return decoded_len;
}

pub fn isValidHttp2SettingsHeader(value: []const u8) bool {
    const decoded_len = http2SettingsDecodedLength(http_headers.trimValue(value)) orelse return false;
    return decoded_len % 6 == 0;
}

pub fn isH2cUpgradeHeaders(headers: []const u8) bool {
    const upgrade = http_headers.findHeaderValue(headers, "Upgrade") orelse return false;
    if (!std.ascii.eqlIgnoreCase(http_headers.trimValue(upgrade), "h2c")) return false;
    if (!http_headers.hasHeaderToken(headers, "Connection", "Upgrade")) return false;
    if (!http_headers.hasHeaderToken(headers, "Connection", "HTTP2-Settings")) return false;
    const settings = http_headers.findHeaderValue(headers, "HTTP2-Settings") orelse return false;
    return isValidHttp2SettingsHeader(settings);
}

const RequestTarget = struct {
    path: []const u8,
    query: []const u8,
    authority: ?[]const u8 = null,
};

fn splitPathAndQuery(value: []const u8) RequestTarget {
    const query_pos = std.mem.indexOfScalar(u8, value, '?');
    return .{
        .path = if (query_pos) |idx| value[0..idx] else value,
        .query = if (query_pos) |idx| if (idx + 1 < value.len) value[idx + 1 ..] else "" else "",
    };
}

pub fn parseRequestTarget(value: []const u8) !RequestTarget {
    if (value.len == 0) return error.MalformedRequest;
    for (value) |byte| {
        if (byte <= 0x20 or byte == 0x7f or byte == '#' or byte == '\\') return error.MalformedRequest;
    }
    if (std.mem.eql(u8, value, "*")) return .{ .path = "*", .query = "" };
    if (value[0] == '/') return splitPathAndQuery(value);

    const scheme_len: usize = if (std.ascii.startsWithIgnoreCase(value, "http://"))
        "http://".len
    else if (std.ascii.startsWithIgnoreCase(value, "https://"))
        "https://".len
    else
        return error.MalformedRequest;

    const rest = value[scheme_len..];
    const slash_pos = std.mem.indexOfScalar(u8, rest, '/');
    const query_pos = std.mem.indexOfScalar(u8, rest, '?');
    const authority_end = @min(slash_pos orelse rest.len, query_pos orelse rest.len);
    if (authority_end == 0) return error.MalformedRequest;
    const uri = std.Uri.parse(value) catch return error.MalformedRequest;
    if (uri.host == null or uri.host.?.isEmpty() or uri.user != null or uri.password != null) return error.MalformedRequest;
    var result = if (authority_end < rest.len and rest[authority_end] == '/')
        splitPathAndQuery(rest[authority_end..])
    else
        RequestTarget{ .path = "/", .query = if (query_pos) |query| rest[query + 1 ..] else "" };
    result.authority = rest[0..authority_end];
    return result;
}

fn normalizeTargetHost(allocator: std.mem.Allocator, headers: []const u8, target: RequestTarget) ![]const u8 {
    const authority = target.authority orelse return headers;
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    try out.print(allocator, "Host: {s}", .{authority});
    var lines = std.mem.splitSequence(u8, headers, "\r\n");
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (std.ascii.eqlIgnoreCase(line[0..colon], "Host")) continue;
        try out.print(allocator, "\r\n{s}", .{line});
    }
    return out.toOwnedSlice(allocator);
}

fn validateRequestLine(method: []const u8, target: []const u8, extra: ?[]const u8) !void {
    if (method.len == 0 or extra != null) return error.MalformedRequest;
    for (method) |byte| {
        if (!http_headers.isHeaderNameByte(byte)) return error.MalformedRequest;
    }
    if (std.mem.eql(u8, target, "*") and !std.mem.eql(u8, method, "OPTIONS")) return error.MalformedRequest;
}

test "request target parser accepts origin, asterisk, and absolute forms" {
    const origin = try parseRequestTarget("/static/hello.txt?x=1");
    try std.testing.expectEqualStrings("/static/hello.txt", origin.path);
    try std.testing.expectEqualStrings("x=1", origin.query);

    const absolute = try parseRequestTarget("http://example.test/static/hello.txt?x=1");
    try std.testing.expectEqualStrings("/static/hello.txt", absolute.path);
    try std.testing.expectEqualStrings("x=1", absolute.query);

    const absolute_root_query = try parseRequestTarget("https://example.test?x=1");
    try std.testing.expectEqualStrings("/", absolute_root_query.path);
    try std.testing.expectEqualStrings("x=1", absolute_root_query.query);

    const asterisk = try parseRequestTarget("*");
    try std.testing.expectEqualStrings("*", asterisk.path);
    try std.testing.expectEqualStrings("", asterisk.query);

    try std.testing.expectError(error.MalformedRequest, parseRequestTarget("not-a-target"));
    try std.testing.expectError(error.MalformedRequest, parseRequestTarget("http:///missing-host"));
}

// Read the whole request envelope while the backing buffer is still alive.
// Method/path/header slices all point into it.
pub fn parse(
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    max_request_bytes: usize,
    max_body_bytes: usize,
    read_body_timeout_ms: u32,
    max_chunk_line_bytes: usize,
    prefill: []const u8,
    fns: StreamFns,
) !HttpRequest {
    const request_buffer = try allocator.alloc(u8, max_request_bytes);
    var used: usize = 0;

    const prefill_len = @min(prefill.len, request_buffer.len);
    if (prefill_len > 0) {
        @memcpy(request_buffer[0..prefill_len], prefill[0..prefill_len]);
        used = prefill_len;
    }

    while (used < request_buffer.len) {
        if (std.mem.indexOf(u8, request_buffer[0..used], "\r\n\r\n") != null) break;
        const n = try fns.read(stream, request_buffer[used..]);
        if (n == 0) return error.ConnectionClosed;
        used += n;

        if (std.mem.indexOf(u8, request_buffer[0..used], "\r\n\r\n") != null) break;
        if (used == request_buffer.len) return error.RequestTooLarge;
    }

    const header_end = (std.mem.indexOf(u8, request_buffer[0..used], "\r\n\r\n") orelse return error.MalformedRequest) + 4;
    const header_bytes = request_buffer[0..header_end];
    const body_tail = request_buffer[header_end..used];

    const request_line_end = std.mem.indexOf(u8, header_bytes, "\r\n") orelse return error.MalformedRequest;
    const request_line = header_bytes[0..request_line_end];
    var request_parts = std.mem.splitSequence(u8, request_line, " ");

    const method = request_parts.next() orelse return error.MalformedRequest;
    const path_and_query = request_parts.next() orelse return error.MalformedRequest;
    const version = request_parts.next() orelse return error.MalformedRequest;

    try validateRequestLine(method, path_and_query, request_parts.next());
    const target = try parseRequestTarget(path_and_query);

    const headers_start = request_line_end + 2;
    const headers_end = if (header_end >= 4) header_end - 4 else 0;
    var headers = if (headers_start <= headers_end) header_bytes[headers_start..headers_end] else "";
    try http_headers.validateHeaderBlock(headers);
    try http_headers.validateRequestFraming(headers);

    if (!std.mem.eql(u8, version, "HTTP/1.1") and !std.mem.eql(u8, version, "HTTP/1.0")) return error.UnsupportedHttpVersion;
    if (std.mem.startsWith(u8, version, "HTTP/1.1") and http_headers.findHeaderValue(headers, "Host") == null) {
        return error.MissingHostHeader;
    }

    headers = try normalizeTargetHost(allocator, headers, target);
    if (isH2cUpgradeHeaders(headers)) {
        return HttpRequest{
            .method = method,
            .path = target.path,
            .query = target.query,
            .headers = headers,
            .version = version,
            .body = "",
            .close_connection = true,
            .h2c_upgrade_tail = body_tail,
        };
    }

    if (http_headers.findHeaderValue(headers, "Expect")) |expect| {
        if (!http_headers.hasConnectionToken(expect, "100-continue")) return error.ExpectationFailed;
        try fns.write_all(stream, "HTTP/1.1 100 Continue\r\n\r\n");
    }

    try fns.set_read_timeout(stream, read_body_timeout_ms);
    const body_read = try request_body.readBody(stream, allocator, headers, body_tail, max_body_bytes, max_chunk_line_bytes, fns.read);
    const close_connection = http_headers.parseConnectionClose(version, headers) or body_read.discarded_pipeline_bytes;

    return HttpRequest{
        .method = method,
        .path = target.path,
        .query = target.query,
        .headers = headers,
        .version = version,
        .body = body_read.body,
        .close_connection = close_connection,
    };
}

pub fn parseHeadersOnly(
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    max_request_bytes: usize,
    prefill: []const u8,
    fns: StreamFns,
) !HttpRequest {
    const request_buffer = try allocator.alloc(u8, max_request_bytes);
    var used: usize = 0;

    const prefill_len = @min(prefill.len, request_buffer.len);
    if (prefill_len > 0) {
        @memcpy(request_buffer[0..prefill_len], prefill[0..prefill_len]);
        used = prefill_len;
    }

    while (used < request_buffer.len) {
        if (std.mem.indexOf(u8, request_buffer[0..used], "\r\n\r\n") != null) break;
        const n = try fns.read(stream, request_buffer[used..]);
        if (n == 0) return error.ConnectionClosed;
        used += n;
    }
    if (std.mem.indexOf(u8, request_buffer[0..used], "\r\n\r\n") == null) return error.RequestTooLarge;

    const header_end = (std.mem.indexOf(u8, request_buffer[0..used], "\r\n\r\n") orelse return error.MalformedRequest) + 4;
    const header_bytes = request_buffer[0..header_end];
    const request_line_end = std.mem.indexOf(u8, header_bytes, "\r\n") orelse return error.MalformedRequest;
    const request_line = header_bytes[0..request_line_end];
    var request_parts = std.mem.splitSequence(u8, request_line, " ");

    const method = request_parts.next() orelse return error.MalformedRequest;
    const path_and_query = request_parts.next() orelse return error.MalformedRequest;
    const version = request_parts.next() orelse return error.MalformedRequest;

    try validateRequestLine(method, path_and_query, request_parts.next());
    const target = try parseRequestTarget(path_and_query);

    const headers_start = request_line_end + 2;
    const headers_end = if (header_end >= 4) header_end - 4 else 0;
    var headers = if (headers_start <= headers_end) header_bytes[headers_start..headers_end] else "";
    try http_headers.validateHeaderBlock(headers);
    try http_headers.validateRequestFraming(headers);

    if (!std.mem.eql(u8, version, "HTTP/1.1") and !std.mem.eql(u8, version, "HTTP/1.0")) return error.UnsupportedHttpVersion;
    if (std.mem.startsWith(u8, version, "HTTP/1.1") and http_headers.findHeaderValue(headers, "Host") == null) {
        return error.MissingHostHeader;
    }

    headers = try normalizeTargetHost(allocator, headers, target);
    return HttpRequest{
        .method = method,
        .path = target.path,
        .query = target.query,
        .headers = headers,
        .version = version,
        .body = "",
        .close_connection = true,
    };
}
