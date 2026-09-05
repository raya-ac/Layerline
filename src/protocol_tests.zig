const std = @import("std");
const request = @import("request.zig");
const h2 = @import("h2_native.zig");
const h2_support = @import("http2_support.zig");
const cache = @import("buffered_cache.zig");
const static_files = @import("static_files.zig");

test {
    _ = @import("http3_server.zig");
}

test "static conditional precedence and weak ETags" {
    const mtime = std.Io.Timestamp.fromNanoseconds(@as(i96, 784111777) * std.time.ns_per_s);
    try std.testing.expect(!static_files.isNotModified("If-None-Match: \"old\"\r\nIf-Modified-Since: Sun, 06 Nov 1994 08:49:37 GMT", "\"new\"", mtime));
    try std.testing.expect(static_files.isNotModified("If-None-Match: W/\"new\"", "\"new\"", mtime));
    try std.testing.expect(static_files.etagMatches("\"a,b\", W/\"new\"", "\"new\""));
    try std.testing.expect(!static_files.etagMatches("\"new\"garbage", "\"new\""));
    try std.testing.expect(static_files.isNotModified("If-Modified-Since: Sun, 06 Nov 1994 08:49:37 GMT", "\"new\"", mtime));
}

test "microcache obeys privacy across repeated Cache-Control fields" {
    const policy: cache.Policy = .{ .enabled = true, .max_bytes = 4096, .max_entry_bytes = 1024, .ttl_ms = 60000 };
    for ([_][]const u8{ "private", "private=\"x-user\"", "no-cache", "no-cache=\"etag\"", "no-store", "max-age=0", "s-maxage=30", "max-age=garbage" }) |value| {
        const headers = [_]h2.Header{
            .{ .name = "cache-control", .value = "public, max-age=3600" },
            .{ .name = "Cache-Control", .value = value },
        };
        try std.testing.expect(!cache.responseCanStore(.{ .status_code = 200, .content_type = "text/plain", .body = "private", .headers = &headers }, policy));
    }
    try std.testing.expect(cache.responseCanStore(.{ .status_code = 200, .content_type = "text/plain", .body = "public" }, policy));
    for ([_][]const u8{ "Range: bytes=0-1", "If-None-Match: x", "Cache-Control: no-cache", "Pragma: no-cache" }) |headers| {
        try std.testing.expect(!cache.requestCanUse(.{ .method = "GET", .path = "/", .query = "", .headers = headers, .version = "HTTP/2.0", .body = "", .close_connection = false }, policy));
    }
}

fn unexpectedRead(_: std.Io.net.Stream, _: []u8) !usize {
    return error.UnexpectedRead;
}

fn unexpectedWrite(_: std.Io.net.Stream, _: []const u8) !void {
    return error.UnexpectedWrite;
}

fn timeout(_: std.Io.net.Stream, _: u32) !void {}

const fns: request.StreamFns = .{ .read = unexpectedRead, .write_all = unexpectedWrite, .set_read_timeout = timeout };

test "complete prefills route without reading and absolute authority wins" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const req = try request.parse(undefined, arena.allocator(), 4096, 4096, 100, 1024, "GET http://actual.test/health?q=1 HTTP/1.1\r\nHost: wrong.test\r\n\r\n", fns);
    try std.testing.expectEqualStrings("/health", req.path);
    try std.testing.expectEqualStrings("q=1", req.query);
    try std.testing.expectEqualStrings("Host: actual.test", req.headers);
}

test "invalid HTTP1 envelopes fail before reads or interim responses" {
    const cases = [_][]const u8{
        "GET / HTTP/1.1 extra\r\nHost: test\r\n\r\n",
        "G\tET / HTTP/1.1\r\nHost: test\r\n\r\n",
        "GET * HTTP/1.1\r\nHost: test\r\n\r\n",
        "GET /#fragment HTTP/1.1\r\nHost: test\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: one\r\nHost: two\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: test\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\nExpect: 100-continue\r\n\r\n",
        "POST / HTTP/1.1\r\nHost: test\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n",
    };
    for (cases) |bytes| {
        var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
        defer arena.deinit();
        if (request.parse(undefined, arena.allocator(), 4096, 4096, 100, 1024, bytes, fns)) |_| {
            return error.AcceptedInvalidEnvelope;
        } else |err| {
            try std.testing.expect(err == error.MalformedRequest or err == error.BadRequest);
        }
    }
}

test "HTTP2 conversion rejects upstream header injection and ambiguous fields" {
    const invalid = [_]h2.Header{
        .{ .name = "x-test", .value = "ok\r\nContent-Length: 99" },
        .{ .name = "x-test\nInjected", .value = "yes" },
        .{ .name = "X-Test", .value = "yes" },
        .{ .name = "connection", .value = "keep-alive" },
        .{ .name = "transfer-encoding", .value = "chunked" },
        .{ .name = ":path", .value = "/other" },
        .{ .name = "host", .value = "other.test" },
    };
    for (invalid) |header| {
        var fields = [_]h2.Header{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "http" },
            .{ .name = ":authority", .value = "test" },
            .{ .name = ":path", .value = "/" },
            header,
        };
        const decoded = h2.DecodedHeaders{ .headers = .{ .items = &fields, .capacity = fields.len } };
        try std.testing.expectError(error.BadRequest, h2_support.parseRequest(std.testing.allocator, &decoded));
    }
}
