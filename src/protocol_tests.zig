const std = @import("std");
const request = @import("request.zig");
const h2 = @import("h2_native.zig");
const h2_support = @import("http2_support.zig");

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
