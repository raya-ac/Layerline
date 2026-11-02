const std = @import("std");
const request = @import("request.zig");
const headers = @import("http_headers.zig");
const trailers = @import("request_trailers.zig");

pub fn appendFraming(allocator: std.mem.Allocator, out: *std.ArrayList(u8), req: request.HttpRequest, upgrade: bool) !void {
    try trailers.validateBlock(req.trailers, req.headers);
    if (req.trailers.len == 0) {
        if (upgrade and req.body.len == 0) return out.appendSlice(allocator, "\r\n");
        return out.print(allocator, "Content-Length: {d}\r\n\r\n", .{req.body.len});
    }
    try out.appendSlice(allocator, "Transfer-Encoding: chunked\r\nTrailer: ");
    var lines = std.mem.splitSequence(u8, req.trailers, "\r\n");
    var cursor: usize = 0;
    var count: usize = 0;
    while (lines.next()) |line| {
        const name = line[0..std.mem.indexOfScalar(u8, line, ':').?];
        if (headers.findHeaderValue(req.trailers[0..cursor], name) == null) {
            if (count != 0) try out.appendSlice(allocator, ", ");
            try out.appendSlice(allocator, name);
            count += 1;
        }
        cursor += line.len + 2;
    }
    try out.appendSlice(allocator, "\r\n\r\n");
}

pub fn write(stream: std.Io.net.Stream, req: request.HttpRequest, write_all: *const fn (std.Io.net.Stream, []const u8) anyerror!void) !void {
    if (req.trailers.len == 0) {
        if (req.body.len != 0) try write_all(stream, req.body);
        return;
    }
    // Both proxy paths share these boundaries; trailer values never become
    // ordinary headers, even for a zero-length body or repeated field names.
    if (req.body.len != 0) {
        var buffer: [32]u8 = undefined;
        const chunk = try std.fmt.bufPrint(&buffer, "{x}\r\n", .{req.body.len});
        try write_all(stream, chunk);
        try write_all(stream, req.body);
        try write_all(stream, "\r\n");
    }
    try write_all(stream, "0\r\n");
    try write_all(stream, req.trailers);
    try write_all(stream, "\r\n\r\n");
}

test "proxy trailer framing is unambiguous for empty and nonempty bodies" {
    const Sink = struct {
        var bytes: std.ArrayList(u8) = .empty;
        fn writeAll(_: std.Io.net.Stream, value: []const u8) !void {
            try bytes.appendSlice(std.testing.allocator, value);
        }
    };
    Sink.bytes = .empty;
    defer Sink.bytes.deinit(std.testing.allocator);
    var req: request.HttpRequest = .{ .method = "POST", .path = "/", .query = "", .headers = "", .version = "HTTP/2.0", .body = "hello", .trailers = "Digest: one\r\ndigest: two", .close_connection = false };
    var out = std.ArrayList(u8).empty;
    defer out.deinit(std.testing.allocator);
    try appendFraming(std.testing.allocator, &out, req, false);
    try std.testing.expectEqualStrings("Transfer-Encoding: chunked\r\nTrailer: Digest\r\n\r\n", out.items);
    const stream: std.Io.net.Stream = .{ .socket = .{ .handle = 123, .address = undefined } };
    try write(stream, req, Sink.writeAll);
    try std.testing.expectEqualStrings("5\r\nhello\r\n0\r\nDigest: one\r\ndigest: two\r\n\r\n", Sink.bytes.items);
    Sink.bytes.clearRetainingCapacity();
    req.body = "";
    try write(stream, req, Sink.writeAll);
    try std.testing.expectEqualStrings("0\r\nDigest: one\r\ndigest: two\r\n\r\n", Sink.bytes.items);
}
