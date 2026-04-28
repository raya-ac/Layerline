const std = @import("std");

pub const ResponseHead = struct {
    status_code: u16,
    status_text: []const u8,
    server: []const u8,
    content_type: []const u8,
    content_length: usize,
    close_connection: bool,
};

pub fn connectionValue(close_connection: bool) []const u8 {
    return if (close_connection) "close" else "keep-alive";
}

pub fn canSendBody(status_code: u16, is_head: bool) bool {
    if (is_head) return false;
    if (status_code >= 100 and status_code < 200) return false;
    return status_code != 204 and status_code != 304;
}

pub fn statusClass(status_code: u16) u16 {
    return status_code / 100;
}

pub fn formatHttp1BaseHeaders(buffer: []u8, head: ResponseHead) ![]const u8 {
    return std.fmt.bufPrint(
        buffer,
        "HTTP/1.1 {d} {s}\r\n" ++
            "Server: {s}\r\n" ++
            "Content-Type: {s}\r\n" ++
            "Content-Length: {d}\r\n" ++
            "Connection: {s}\r\n",
        .{
            head.status_code,
            head.status_text,
            head.server,
            head.content_type,
            head.content_length,
            connectionValue(head.close_connection),
        },
    );
}

test "formats HTTP/1 base headers without heap allocation" {
    var buffer: [256]u8 = undefined;
    const rendered = try formatHttp1BaseHeaders(&buffer, .{
        .status_code = 200,
        .status_text = "OK",
        .server = "Layerline",
        .content_type = "text/plain; charset=utf-8",
        .content_length = 5,
        .close_connection = false,
    });

    try std.testing.expectEqualStrings(
        "HTTP/1.1 200 OK\r\n" ++
            "Server: Layerline\r\n" ++
            "Content-Type: text/plain; charset=utf-8\r\n" ++
            "Content-Length: 5\r\n" ++
            "Connection: keep-alive\r\n",
        rendered,
    );
}

test "formats close connection and empty bodies consistently" {
    var buffer: [256]u8 = undefined;
    const rendered = try formatHttp1BaseHeaders(&buffer, .{
        .status_code = 404,
        .status_text = "Not Found",
        .server = "Layerline",
        .content_type = "text/html; charset=utf-8",
        .content_length = 0,
        .close_connection = true,
    });

    try std.testing.expect(std.mem.endsWith(u8, rendered, "Connection: close\r\n"));
    try std.testing.expect(std.mem.indexOf(u8, rendered, "Content-Length: 0\r\n") != null);
}

test "body policy rejects HEAD and body-forbidden status codes" {
    try std.testing.expect(!canSendBody(200, true));
    try std.testing.expect(!canSendBody(101, false));
    try std.testing.expect(!canSendBody(204, false));
    try std.testing.expect(!canSendBody(304, false));
    try std.testing.expect(canSendBody(200, false));
}

test "status class keeps metrics grouping simple" {
    try std.testing.expectEqual(@as(u16, 2), statusClass(204));
    try std.testing.expectEqual(@as(u16, 4), statusClass(404));
    try std.testing.expectEqual(@as(u16, 5), statusClass(503));
}
