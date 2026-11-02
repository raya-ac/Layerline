const std = @import("std");
const headers = @import("http_headers.zig");
const proxy = @import("proxy_utils.zig");

pub fn validateField(name: []const u8, value: []const u8, initial: []const u8) !void {
    if (name.len == 0 or !headers.validFieldValue(value)) return error.BadRequest;
    for (name) |byte| if (!headers.isHeaderNameByte(byte)) return error.BadRequest;
    if (proxy.isForbiddenTrailer(name) or proxy.isConnectionField(initial, name)) return error.BadRequest;
    if (std.ascii.startsWithIgnoreCase(name, "x-forwarded-") or std.ascii.eqlIgnoreCase(name, "accept") or std.ascii.startsWithIgnoreCase(name, "accept-")) return error.BadRequest;
    for ([_][]const u8{ "forwarded", "x-real-ip", "x-http-method-override", "x-method-override", "max-forwards", "pragma", "origin", "referer" }) |forbidden| {
        if (std.ascii.eqlIgnoreCase(name, forbidden)) return error.BadRequest;
    }
}

pub fn validateBlock(fields: []const u8, initial: []const u8) !void {
    try headers.validateHeaderBlock(fields);
    if (fields.len == 0) return;
    var lines = std.mem.splitSequence(u8, fields, "\r\n");
    while (lines.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':').?;
        try validateField(line[0..colon], headers.trimValue(line[colon + 1 ..]), initial);
    }
}

pub fn fromFields(allocator: std.mem.Allocator, fields: anytype, initial: []const u8) ![]const u8 {
    if (fields.len > headers.MAX_HTTP1_HEADER_FIELDS) return error.BadRequest;
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);
    for (fields, 0..) |field, index| {
        try validateField(field.name, field.value, initial);
        if (index != 0) try out.appendSlice(allocator, "\r\n");
        try out.print(allocator, "{s}: {s}", .{ field.name, field.value });
    }
    return out.toOwnedSlice(allocator);
}

test "request trailers stay separate and cannot override routing auth or hop fields" {
    try validateBlock("Content-Digest: sha-256=:test:\r\nX-Result: yes\r\nX-Result: again", "Host: site.test");
    for ([_][]const u8{ "Host", "Content-Length", "Content-Type", "Cookie", "Authorization", "Connection", "Transfer-Encoding", "Trailer", "Cache-Control", "If-Match", "X-Forwarded-For", "Forwarded", "Origin", "X-Http-Method-Override" }) |name| {
        try std.testing.expectError(error.BadRequest, validateField(name, "changed", ""));
    }
    try std.testing.expectError(error.BadRequest, validateField("X-Hop", "changed", "Connection: keep-alive\r\nConnection: X-Hop"));
    try std.testing.expectError(error.BadRequest, validateField(":path", "/admin", ""));
    try std.testing.expectError(error.BadRequest, validateField("digest", "ok\r\nx: bad", ""));
}

test "trailer serialization releases every failed allocation and retains duplicate order" {
    const Case = struct {
        fn run(allocator: std.mem.Allocator) !void {
            const Field = struct { name: []const u8, value: []const u8 };
            const value = try fromFields(allocator, &[_]Field{ .{ .name = "digest", .value = "one" }, .{ .name = "digest", .value = "two" } }, "Host: test");
            defer allocator.free(value);
            try std.testing.expectEqualStrings("digest: one\r\ndigest: two", value);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Case.run, .{});
}
