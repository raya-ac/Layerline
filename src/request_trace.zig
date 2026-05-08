const std = @import("std");
const http_headers = @import("http_headers.zig");

pub const Generator = struct {
    counter: std.atomic.Value(u64) = std.atomic.Value(u64).init(0),

    pub fn resolve(self: *Generator, io: std.Io, allocator: std.mem.Allocator, headers: []const u8) ![]const u8 {
        if (fromHeaders(headers)) |request_id| return request_id;

        const now_ms_raw = std.Io.Timestamp.now(io, .real).toMilliseconds();
        const now_ms: u64 = if (now_ms_raw > 0) @intCast(now_ms_raw) else 0;
        const sequence = self.counter.fetchAdd(1, .monotonic) + 1;
        return try std.fmt.allocPrint(allocator, "ll-{x:0>16}-{x:0>16}", .{ now_ms, sequence });
    }
};

pub fn isValid(value: []const u8) bool {
    if (value.len == 0 or value.len > 128) return false;
    for (value) |byte| {
        const valid = std.ascii.isAlphanumeric(byte) or
            byte == '-' or
            byte == '_' or
            byte == '.' or
            byte == ':' or
            byte == '/' or
            byte == '@';
        if (!valid) return false;
    }
    return true;
}

pub fn fromHeaders(headers: []const u8) ?[]const u8 {
    const raw = http_headers.findHeaderValue(headers, "X-Request-Id") orelse return null;
    const value = http_headers.trimValue(raw);
    if (!isValid(value)) return null;
    return value;
}

test "request id validation preserves safe inbound ids" {
    try std.testing.expect(isValid("client-123_abc.DEF:/@"));
    try std.testing.expect(!isValid(""));
    try std.testing.expect(!isValid("bad id"));
    try std.testing.expect(!isValid("bad\r\nid"));
    try std.testing.expectEqualStrings("client-123", fromHeaders("Host: example.test\r\nX-Request-Id: client-123\r\n").?);
    try std.testing.expect(fromHeaders("X-Request-Id: invalid value\r\n") == null);
}
