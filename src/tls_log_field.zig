const std = @import("std");

pub const max_bytes = 256;

pub fn field(bytes: []const u8) Field {
    return .{ .bytes = bytes };
}

const Field = struct {
    bytes: []const u8,

    pub fn format(self: Field, writer: *std.Io.Writer) std.Io.Writer.Error!void {
        try writer.writeByte('"');
        // TLS names are unauthenticated bytes, not safe terminal or log text.
        try std.zig.stringEscape(self.bytes[0..@min(self.bytes.len, max_bytes)], writer);
        if (self.bytes.len > max_bytes) try writer.writeAll("...");
        try writer.writeByte('"');
    }
};

test "TLS diagnostics quote ordinary fields and delimit empty values" {
    try std.testing.expectFmt("sni=\"layerline.dev\" alpn=\"\"", "sni={f} alpn={f}", .{ field("layerline.dev"), field("") });
}

test "TLS diagnostics escape line breaks terminal controls and delimiter spoofing" {
    try std.testing.expectFmt("\"a\\n\\r\\t\\x00\\x1b\\\"\\\\b\"", "{f}", .{field("a\n\r\t\x00\x1b\"\\b")});
    try std.testing.expectFmt("\"\\xe2\\x80\\xa8\\xe2\\x80\\xae\"", "{f}", .{field("\xe2\x80\xa8\xe2\x80\xae")});
}

test "TLS diagnostics keep every byte value printable on one line" {
    var input: [256]u8 = undefined;
    for (&input, 0..) |*byte, i| byte.* = @intCast(i);
    var buffer: [4 * max_bytes + 5]u8 = undefined;
    const result = try std.fmt.bufPrint(&buffer, "{f}", .{field(&input)});
    for (result) |byte| try std.testing.expect(byte >= ' ' and byte <= '~');
    try std.testing.expect(result[0] == '"' and result[result.len - 1] == '"');
}

test "TLS diagnostics cap expanded fields without allocating and mark truncation" {
    const input: [max_bytes + 1]u8 = @splat(0xff);
    var buffer: [4 * max_bytes + 5]u8 = undefined;
    const result = try std.fmt.bufPrint(&buffer, "{f}", .{field(&input)});
    try std.testing.expectEqual(buffer.len, result.len);
    try std.testing.expect(std.mem.endsWith(u8, result, "...\""));
    for (result) |byte| try std.testing.expect(byte >= ' ' and byte <= '~');
    try std.testing.expectFmt("\"" ++ "x" ** max_bytes ++ "\"", "{f}", .{field("x" ** max_bytes)});
}
