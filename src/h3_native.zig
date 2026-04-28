const std = @import("std");

pub const Error = error{
    BufferTooSmall,
    VarIntTooLarge,
    Truncated,
    InvalidVarInt,
    InvalidFrame,
    InvalidHeaderBlock,
};

pub const VarInt = struct {
    value: u62,
    len: usize,
};

pub fn varIntLen(value: u64) Error!usize {
    if (value <= 63) return 1;
    if (value <= 16_383) return 2;
    if (value <= 1_073_741_823) return 4;
    if (value <= 4_611_686_018_427_387_903) return 8;
    return error.VarIntTooLarge;
}

pub fn encodeVarInt(out: []u8, value: u64) Error!usize {
    const len = try varIntLen(value);
    if (out.len < len) return error.BufferTooSmall;

    switch (len) {
        1 => out[0] = @intCast(value),
        2 => {
            const wire = @as(u16, @intCast(value)) | 0x4000;
            std.mem.writeInt(u16, out[0..2], wire, .big);
        },
        4 => {
            const wire = @as(u32, @intCast(value)) | 0x8000_0000;
            std.mem.writeInt(u32, out[0..4], wire, .big);
        },
        8 => {
            const wire = value | 0xc000_0000_0000_0000;
            std.mem.writeInt(u64, out[0..8], wire, .big);
        },
        else => unreachable,
    }

    return len;
}

pub fn decodeVarInt(input: []const u8) Error!VarInt {
    if (input.len == 0) return error.Truncated;
    const tag = input[0] >> 6;
    const len: usize = switch (tag) {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        else => unreachable,
    };
    if (input.len < len) return error.Truncated;

    const value: u64 = switch (len) {
        1 => input[0] & 0x3f,
        2 => std.mem.readInt(u16, input[0..2], .big) & 0x3fff,
        4 => std.mem.readInt(u32, input[0..4], .big) & 0x3fff_ffff,
        8 => std.mem.readInt(u64, input[0..8], .big) & 0x3fff_ffff_ffff_ffff,
        else => unreachable,
    };

    return .{ .value = @intCast(value), .len = len };
}

pub const FrameType = enum(u64) {
    data = 0x00,
    headers = 0x01,
    cancel_push = 0x03,
    settings = 0x04,
    push_promise = 0x05,
    goaway = 0x07,
    max_push_id = 0x0d,
};

pub const FrameHeader = struct {
    frame_type: u64,
    length: u64,
    len: usize,
};

pub fn encodeFrameHeader(out: []u8, frame_type: u64, length: u64) Error!usize {
    var offset: usize = 0;
    offset += try encodeVarInt(out[offset..], frame_type);
    offset += try encodeVarInt(out[offset..], length);
    return offset;
}

pub fn decodeFrameHeader(input: []const u8) Error!FrameHeader {
    const ty = try decodeVarInt(input);
    const len = try decodeVarInt(input[ty.len..]);
    return .{
        .frame_type = ty.value,
        .length = len.value,
        .len = ty.len + len.len,
    };
}

pub fn appendFrame(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(u8),
    frame_type: FrameType,
    payload: []const u8,
) !void {
    var header_buf: [16]u8 = undefined;
    const header_len = try encodeFrameHeader(&header_buf, @intFromEnum(frame_type), payload.len);
    try out.appendSlice(allocator, header_buf[0..header_len]);
    try out.appendSlice(allocator, payload);
}

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

// Minimal QPACK encoder for static responses. It deliberately uses literal
// field lines only, so it does not depend on dynamic table state.
pub fn encodeLiteralHeaders(
    allocator: std.mem.Allocator,
    headers: []const Header,
) ![]u8 {
    var out = std.ArrayListUnmanaged(u8).empty;
    errdefer out.deinit(allocator);

    // Required prefix: Required Insert Count = 0, Delta Base = 0.
    try out.append(allocator, 0x00);
    try out.append(allocator, 0x00);

    for (headers) |header| {
        try appendLiteralHeader(allocator, &out, header.name, header.value);
    }

    return out.toOwnedSlice(allocator);
}

fn appendLiteralHeader(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(u8),
    name: []const u8,
    value: []const u8,
) !void {
    // Literal Field Line With Literal Name, no Huffman, no indexing.
    try out.append(allocator, 0x20);
    try appendQpackString(allocator, out, name);
    try appendQpackString(allocator, out, value);
}

fn appendQpackString(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(u8),
    value: []const u8,
) !void {
    var len_buf: [8]u8 = undefined;
    const len_len = try encodeVarInt(&len_buf, value.len);
    len_buf[0] &= 0x7f;
    try out.appendSlice(allocator, len_buf[0..len_len]);
    try out.appendSlice(allocator, value);
}

pub fn buildHeadersFrame(
    allocator: std.mem.Allocator,
    headers: []const Header,
) ![]u8 {
    const encoded = try encodeLiteralHeaders(allocator, headers);
    defer allocator.free(encoded);

    var out = std.ArrayListUnmanaged(u8).empty;
    errdefer out.deinit(allocator);
    try appendFrame(allocator, &out, .headers, encoded);
    return out.toOwnedSlice(allocator);
}

pub fn buildDataFrame(allocator: std.mem.Allocator, body: []const u8) ![]u8 {
    var out = std.ArrayListUnmanaged(u8).empty;
    errdefer out.deinit(allocator);
    try appendFrame(allocator, &out, .data, body);
    return out.toOwnedSlice(allocator);
}

test "QUIC varint round trips boundary values" {
    const values = [_]u64{
        0,
        63,
        64,
        16_383,
        16_384,
        1_073_741_823,
        1_073_741_824,
        4_611_686_018_427_387_903,
    };

    for (values) |value| {
        var buf: [8]u8 = undefined;
        const written = try encodeVarInt(&buf, value);
        const decoded = try decodeVarInt(buf[0..written]);
        try std.testing.expectEqual(value, decoded.value);
        try std.testing.expectEqual(written, decoded.len);
    }
}

test "HTTP/3 frame header encodes and decodes" {
    var buf: [16]u8 = undefined;
    const written = try encodeFrameHeader(&buf, @intFromEnum(FrameType.headers), 1234);
    const decoded = try decodeFrameHeader(buf[0..written]);
    try std.testing.expectEqual(@as(u64, @intFromEnum(FrameType.headers)), decoded.frame_type);
    try std.testing.expectEqual(@as(u64, 1234), decoded.length);
    try std.testing.expectEqual(written, decoded.len);
}

test "minimal QPACK literal header block starts with zero base state" {
    const headers = [_]Header{
        .{ .name = ":status", .value = "200" },
        .{ .name = "content-type", .value = "text/html; charset=utf-8" },
    };
    const encoded = try encodeLiteralHeaders(std.testing.allocator, &headers);
    defer std.testing.allocator.free(encoded);

    try std.testing.expect(encoded.len > 2);
    try std.testing.expectEqual(@as(u8, 0), encoded[0]);
    try std.testing.expectEqual(@as(u8, 0), encoded[1]);
}
