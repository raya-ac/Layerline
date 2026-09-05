const std = @import("std");
const hpack = @import("h2_native.zig");

pub const Error = error{
    BufferTooSmall,
    VarIntTooLarge,
    Truncated,
    InvalidVarInt,
    InvalidFrame,
    InvalidHeaderBlock,
    HuffmanUnsupported,
    DynamicTableUnsupported,
    UnknownStaticTableIndex,
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

const PrefixedInteger = struct {
    value: u64,
    len: usize,
};

fn decodePrefixedInteger(input: []const u8, prefix_bits: u4) Error!PrefixedInteger {
    if (input.len == 0) return error.Truncated;
    const mask: u8 = if (prefix_bits == 8) 0xff else (@as(u8, 1) << @as(u3, @intCast(prefix_bits))) - 1;
    var value: u64 = input[0] & mask;
    if (value < mask) return .{ .value = value, .len = 1 };

    var shift: u6 = 0;
    var offset: usize = 1;
    while (true) {
        if (offset >= input.len) return error.Truncated;
        const byte = input[offset];
        offset += 1;
        const payload: u64 = byte & 0x7f;
        if (payload > (std.math.maxInt(u64) - value) >> shift) return error.VarIntTooLarge;
        value += payload << shift;
        if ((byte & 0x80) == 0) break;
        if (shift > 56) return error.VarIntTooLarge;
        shift += 7;
    }
    return .{ .value = value, .len = offset };
}

const StringLiteral = struct {
    value: []const u8,
    len: usize,
};

fn decodeStringLiteral(input: []const u8, prefix_bits: u4) Error!StringLiteral {
    if (input.len == 0) return error.Truncated;
    const huffman_bit = @as(u8, 1) << @as(u3, @intCast(prefix_bits));
    if ((input[0] & huffman_bit) != 0) return error.HuffmanUnsupported;
    const len_vi = try decodePrefixedInteger(input, prefix_bits);
    if (len_vi.value > std.math.maxInt(usize)) return error.VarIntTooLarge;
    const value_len: usize = @intCast(len_vi.value);
    if (value_len > input.len - len_vi.len) return error.Truncated;
    return .{
        .value = input[len_vi.len .. len_vi.len + value_len],
        .len = len_vi.len + value_len,
    };
}

fn staticHeader(index: u64) Error!Header {
    return switch (index) {
        0 => .{ .name = ":authority", .value = "" },
        1 => .{ .name = ":path", .value = "/" },
        15 => .{ .name = ":method", .value = "CONNECT" },
        16 => .{ .name = ":method", .value = "DELETE" },
        17 => .{ .name = ":method", .value = "GET" },
        18 => .{ .name = ":method", .value = "HEAD" },
        19 => .{ .name = ":method", .value = "OPTIONS" },
        20 => .{ .name = ":method", .value = "POST" },
        21 => .{ .name = ":method", .value = "PUT" },
        22 => .{ .name = ":scheme", .value = "http" },
        23 => .{ .name = ":scheme", .value = "https" },
        29 => .{ .name = "accept", .value = "*/*" },
        31 => .{ .name = "accept-encoding", .value = "gzip, deflate, br" },
        84 => .{ .name = "authorization", .value = "" },
        95 => .{ .name = "user-agent", .value = "" },
        else => error.UnknownStaticTableIndex,
    };
}

fn appendDecodedHeader(allocator: std.mem.Allocator, out: *std.ArrayListUnmanaged(Header), name: []const u8, value: []const u8) !void {
    try out.append(allocator, .{ .name = name, .value = value });
}

pub fn decodeHeaderBlock(allocator: std.mem.Allocator, block: []const u8) ![]Header {
    var offset: usize = 0;
    const required_insert_count = try decodePrefixedInteger(block[offset..], 8);
    offset += required_insert_count.len;
    if (required_insert_count.value != 0) return error.DynamicTableUnsupported;

    const delta_base = try decodePrefixedInteger(block[offset..], 7);
    offset += delta_base.len;

    var out = std.ArrayListUnmanaged(Header).empty;
    errdefer out.deinit(allocator);

    while (offset < block.len) {
        const first = block[offset];
        if ((first & 0x80) != 0) {
            const uses_static = (first & 0x40) != 0;
            const index = try decodePrefixedInteger(block[offset..], 6);
            offset += index.len;
            if (!uses_static) return error.DynamicTableUnsupported;
            const header = try staticHeader(index.value);
            try appendDecodedHeader(allocator, &out, header.name, header.value);
            continue;
        }

        if ((first & 0x40) != 0) {
            const uses_static = (first & 0x10) != 0;
            const index = try decodePrefixedInteger(block[offset..], 4);
            offset += index.len;
            if (!uses_static) return error.DynamicTableUnsupported;
            const name = (try staticHeader(index.value)).name;
            const value = try decodeStringLiteral(block[offset..], 7);
            offset += value.len;
            try appendDecodedHeader(allocator, &out, name, value.value);
            continue;
        }

        if ((first & 0x20) != 0) {
            const name = try decodeStringLiteral(block[offset..], 3);
            offset += name.len;
            const value = try decodeStringLiteral(block[offset..], 7);
            offset += value.len;
            try appendDecodedHeader(allocator, &out, name.value, value.value);
            continue;
        }

        return error.DynamicTableUnsupported;
    }

    return out.toOwnedSlice(allocator);
}

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
    try hpack.encodeInteger(allocator, out, 0x20, 3, name.len);
    try out.appendSlice(allocator, name);
    try appendQpackString(allocator, out, value);
}

fn appendQpackString(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(u8),
    value: []const u8,
) !void {
    try hpack.encodeInteger(allocator, out, 0, 7, value.len);
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

test "QPACK literal fields use RFC9204 prefixed lengths" {
    const encoded = try encodeLiteralHeaders(std.testing.allocator, &.{.{ .name = ":status", .value = "200" }});
    defer std.testing.allocator.free(encoded);
    // NameLen=7 saturates the 3-bit prefix and requires a zero continuation.
    try std.testing.expectEqualSlices(u8, "\x00\x00\x27\x00:status\x03200", encoded);
}

test "QPACK literal lengths cross prefix boundaries without QUIC varints" {
    for ([_]usize{ 0, 6, 7, 8, 63, 64, 126, 127, 128, 255, 16384 }) |len| {
        const value = try std.testing.allocator.alloc(u8, len);
        defer std.testing.allocator.free(value);
        @memset(value, 'a');
        const encoded = try encodeLiteralHeaders(std.testing.allocator, &.{.{ .name = "x-test", .value = value }});
        defer std.testing.allocator.free(encoded);
        const decoded = try decodeHeaderBlock(std.testing.allocator, encoded);
        defer std.testing.allocator.free(decoded);
        try std.testing.expectEqualStrings("x-test", decoded[0].name);
        try std.testing.expectEqualStrings(value, decoded[0].value);
        if (len == 127) try std.testing.expectEqualSlices(u8, "\x7f\x00", encoded[9..11]);
    }
}

test "QPACK rejects overflowing prefixed integers and truncated strings" {
    try std.testing.expectError(error.VarIntTooLarge, decodePrefixedInteger("\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x7f", 8));
    try std.testing.expectError(error.Truncated, decodeHeaderBlock(std.testing.allocator, "\x00\x00\x27\x00short"));
}

test "minimal QPACK decoder reads static and literal request headers" {
    const block = "\x00\x00\xd1\x51\x07/health";

    const headers = try decodeHeaderBlock(std.testing.allocator, block);
    defer std.testing.allocator.free(headers);

    try std.testing.expectEqual(@as(usize, 2), headers.len);
    try std.testing.expectEqualStrings(":method", headers[0].name);
    try std.testing.expectEqualStrings("GET", headers[0].value);
    try std.testing.expectEqualStrings(":path", headers[1].name);
    try std.testing.expectEqualStrings("/health", headers[1].value);
}
