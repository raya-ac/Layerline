const std = @import("std");

pub const Error = error{
    BadFrame,
    BadHeaderBlock,
    BufferTooSmall,
    HeaderListTooLarge,
    IntegerOverflow,
    OutOfMemory,
    Truncated,
};

pub const FRAME_DATA: u8 = 0x0;
pub const FRAME_HEADERS: u8 = 0x1;
pub const FRAME_RST_STREAM: u8 = 0x3;
pub const FRAME_SETTINGS: u8 = 0x4;
pub const FRAME_PING: u8 = 0x6;
pub const FRAME_GOAWAY: u8 = 0x7;
pub const FRAME_WINDOW_UPDATE: u8 = 0x8;

pub const FLAG_END_STREAM: u8 = 0x1;
pub const FLAG_ACK: u8 = 0x1;
pub const FLAG_END_HEADERS: u8 = 0x4;
pub const FLAG_PADDED: u8 = 0x8;
pub const FLAG_PRIORITY: u8 = 0x20;

pub const FrameHeader = struct {
    length: usize,
    frame_type: u8,
    flags: u8,
    stream_id: u32,
};

pub const Header = struct {
    name: []const u8,
    value: []const u8,
};

pub const DecodedHeaders = struct {
    headers: std.ArrayList(Header),

    pub fn deinit(self: *DecodedHeaders, allocator: std.mem.Allocator) void {
        self.headers.deinit(allocator);
    }

    pub fn get(self: *const DecodedHeaders, name: []const u8) ?[]const u8 {
        for (self.headers.items) |header| {
            if (std.ascii.eqlIgnoreCase(header.name, name)) return header.value;
        }
        return null;
    }
};

const StaticEntry = struct {
    name: []const u8,
    value: []const u8,
};

const DynamicEntry = struct {
    name: []const u8,
    value: []const u8,
};

const STATIC_TABLE = [_]StaticEntry{
    .{ .name = ":authority", .value = "" },
    .{ .name = ":method", .value = "GET" },
    .{ .name = ":method", .value = "POST" },
    .{ .name = ":path", .value = "/" },
    .{ .name = ":path", .value = "/index.html" },
    .{ .name = ":scheme", .value = "http" },
    .{ .name = ":scheme", .value = "https" },
    .{ .name = ":status", .value = "200" },
    .{ .name = ":status", .value = "204" },
    .{ .name = ":status", .value = "206" },
    .{ .name = ":status", .value = "304" },
    .{ .name = ":status", .value = "400" },
    .{ .name = ":status", .value = "404" },
    .{ .name = ":status", .value = "500" },
    .{ .name = "accept-charset", .value = "" },
    .{ .name = "accept-encoding", .value = "gzip, deflate" },
    .{ .name = "accept-language", .value = "" },
    .{ .name = "accept-ranges", .value = "" },
    .{ .name = "accept", .value = "" },
    .{ .name = "access-control-allow-origin", .value = "" },
    .{ .name = "age", .value = "" },
    .{ .name = "allow", .value = "" },
    .{ .name = "authorization", .value = "" },
    .{ .name = "cache-control", .value = "" },
    .{ .name = "content-disposition", .value = "" },
    .{ .name = "content-encoding", .value = "" },
    .{ .name = "content-language", .value = "" },
    .{ .name = "content-length", .value = "" },
    .{ .name = "content-location", .value = "" },
    .{ .name = "content-range", .value = "" },
    .{ .name = "content-type", .value = "" },
    .{ .name = "cookie", .value = "" },
    .{ .name = "date", .value = "" },
    .{ .name = "etag", .value = "" },
    .{ .name = "expect", .value = "" },
    .{ .name = "expires", .value = "" },
    .{ .name = "from", .value = "" },
    .{ .name = "host", .value = "" },
    .{ .name = "if-match", .value = "" },
    .{ .name = "if-modified-since", .value = "" },
    .{ .name = "if-none-match", .value = "" },
    .{ .name = "if-range", .value = "" },
    .{ .name = "if-unmodified-since", .value = "" },
    .{ .name = "last-modified", .value = "" },
    .{ .name = "link", .value = "" },
    .{ .name = "location", .value = "" },
    .{ .name = "max-forwards", .value = "" },
    .{ .name = "proxy-authenticate", .value = "" },
    .{ .name = "proxy-authorization", .value = "" },
    .{ .name = "range", .value = "" },
    .{ .name = "referer", .value = "" },
    .{ .name = "refresh", .value = "" },
    .{ .name = "retry-after", .value = "" },
    .{ .name = "server", .value = "" },
    .{ .name = "set-cookie", .value = "" },
    .{ .name = "strict-transport-security", .value = "" },
    .{ .name = "transfer-encoding", .value = "" },
    .{ .name = "user-agent", .value = "" },
    .{ .name = "vary", .value = "" },
    .{ .name = "via", .value = "" },
    .{ .name = "www-authenticate", .value = "" },
};

// RFC 7541's HPACK Huffman code table. Keeping it local means h2c request
// decoding works with stock clients without linking a compression library.
const HUFFMAN_CODES = [_]u32{
    0x1ff8,    0x7fffd8,  0xfffffe2,  0xfffffe3, 0xfffffe4, 0xfffffe5,  0xfffffe6,  0xfffffe7,
    0xfffffe8, 0xffffea,  0x3ffffffc, 0xfffffe9, 0xfffffea, 0x3ffffffd, 0xfffffeb,  0xfffffec,
    0xfffffed, 0xfffffee, 0xfffffef,  0xffffff0, 0xffffff1, 0xffffff2,  0x3ffffffe, 0xffffff3,
    0xffffff4, 0xffffff5, 0xffffff6,  0xffffff7, 0xffffff8, 0xffffff9,  0xffffffa,  0xffffffb,
    0x14,      0x3f8,     0x3f9,      0xffa,     0x1ff9,    0x15,       0xf8,       0x7fa,
    0x3fa,     0x3fb,     0xf9,       0x7fb,     0xfa,      0x16,       0x17,       0x18,
    0x0,       0x1,       0x2,        0x19,      0x1a,      0x1b,       0x1c,       0x1d,
    0x1e,      0x1f,      0x5c,       0xfb,      0x7ffc,    0x20,       0xffb,      0x3fc,
    0x1ffa,    0x21,      0x5d,       0x5e,      0x5f,      0x60,       0x61,       0x62,
    0x63,      0x64,      0x65,       0x66,      0x67,      0x68,       0x69,       0x6a,
    0x6b,      0x6c,      0x6d,       0x6e,      0x6f,      0x70,       0x71,       0x72,
    0xfc,      0x73,      0xfd,       0x1ffb,    0x7fff0,   0x1ffc,     0x3ffc,     0x22,
    0x7ffd,    0x3,       0x23,       0x4,       0x24,      0x5,        0x25,       0x26,
    0x27,      0x6,       0x74,       0x75,      0x28,      0x29,       0x2a,       0x7,
    0x2b,      0x76,      0x2c,       0x8,       0x9,       0x2d,       0x77,       0x78,
    0x79,      0x7a,      0x7b,       0x7ffe,    0x7fc,     0x3ffd,     0x1ffd,     0xffffffc,
    0xfffe6,   0x3fffd2,  0xfffe7,    0xfffe8,   0x3fffd3,  0x3fffd4,   0x3fffd5,   0x7fffd9,
    0x3fffd6,  0x7fffda,  0x7fffdb,   0x7fffdc,  0x7fffdd,  0x7fffde,   0xffffeb,   0x7fffdf,
    0xffffec,  0xffffed,  0x3fffd7,   0x7fffe0,  0xffffee,  0x7fffe1,   0x7fffe2,   0x7fffe3,
    0x7fffe4,  0x1fffdc,  0x3fffd8,   0x7fffe5,  0x3fffd9,  0x7fffe6,   0x7fffe7,   0xffffef,
    0x3fffda,  0x1fffdd,  0xfffe9,    0x3fffdb,  0x3fffdc,  0x7fffe8,   0x7fffe9,   0x1fffde,
    0x7fffea,  0x3fffdd,  0x3fffde,   0xfffff0,  0x1fffdf,  0x3fffdf,   0x7fffeb,   0x7fffec,
    0x1fffe0,  0x1fffe1,  0x3fffe0,   0x1fffe2,  0x7fffed,  0x3fffe1,   0x7fffee,   0x7fffef,
    0xfffea,   0x3fffe2,  0x3fffe3,   0x3fffe4,  0x7ffff0,  0x3fffe5,   0x3fffe6,   0x7ffff1,
    0x3ffffe0, 0x3ffffe1, 0xfffeb,    0x7fff1,   0x3fffe7,  0x7ffff2,   0x3fffe8,   0x1ffffec,
    0x3ffffe2, 0x3ffffe3, 0x3ffffe4,  0x7ffffde, 0x7ffffdf, 0x3ffffe5,  0xfffff1,   0x1ffffed,
    0x7fff2,   0x1fffe3,  0x3ffffe6,  0x7ffffe0, 0x7ffffe1, 0x3ffffe7,  0x7ffffe2,  0xfffff2,
    0x1fffe4,  0x1fffe5,  0x3ffffe8,  0x3ffffe9, 0xffffffd, 0x7ffffe3,  0x7ffffe4,  0x7ffffe5,
    0xfffec,   0xfffff3,  0xfffed,    0x1fffe6,  0x3fffe9,  0x1fffe7,   0x1fffe8,   0x7ffff3,
    0x3fffea,  0x3fffeb,  0x1ffffee,  0x1ffffef, 0xfffff4,  0xfffff5,   0x3ffffea,  0x7ffff4,
    0x3ffffeb, 0x7ffffe6, 0x3ffffec,  0x3ffffed, 0x7ffffe7, 0x7ffffe8,  0x7ffffe9,  0x7ffffea,
    0x7ffffeb, 0xffffffe, 0x7ffffec,  0x7ffffed, 0x7ffffee, 0x7ffffef,  0x7fffff0,  0x3ffffee,
};

const HUFFMAN_CODE_LENS = [_]u8{
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28,
    28, 28, 28, 28, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 28,
    6,  10, 10, 12, 13, 6,  8,  11, 10, 10, 8,  11, 8,  6,  6,  6,
    5,  5,  5,  6,  6,  6,  6,  6,  6,  6,  7,  8,  15, 6,  12, 10,
    13, 6,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,  7,
    7,  7,  7,  7,  7,  7,  7,  7,  8,  7,  8,  13, 19, 13, 14, 6,
    15, 5,  6,  5,  6,  5,  6,  6,  6,  5,  7,  7,  6,  6,  6,  5,
    6,  7,  6,  5,  5,  6,  7,  7,  7,  7,  7,  15, 11, 14, 13, 28,
    20, 22, 20, 20, 22, 22, 22, 23, 22, 23, 23, 23, 23, 23, 24, 23,
    24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24,
    22, 21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23,
    21, 21, 22, 21, 23, 22, 23, 23, 20, 22, 22, 22, 23, 22, 22, 23,
    26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25,
    19, 21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27,
    20, 24, 20, 21, 22, 21, 21, 23, 22, 22, 25, 25, 24, 24, 26, 23,
    26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26,
};

fn staticEntry(index: u64) Error!StaticEntry {
    if (index == 0 or index > STATIC_TABLE.len) return error.BadHeaderBlock;
    return STATIC_TABLE[@intCast(index - 1)];
}

pub fn staticName(index: u64) Error![]const u8 {
    return (try staticEntry(index)).name;
}

fn headerEntrySize(name: []const u8, value: []const u8) usize {
    return name.len + value.len + 32;
}

pub const HpackDecoder = struct {
    allocator: std.mem.Allocator,
    dynamic: std.ArrayList(DynamicEntry) = .empty,
    dynamic_size: usize = 0,
    dynamic_capacity: usize = 4096,
    max_dynamic_size: usize = 4096,

    pub fn init(allocator: std.mem.Allocator) HpackDecoder {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *HpackDecoder) void {
        self.clearDynamicTable();
        self.dynamic.deinit(self.allocator);
    }

    fn clearDynamicTable(self: *HpackDecoder) void {
        for (self.dynamic.items) |entry| {
            self.allocator.free(entry.name);
            self.allocator.free(entry.value);
        }
        self.dynamic.clearRetainingCapacity();
        self.dynamic_size = 0;
    }

    fn evictDynamicEntries(self: *HpackDecoder) void {
        while (self.dynamic_size > self.dynamic_capacity and self.dynamic.items.len > 0) {
            const last_index = self.dynamic.items.len - 1;
            const entry = self.dynamic.items[last_index];
            self.dynamic.items.len = last_index;
            self.dynamic_size -= headerEntrySize(entry.name, entry.value);
            self.allocator.free(entry.name);
            self.allocator.free(entry.value);
        }
    }

    fn insertDynamic(self: *HpackDecoder, name: []const u8, value: []const u8) Error!void {
        const entry_size = headerEntrySize(name, value);
        if (entry_size > self.dynamic_capacity) {
            self.clearDynamicTable();
            return;
        }

        const entry = DynamicEntry{
            .name = try self.allocator.dupe(u8, name),
            .value = try self.allocator.dupe(u8, value),
        };
        errdefer {
            self.allocator.free(entry.name);
            self.allocator.free(entry.value);
        }

        try self.dynamic.append(self.allocator, entry);
        var i = self.dynamic.items.len - 1;
        while (i > 0) : (i -= 1) {
            self.dynamic.items[i] = self.dynamic.items[i - 1];
        }
        self.dynamic.items[0] = entry;
        self.dynamic_size += entry_size;
        self.evictDynamicEntries();
    }

    fn indexedEntry(self: *HpackDecoder, index: u64) Error!Header {
        if (index == 0) return error.BadHeaderBlock;
        if (index <= STATIC_TABLE.len) {
            const entry = STATIC_TABLE[@intCast(index - 1)];
            return .{ .name = entry.name, .value = entry.value };
        }

        const dynamic_index_u64 = index - STATIC_TABLE.len - 1;
        const dynamic_index = std.math.cast(usize, dynamic_index_u64) orelse return error.BadHeaderBlock;
        if (dynamic_index >= self.dynamic.items.len) return error.BadHeaderBlock;
        const entry = self.dynamic.items[dynamic_index];
        return .{ .name = entry.name, .value = entry.value };
    }

    fn indexedName(self: *HpackDecoder, index: u64) Error![]const u8 {
        return (try self.indexedEntry(index)).name;
    }

    pub fn setDynamicTableSize(self: *HpackDecoder, size: u64) Error!void {
        const cast_size = std.math.cast(usize, size) orelse return error.IntegerOverflow;
        if (cast_size > self.max_dynamic_size) return error.BadHeaderBlock;
        self.dynamic_capacity = cast_size;
        self.evictDynamicEntries();
    }

    pub fn decodeHeaderBlock(self: *HpackDecoder, allocator: std.mem.Allocator, block: []const u8) Error!DecodedHeaders {
        var headers = std.ArrayList(Header).empty;
        errdefer headers.deinit(allocator);

        var offset: usize = 0;
        while (offset < block.len) {
            const byte = block[offset];
            if ((byte & 0x80) != 0) {
                const decoded = try decodeInteger(block[offset..], 7);
                const entry = try self.indexedEntry(decoded.value);
                try appendDecoded(&headers, allocator, entry.name, entry.value);
                offset += decoded.len;
                continue;
            }

            if ((byte & 0xe0) == 0x20) {
                const decoded_size = try decodeInteger(block[offset..], 5);
                try self.setDynamicTableSize(decoded_size.value);
                offset += decoded_size.len;
                continue;
            }

            const uses_incremental_indexing = (byte & 0x40) != 0;
            const prefix_bits: u3 = if (uses_incremental_indexing) 6 else 4;
            if (!uses_incremental_indexing and (byte & 0xf0) != 0 and (byte & 0xf0) != 0x10) {
                return error.BadHeaderBlock;
            }

            const name_index = try decodeInteger(block[offset..], prefix_bits);
            offset += name_index.len;

            const name = if (name_index.value == 0) blk: {
                const decoded_name = try decodeString(allocator, block[offset..]);
                offset += decoded_name.len;
                break :blk decoded_name.value;
            } else try self.indexedName(name_index.value);

            const decoded_value = try decodeString(allocator, block[offset..]);
            offset += decoded_value.len;
            try appendDecoded(&headers, allocator, name, decoded_value.value);
            if (uses_incremental_indexing) try self.insertDynamic(name, decoded_value.value);
        }

        return .{ .headers = headers };
    }
};

pub fn parseFrameHeader(bytes: []const u8) Error!FrameHeader {
    if (bytes.len < 9) return error.Truncated;
    const length = (@as(usize, bytes[0]) << 16) | (@as(usize, bytes[1]) << 8) | bytes[2];
    const stream_id_raw = std.mem.readInt(u32, bytes[5..9], .big);
    return .{
        .length = length,
        .frame_type = bytes[3],
        .flags = bytes[4],
        .stream_id = stream_id_raw & 0x7fff_ffff,
    };
}

pub fn writeFrameHeader(out: []u8, length: usize, frame_type: u8, flags: u8, stream_id: u32) Error![]const u8 {
    if (out.len < 9) return error.BufferTooSmall;
    if (length > 0x00ff_ffff) return error.BadFrame;
    out[0] = @intCast((length >> 16) & 0xff);
    out[1] = @intCast((length >> 8) & 0xff);
    out[2] = @intCast(length & 0xff);
    out[3] = frame_type;
    out[4] = flags;
    std.mem.writeInt(u32, out[5..9], stream_id & 0x7fff_ffff, .big);
    return out[0..9];
}

pub fn appendFrame(allocator: std.mem.Allocator, out: *std.ArrayList(u8), frame_type: u8, flags: u8, stream_id: u32, payload: []const u8) !void {
    var header: [9]u8 = undefined;
    const head = try writeFrameHeader(&header, payload.len, frame_type, flags, stream_id);
    try out.appendSlice(allocator, head);
    try out.appendSlice(allocator, payload);
}

pub fn encodeInteger(allocator: std.mem.Allocator, out: *std.ArrayList(u8), first_mask: u8, prefix_bits: u3, value: u64) !void {
    const max_prefix = (@as(u64, 1) << prefix_bits) - 1;
    if (value < max_prefix) {
        try out.append(allocator, first_mask | @as(u8, @intCast(value)));
        return;
    }

    try out.append(allocator, first_mask | @as(u8, @intCast(max_prefix)));
    var remaining = value - max_prefix;
    while (remaining >= 128) {
        try out.append(allocator, @as(u8, @intCast(remaining & 0x7f)) | 0x80);
        remaining >>= 7;
    }
    try out.append(allocator, @intCast(remaining));
}

fn decodeInteger(input: []const u8, prefix_bits: u3) Error!struct { value: u64, len: usize } {
    if (input.len == 0) return error.Truncated;
    const max_prefix = (@as(u8, 1) << prefix_bits) - 1;
    var value: u64 = input[0] & max_prefix;
    if (value < max_prefix) return .{ .value = value, .len = 1 };

    var shift: u6 = 0;
    var offset: usize = 1;
    while (offset < input.len) : (offset += 1) {
        const byte = input[offset];
        value += (@as(u64, byte & 0x7f) << shift);
        if ((byte & 0x80) == 0) return .{ .value = value, .len = offset + 1 };
        if (shift >= 56) return error.IntegerOverflow;
        shift += 7;
    }
    return error.Truncated;
}

pub fn appendString(allocator: std.mem.Allocator, out: *std.ArrayList(u8), value: []const u8) !void {
    try encodeInteger(allocator, out, 0x00, 7, value.len);
    try out.appendSlice(allocator, value);
}

fn findHuffmanSymbol(code: u32, code_len: u8) ?u8 {
    for (HUFFMAN_CODES, 0..) |candidate, symbol| {
        if (HUFFMAN_CODE_LENS[symbol] == code_len and candidate == code) {
            return @intCast(symbol);
        }
    }
    return null;
}

pub fn decodeHuffmanString(allocator: std.mem.Allocator, encoded: []const u8) Error![]const u8 {
    var out = std.ArrayList(u8).empty;
    errdefer out.deinit(allocator);

    var code: u32 = 0;
    var code_len: u8 = 0;
    for (encoded) |byte| {
        var bit: u8 = 0x80;
        while (bit != 0) : (bit >>= 1) {
            code = (code << 1) | if ((byte & bit) != 0) @as(u32, 1) else 0;
            code_len += 1;
            if (code_len > 30) return error.BadHeaderBlock;

            if (findHuffmanSymbol(code, code_len)) |symbol| {
                try out.append(allocator, symbol);
                code = 0;
                code_len = 0;
            }
        }
    }

    if (code_len > 7) return error.BadHeaderBlock;
    if (code_len > 0) {
        const valid_padding = (@as(u32, 1) << @intCast(code_len)) - 1;
        if (code != valid_padding) return error.BadHeaderBlock;
    }

    return out.toOwnedSlice(allocator);
}

fn decodeString(allocator: std.mem.Allocator, input: []const u8) Error!struct { value: []const u8, len: usize } {
    if (input.len == 0) return error.Truncated;
    const is_huffman = (input[0] & 0x80) != 0;
    const decoded_len = try decodeInteger(input, 7);
    const start = decoded_len.len;
    const value_len = std.math.cast(usize, decoded_len.value) orelse return error.IntegerOverflow;
    const end = start + value_len;
    if (end > input.len) return error.Truncated;
    const value = if (is_huffman)
        try decodeHuffmanString(allocator, input[start..end])
    else
        try allocator.dupe(u8, input[start..end]);
    return .{ .value = value, .len = end };
}

fn appendDecoded(headers: *std.ArrayList(Header), allocator: std.mem.Allocator, name: []const u8, value: []const u8) !void {
    if (headers.items.len >= 128) return error.HeaderListTooLarge;
    try headers.append(allocator, .{ .name = name, .value = value });
}

pub fn decodeHeaderBlock(allocator: std.mem.Allocator, block: []const u8) Error!DecodedHeaders {
    var decoder = HpackDecoder.init(allocator);
    defer decoder.deinit();
    return decoder.decodeHeaderBlock(allocator, block);
}

pub fn appendHeaderIndexedName(allocator: std.mem.Allocator, out: *std.ArrayList(u8), name_index: u64, value: []const u8) !void {
    try encodeInteger(allocator, out, 0x00, 4, name_index);
    try appendString(allocator, out, value);
}

pub fn appendHeaderLiteralName(allocator: std.mem.Allocator, out: *std.ArrayList(u8), name: []const u8, value: []const u8) !void {
    try out.append(allocator, 0x00);
    try appendString(allocator, out, name);
    try appendString(allocator, out, value);
}

pub fn appendStatus(allocator: std.mem.Allocator, out: *std.ArrayList(u8), status_code: u16) !void {
    const index: ?u64 = switch (status_code) {
        200 => 8,
        204 => 9,
        206 => 10,
        304 => 11,
        400 => 12,
        404 => 13,
        500 => 14,
        else => null,
    };
    if (index) |idx| {
        try encodeInteger(allocator, out, 0x80, 7, idx);
        return;
    }

    var status_buf: [3]u8 = undefined;
    const rendered = try std.fmt.bufPrint(&status_buf, "{d}", .{status_code});
    try appendHeaderLiteralName(allocator, out, ":status", rendered);
}

test "frame header round trips" {
    var buf: [9]u8 = undefined;
    _ = try writeFrameHeader(&buf, 4096, FRAME_HEADERS, FLAG_END_HEADERS, 17);
    const parsed = try parseFrameHeader(&buf);
    try std.testing.expectEqual(@as(usize, 4096), parsed.length);
    try std.testing.expectEqual(FRAME_HEADERS, parsed.frame_type);
    try std.testing.expectEqual(FLAG_END_HEADERS, parsed.flags);
    try std.testing.expectEqual(@as(u32, 17), parsed.stream_id);
}

test "decodes static and literal request headers" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var block = std.ArrayList(u8).empty;
    defer block.deinit(std.testing.allocator);
    try encodeInteger(std.testing.allocator, &block, 0x80, 7, 2);
    try appendHeaderIndexedName(std.testing.allocator, &block, 4, "/health");
    try appendHeaderIndexedName(std.testing.allocator, &block, 1, "example.test");

    var decoded = try decodeHeaderBlock(allocator, block.items);
    defer decoded.deinit(allocator);
    try std.testing.expectEqualStrings("GET", decoded.get(":method").?);
    try std.testing.expectEqualStrings("/health", decoded.get(":path").?);
    try std.testing.expectEqualStrings("example.test", decoded.get(":authority").?);
}

test "keeps HPACK dynamic table across header blocks" {
    var decoder = HpackDecoder.init(std.testing.allocator);
    defer decoder.deinit();

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var first = std.ArrayList(u8).empty;
    defer first.deinit(std.testing.allocator);
    try encodeInteger(std.testing.allocator, &first, 0x40, 6, 1);
    try appendString(std.testing.allocator, &first, "example.test");
    var decoded_first = try decoder.decodeHeaderBlock(allocator, first.items);
    defer decoded_first.deinit(allocator);
    try std.testing.expectEqualStrings("example.test", decoded_first.get(":authority").?);

    var second = std.ArrayList(u8).empty;
    defer second.deinit(std.testing.allocator);
    try encodeInteger(std.testing.allocator, &second, 0x80, 7, STATIC_TABLE.len + 1);
    var decoded_second = try decoder.decodeHeaderBlock(allocator, second.items);
    defer decoded_second.deinit(allocator);
    try std.testing.expectEqualStrings("example.test", decoded_second.get(":authority").?);
}

test "decodes HPACK Huffman string literals" {
    const encoded = [_]u8{ 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff };
    const decoded = try decodeHuffmanString(std.testing.allocator, &encoded);
    defer std.testing.allocator.free(decoded);
    try std.testing.expectEqualStrings("www.example.com", decoded);
}

test "encodes response status and literal headers" {
    var out = std.ArrayList(u8).empty;
    defer out.deinit(std.testing.allocator);
    try appendStatus(std.testing.allocator, &out, 200);
    try appendHeaderIndexedName(std.testing.allocator, &out, 31, "text/plain");
    try std.testing.expect(out.items.len > 2);
    try std.testing.expectEqual(@as(u8, 0x88), out.items[0]);
}
