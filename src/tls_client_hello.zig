const std = @import("std");

pub const Error = error{
    BadClientHello,
    BufferTooSmall,
    IntegerOverflow,
    NotClientHello,
    OutOfMemory,
    Truncated,
};

pub const ClientHelloInfo = struct {
    sni: ?[]const u8 = null,
    alpn: ?[]const u8 = null,
    supports_tls13: bool = false,
    offers_h2: bool = false,
    offers_http11: bool = false,

    pub fn deinit(self: *ClientHelloInfo, allocator: std.mem.Allocator) void {
        if (self.sni) |value| allocator.free(value);
        if (self.alpn) |value| allocator.free(value);
        self.* = .{};
    }
};

pub fn looksLikeTlsClientHello(bytes: []const u8) bool {
    return bytes.len >= 1 and bytes[0] == 0x16;
}

pub fn recordLength(bytes: []const u8) Error!usize {
    if (bytes.len < 5) return error.BufferTooSmall;
    if (bytes[0] != 0x16) return error.NotClientHello;
    if (bytes[1] != 0x03) return error.NotClientHello;
    const len = (@as(u16, bytes[3]) << 8) | bytes[4];
    return 5 + @as(usize, len);
}

fn readU16(bytes: []const u8, offset: *usize) Error!u16 {
    if (bytes.len < offset.* + 2) return error.Truncated;
    const value = (@as(u16, bytes[offset.*]) << 8) | bytes[offset.* + 1];
    offset.* += 2;
    return value;
}

fn readU24(bytes: []const u8, offset: *usize) Error!usize {
    if (bytes.len < offset.* + 3) return error.Truncated;
    const value = (@as(usize, bytes[offset.*]) << 16) |
        (@as(usize, bytes[offset.* + 1]) << 8) |
        @as(usize, bytes[offset.* + 2]);
    offset.* += 3;
    return value;
}

fn take(bytes: []const u8, offset: *usize, len: usize) Error![]const u8 {
    if (len > bytes.len or offset.* > bytes.len - len) return error.Truncated;
    const out = bytes[offset.* .. offset.* + len];
    offset.* += len;
    return out;
}

fn parseServerName(allocator: std.mem.Allocator, payload: []const u8, info: *ClientHelloInfo) Error!void {
    var offset: usize = 0;
    const list_len = try readU16(payload, &offset);
    const list = try take(payload, &offset, list_len);
    var list_offset: usize = 0;
    while (list_offset < list.len) {
        const name_type = (try take(list, &list_offset, 1))[0];
        const name_len = try readU16(list, &list_offset);
        const name = try take(list, &list_offset, name_len);
        if (name_type == 0 and name.len > 0 and info.sni == null) {
            info.sni = try allocator.dupe(u8, name);
        }
    }
}

fn appendAlpn(allocator: std.mem.Allocator, out: *std.ArrayList(u8), value: []const u8) !void {
    if (out.items.len > 0) try out.append(allocator, ',');
    try out.appendSlice(allocator, value);
}

fn parseAlpn(allocator: std.mem.Allocator, payload: []const u8, info: *ClientHelloInfo) Error!void {
    var offset: usize = 0;
    const list_len = try readU16(payload, &offset);
    const list = try take(payload, &offset, list_len);
    var list_offset: usize = 0;
    var protocols = std.ArrayList(u8).empty;
    errdefer protocols.deinit(allocator);

    while (list_offset < list.len) {
        const proto_len = (try take(list, &list_offset, 1))[0];
        const proto = try take(list, &list_offset, proto_len);
        if (std.mem.eql(u8, proto, "h2")) info.offers_h2 = true;
        if (std.mem.eql(u8, proto, "http/1.1")) info.offers_http11 = true;
        try appendAlpn(allocator, &protocols, proto);
    }

    if (protocols.items.len > 0) {
        if (info.alpn) |old| allocator.free(old);
        info.alpn = try protocols.toOwnedSlice(allocator);
    }
}

fn parseSupportedVersions(payload: []const u8, info: *ClientHelloInfo) Error!void {
    var offset: usize = 0;
    const list_len = (try take(payload, &offset, 1))[0];
    const list = try take(payload, &offset, list_len);
    if (list.len % 2 != 0) return error.BadClientHello;
    var list_offset: usize = 0;
    while (list_offset < list.len) {
        const version = try readU16(list, &list_offset);
        if (version == 0x0304) info.supports_tls13 = true;
    }
}

fn parseExtensions(allocator: std.mem.Allocator, extensions: []const u8, info: *ClientHelloInfo) Error!void {
    var offset: usize = 0;
    while (offset < extensions.len) {
        const ext_type = try readU16(extensions, &offset);
        const ext_len = try readU16(extensions, &offset);
        const payload = try take(extensions, &offset, ext_len);
        switch (ext_type) {
            0x0000 => try parseServerName(allocator, payload, info),
            0x0010 => try parseAlpn(allocator, payload, info),
            0x002b => try parseSupportedVersions(payload, info),
            else => {},
        }
    }
}

pub fn parse(allocator: std.mem.Allocator, record: []const u8) Error!ClientHelloInfo {
    const needed = try recordLength(record);
    if (record.len < needed) return error.Truncated;
    const fragment = record[5..needed];

    var offset: usize = 0;
    const handshake_type = (try take(fragment, &offset, 1))[0];
    if (handshake_type != 0x01) return error.NotClientHello;
    const handshake_len = try readU24(fragment, &offset);
    const body = try take(fragment, &offset, handshake_len);

    var body_offset: usize = 0;
    _ = try readU16(body, &body_offset);
    _ = try take(body, &body_offset, 32);
    const session_id_len = (try take(body, &body_offset, 1))[0];
    _ = try take(body, &body_offset, session_id_len);
    const cipher_suites_len = try readU16(body, &body_offset);
    if (cipher_suites_len % 2 != 0) return error.BadClientHello;
    _ = try take(body, &body_offset, cipher_suites_len);
    const compression_methods_len = (try take(body, &body_offset, 1))[0];
    _ = try take(body, &body_offset, compression_methods_len);

    var info = ClientHelloInfo{};
    errdefer info.deinit(allocator);

    if (body_offset < body.len) {
        const extensions_len = try readU16(body, &body_offset);
        const extensions = try take(body, &body_offset, extensions_len);
        try parseExtensions(allocator, extensions, &info);
    }

    return info;
}

fn appendU16(allocator: std.mem.Allocator, out: *std.ArrayList(u8), value: usize) !void {
    var buf: [2]u8 = undefined;
    std.mem.writeInt(u16, &buf, @intCast(value), .big);
    try out.appendSlice(allocator, &buf);
}

fn appendU24(allocator: std.mem.Allocator, out: *std.ArrayList(u8), value: usize) !void {
    try out.append(allocator, @intCast((value >> 16) & 0xff));
    try out.append(allocator, @intCast((value >> 8) & 0xff));
    try out.append(allocator, @intCast(value & 0xff));
}

fn appendExtension(allocator: std.mem.Allocator, out: *std.ArrayList(u8), ext_type: u16, payload: []const u8) !void {
    try appendU16(allocator, out, ext_type);
    try appendU16(allocator, out, payload.len);
    try out.appendSlice(allocator, payload);
}

test "parses SNI ALPN and TLS 1.3 support from ClientHello" {
    const allocator = std.testing.allocator;
    var extensions = std.ArrayList(u8).empty;
    defer extensions.deinit(allocator);

    var sni = std.ArrayList(u8).empty;
    defer sni.deinit(allocator);
    try appendU16(allocator, &sni, 3 + "layerline.dev".len);
    try sni.append(allocator, 0);
    try appendU16(allocator, &sni, "layerline.dev".len);
    try sni.appendSlice(allocator, "layerline.dev");
    try appendExtension(allocator, &extensions, 0x0000, sni.items);

    var alpn = std.ArrayList(u8).empty;
    defer alpn.deinit(allocator);
    try appendU16(allocator, &alpn, 1 + "h2".len + 1 + "http/1.1".len);
    try alpn.append(allocator, "h2".len);
    try alpn.appendSlice(allocator, "h2");
    try alpn.append(allocator, "http/1.1".len);
    try alpn.appendSlice(allocator, "http/1.1");
    try appendExtension(allocator, &extensions, 0x0010, alpn.items);

    const supported_versions = [_]u8{ 0x02, 0x03, 0x04 };
    try appendExtension(allocator, &extensions, 0x002b, &supported_versions);

    var body = std.ArrayList(u8).empty;
    defer body.deinit(allocator);
    try appendU16(allocator, &body, 0x0303);
    try body.appendNTimes(allocator, 0x42, 32);
    try body.append(allocator, 0);
    try appendU16(allocator, &body, 2);
    try appendU16(allocator, &body, 0x1301);
    try body.append(allocator, 1);
    try body.append(allocator, 0);
    try appendU16(allocator, &body, extensions.items.len);
    try body.appendSlice(allocator, extensions.items);

    var handshake = std.ArrayList(u8).empty;
    defer handshake.deinit(allocator);
    try handshake.append(allocator, 0x01);
    try appendU24(allocator, &handshake, body.items.len);
    try handshake.appendSlice(allocator, body.items);

    var record = std.ArrayList(u8).empty;
    defer record.deinit(allocator);
    try record.appendSlice(allocator, &.{ 0x16, 0x03, 0x01 });
    try appendU16(allocator, &record, handshake.items.len);
    try record.appendSlice(allocator, handshake.items);

    var info = try parse(allocator, record.items);
    defer info.deinit(allocator);
    try std.testing.expectEqualStrings("layerline.dev", info.sni.?);
    try std.testing.expectEqualStrings("h2,http/1.1", info.alpn.?);
    try std.testing.expect(info.supports_tls13);
    try std.testing.expect(info.offers_h2);
    try std.testing.expect(info.offers_http11);
}
