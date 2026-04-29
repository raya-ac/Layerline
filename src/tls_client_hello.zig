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
    legacy_session_id: ?[]const u8 = null,
    x25519_key_share: ?[32]u8 = null,
    supports_tls13: bool = false,
    offers_aes_128_gcm_sha256: bool = false,
    offers_ecdsa_secp256r1_sha256: bool = false,
    offers_rsa_pss_rsae_sha256: bool = false,
    offers_ed25519: bool = false,
    offers_h2: bool = false,
    offers_http11: bool = false,

    pub fn deinit(self: *ClientHelloInfo, allocator: std.mem.Allocator) void {
        if (self.sni) |value| allocator.free(value);
        if (self.alpn) |value| allocator.free(value);
        if (self.legacy_session_id) |value| allocator.free(value);
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

fn parseSignatureAlgorithms(payload: []const u8, info: *ClientHelloInfo) Error!void {
    var offset: usize = 0;
    const list_len = try readU16(payload, &offset);
    const list = try take(payload, &offset, list_len);
    if (list.len % 2 != 0) return error.BadClientHello;
    var list_offset: usize = 0;
    while (list_offset < list.len) {
        const scheme = try readU16(list, &list_offset);
        if (scheme == 0x0403) info.offers_ecdsa_secp256r1_sha256 = true;
        if (scheme == 0x0804) info.offers_rsa_pss_rsae_sha256 = true;
        if (scheme == 0x0807) info.offers_ed25519 = true;
    }
}

fn parseKeyShare(payload: []const u8, info: *ClientHelloInfo) Error!void {
    var offset: usize = 0;
    const shares_len = try readU16(payload, &offset);
    const shares = try take(payload, &offset, shares_len);
    var shares_offset: usize = 0;
    while (shares_offset < shares.len) {
        const group = try readU16(shares, &shares_offset);
        const key_len = try readU16(shares, &shares_offset);
        const key = try take(shares, &shares_offset, key_len);
        if (group == 0x001d and key.len == 32 and info.x25519_key_share == null) {
            info.x25519_key_share = key[0..32].*;
        }
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
            0x000d => try parseSignatureAlgorithms(payload, info),
            0x0010 => try parseAlpn(allocator, payload, info),
            0x002b => try parseSupportedVersions(payload, info),
            0x0033 => try parseKeyShare(payload, info),
            else => {},
        }
    }
}

fn parseCipherSuites(cipher_suites: []const u8, info: *ClientHelloInfo) Error!void {
    if (cipher_suites.len % 2 != 0) return error.BadClientHello;
    var offset: usize = 0;
    while (offset < cipher_suites.len) {
        const suite = try readU16(cipher_suites, &offset);
        if (suite == 0x1301) info.offers_aes_128_gcm_sha256 = true;
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
    const session_id = try take(body, &body_offset, session_id_len);
    const cipher_suites_len = try readU16(body, &body_offset);
    const cipher_suites = try take(body, &body_offset, cipher_suites_len);
    const compression_methods_len = (try take(body, &body_offset, 1))[0];
    _ = try take(body, &body_offset, compression_methods_len);

    var info = ClientHelloInfo{};
    errdefer info.deinit(allocator);
    if (session_id.len > 0) info.legacy_session_id = try allocator.dupe(u8, session_id);
    try parseCipherSuites(cipher_suites, &info);

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

    var signature_algorithms = std.ArrayList(u8).empty;
    defer signature_algorithms.deinit(allocator);
    try appendU16(allocator, &signature_algorithms, 6);
    try appendU16(allocator, &signature_algorithms, 0x0403);
    try appendU16(allocator, &signature_algorithms, 0x0804);
    try appendU16(allocator, &signature_algorithms, 0x0807);
    try appendExtension(allocator, &extensions, 0x000d, signature_algorithms.items);

    var key_share = std.ArrayList(u8).empty;
    defer key_share.deinit(allocator);
    const client_key = [_]u8{0x55} ** 32;
    try appendU16(allocator, &key_share, 2 + 2 + client_key.len);
    try appendU16(allocator, &key_share, 0x001d);
    try appendU16(allocator, &key_share, client_key.len);
    try key_share.appendSlice(allocator, &client_key);
    try appendExtension(allocator, &extensions, 0x0033, key_share.items);

    var body = std.ArrayList(u8).empty;
    defer body.deinit(allocator);
    try appendU16(allocator, &body, 0x0303);
    try body.appendNTimes(allocator, 0x42, 32);
    try body.append(allocator, 3);
    try body.appendSlice(allocator, "sid");
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
    try std.testing.expectEqualStrings("sid", info.legacy_session_id.?);
    try std.testing.expect(info.supports_tls13);
    try std.testing.expect(info.offers_aes_128_gcm_sha256);
    try std.testing.expect(info.offers_ecdsa_secp256r1_sha256);
    try std.testing.expect(info.offers_rsa_pss_rsae_sha256);
    try std.testing.expect(info.offers_ed25519);
    try std.testing.expectEqualSlices(u8, &client_key, &info.x25519_key_share.?);
    try std.testing.expect(info.offers_h2);
    try std.testing.expect(info.offers_http11);
}
