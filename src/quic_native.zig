const std = @import("std");
const h3 = @import("h3_native.zig");
const Aes128 = std.crypto.core.aes.Aes128;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;

pub const Version = enum(u32) {
    negotiation = 0x00000000,
    v1 = 0x00000001,
    v2 = 0x6b3343cf,
};

pub const LongPacketType = enum(u2) {
    initial = 0,
    zero_rtt = 1,
    handshake = 2,
    retry = 3,
};

pub const ConnectionId = struct {
    bytes: [20]u8 = undefined,
    len: u8 = 0,

    pub fn init(input: []const u8) !ConnectionId {
        if (input.len > 20) return error.ConnectionIdTooLong;
        var cid = ConnectionId{ .len = @intCast(input.len) };
        @memcpy(cid.bytes[0..input.len], input);
        return cid;
    }

    pub fn slice(self: *const ConnectionId) []const u8 {
        return self.bytes[0..self.len];
    }
};

pub const LongHeader = struct {
    first: u8,
    packet_type: LongPacketType,
    version: u32,
    dcid: ConnectionId,
    scid: ConnectionId,
    header_len: usize,
};

pub const ProtectedLongHeader = struct {
    long: LongHeader,
    token: []const u8,
    payload_len: u64,
    packet_number_offset: usize,
    packet_number_len: usize,
};

pub const InitialHeader = ProtectedLongHeader;

pub fn parseLongHeader(input: []const u8) !LongHeader {
    if (input.len < 7) return error.Truncated;
    const first = input[0];
    if ((first & 0x80) == 0 or (first & 0x40) == 0) return error.InvalidLongHeader;

    const version = std.mem.readInt(u32, input[1..5], .big);
    var offset: usize = 5;

    const dcid_len = input[offset];
    offset += 1;
    if (dcid_len > 20 or input.len < offset + dcid_len) return error.InvalidConnectionId;
    const dcid = try ConnectionId.init(input[offset .. offset + dcid_len]);
    offset += dcid_len;

    if (input.len < offset + 1) return error.Truncated;
    const scid_len = input[offset];
    offset += 1;
    if (scid_len > 20 or input.len < offset + scid_len) return error.InvalidConnectionId;
    const scid = try ConnectionId.init(input[offset .. offset + scid_len]);
    offset += scid_len;

    return .{
        .first = first,
        .packet_type = @enumFromInt((first >> 4) & 0x03),
        .version = version,
        .dcid = dcid,
        .scid = scid,
        .header_len = offset,
    };
}

pub fn parseProtectedLongHeader(input: []const u8) !ProtectedLongHeader {
    const long = try parseLongHeader(input);

    var offset = long.header_len;
    var token_start = offset;
    var token_end = offset;
    if (long.packet_type == .initial) {
        const token_len = try h3.decodeVarInt(input[offset..]);
        offset += token_len.len;
        if (input.len < offset + token_len.value) return error.Truncated;

        token_start = offset;
        token_end = token_start + @as(usize, @intCast(token_len.value));
        offset = token_end;
    } else if (long.packet_type == .retry) {
        return error.UnsupportedPacketType;
    }

    const packet_len = try h3.decodeVarInt(input[offset..]);
    offset += packet_len.len;

    const packet_number_len = @as(usize, long.first & 0x03) + 1;
    if (input.len < offset + packet_number_len) return error.Truncated;

    return .{
        .long = long,
        .token = input[token_start..token_end],
        .payload_len = packet_len.value,
        .packet_number_offset = offset,
        .packet_number_len = packet_number_len,
    };
}

pub fn parseInitialHeader(input: []const u8) !InitialHeader {
    const parsed = try parseProtectedLongHeader(input);
    if (parsed.long.packet_type != .initial) return error.NotInitial;
    return parsed;
}

pub fn protectedLongPacketLen(input: []const u8) !usize {
    const parsed = try parseProtectedLongHeader(input);
    return parsed.packet_number_offset + @as(usize, @intCast(parsed.payload_len));
}

pub fn encodeVersionNegotiation(
    out: []u8,
    original_dcid: []const u8,
    original_scid: []const u8,
    versions: []const u32,
) !usize {
    if (original_dcid.len > 20 or original_scid.len > 20) return error.ConnectionIdTooLong;

    const need = 1 + 4 + 1 + original_scid.len + 1 + original_dcid.len + versions.len * 4;
    if (out.len < need) return error.BufferTooSmall;

    var offset: usize = 0;
    out[offset] = 0x80 | 0x40 | 0x2a;
    offset += 1;
    std.mem.writeInt(u32, out[offset..][0..4], 0, .big);
    offset += 4;

    out[offset] = @intCast(original_scid.len);
    offset += 1;
    @memcpy(out[offset .. offset + original_scid.len], original_scid);
    offset += original_scid.len;

    out[offset] = @intCast(original_dcid.len);
    offset += 1;
    @memcpy(out[offset .. offset + original_dcid.len], original_dcid);
    offset += original_dcid.len;

    for (versions) |version| {
        std.mem.writeInt(u32, out[offset..][0..4], version, .big);
        offset += 4;
    }

    return offset;
}

pub fn isSupportedVersion(version: u32) bool {
    return version == @intFromEnum(Version.v1) or version == @intFromEnum(Version.v2);
}

pub const InitialSecrets = struct {
    client: DirectionKeys,
    server: DirectionKeys,
};

pub const DirectionKeys = struct {
    secret: [32]u8,
    key: [16]u8,
    iv: [12]u8,
    hp: [16]u8,
};

pub const PacketKeys = struct {
    key: [16]u8,
    iv: [12]u8,
    hp: [16]u8,
};

pub const ProtectedLongPacketInput = struct {
    packet_type: LongPacketType,
    dcid: []const u8,
    scid: []const u8,
    packet_number: u64,
    keys: PacketKeys,
    plaintext: []const u8,
};

pub const ProtectedShortPacketInput = struct {
    dcid: []const u8,
    packet_number: u64,
    keys: PacketKeys,
    plaintext: []const u8,
};

pub const DecryptedInitial = struct {
    packet_number: u64,
    plaintext: []u8,
};

pub const ClientHelloInfo = struct {
    alpn: ?[]const u8 = null,
    server_name: ?[]const u8 = null,
    legacy_session_id: []const u8 = "",
    x25519_key_share: ?[32]u8 = null,
    supports_tls13: bool = false,
    supports_aes_128_gcm_sha256: bool = false,
    supports_ed25519: bool = false,
    has_quic_transport_parameters: bool = false,
};

const v1_initial_salt = [_]u8{
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
    0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
};

fn hkdfExpandLabel(
    key: [HkdfSha256.prk_length]u8,
    label: []const u8,
    context: []const u8,
    comptime len: usize,
) [len]u8 {
    const tls13 = "tls13 ";
    var buf: [2 + 1 + tls13.len + 64 + 1 + 64]u8 = undefined;
    std.mem.writeInt(u16, buf[0..2], len, .big);
    buf[2] = @intCast(tls13.len + label.len);
    @memcpy(buf[3..][0..tls13.len], tls13);
    var offset: usize = 3 + tls13.len;
    @memcpy(buf[offset..][0..label.len], label);
    offset += label.len;
    buf[offset] = @intCast(context.len);
    offset += 1;
    @memcpy(buf[offset..][0..context.len], context);
    offset += context.len;

    var out: [len]u8 = undefined;
    HkdfSha256.expand(&out, buf[0..offset], key);
    return out;
}

pub fn deriveInitialSecrets(dcid: []const u8) InitialSecrets {
    const initial_secret = HkdfSha256.extract(&v1_initial_salt, dcid);
    const client_secret = hkdfExpandLabel(initial_secret, "client in", "", 32);
    const server_secret = hkdfExpandLabel(initial_secret, "server in", "", 32);

    return .{
        .client = deriveDirectionKeys(client_secret),
        .server = deriveDirectionKeys(server_secret),
    };
}

fn deriveDirectionKeys(secret: [32]u8) DirectionKeys {
    return .{
        .secret = secret,
        .key = hkdfExpandLabel(secret, "quic key", "", 16),
        .iv = hkdfExpandLabel(secret, "quic iv", "", 12),
        .hp = hkdfExpandLabel(secret, "quic hp", "", 16),
    };
}

pub fn packetKeysFromInitialDirection(keys: DirectionKeys) PacketKeys {
    return .{
        .key = keys.key,
        .iv = keys.iv,
        .hp = keys.hp,
    };
}

pub fn decryptClientInitial(
    allocator: std.mem.Allocator,
    packet: []const u8,
) !DecryptedInitial {
    const parsed = try parseInitialHeader(packet);
    return decryptClientInitialWithOriginalDcid(allocator, packet, parsed.long.dcid.slice());
}

pub fn decryptClientInitialWithOriginalDcid(
    allocator: std.mem.Allocator,
    packet: []const u8,
    original_dcid: []const u8,
) !DecryptedInitial {
    const parsed = try parseInitialHeader(packet);
    if (parsed.long.version != @intFromEnum(Version.v1)) return error.UnsupportedVersion;

    const secrets = deriveInitialSecrets(original_dcid);
    return decryptProtectedLongPacketWithKeys(allocator, packet, packetKeysFromInitialDirection(secrets.client));
}

pub fn decryptProtectedLongPacketWithKeys(
    allocator: std.mem.Allocator,
    packet: []const u8,
    keys: PacketKeys,
) !DecryptedInitial {
    const parsed = try parseProtectedLongHeader(packet);
    const sample_offset = parsed.packet_number_offset + 4;
    if (packet.len < sample_offset + 16) return error.Truncated;
    const sample: *const [16]u8 = packet[sample_offset..][0..16];

    const aes = Aes128.initEnc(keys.hp);
    var mask: [16]u8 = undefined;
    aes.encrypt(&mask, sample);

    const first = packet[0] ^ (mask[0] & 0x0f);
    const pn_len = @as(usize, first & 0x03) + 1;
    if (packet.len < parsed.packet_number_offset + pn_len) return error.Truncated;

    const packet_end = parsed.packet_number_offset + @as(usize, @intCast(parsed.payload_len));
    if (packet.len < packet_end or packet_end < parsed.packet_number_offset + pn_len + Aes128Gcm.tag_length) {
        return error.Truncated;
    }

    var header = try allocator.alloc(u8, parsed.packet_number_offset + pn_len);
    defer allocator.free(header);
    @memcpy(header, packet[0..header.len]);
    header[0] = first;
    for (header[parsed.packet_number_offset..], 0..) |*b, i| {
        b.* ^= mask[i + 1];
    }

    const packet_number = decodePacketNumber(header[parsed.packet_number_offset..]);
    const ciphertext_start = parsed.packet_number_offset + pn_len;
    const tag_start = packet_end - Aes128Gcm.tag_length;
    const ciphertext = packet[ciphertext_start..tag_start];
    const tag: [Aes128Gcm.tag_length]u8 = packet[tag_start..packet_end][0..Aes128Gcm.tag_length].*;

    var nonce = keys.iv;
    applyPacketNumberToNonce(&nonce, packet_number);

    const plaintext = try allocator.alloc(u8, ciphertext.len);
    errdefer allocator.free(plaintext);
    try Aes128Gcm.decrypt(plaintext, ciphertext, tag, header, nonce, keys.key);

    return .{
        .packet_number = packet_number,
        .plaintext = plaintext,
    };
}

pub fn decryptProtectedShortPacketWithKeys(
    allocator: std.mem.Allocator,
    packet: []const u8,
    dcid_len: usize,
    keys: PacketKeys,
) !DecryptedInitial {
    if (packet.len < 1 + dcid_len + 4 + 16) return error.Truncated;
    if ((packet[0] & 0x80) != 0 or (packet[0] & 0x40) == 0) return error.InvalidShortHeader;

    const packet_number_offset = 1 + dcid_len;
    const sample_offset = packet_number_offset + 4;
    if (packet.len < sample_offset + 16) return error.Truncated;
    const sample: *const [16]u8 = packet[sample_offset..][0..16];

    const aes = Aes128.initEnc(keys.hp);
    var mask: [16]u8 = undefined;
    aes.encrypt(&mask, sample);

    const first = packet[0] ^ (mask[0] & 0x1f);
    const pn_len = @as(usize, first & 0x03) + 1;
    if (packet.len < packet_number_offset + pn_len + Aes128Gcm.tag_length) return error.Truncated;

    var header = try allocator.alloc(u8, packet_number_offset + pn_len);
    defer allocator.free(header);
    @memcpy(header, packet[0..header.len]);
    header[0] = first;
    for (header[packet_number_offset..], 0..) |*b, i| {
        b.* ^= mask[i + 1];
    }

    const packet_number = decodePacketNumber(header[packet_number_offset..]);
    const ciphertext_start = packet_number_offset + pn_len;
    const tag_start = packet.len - Aes128Gcm.tag_length;
    const ciphertext = packet[ciphertext_start..tag_start];
    const tag: [Aes128Gcm.tag_length]u8 = packet[tag_start..][0..Aes128Gcm.tag_length].*;

    var nonce = keys.iv;
    applyPacketNumberToNonce(&nonce, packet_number);

    const plaintext = try allocator.alloc(u8, ciphertext.len);
    errdefer allocator.free(plaintext);
    try Aes128Gcm.decrypt(plaintext, ciphertext, tag, header, nonce, keys.key);

    return .{
        .packet_number = packet_number,
        .plaintext = plaintext,
    };
}

pub fn buildProtectedLongPacket(
    allocator: std.mem.Allocator,
    input: ProtectedLongPacketInput,
) ![]u8 {
    if (input.dcid.len > 20 or input.scid.len > 20) return error.ConnectionIdTooLong;
    if (input.plaintext.len < 16) return error.PayloadTooSmallForHeaderProtection;

    const pn_len: usize = 4;
    const payload_len = pn_len + input.plaintext.len + Aes128Gcm.tag_length;

    var packet = std.ArrayListUnmanaged(u8).empty;
    errdefer packet.deinit(allocator);

    try packet.append(allocator, 0x80 | 0x40 | (@as(u8, @intFromEnum(input.packet_type)) << 4) | @as(u8, @intCast(pn_len - 1)));
    var version_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &version_buf, @intFromEnum(Version.v1), .big);
    try packet.appendSlice(allocator, &version_buf);
    try packet.append(allocator, @intCast(input.dcid.len));
    try packet.appendSlice(allocator, input.dcid);
    try packet.append(allocator, @intCast(input.scid.len));
    try packet.appendSlice(allocator, input.scid);
    if (input.packet_type == .initial) {
        try appendVarInt(allocator, &packet, 0);
    }
    try appendVarInt(allocator, &packet, payload_len);

    const pn_offset = packet.items.len;
    var pn_buf: [4]u8 = undefined;
    encodePacketNumber(&pn_buf, input.packet_number);
    try packet.appendSlice(allocator, &pn_buf);

    const header_len = packet.items.len;
    var nonce = input.keys.iv;
    applyPacketNumberToNonce(&nonce, input.packet_number);

    const ciphertext_start = packet.items.len;
    try packet.resize(allocator, packet.items.len + input.plaintext.len + Aes128Gcm.tag_length);
    const ciphertext = packet.items[ciphertext_start .. ciphertext_start + input.plaintext.len];
    const tag = packet.items[ciphertext_start + input.plaintext.len ..][0..Aes128Gcm.tag_length];
    Aes128Gcm.encrypt(ciphertext, tag, input.plaintext, packet.items[0..header_len], nonce, input.keys.key);

    const sample_offset = pn_offset + 4;
    if (packet.items.len < sample_offset + 16) return error.PayloadTooSmallForHeaderProtection;
    const sample: *const [16]u8 = packet.items[sample_offset..][0..16];
    const aes = Aes128.initEnc(input.keys.hp);
    var mask: [16]u8 = undefined;
    aes.encrypt(&mask, sample);
    packet.items[0] ^= mask[0] & 0x0f;
    for (packet.items[pn_offset .. pn_offset + pn_len], 0..) |*b, i| {
        b.* ^= mask[i + 1];
    }

    return packet.toOwnedSlice(allocator);
}

pub fn buildProtectedShortPacket(
    allocator: std.mem.Allocator,
    input: ProtectedShortPacketInput,
) ![]u8 {
    if (input.dcid.len > 20) return error.ConnectionIdTooLong;
    if (input.plaintext.len < 16) return error.PayloadTooSmallForHeaderProtection;

    const pn_len: usize = 4;

    var packet = std.ArrayListUnmanaged(u8).empty;
    errdefer packet.deinit(allocator);

    try packet.append(allocator, 0x40 | @as(u8, @intCast(pn_len - 1)));
    try packet.appendSlice(allocator, input.dcid);

    const pn_offset = packet.items.len;
    var pn_buf: [4]u8 = undefined;
    encodePacketNumber(&pn_buf, input.packet_number);
    try packet.appendSlice(allocator, &pn_buf);

    const header_len = packet.items.len;
    var nonce = input.keys.iv;
    applyPacketNumberToNonce(&nonce, input.packet_number);

    const ciphertext_start = packet.items.len;
    try packet.resize(allocator, packet.items.len + input.plaintext.len + Aes128Gcm.tag_length);
    const ciphertext = packet.items[ciphertext_start .. ciphertext_start + input.plaintext.len];
    const tag = packet.items[ciphertext_start + input.plaintext.len ..][0..Aes128Gcm.tag_length];
    Aes128Gcm.encrypt(ciphertext, tag, input.plaintext, packet.items[0..header_len], nonce, input.keys.key);

    const sample_offset = pn_offset + 4;
    if (packet.items.len < sample_offset + 16) return error.PayloadTooSmallForHeaderProtection;
    const sample: *const [16]u8 = packet.items[sample_offset..][0..16];
    const aes = Aes128.initEnc(input.keys.hp);
    var mask: [16]u8 = undefined;
    aes.encrypt(&mask, sample);
    packet.items[0] ^= mask[0] & 0x1f;
    for (packet.items[pn_offset .. pn_offset + pn_len], 0..) |*b, i| {
        b.* ^= mask[i + 1];
    }

    return packet.toOwnedSlice(allocator);
}

fn decodePacketNumber(bytes: []const u8) u64 {
    var n: u64 = 0;
    for (bytes) |b| {
        n = (n << 8) | b;
    }
    return n;
}

fn encodePacketNumber(out: []u8, packet_number: u64) void {
    var n = packet_number;
    var i = out.len;
    while (i > 0) {
        i -= 1;
        out[i] = @intCast(n & 0xff);
        n >>= 8;
    }
}

fn applyPacketNumberToNonce(nonce: *[12]u8, packet_number: u64) void {
    var pn_buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &pn_buf, packet_number, .big);
    for (pn_buf, 0..) |b, i| {
        nonce[4 + i] ^= b;
    }
}

pub fn extractCryptoData(
    allocator: std.mem.Allocator,
    plaintext: []const u8,
) ![]u8 {
    var crypto = std.ArrayListUnmanaged(u8).empty;
    errdefer crypto.deinit(allocator);

    try appendCryptoData(allocator, plaintext, &crypto);
    return crypto.toOwnedSlice(allocator);
}

pub fn appendCryptoData(
    allocator: std.mem.Allocator,
    plaintext: []const u8,
    crypto: *std.ArrayListUnmanaged(u8),
) !void {
    var offset: usize = 0;
    while (offset < plaintext.len) {
        const frame_type_vi = try h3.decodeVarInt(plaintext[offset..]);
        offset += frame_type_vi.len;
        const frame_type = frame_type_vi.value;

        switch (frame_type) {
            0x00 => {},
            0x01 => {},
            0x02, 0x03 => {
                const largest = try h3.decodeVarInt(plaintext[offset..]);
                offset += largest.len;
                const delay = try h3.decodeVarInt(plaintext[offset..]);
                offset += delay.len;
                const range_count = try h3.decodeVarInt(plaintext[offset..]);
                offset += range_count.len;
                const first_range = try h3.decodeVarInt(plaintext[offset..]);
                offset += first_range.len;
                var i: u64 = 0;
                while (i < range_count.value) : (i += 1) {
                    const gap = try h3.decodeVarInt(plaintext[offset..]);
                    offset += gap.len;
                    const range = try h3.decodeVarInt(plaintext[offset..]);
                    offset += range.len;
                }
                if (frame_type == 0x03) {
                    const ect0 = try h3.decodeVarInt(plaintext[offset..]);
                    offset += ect0.len;
                    const ect1 = try h3.decodeVarInt(plaintext[offset..]);
                    offset += ect1.len;
                    const ce = try h3.decodeVarInt(plaintext[offset..]);
                    offset += ce.len;
                }
            },
            0x06 => {
                const crypto_offset = try h3.decodeVarInt(plaintext[offset..]);
                offset += crypto_offset.len;
                const len = try h3.decodeVarInt(plaintext[offset..]);
                offset += len.len;
                const end = offset + @as(usize, @intCast(len.value));
                if (plaintext.len < end) return error.Truncated;
                const crypto_start = @as(usize, @intCast(crypto_offset.value));
                if (crypto_start > crypto.items.len) return error.CryptoGap;
                const overlap = crypto.items.len - crypto_start;
                if (overlap < len.value) {
                    const append_start = offset + overlap;
                    try crypto.appendSlice(allocator, plaintext[append_start..end]);
                }
                offset = end;
            },
            0x08...0x0f => {
                const stream_id = try h3.decodeVarInt(plaintext[offset..]);
                offset += stream_id.len;
                if ((frame_type & 0x04) != 0) {
                    const stream_offset = try h3.decodeVarInt(plaintext[offset..]);
                    offset += stream_offset.len;
                }
                const data_len = if ((frame_type & 0x02) != 0) len: {
                    const len = try h3.decodeVarInt(plaintext[offset..]);
                    offset += len.len;
                    break :len @as(usize, @intCast(len.value));
                } else plaintext.len - offset;
                if (plaintext.len < offset + data_len) return error.Truncated;
                offset += data_len;
            },
            0x10, 0x12, 0x13, 0x14, 0x16, 0x17, 0x19 => {
                const ignored = try h3.decodeVarInt(plaintext[offset..]);
                offset += ignored.len;
            },
            0x11, 0x15 => {
                const stream_id = try h3.decodeVarInt(plaintext[offset..]);
                offset += stream_id.len;
                const value = try h3.decodeVarInt(plaintext[offset..]);
                offset += value.len;
            },
            0x18 => {
                const sequence = try h3.decodeVarInt(plaintext[offset..]);
                offset += sequence.len;
                const retire_prior = try h3.decodeVarInt(plaintext[offset..]);
                offset += retire_prior.len;
                if (plaintext.len < offset + 1) return error.Truncated;
                const cid_len = plaintext[offset];
                offset += 1;
                if (plaintext.len < offset + cid_len + 16) return error.Truncated;
                offset += cid_len + 16;
            },
            0x1a, 0x1b => {
                if (plaintext.len < offset + 8) return error.Truncated;
                offset += 8;
            },
            0x1c, 0x1d => {
                const error_code = try h3.decodeVarInt(plaintext[offset..]);
                offset += error_code.len;
                if (frame_type == 0x1c) {
                    const failed_frame = try h3.decodeVarInt(plaintext[offset..]);
                    offset += failed_frame.len;
                }
                const reason_len = try h3.decodeVarInt(plaintext[offset..]);
                offset += reason_len.len + @as(usize, @intCast(reason_len.value));
                if (offset > plaintext.len) return error.Truncated;
            },
            0x1e => {},
            else => return error.UnsupportedFrame,
        }
    }
}

pub fn buildAckFrame(
    allocator: std.mem.Allocator,
    largest_acknowledged: u64,
    ack_delay: u64,
) ![]u8 {
    var out = std.ArrayListUnmanaged(u8).empty;
    errdefer out.deinit(allocator);
    try appendVarInt(allocator, &out, 0x02);
    try appendVarInt(allocator, &out, largest_acknowledged);
    try appendVarInt(allocator, &out, ack_delay);
    try appendVarInt(allocator, &out, 0);
    try appendVarInt(allocator, &out, 0);
    return out.toOwnedSlice(allocator);
}

pub fn buildCryptoFrame(
    allocator: std.mem.Allocator,
    crypto_offset: u64,
    crypto_data: []const u8,
) ![]u8 {
    var out = std.ArrayListUnmanaged(u8).empty;
    errdefer out.deinit(allocator);
    try appendVarInt(allocator, &out, 0x06);
    try appendVarInt(allocator, &out, crypto_offset);
    try appendVarInt(allocator, &out, crypto_data.len);
    try out.appendSlice(allocator, crypto_data);
    return out.toOwnedSlice(allocator);
}

pub fn buildStreamFrame(
    allocator: std.mem.Allocator,
    stream_id: u64,
    data: []const u8,
    fin: bool,
) ![]u8 {
    return buildStreamFrameAt(allocator, stream_id, 0, data, fin);
}

pub fn buildStreamFrameAt(
    allocator: std.mem.Allocator,
    stream_id: u64,
    stream_offset: u64,
    data: []const u8,
    fin: bool,
) ![]u8 {
    var out = std.ArrayListUnmanaged(u8).empty;
    errdefer out.deinit(allocator);
    const has_offset = stream_offset != 0;
    try appendVarInt(allocator, &out, 0x08 | 0x02 | (if (has_offset) @as(u64, 0x04) else @as(u64, 0)) | if (fin) @as(u64, 0x01) else @as(u64, 0));
    try appendVarInt(allocator, &out, stream_id);
    if (has_offset) {
        try appendVarInt(allocator, &out, stream_offset);
    }
    try appendVarInt(allocator, &out, data.len);
    try out.appendSlice(allocator, data);
    return out.toOwnedSlice(allocator);
}

pub fn buildDefaultTransportParameters(
    allocator: std.mem.Allocator,
    original_destination_connection_id: []const u8,
    initial_source_connection_id: []const u8,
) ![]u8 {
    var out = std.ArrayListUnmanaged(u8).empty;
    errdefer out.deinit(allocator);

    try appendBytesTransportParameter(allocator, &out, 0x00, original_destination_connection_id); // original_destination_connection_id
    try appendTransportParameter(allocator, &out, 0x01, 30_000); // max_idle_timeout
    try appendTransportParameter(allocator, &out, 0x04, 1_048_576); // initial_max_data
    try appendTransportParameter(allocator, &out, 0x05, 262_144); // initial_max_stream_data_bidi_local
    try appendTransportParameter(allocator, &out, 0x06, 262_144); // initial_max_stream_data_bidi_remote
    try appendTransportParameter(allocator, &out, 0x07, 262_144); // initial_max_stream_data_uni
    try appendTransportParameter(allocator, &out, 0x08, 64); // initial_max_streams_bidi
    try appendTransportParameter(allocator, &out, 0x09, 16); // initial_max_streams_uni
    try appendTransportParameter(allocator, &out, 0x0e, 2); // active_connection_id_limit
    try appendBytesTransportParameter(allocator, &out, 0x0f, initial_source_connection_id); // initial_source_connection_id

    return out.toOwnedSlice(allocator);
}

fn appendTransportParameter(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(u8),
    id: u64,
    value: u64,
) !void {
    var value_buf: [8]u8 = undefined;
    const value_len = try h3.encodeVarInt(&value_buf, value);
    try appendVarInt(allocator, out, id);
    try appendVarInt(allocator, out, value_len);
    try out.appendSlice(allocator, value_buf[0..value_len]);
}

fn appendBytesTransportParameter(
    allocator: std.mem.Allocator,
    out: *std.ArrayListUnmanaged(u8),
    id: u64,
    value: []const u8,
) !void {
    try appendVarInt(allocator, out, id);
    try appendVarInt(allocator, out, value.len);
    try out.appendSlice(allocator, value);
}

pub fn parseClientHello(crypto_data: []const u8) !ClientHelloInfo {
    if (crypto_data.len < 4 or crypto_data[0] != 0x01) return error.NotClientHello;
    const handshake_len = (@as(usize, crypto_data[1]) << 16) |
        (@as(usize, crypto_data[2]) << 8) |
        @as(usize, crypto_data[3]);
    if (crypto_data.len < 4 + handshake_len) return error.Truncated;

    const body = crypto_data[4 .. 4 + handshake_len];
    var offset: usize = 0;
    if (body.len < 34) return error.InvalidClientHello;
    offset += 2; // legacy_version
    offset += 32; // random

    var info = ClientHelloInfo{};

    const session_len = body[offset];
    offset += 1;
    if (body.len < offset + session_len + 2) return error.Truncated;
    info.legacy_session_id = body[offset .. offset + session_len];
    offset += session_len;

    const cipher_len = std.mem.readInt(u16, body[offset..][0..2], .big);
    offset += 2;
    if (body.len < offset + cipher_len + 1) return error.Truncated;
    var cipher_offset = offset;
    while (cipher_offset + 2 <= offset + cipher_len) : (cipher_offset += 2) {
        const suite = std.mem.readInt(u16, body[cipher_offset..][0..2], .big);
        if (suite == 0x1301) info.supports_aes_128_gcm_sha256 = true;
    }
    offset += cipher_len;

    const compression_len = body[offset];
    offset += 1;
    if (body.len < offset + compression_len) return error.Truncated;
    offset += compression_len;

    if (body.len < offset + 2) return info;
    const extensions_len = std.mem.readInt(u16, body[offset..][0..2], .big);
    offset += 2;
    if (body.len < offset + extensions_len) return error.Truncated;
    const extensions_end = offset + extensions_len;

    while (offset + 4 <= extensions_end) {
        const ext_type = std.mem.readInt(u16, body[offset..][0..2], .big);
        const ext_len = std.mem.readInt(u16, body[offset + 2 ..][0..2], .big);
        offset += 4;
        if (extensions_end < offset + ext_len) return error.Truncated;
        const ext = body[offset .. offset + ext_len];
        offset += ext_len;

        switch (ext_type) {
            0x0000 => info.server_name = parseSni(ext) catch info.server_name,
            0x000d => info.supports_ed25519 = parseSignatureSchemes(ext) catch info.supports_ed25519,
            0x0010 => info.alpn = parseAlpn(ext) catch info.alpn,
            0x002b => info.supports_tls13 = parseSupportedVersions(ext) catch info.supports_tls13,
            0x0033 => info.x25519_key_share = parseX25519KeyShare(ext) catch info.x25519_key_share,
            0x0039 => info.has_quic_transport_parameters = true,
            else => {},
        }
    }

    return info;
}

fn parseAlpn(ext: []const u8) ![]const u8 {
    if (ext.len < 3) return error.InvalidClientHello;
    const list_len = std.mem.readInt(u16, ext[0..2], .big);
    if (ext.len < 2 + list_len) return error.Truncated;
    const name_len = ext[2];
    if (ext.len < 3 + name_len) return error.Truncated;
    return ext[3 .. 3 + name_len];
}

fn parseSni(ext: []const u8) ![]const u8 {
    if (ext.len < 5) return error.InvalidClientHello;
    const list_len = std.mem.readInt(u16, ext[0..2], .big);
    if (ext.len < 2 + list_len or ext[2] != 0) return error.InvalidClientHello;
    const name_len = std.mem.readInt(u16, ext[3..5], .big);
    if (ext.len < 5 + name_len) return error.Truncated;
    return ext[5 .. 5 + name_len];
}

fn parseSupportedVersions(ext: []const u8) !bool {
    if (ext.len < 1) return error.InvalidClientHello;
    const list_len = ext[0];
    if (ext.len < 1 + list_len or list_len % 2 != 0) return error.Truncated;

    var offset: usize = 1;
    const end = 1 + @as(usize, list_len);
    while (offset + 2 <= end) : (offset += 2) {
        const version = std.mem.readInt(u16, ext[offset..][0..2], .big);
        if (version == 0x0304) return true;
    }
    return false;
}

fn parseSignatureSchemes(ext: []const u8) !bool {
    if (ext.len < 2) return error.InvalidClientHello;
    const list_len = std.mem.readInt(u16, ext[0..2], .big);
    if (ext.len < 2 + list_len or list_len % 2 != 0) return error.Truncated;

    var offset: usize = 2;
    const end = 2 + @as(usize, list_len);
    while (offset + 2 <= end) : (offset += 2) {
        const scheme = std.mem.readInt(u16, ext[offset..][0..2], .big);
        if (scheme == 0x0807) return true;
    }
    return false;
}

fn parseX25519KeyShare(ext: []const u8) !?[32]u8 {
    if (ext.len < 2) return error.InvalidClientHello;
    const list_len = std.mem.readInt(u16, ext[0..2], .big);
    if (ext.len < 2 + list_len) return error.Truncated;

    var offset: usize = 2;
    const end = 2 + @as(usize, list_len);
    while (offset + 4 <= end) {
        const group = std.mem.readInt(u16, ext[offset..][0..2], .big);
        const key_len = std.mem.readInt(u16, ext[offset + 2 ..][0..2], .big);
        offset += 4;
        if (end < offset + key_len) return error.Truncated;
        if (group == 0x001d and key_len == 32) {
            return ext[offset..][0..32].*;
        }
        offset += key_len;
    }
    return null;
}

fn appendVarInt(allocator: std.mem.Allocator, out: *std.ArrayListUnmanaged(u8), value: u64) !void {
    var buf: [8]u8 = undefined;
    const len = try h3.encodeVarInt(&buf, value);
    try out.appendSlice(allocator, buf[0..len]);
}

fn appendU16(allocator: std.mem.Allocator, out: *std.ArrayListUnmanaged(u8), value: u16) !void {
    var buf: [2]u8 = undefined;
    std.mem.writeInt(u16, &buf, value, .big);
    try out.appendSlice(allocator, &buf);
}

fn appendU24HandshakeHeader(allocator: std.mem.Allocator, out: *std.ArrayListUnmanaged(u8), kind: u8, len: usize) !void {
    if (len > 0x00ff_ffff) return error.HandshakeMessageTooLarge;
    try out.append(allocator, kind);
    try out.append(allocator, @intCast((len >> 16) & 0xff));
    try out.append(allocator, @intCast((len >> 8) & 0xff));
    try out.append(allocator, @intCast(len & 0xff));
}

fn appendTlsExtension(allocator: std.mem.Allocator, out: *std.ArrayListUnmanaged(u8), extension_type: u16, payload: []const u8) !void {
    try appendU16(allocator, out, extension_type);
    try appendU16(allocator, out, @intCast(payload.len));
    try out.appendSlice(allocator, payload);
}

test "parse QUIC v1 initial long header" {
    var packet: [64]u8 = undefined;
    var offset: usize = 0;
    packet[offset] = 0xc3;
    offset += 1;
    std.mem.writeInt(u32, packet[offset..][0..4], @intFromEnum(Version.v1), .big);
    offset += 4;
    packet[offset] = 4;
    offset += 1;
    @memcpy(packet[offset..][0..4], "dcid");
    offset += 4;
    packet[offset] = 4;
    offset += 1;
    @memcpy(packet[offset..][0..4], "scid");
    offset += 4;
    packet[offset] = 0;
    offset += 1;
    packet[offset] = 4;
    offset += 1;
    packet[offset] = 0xaa;
    packet[offset + 1] = 0xbb;
    packet[offset + 2] = 0xcc;
    packet[offset + 3] = 0xdd;
    offset += 4;

    const parsed = try parseInitialHeader(packet[0..offset]);
    try std.testing.expectEqual(@as(u32, @intFromEnum(Version.v1)), parsed.long.version);
    try std.testing.expectEqual(LongPacketType.initial, parsed.long.packet_type);
    try std.testing.expectEqualStrings("dcid", parsed.long.dcid.slice());
    try std.testing.expectEqualStrings("scid", parsed.long.scid.slice());
    try std.testing.expectEqual(@as(usize, 4), parsed.packet_number_len);
}

test "parse h3 ClientHello capabilities" {
    const allocator = std.testing.allocator;
    const client_key = [_]u8{0x55} ** 32;

    var extensions = std.ArrayListUnmanaged(u8).empty;
    defer extensions.deinit(allocator);

    var alpn = std.ArrayListUnmanaged(u8).empty;
    defer alpn.deinit(allocator);
    try appendU16(allocator, &alpn, 3);
    try alpn.append(allocator, 2);
    try alpn.appendSlice(allocator, "h3");
    try appendTlsExtension(allocator, &extensions, 0x0010, alpn.items);

    var supported_versions = [_]u8{ 2, 0x03, 0x04 };
    try appendTlsExtension(allocator, &extensions, 0x002b, &supported_versions);

    var signature_schemes = std.ArrayListUnmanaged(u8).empty;
    defer signature_schemes.deinit(allocator);
    try appendU16(allocator, &signature_schemes, 2);
    try appendU16(allocator, &signature_schemes, 0x0807);
    try appendTlsExtension(allocator, &extensions, 0x000d, signature_schemes.items);

    var key_share = std.ArrayListUnmanaged(u8).empty;
    defer key_share.deinit(allocator);
    try appendU16(allocator, &key_share, 36);
    try appendU16(allocator, &key_share, 0x001d);
    try appendU16(allocator, &key_share, 32);
    try key_share.appendSlice(allocator, &client_key);
    try appendTlsExtension(allocator, &extensions, 0x0033, key_share.items);

    try appendTlsExtension(allocator, &extensions, 0x0039, "");

    var body = std.ArrayListUnmanaged(u8).empty;
    defer body.deinit(allocator);
    try appendU16(allocator, &body, 0x0303);
    try body.appendNTimes(allocator, 0x11, 32);
    try body.append(allocator, 3);
    try body.appendSlice(allocator, "sid");
    try appendU16(allocator, &body, 2);
    try appendU16(allocator, &body, 0x1301);
    try body.append(allocator, 1);
    try body.append(allocator, 0);
    try appendU16(allocator, &body, @intCast(extensions.items.len));
    try body.appendSlice(allocator, extensions.items);

    var hello = std.ArrayListUnmanaged(u8).empty;
    defer hello.deinit(allocator);
    try appendU24HandshakeHeader(allocator, &hello, 0x01, body.items.len);
    try hello.appendSlice(allocator, body.items);

    const parsed = try parseClientHello(hello.items);
    try std.testing.expectEqualStrings("h3", parsed.alpn.?);
    try std.testing.expectEqualStrings("sid", parsed.legacy_session_id);
    try std.testing.expectEqualSlices(u8, &client_key, &parsed.x25519_key_share.?);
    try std.testing.expect(parsed.supports_tls13);
    try std.testing.expect(parsed.supports_aes_128_gcm_sha256);
    try std.testing.expect(parsed.supports_ed25519);
    try std.testing.expect(parsed.has_quic_transport_parameters);
}

test "reassembles CRYPTO frames across packets" {
    const allocator = std.testing.allocator;
    const first = try buildCryptoFrame(allocator, 0, "hello ");
    defer allocator.free(first);
    const second = try buildCryptoFrame(allocator, 6, "world");
    defer allocator.free(second);

    var crypto = std.ArrayListUnmanaged(u8).empty;
    defer crypto.deinit(allocator);
    try appendCryptoData(allocator, first, &crypto);
    try appendCryptoData(allocator, first, &crypto);
    try appendCryptoData(allocator, second, &crypto);

    try std.testing.expectEqualStrings("hello world", crypto.items);
}

test "version negotiation swaps connection IDs" {
    var out: [64]u8 = undefined;
    const len = try encodeVersionNegotiation(&out, "client-dcid", "client-scid", &.{@intFromEnum(Version.v1)});
    const parsed = try parseLongHeader(out[0..len]);

    try std.testing.expectEqual(@as(u32, 0), parsed.version);
    try std.testing.expectEqualStrings("client-scid", parsed.dcid.slice());
    try std.testing.expectEqualStrings("client-dcid", parsed.scid.slice());
}

test "decrypt QUIC v1 initial payload generated with native keys" {
    const allocator = std.testing.allocator;
    const dcid = "\x83\x94\xc8\xf0\x3e\x51\x57\x08";
    const scid = "scid";
    const packet_number: u64 = 1;
    const pn_len: usize = 4;

    var tls_bytes: [72]u8 = undefined;
    @memset(&tls_bytes, 0x42);

    var plaintext = std.ArrayListUnmanaged(u8).empty;
    defer plaintext.deinit(allocator);
    try appendVarInt(allocator, &plaintext, 0x06);
    try appendVarInt(allocator, &plaintext, 0);
    try appendVarInt(allocator, &plaintext, tls_bytes.len);
    try plaintext.appendSlice(allocator, &tls_bytes);

    const secrets = deriveInitialSecrets(dcid);
    const keys = secrets.client;
    const payload_len = pn_len + plaintext.items.len + Aes128Gcm.tag_length;

    var packet = std.ArrayListUnmanaged(u8).empty;
    defer packet.deinit(allocator);
    try packet.append(allocator, 0xc0 | @as(u8, @intCast(pn_len - 1)));
    var version_buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &version_buf, @intFromEnum(Version.v1), .big);
    try packet.appendSlice(allocator, &version_buf);
    try packet.append(allocator, dcid.len);
    try packet.appendSlice(allocator, dcid);
    try packet.append(allocator, scid.len);
    try packet.appendSlice(allocator, scid);
    try appendVarInt(allocator, &packet, 0);
    try appendVarInt(allocator, &packet, payload_len);

    const pn_offset = packet.items.len;
    var pn_buf: [4]u8 = undefined;
    encodePacketNumber(&pn_buf, packet_number);
    try packet.appendSlice(allocator, &pn_buf);

    const header_len = packet.items.len;
    var nonce = keys.iv;
    applyPacketNumberToNonce(&nonce, packet_number);

    const ciphertext_start = packet.items.len;
    try packet.resize(allocator, packet.items.len + plaintext.items.len + Aes128Gcm.tag_length);
    const ciphertext = packet.items[ciphertext_start .. ciphertext_start + plaintext.items.len];
    const tag = packet.items[ciphertext_start + plaintext.items.len ..][0..Aes128Gcm.tag_length];
    Aes128Gcm.encrypt(ciphertext, tag, plaintext.items, packet.items[0..header_len], nonce, keys.key);

    const sample_offset = pn_offset + 4;
    const sample: *const [16]u8 = packet.items[sample_offset..][0..16];
    const aes = Aes128.initEnc(keys.hp);
    var mask: [16]u8 = undefined;
    aes.encrypt(&mask, sample);
    packet.items[0] ^= mask[0] & 0x0f;
    for (packet.items[pn_offset .. pn_offset + pn_len], 0..) |*b, i| {
        b.* ^= mask[i + 1];
    }

    const decrypted = try decryptClientInitial(allocator, packet.items);
    defer allocator.free(decrypted.plaintext);

    try std.testing.expectEqual(packet_number, decrypted.packet_number);
    try std.testing.expectEqualSlices(u8, plaintext.items, decrypted.plaintext);
}

test "build protected server Initial packet with ACK and CRYPTO frames" {
    const allocator = std.testing.allocator;
    const original_dcid = "\x83\x94\xc8\xf0\x3e\x51\x57\x08";
    const client_scid = "client";
    const server_scid = "server";
    const server_crypto = "server hello bytes that are comfortably longer than header protection sample";

    const ack = try buildAckFrame(allocator, 1, 0);
    defer allocator.free(ack);
    const crypto = try buildCryptoFrame(allocator, 0, server_crypto);
    defer allocator.free(crypto);

    var plaintext = std.ArrayListUnmanaged(u8).empty;
    defer plaintext.deinit(allocator);
    try plaintext.appendSlice(allocator, ack);
    try plaintext.appendSlice(allocator, crypto);

    const secrets = deriveInitialSecrets(original_dcid);
    const packet = try buildProtectedLongPacket(allocator, .{
        .packet_type = .initial,
        .dcid = client_scid,
        .scid = server_scid,
        .packet_number = 0,
        .keys = packetKeysFromInitialDirection(secrets.server),
        .plaintext = plaintext.items,
    });
    defer allocator.free(packet);

    const parsed = try parseInitialHeader(packet);
    try std.testing.expectEqualStrings(client_scid, parsed.long.dcid.slice());
    try std.testing.expectEqualStrings(server_scid, parsed.long.scid.slice());

    const decrypted = try decryptProtectedLongPacketWithKeys(allocator, packet, packetKeysFromInitialDirection(secrets.server));
    defer allocator.free(decrypted.plaintext);
    try std.testing.expectEqual(@as(u64, 0), decrypted.packet_number);
    try std.testing.expectEqualSlices(u8, plaintext.items, decrypted.plaintext);

    const extracted = try extractCryptoData(allocator, decrypted.plaintext);
    defer allocator.free(extracted);
    try std.testing.expectEqualSlices(u8, server_crypto, extracted);
}

test "build protected Handshake packet with CRYPTO frame" {
    const allocator = std.testing.allocator;
    const keys = PacketKeys{
        .key = [_]u8{0x10} ** 16,
        .iv = [_]u8{0x20} ** 12,
        .hp = [_]u8{0x30} ** 16,
    };
    const handshake_crypto = "encrypted extensions bytes for the handshake encryption level";
    const crypto = try buildCryptoFrame(allocator, 0, handshake_crypto);
    defer allocator.free(crypto);

    const packet = try buildProtectedLongPacket(allocator, .{
        .packet_type = .handshake,
        .dcid = "client",
        .scid = "server",
        .packet_number = 3,
        .keys = keys,
        .plaintext = crypto,
    });
    defer allocator.free(packet);

    const parsed = try parseProtectedLongHeader(packet);
    try std.testing.expectEqual(LongPacketType.handshake, parsed.long.packet_type);

    const decrypted = try decryptProtectedLongPacketWithKeys(allocator, packet, keys);
    defer allocator.free(decrypted.plaintext);
    try std.testing.expectEqual(@as(u64, 3), decrypted.packet_number);

    const extracted = try extractCryptoData(allocator, decrypted.plaintext);
    defer allocator.free(extracted);
    try std.testing.expectEqualSlices(u8, handshake_crypto, extracted);
}

test "build protected 1-RTT short packet with STREAM frame" {
    const allocator = std.testing.allocator;
    const keys = PacketKeys{
        .key = [_]u8{0x44} ** 16,
        .iv = [_]u8{0x55} ** 12,
        .hp = [_]u8{0x66} ** 16,
    };
    const stream = try buildStreamFrame(allocator, 0, "HTTP/3 payload bytes", true);
    defer allocator.free(stream);

    const packet = try buildProtectedShortPacket(allocator, .{
        .dcid = "clientid",
        .packet_number = 9,
        .keys = keys,
        .plaintext = stream,
    });
    defer allocator.free(packet);

    const decrypted = try decryptProtectedShortPacketWithKeys(allocator, packet, "clientid".len, keys);
    defer allocator.free(decrypted.plaintext);
    try std.testing.expectEqual(@as(u64, 9), decrypted.packet_number);
    try std.testing.expectEqualSlices(u8, stream, decrypted.plaintext);
}

test "build STREAM frame with explicit offset" {
    const allocator = std.testing.allocator;
    const frame = try buildStreamFrameAt(allocator, 0, 300, "abc", true);
    defer allocator.free(frame);

    var offset: usize = 0;
    const frame_type = try h3.decodeVarInt(frame[offset..]);
    offset += frame_type.len;
    try std.testing.expectEqual(@as(u64, 0x0f), frame_type.value);

    const stream_id = try h3.decodeVarInt(frame[offset..]);
    offset += stream_id.len;
    try std.testing.expectEqual(@as(u64, 0), stream_id.value);

    const stream_offset = try h3.decodeVarInt(frame[offset..]);
    offset += stream_offset.len;
    try std.testing.expectEqual(@as(u64, 300), stream_offset.value);

    const len = try h3.decodeVarInt(frame[offset..]);
    offset += len.len;
    try std.testing.expectEqual(@as(u64, 3), len.value);
    try std.testing.expectEqualSlices(u8, "abc", frame[offset..]);
}
