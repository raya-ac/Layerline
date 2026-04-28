const std = @import("std");

const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;
pub const X25519 = std.crypto.dh.X25519;

pub const CipherSuite = enum(u16) {
    tls_aes_128_gcm_sha256 = 0x1301,
};

pub const NamedGroup = enum(u16) {
    x25519 = 0x001d,
};

pub const SignatureScheme = enum(u16) {
    ed25519 = 0x0807,
};

pub const ServerHelloInput = struct {
    legacy_session_id: []const u8,
    random: [32]u8,
    x25519_public_key: [32]u8,
};

pub const TrafficSecrets = struct {
    handshake_secret: [32]u8,
    client_handshake_traffic_secret: [32]u8,
    server_handshake_traffic_secret: [32]u8,
    client_finished_key: [32]u8,
    server_finished_key: [32]u8,
};

pub const QuicPacketKeys = struct {
    key: [16]u8,
    iv: [12]u8,
    hp: [16]u8,
};

pub fn buildServerHello(allocator: std.mem.Allocator, input: ServerHelloInput) ![]u8 {
    if (input.legacy_session_id.len > 32) return error.InvalidSessionId;

    var body = std.ArrayListUnmanaged(u8).empty;
    defer body.deinit(allocator);

    try appendU16(allocator, &body, 0x0303);
    try body.appendSlice(allocator, &input.random);
    try body.append(allocator, @intCast(input.legacy_session_id.len));
    try body.appendSlice(allocator, input.legacy_session_id);
    try appendU16(allocator, &body, @intFromEnum(CipherSuite.tls_aes_128_gcm_sha256));
    try body.append(allocator, 0);

    var extensions = std.ArrayListUnmanaged(u8).empty;
    defer extensions.deinit(allocator);

    var supported_versions_payload = [_]u8{ 0x03, 0x04 };
    try appendExtension(allocator, &extensions, 0x002b, &supported_versions_payload);

    var key_share_payload = std.ArrayListUnmanaged(u8).empty;
    defer key_share_payload.deinit(allocator);
    try appendU16(allocator, &key_share_payload, @intFromEnum(NamedGroup.x25519));
    try appendU16(allocator, &key_share_payload, input.x25519_public_key.len);
    try key_share_payload.appendSlice(allocator, &input.x25519_public_key);
    try appendExtension(allocator, &extensions, 0x0033, key_share_payload.items);

    try appendU16(allocator, &body, extensions.items.len);
    try body.appendSlice(allocator, extensions.items);

    var out = std.ArrayListUnmanaged(u8).empty;
    errdefer out.deinit(allocator);
    try appendHandshakeHeader(allocator, &out, 0x02, body.items.len);
    try out.appendSlice(allocator, body.items);
    return out.toOwnedSlice(allocator);
}

pub fn transcriptHash(messages: []const []const u8) [32]u8 {
    var hasher = Sha256.init(.{});
    for (messages) |message| {
        hasher.update(message);
    }
    return hasher.finalResult();
}

pub fn deriveTrafficSecrets(shared_secret: [32]u8, transcript_hash: [32]u8) TrafficSecrets {
    const zero = [_]u8{0} ** 32;
    const early_secret = HkdfSha256.extract(&zero, "");
    const empty_hash = hashBytes("");
    const derived = hkdfExpandLabel(early_secret, "derived", &empty_hash, 32);
    const handshake_secret = HkdfSha256.extract(&derived, &shared_secret);
    const client_hs = hkdfExpandLabel(handshake_secret, "c hs traffic", &transcript_hash, 32);
    const server_hs = hkdfExpandLabel(handshake_secret, "s hs traffic", &transcript_hash, 32);

    return .{
        .handshake_secret = handshake_secret,
        .client_handshake_traffic_secret = client_hs,
        .server_handshake_traffic_secret = server_hs,
        .client_finished_key = hkdfExpandLabel(client_hs, "finished", "", 32),
        .server_finished_key = hkdfExpandLabel(server_hs, "finished", "", 32),
    };
}

pub fn deriveQuicPacketKeys(traffic_secret: [32]u8) QuicPacketKeys {
    return .{
        .key = hkdfExpandLabel(traffic_secret, "quic key", "", Aes128Gcm.key_length),
        .iv = hkdfExpandLabel(traffic_secret, "quic iv", "", 12),
        .hp = hkdfExpandLabel(traffic_secret, "quic hp", "", 16),
    };
}

pub fn finishedVerifyData(finished_key: [32]u8, transcript_hash_value: [32]u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.auth.hmac.sha2.HmacSha256.create(&out, &transcript_hash_value, &finished_key);
    return out;
}

fn hashBytes(bytes: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    Sha256.hash(bytes, &out, .{});
    return out;
}

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

fn appendHandshakeHeader(allocator: std.mem.Allocator, out: *std.ArrayListUnmanaged(u8), kind: u8, len: usize) !void {
    if (len > 0x00ff_ffff) return error.HandshakeMessageTooLarge;
    try out.append(allocator, kind);
    try out.append(allocator, @intCast((len >> 16) & 0xff));
    try out.append(allocator, @intCast((len >> 8) & 0xff));
    try out.append(allocator, @intCast(len & 0xff));
}

fn appendExtension(allocator: std.mem.Allocator, out: *std.ArrayListUnmanaged(u8), extension_type: u16, payload: []const u8) !void {
    try appendU16(allocator, out, extension_type);
    try appendU16(allocator, out, payload.len);
    try out.appendSlice(allocator, payload);
}

fn appendU16(allocator: std.mem.Allocator, out: *std.ArrayListUnmanaged(u8), value: u64) !void {
    if (value > std.math.maxInt(u16)) return error.IntegerTooLarge;
    var buf: [2]u8 = undefined;
    std.mem.writeInt(u16, &buf, @intCast(value), .big);
    try out.appendSlice(allocator, &buf);
}

test "builds TLS 1.3 ServerHello with X25519 key share" {
    const kp = try X25519.KeyPair.generateDeterministic([_]u8{0x11} ** 32);
    const msg = try buildServerHello(std.testing.allocator, .{
        .legacy_session_id = "sid",
        .random = [_]u8{0x22} ** 32,
        .x25519_public_key = kp.public_key,
    });
    defer std.testing.allocator.free(msg);

    try std.testing.expectEqual(@as(u8, 0x02), msg[0]);
    try std.testing.expect(std.mem.indexOf(u8, msg, &kp.public_key) != null);
    try std.testing.expect(std.mem.indexOf(u8, msg, "\x00\x2b\x00\x02\x03\x04") != null);
}

test "derives TLS and QUIC handshake keys from X25519 shared secret" {
    const client = try X25519.KeyPair.generateDeterministic([_]u8{0x33} ** 32);
    const server = try X25519.KeyPair.generateDeterministic([_]u8{0x44} ** 32);
    const client_shared = try X25519.scalarmult(client.secret_key, server.public_key);
    const server_shared = try X25519.scalarmult(server.secret_key, client.public_key);
    try std.testing.expectEqualSlices(u8, &client_shared, &server_shared);

    const th = transcriptHash(&.{ "client hello", "server hello" });
    const secrets = deriveTrafficSecrets(server_shared, th);
    const packet_keys = deriveQuicPacketKeys(secrets.server_handshake_traffic_secret);
    const verify_data = finishedVerifyData(secrets.server_finished_key, th);

    try std.testing.expect(!std.mem.allEqual(u8, &packet_keys.key, 0));
    try std.testing.expect(!std.mem.allEqual(u8, &packet_keys.iv, 0));
    try std.testing.expect(!std.mem.allEqual(u8, &packet_keys.hp, 0));
    try std.testing.expect(!std.mem.allEqual(u8, &verify_data, 0));
}
