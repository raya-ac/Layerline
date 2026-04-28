const std = @import("std");

const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;
pub const Ed25519 = std.crypto.sign.Ed25519;
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
    master_secret: [32]u8,
    client_handshake_traffic_secret: [32]u8,
    server_handshake_traffic_secret: [32]u8,
    client_finished_key: [32]u8,
    server_finished_key: [32]u8,
};

pub const ApplicationSecrets = struct {
    client_application_traffic_secret: [32]u8,
    server_application_traffic_secret: [32]u8,
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

pub fn buildEncryptedExtensions(
    allocator: std.mem.Allocator,
    alpn: []const u8,
    quic_transport_parameters: []const u8,
) ![]u8 {
    var extensions = std.ArrayListUnmanaged(u8).empty;
    defer extensions.deinit(allocator);

    var alpn_payload = std.ArrayListUnmanaged(u8).empty;
    defer alpn_payload.deinit(allocator);
    try appendU16(allocator, &alpn_payload, 1 + alpn.len);
    try alpn_payload.append(allocator, @intCast(alpn.len));
    try alpn_payload.appendSlice(allocator, alpn);
    try appendExtension(allocator, &extensions, 0x0010, alpn_payload.items);

    try appendExtension(allocator, &extensions, 0x0039, quic_transport_parameters);

    var body = std.ArrayListUnmanaged(u8).empty;
    defer body.deinit(allocator);
    try appendU16(allocator, &body, extensions.items.len);
    try body.appendSlice(allocator, extensions.items);

    var out = std.ArrayListUnmanaged(u8).empty;
    errdefer out.deinit(allocator);
    try appendHandshakeHeader(allocator, &out, 0x08, body.items.len);
    try out.appendSlice(allocator, body.items);
    return out.toOwnedSlice(allocator);
}

pub fn buildCertificate(allocator: std.mem.Allocator, cert_chain_der: []const []const u8) ![]u8 {
    var certificate_list = std.ArrayListUnmanaged(u8).empty;
    defer certificate_list.deinit(allocator);

    for (cert_chain_der) |cert_der| {
        try appendU24(allocator, &certificate_list, cert_der.len);
        try certificate_list.appendSlice(allocator, cert_der);
        try appendU16(allocator, &certificate_list, 0);
    }

    var body = std.ArrayListUnmanaged(u8).empty;
    defer body.deinit(allocator);
    try body.append(allocator, 0);
    try appendU24(allocator, &body, certificate_list.items.len);
    try body.appendSlice(allocator, certificate_list.items);

    var out = std.ArrayListUnmanaged(u8).empty;
    errdefer out.deinit(allocator);
    try appendHandshakeHeader(allocator, &out, 0x0b, body.items.len);
    try out.appendSlice(allocator, body.items);
    return out.toOwnedSlice(allocator);
}

pub fn buildCertificateVerify(allocator: std.mem.Allocator, scheme: SignatureScheme, signature: []const u8) ![]u8 {
    var body = std.ArrayListUnmanaged(u8).empty;
    defer body.deinit(allocator);
    try appendU16(allocator, &body, @intFromEnum(scheme));
    try appendU16(allocator, &body, signature.len);
    try body.appendSlice(allocator, signature);

    var out = std.ArrayListUnmanaged(u8).empty;
    errdefer out.deinit(allocator);
    try appendHandshakeHeader(allocator, &out, 0x0f, body.items.len);
    try out.appendSlice(allocator, body.items);
    return out.toOwnedSlice(allocator);
}

pub fn buildFinished(allocator: std.mem.Allocator, verify_data: [32]u8) ![]u8 {
    var out = std.ArrayListUnmanaged(u8).empty;
    errdefer out.deinit(allocator);
    try appendHandshakeHeader(allocator, &out, 0x14, verify_data.len);
    try out.appendSlice(allocator, &verify_data);
    return out.toOwnedSlice(allocator);
}

pub fn certificateVerifySignatureInput(allocator: std.mem.Allocator, transcript_hash_value: [32]u8) ![]u8 {
    var out = std.ArrayListUnmanaged(u8).empty;
    errdefer out.deinit(allocator);
    try out.appendNTimes(allocator, 0x20, 64);
    try out.appendSlice(allocator, "TLS 1.3, server CertificateVerify");
    try out.append(allocator, 0);
    try out.appendSlice(allocator, &transcript_hash_value);
    return out.toOwnedSlice(allocator);
}

pub fn signCertificateVerifyEd25519(key_pair: Ed25519.KeyPair, transcript_hash_value: [32]u8) ![Ed25519.Signature.encoded_length]u8 {
    var input_buf: [64 + "TLS 1.3, server CertificateVerify".len + 1 + 32]u8 = undefined;
    @memset(input_buf[0..64], 0x20);
    const context = "TLS 1.3, server CertificateVerify";
    @memcpy(input_buf[64..][0..context.len], context);
    input_buf[64 + context.len] = 0;
    @memcpy(input_buf[64 + context.len + 1 ..], &transcript_hash_value);

    const signature = try key_pair.sign(&input_buf, null);
    return signature.toBytes();
}

pub fn buildSelfSignedEd25519Certificate(
    allocator: std.mem.Allocator,
    key_pair: Ed25519.KeyPair,
    common_name: []const u8,
) ![]u8 {
    const algorithm_oid = try derOid(allocator, "\x2b\x65\x70");
    defer allocator.free(algorithm_oid);
    const algorithm = try derSequenceFromParts(allocator, &.{algorithm_oid});
    defer allocator.free(algorithm);

    const version_integer = try derInteger(allocator, "\x02");
    defer allocator.free(version_integer);
    const version = try derExplicit(allocator, 0, version_integer);
    defer allocator.free(version);

    const serial = try derInteger(allocator, "\x01\x33\x7a");
    defer allocator.free(serial);

    const name = try derNameCommonName(allocator, common_name);
    defer allocator.free(name);

    const not_before = try derUtcTime(allocator, "260101000000Z");
    defer allocator.free(not_before);
    const not_after = try derUtcTime(allocator, "360101000000Z");
    defer allocator.free(not_after);
    const validity = try derSequenceFromParts(allocator, &.{ not_before, not_after });
    defer allocator.free(validity);

    const subject_public_key = try derBitString(allocator, &key_pair.public_key.toBytes());
    defer allocator.free(subject_public_key);
    const spki = try derSequenceFromParts(allocator, &.{ algorithm, subject_public_key });
    defer allocator.free(spki);

    const extension_sequence = try buildCertificateExtensions(allocator);
    defer allocator.free(extension_sequence);
    const extensions = try derExplicit(allocator, 3, extension_sequence);
    defer allocator.free(extensions);

    const tbs = try derSequenceFromParts(allocator, &.{
        version,
        serial,
        algorithm,
        name,
        validity,
        name,
        spki,
        extensions,
    });
    defer allocator.free(tbs);

    const signature = try key_pair.sign(tbs, null);
    const signature_bytes = signature.toBytes();
    const signature_value = try derBitString(allocator, &signature_bytes);
    defer allocator.free(signature_value);

    return derSequenceFromParts(allocator, &.{ tbs, algorithm, signature_value });
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
    const early_secret = HkdfSha256.extract(&zero, &zero);
    const empty_hash = hashBytes("");
    const derived = hkdfExpandLabel(early_secret, "derived", &empty_hash, 32);
    const handshake_secret = HkdfSha256.extract(&derived, &shared_secret);
    const application_derived = hkdfExpandLabel(handshake_secret, "derived", &empty_hash, 32);
    const master_secret = HkdfSha256.extract(&application_derived, &zero);
    const client_hs = hkdfExpandLabel(handshake_secret, "c hs traffic", &transcript_hash, 32);
    const server_hs = hkdfExpandLabel(handshake_secret, "s hs traffic", &transcript_hash, 32);

    return .{
        .handshake_secret = handshake_secret,
        .master_secret = master_secret,
        .client_handshake_traffic_secret = client_hs,
        .server_handshake_traffic_secret = server_hs,
        .client_finished_key = hkdfExpandLabel(client_hs, "finished", "", 32),
        .server_finished_key = hkdfExpandLabel(server_hs, "finished", "", 32),
    };
}

pub fn deriveApplicationTrafficSecrets(master_secret: [32]u8, transcript_hash_value: [32]u8) ApplicationSecrets {
    return .{
        .client_application_traffic_secret = hkdfExpandLabel(master_secret, "c ap traffic", &transcript_hash_value, 32),
        .server_application_traffic_secret = hkdfExpandLabel(master_secret, "s ap traffic", &transcript_hash_value, 32),
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
    try appendU24Bytes(allocator, out, len);
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

fn appendU24(allocator: std.mem.Allocator, out: *std.ArrayListUnmanaged(u8), value: usize) !void {
    if (value > 0x00ff_ffff) return error.IntegerTooLarge;
    try appendU24Bytes(allocator, out, value);
}

fn appendU24Bytes(allocator: std.mem.Allocator, out: *std.ArrayListUnmanaged(u8), value: usize) !void {
    try out.append(allocator, @intCast((value >> 16) & 0xff));
    try out.append(allocator, @intCast((value >> 8) & 0xff));
    try out.append(allocator, @intCast(value & 0xff));
}

fn buildCertificateExtensions(allocator: std.mem.Allocator) ![]u8 {
    const basic_constraints_value = try derSequenceFromParts(allocator, &.{});
    defer allocator.free(basic_constraints_value);
    const basic_constraints_octets = try derOctetString(allocator, basic_constraints_value);
    defer allocator.free(basic_constraints_octets);
    const basic_constraints_oid = try derOid(allocator, "\x55\x1d\x13");
    defer allocator.free(basic_constraints_oid);
    const basic_constraints = try derSequenceFromParts(allocator, &.{ basic_constraints_oid, basic_constraints_octets });
    defer allocator.free(basic_constraints);

    const key_usage_bits = [_]u8{ 0x03, 0x02, 0x07, 0x80 };
    const key_usage_octets = try derOctetString(allocator, &key_usage_bits);
    defer allocator.free(key_usage_octets);
    const key_usage_oid = try derOid(allocator, "\x55\x1d\x0f");
    defer allocator.free(key_usage_oid);
    const key_usage = try derSequenceFromParts(allocator, &.{ key_usage_oid, key_usage_octets });
    defer allocator.free(key_usage);

    const server_auth_oid = try derOid(allocator, "\x2b\x06\x01\x05\x05\x07\x03\x01");
    defer allocator.free(server_auth_oid);
    const eku_value = try derSequenceFromParts(allocator, &.{server_auth_oid});
    defer allocator.free(eku_value);
    const eku_octets = try derOctetString(allocator, eku_value);
    defer allocator.free(eku_octets);
    const eku_oid = try derOid(allocator, "\x55\x1d\x25");
    defer allocator.free(eku_oid);
    const eku = try derSequenceFromParts(allocator, &.{ eku_oid, eku_octets });
    defer allocator.free(eku);

    var san_value_body = std.ArrayListUnmanaged(u8).empty;
    defer san_value_body.deinit(allocator);
    try appendDerLengthPrefixed(allocator, &san_value_body, 0x82, "localhost");
    try appendDerLengthPrefixed(allocator, &san_value_body, 0x87, &.{ 127, 0, 0, 1 });
    const san_value = try derTlv(allocator, 0x30, san_value_body.items);
    defer allocator.free(san_value);
    const san_octets = try derOctetString(allocator, san_value);
    defer allocator.free(san_octets);
    const san_oid = try derOid(allocator, "\x55\x1d\x11");
    defer allocator.free(san_oid);
    const san = try derSequenceFromParts(allocator, &.{ san_oid, san_octets });
    defer allocator.free(san);

    return derSequenceFromParts(allocator, &.{ basic_constraints, key_usage, eku, san });
}

fn derNameCommonName(allocator: std.mem.Allocator, common_name: []const u8) ![]u8 {
    const cn_oid = try derOid(allocator, "\x55\x04\x03");
    defer allocator.free(cn_oid);
    const cn_value = try derUtf8String(allocator, common_name);
    defer allocator.free(cn_value);
    const attr = try derSequenceFromParts(allocator, &.{ cn_oid, cn_value });
    defer allocator.free(attr);
    const rdn = try derSetFromParts(allocator, &.{attr});
    defer allocator.free(rdn);
    return derSequenceFromParts(allocator, &.{rdn});
}

fn derSequenceFromParts(allocator: std.mem.Allocator, parts: []const []const u8) ![]u8 {
    return derConstructedFromParts(allocator, 0x30, parts);
}

fn derSetFromParts(allocator: std.mem.Allocator, parts: []const []const u8) ![]u8 {
    return derConstructedFromParts(allocator, 0x31, parts);
}

fn derConstructedFromParts(allocator: std.mem.Allocator, tag: u8, parts: []const []const u8) ![]u8 {
    var body = std.ArrayListUnmanaged(u8).empty;
    defer body.deinit(allocator);
    for (parts) |part| {
        try body.appendSlice(allocator, part);
    }
    return derTlv(allocator, tag, body.items);
}

fn derExplicit(allocator: std.mem.Allocator, tag_number: u8, content: []const u8) ![]u8 {
    if (tag_number > 30) return error.UnsupportedDerTag;
    return derTlv(allocator, 0xa0 | tag_number, content);
}

fn derInteger(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    return derTlv(allocator, 0x02, value);
}

fn derOid(allocator: std.mem.Allocator, encoded_oid: []const u8) ![]u8 {
    return derTlv(allocator, 0x06, encoded_oid);
}

fn derUtf8String(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    return derTlv(allocator, 0x0c, value);
}

fn derUtcTime(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    return derTlv(allocator, 0x17, value);
}

fn derOctetString(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    return derTlv(allocator, 0x04, value);
}

fn derBitString(allocator: std.mem.Allocator, value: []const u8) ![]u8 {
    var body = std.ArrayListUnmanaged(u8).empty;
    defer body.deinit(allocator);
    try body.append(allocator, 0);
    try body.appendSlice(allocator, value);
    return derTlv(allocator, 0x03, body.items);
}

fn derTlv(allocator: std.mem.Allocator, tag: u8, value: []const u8) ![]u8 {
    var out = std.ArrayListUnmanaged(u8).empty;
    errdefer out.deinit(allocator);
    try out.append(allocator, tag);
    try appendDerLength(allocator, &out, value.len);
    try out.appendSlice(allocator, value);
    return out.toOwnedSlice(allocator);
}

fn appendDerLengthPrefixed(allocator: std.mem.Allocator, out: *std.ArrayListUnmanaged(u8), tag: u8, value: []const u8) !void {
    try out.append(allocator, tag);
    try appendDerLength(allocator, out, value.len);
    try out.appendSlice(allocator, value);
}

fn appendDerLength(allocator: std.mem.Allocator, out: *std.ArrayListUnmanaged(u8), len: usize) !void {
    if (len < 128) {
        try out.append(allocator, @intCast(len));
        return;
    }

    var buf: [8]u8 = undefined;
    var n = len;
    var i: usize = buf.len;
    while (n > 0) {
        i -= 1;
        buf[i] = @intCast(n & 0xff);
        n >>= 8;
    }
    const used = buf.len - i;
    try out.append(allocator, 0x80 | @as(u8, @intCast(used)));
    try out.appendSlice(allocator, buf[i..]);
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

test "builds TLS 1.3 EncryptedExtensions for h3 over QUIC" {
    const transport_params = "\x04\x04\x80\x10\x00\x00";
    const msg = try buildEncryptedExtensions(std.testing.allocator, "h3", transport_params);
    defer std.testing.allocator.free(msg);

    try std.testing.expectEqual(@as(u8, 0x08), msg[0]);
    try std.testing.expect(std.mem.indexOf(u8, msg, "\x00\x10") != null);
    try std.testing.expect(std.mem.indexOf(u8, msg, "\x00\x39") != null);
    try std.testing.expect(std.mem.indexOf(u8, msg, "h3") != null);
}

test "builds TLS 1.3 certificate, certificate verify, and finished messages" {
    const cert = "fake der certificate bytes";
    const certificate = try buildCertificate(std.testing.allocator, &.{cert});
    defer std.testing.allocator.free(certificate);
    try std.testing.expectEqual(@as(u8, 0x0b), certificate[0]);
    try std.testing.expect(std.mem.indexOf(u8, certificate, cert) != null);

    const kp = try Ed25519.KeyPair.generateDeterministic([_]u8{0x77} ** 32);
    const transcript_hash_value = [_]u8{0x88} ** 32;
    const signature = try signCertificateVerifyEd25519(kp, transcript_hash_value);
    const signature_input = try certificateVerifySignatureInput(std.testing.allocator, transcript_hash_value);
    defer std.testing.allocator.free(signature_input);
    try Ed25519.Signature.fromBytes(signature).verify(signature_input, kp.public_key);

    const certificate_verify = try buildCertificateVerify(std.testing.allocator, .ed25519, &signature);
    defer std.testing.allocator.free(certificate_verify);
    try std.testing.expectEqual(@as(u8, 0x0f), certificate_verify[0]);
    try std.testing.expect(std.mem.indexOf(u8, certificate_verify, &signature) != null);

    const finished = try buildFinished(std.testing.allocator, [_]u8{0x99} ** 32);
    defer std.testing.allocator.free(finished);
    try std.testing.expectEqual(@as(u8, 0x14), finished[0]);
    try std.testing.expectEqual(@as(usize, 36), finished.len);
}

test "builds a self-signed Ed25519 certificate matching its key" {
    const kp = try Ed25519.KeyPair.generateDeterministic([_]u8{0x42} ** 32);
    const cert = try buildSelfSignedEd25519Certificate(std.testing.allocator, kp, "localhost");
    defer std.testing.allocator.free(cert);

    try std.testing.expectEqual(@as(u8, 0x30), cert[0]);
    try std.testing.expect(std.mem.indexOf(u8, cert, "localhost") != null);
    try std.testing.expect(std.mem.indexOf(u8, cert, &kp.public_key.toBytes()) != null);
    try std.testing.expect(std.mem.indexOf(u8, cert, "\x2b\x65\x70") != null);
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
