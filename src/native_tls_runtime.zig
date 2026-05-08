const std = @import("std");

const config_mod = @import("config.zig");
const routing = @import("routing.zig");
const tls13_native = @import("tls13_native.zig");
const tls_client_hello = @import("tls_client_hello.zig");
const tls_pem = @import("tls_pem.zig");

const ServerConfig = config_mod.ServerConfig;

pub const ALERT_HANDSHAKE_FAILURE: u8 = 40;
pub const ALERT_NO_APPLICATION_PROTOCOL: u8 = 120;

const MAX_INNER_PLAINTEXT_BYTES = 16 * 1024;
const MAX_RECORD_BYTES = 5 + MAX_INNER_PLAINTEXT_BYTES + 256;
const CONTENT_TYPE_CHANGE_CIPHER_SPEC: u8 = 0x14;
const CONTENT_TYPE_ALERT: u8 = 0x15;
const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const CONTENT_TYPE_APPLICATION_DATA: u8 = 0x17;

pub const RawReadFn = *const fn (std.Io.net.Stream, []u8) anyerror!usize;
pub const RawWriteAllFn = *const fn (std.Io.net.Stream, []const u8) anyerror!void;

pub const Channel = struct {
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    client_application_keys: tls13_native.TlsRecordKeys,
    server_application_keys: tls13_native.TlsRecordKeys,
    raw_read: RawReadFn,
    raw_write_all: RawWriteAllFn,
    client_sequence: u64 = 0,
    server_sequence: u64 = 0,
    pending_plaintext: ?[]u8 = null,
    pending_offset: usize = 0,

    pub fn deinit(self: *Channel) void {
        if (self.pending_plaintext) |pending| self.allocator.free(pending);
        self.pending_plaintext = null;
        self.pending_offset = 0;
    }
};

pub const Result = struct {
    channel: Channel,
    alpn: ?[]const u8,
};

const SigningKeyKind = enum {
    configured_ecdsa,
    configured_rsa,
    generated_ecdsa,
    generated_ed25519,
};

pub fn isHttp3OverTcpProbe(bytes: []const u8) bool {
    if (bytes.len == 0) return false;
    return bytes[0] == 0x00;
}

pub fn readClientHelloRecord(stream: std.Io.net.Stream, allocator: std.mem.Allocator, prefill: []const u8, raw_read: RawReadFn) ![]u8 {
    var header: [5]u8 = undefined;
    const copied_header: usize = @min(prefill.len, header.len);
    if (copied_header > 0) @memcpy(header[0..copied_header], prefill[0..copied_header]);
    var header_used: usize = copied_header;
    while (header_used < header.len) {
        const n = try raw_read(stream, header[header_used..]);
        if (n == 0) return error.ConnectionClosed;
        header_used += n;
    }

    const record_len = try tls_client_hello.recordLength(&header);
    if (record_len > 5 + 16 * 1024) return error.RequestTooLarge;
    const record = try allocator.alloc(u8, record_len);
    @memcpy(record[0..header.len], &header);
    const copied_body: usize = if (prefill.len > header.len) @min(prefill.len - header.len, record_len - header.len) else 0;
    if (copied_body > 0) {
        @memcpy(record[header.len .. header.len + copied_body], prefill[header.len .. header.len + copied_body]);
    }

    var used = header.len + copied_body;
    while (used < record.len) {
        const n = try raw_read(stream, record[used..]);
        if (n == 0) return error.ConnectionClosed;
        used += n;
    }
    return record;
}

pub fn sendFatalAlert(stream: std.Io.net.Stream, description: u8, raw_write_all: RawWriteAllFn) !void {
    const alert = [_]u8{
        0x15,
        0x03,
        0x03,
        0x00,
        0x02,
        0x02,
        description,
    };
    try raw_write_all(stream, &alert);
}

fn selectedAlpn(info: tls_client_hello.ClientHelloInfo) ?[]const u8 {
    if (info.offers_h2) return "h2";
    if (info.offers_http11) return "http/1.1";
    return null;
}

fn selectedMaterialForClientHello(cfg: *const ServerConfig, info: tls_client_hello.ClientHelloInfo) ?tls_pem.ConfiguredTlsMaterial {
    if (info.sni) |server_name| {
        if (routing.findDomainForHost(cfg, server_name)) |domain| {
            if (domain.tls_material) |material| return material;
        }
    }
    return cfg.tls_material;
}

fn clientHelloHandshakeMessage(record: []const u8) ![]const u8 {
    if (record.len < 5) return error.Truncated;
    const record_len = (@as(usize, record[3]) << 8) | record[4];
    if (record.len < 5 + record_len) return error.Truncated;
    return record[5 .. 5 + record_len];
}

fn readRecordRaw(stream: std.Io.net.Stream, allocator: std.mem.Allocator, raw_read: RawReadFn) ![]u8 {
    var header: [5]u8 = undefined;
    var used: usize = 0;
    while (used < header.len) {
        const n = try raw_read(stream, header[used..]);
        if (n == 0) return error.ConnectionClosed;
        used += n;
    }

    const payload_len = (@as(usize, header[3]) << 8) | header[4];
    if (payload_len > MAX_RECORD_BYTES - 5) return error.RequestTooLarge;
    const record = try allocator.alloc(u8, 5 + payload_len);
    @memcpy(record[0..5], &header);
    used = 5;
    while (used < record.len) {
        const n = try raw_read(stream, record[used..]);
        if (n == 0) return error.ConnectionClosed;
        used += n;
    }
    return record;
}

fn sendPlainRecord(stream: std.Io.net.Stream, content_type: u8, payload: []const u8, raw_write_all: RawWriteAllFn) !void {
    if (payload.len > MAX_INNER_PLAINTEXT_BYTES) return error.TlsPlaintextTooLarge;
    var header: [5]u8 = .{ content_type, 0x03, 0x03, 0, 0 };
    std.mem.writeInt(u16, header[3..5], @intCast(payload.len), .big);
    try raw_write_all(stream, &header);
    if (payload.len > 0) try raw_write_all(stream, payload);
}

fn sendEncryptedRecord(
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    keys: tls13_native.TlsRecordKeys,
    sequence: *u64,
    inner_content_type: u8,
    payload: []const u8,
    raw_write_all: RawWriteAllFn,
) !void {
    if (sequence.* == std.math.maxInt(u64)) return error.TlsSequenceOverflow;
    const record = try tls13_native.encryptTlsRecord(allocator, keys, sequence.*, inner_content_type, payload);
    defer allocator.free(record);
    try raw_write_all(stream, record);
    sequence.* += 1;
}

pub fn readApplicationData(channel: *Channel, out: []u8) !usize {
    if (out.len == 0) return 0;

    while (true) {
        if (channel.pending_plaintext) |pending| {
            const available = pending[channel.pending_offset..];
            const copied = @min(out.len, available.len);
            if (copied > 0) {
                @memcpy(out[0..copied], available[0..copied]);
                channel.pending_offset += copied;
                if (channel.pending_offset >= pending.len) {
                    channel.allocator.free(pending);
                    channel.pending_plaintext = null;
                    channel.pending_offset = 0;
                }
                return copied;
            }

            channel.allocator.free(pending);
            channel.pending_plaintext = null;
            channel.pending_offset = 0;
        }

        const record = try readRecordRaw(channel.stream, channel.allocator, channel.raw_read);
        defer channel.allocator.free(record);

        switch (record[0]) {
            CONTENT_TYPE_CHANGE_CIPHER_SPEC => continue,
            CONTENT_TYPE_ALERT => return 0,
            CONTENT_TYPE_APPLICATION_DATA => {},
            else => return error.UnexpectedTlsRecordType,
        }

        if (channel.client_sequence == std.math.maxInt(u64)) return error.TlsSequenceOverflow;
        var decrypted = try tls13_native.decryptTlsRecord(
            channel.allocator,
            channel.client_application_keys,
            channel.client_sequence,
            record,
        );
        channel.client_sequence += 1;

        switch (decrypted.content_type) {
            CONTENT_TYPE_APPLICATION_DATA => {
                if (decrypted.payload.len == 0) {
                    decrypted.deinit(channel.allocator);
                    continue;
                }
                channel.pending_plaintext = decrypted.payload;
                channel.pending_offset = 0;
            },
            CONTENT_TYPE_ALERT => {
                decrypted.deinit(channel.allocator);
                return 0;
            },
            CONTENT_TYPE_HANDSHAKE => {
                decrypted.deinit(channel.allocator);
                continue;
            },
            else => {
                decrypted.deinit(channel.allocator);
                return error.UnexpectedTlsInnerContentType;
            },
        }
    }
}

pub fn writeApplicationData(channel: *Channel, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const chunk_len = @min(bytes.len - offset, MAX_INNER_PLAINTEXT_BYTES - 1);
        try sendEncryptedRecord(
            channel.stream,
            channel.allocator,
            channel.server_application_keys,
            &channel.server_sequence,
            CONTENT_TYPE_APPLICATION_DATA,
            bytes[offset .. offset + chunk_len],
            channel.raw_write_all,
        );
        offset += chunk_len;
    }
}

fn verifyClientFinished(plain: tls13_native.DecryptedRecord, expected_verify_data: [32]u8) !void {
    if (plain.content_type != CONTENT_TYPE_HANDSHAKE) return error.BadTlsFinished;
    if (plain.payload.len != 4 + expected_verify_data.len) return error.BadTlsFinished;
    if (plain.payload[0] != 0x14) return error.BadTlsFinished;
    const finished_len = (@as(usize, plain.payload[1]) << 16) |
        (@as(usize, plain.payload[2]) << 8) |
        @as(usize, plain.payload[3]);
    if (finished_len != expected_verify_data.len) return error.BadTlsFinished;
    const client_verify_data: [32]u8 = plain.payload[4..][0..32].*;
    if (!std.crypto.timing_safe.eql([32]u8, expected_verify_data, client_verify_data)) {
        return error.BadTlsFinishedVerifyData;
    }
}

pub fn establishTls13(
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    cfg: *const ServerConfig,
    client_hello_record: []const u8,
    info: tls_client_hello.ClientHelloInfo,
    io: std.Io,
    raw_read: RawReadFn,
    raw_write_all: RawWriteAllFn,
) !Result {
    if (!info.supports_tls13) return error.UnsupportedTlsVersion;
    if (!info.offers_aes_128_gcm_sha256) return error.UnsupportedTlsCipherSuite;
    if (!info.offers_ecdsa_secp256r1_sha256 and !info.offers_rsa_pss_rsae_sha256 and !info.offers_ed25519) {
        return error.UnsupportedTlsSignatureScheme;
    }
    const client_x25519 = info.x25519_key_share orelse return error.MissingTlsKeyShare;
    const alpn = selectedAlpn(info);
    if (info.alpn != null and alpn == null) return error.NoApplicationProtocol;

    var server_random: [32]u8 = undefined;
    io.random(&server_random);
    const server_key_pair = tls13_native.X25519.KeyPair.generate(io);
    const shared_secret = try tls13_native.X25519.scalarmult(server_key_pair.secret_key, client_x25519);

    const legacy_session_id = info.legacy_session_id orelse "";
    const server_hello = try tls13_native.buildServerHello(allocator, .{
        .legacy_session_id = legacy_session_id,
        .random = server_random,
        .x25519_public_key = server_key_pair.public_key,
    });
    defer allocator.free(server_hello);

    const client_hello = try clientHelloHandshakeMessage(client_hello_record);
    const hello_hash = tls13_native.transcriptHash(&.{ client_hello, server_hello });
    const traffic = tls13_native.deriveTrafficSecrets(shared_secret, hello_hash);
    const client_handshake_keys = tls13_native.deriveTlsRecordKeys(traffic.client_handshake_traffic_secret);
    const server_handshake_keys = tls13_native.deriveTlsRecordKeys(traffic.server_handshake_traffic_secret);

    const encrypted_extensions = try tls13_native.buildTcpEncryptedExtensions(allocator, alpn);
    defer allocator.free(encrypted_extensions);

    const cert_name = info.sni orelse "localhost";
    const selected_material = selectedMaterialForClientHello(cfg, info);
    const signing_key_kind: SigningKeyKind = if (selected_material) |material| switch (material.private_key) {
        .ecdsa_p256 => if (info.offers_ecdsa_secp256r1_sha256) .configured_ecdsa else return error.UnsupportedTlsSignatureScheme,
        .rsa => if (info.offers_rsa_pss_rsae_sha256) .configured_rsa else return error.UnsupportedTlsSignatureScheme,
    } else if (info.offers_ecdsa_secp256r1_sha256)
        .generated_ecdsa
    else if (info.offers_ed25519)
        .generated_ed25519
    else
        return error.UnsupportedTlsSignatureScheme;

    const generated_ecdsa_key_pair = if (signing_key_kind == .generated_ecdsa)
        tls13_native.EcdsaP256Sha256.KeyPair.generate(io)
    else
        null;
    const generated_ed25519_key_pair = if (signing_key_kind == .generated_ed25519)
        tls13_native.Ed25519.KeyPair.generate(io)
    else
        null;
    var generated_cert_der: ?[]u8 = null;
    defer if (generated_cert_der) |cert| allocator.free(cert);

    const certificate = switch (signing_key_kind) {
        .configured_ecdsa, .configured_rsa => try tls13_native.buildCertificate(allocator, selected_material.?.certificate_chain),
        .generated_ecdsa => blk: {
            generated_cert_der = try tls13_native.buildSelfSignedEcdsaP256Sha256Certificate(allocator, generated_ecdsa_key_pair.?, cert_name);
            break :blk try tls13_native.buildCertificate(allocator, &.{generated_cert_der.?});
        },
        .generated_ed25519 => blk: {
            generated_cert_der = try tls13_native.buildSelfSignedEd25519Certificate(allocator, generated_ed25519_key_pair.?, cert_name);
            break :blk try tls13_native.buildCertificate(allocator, &.{generated_cert_der.?});
        },
    };
    defer allocator.free(certificate);

    const cert_verify_hash = tls13_native.transcriptHash(&.{ client_hello, server_hello, encrypted_extensions, certificate });
    const cert_signature = switch (signing_key_kind) {
        .configured_ecdsa => blk: {
            const key_pair = selected_material.?.private_key.ecdsa_p256;
            break :blk try tls13_native.signCertificateVerifyEcdsaP256Sha256(allocator, key_pair, cert_verify_hash);
        },
        .configured_rsa => blk: {
            const key = selected_material.?.private_key.rsa;
            break :blk try tls13_native.signCertificateVerifyRsaPssSha256(io, allocator, key, cert_verify_hash);
        },
        .generated_ecdsa => try tls13_native.signCertificateVerifyEcdsaP256Sha256(allocator, generated_ecdsa_key_pair.?, cert_verify_hash),
        .generated_ed25519 => blk: {
            const signature = try tls13_native.signCertificateVerifyEd25519(generated_ed25519_key_pair.?, cert_verify_hash);
            break :blk try allocator.dupe(u8, &signature);
        },
    };
    defer allocator.free(cert_signature);
    const signature_scheme: tls13_native.SignatureScheme = switch (signing_key_kind) {
        .configured_ecdsa, .generated_ecdsa => .ecdsa_secp256r1_sha256,
        .configured_rsa => .rsa_pss_rsae_sha256,
        .generated_ed25519 => .ed25519,
    };
    const certificate_verify = try tls13_native.buildCertificateVerify(allocator, signature_scheme, cert_signature);
    defer allocator.free(certificate_verify);

    const finished_hash = tls13_native.transcriptHash(&.{
        client_hello,
        server_hello,
        encrypted_extensions,
        certificate,
        certificate_verify,
    });
    const server_verify_data = tls13_native.finishedVerifyData(traffic.server_finished_key, finished_hash);
    const server_finished = try tls13_native.buildFinished(allocator, server_verify_data);
    defer allocator.free(server_finished);

    const application_hash = tls13_native.transcriptHash(&.{
        client_hello,
        server_hello,
        encrypted_extensions,
        certificate,
        certificate_verify,
        server_finished,
    });

    try sendPlainRecord(stream, CONTENT_TYPE_HANDSHAKE, server_hello, raw_write_all);
    var server_handshake_sequence: u64 = 0;
    try sendEncryptedRecord(stream, allocator, server_handshake_keys, &server_handshake_sequence, CONTENT_TYPE_HANDSHAKE, encrypted_extensions, raw_write_all);
    try sendEncryptedRecord(stream, allocator, server_handshake_keys, &server_handshake_sequence, CONTENT_TYPE_HANDSHAKE, certificate, raw_write_all);
    try sendEncryptedRecord(stream, allocator, server_handshake_keys, &server_handshake_sequence, CONTENT_TYPE_HANDSHAKE, certificate_verify, raw_write_all);
    try sendEncryptedRecord(stream, allocator, server_handshake_keys, &server_handshake_sequence, CONTENT_TYPE_HANDSHAKE, server_finished, raw_write_all);

    var client_handshake_sequence: u64 = 0;
    while (true) {
        const client_record = try readRecordRaw(stream, allocator, raw_read);
        defer allocator.free(client_record);
        if (client_record[0] == CONTENT_TYPE_CHANGE_CIPHER_SPEC) continue;
        if (client_record[0] != CONTENT_TYPE_APPLICATION_DATA) return error.UnexpectedTlsRecordType;

        var client_finished = try tls13_native.decryptTlsRecord(allocator, client_handshake_keys, client_handshake_sequence, client_record);
        defer client_finished.deinit(allocator);
        client_handshake_sequence += 1;
        const expected_client_verify_data = tls13_native.finishedVerifyData(traffic.client_finished_key, application_hash);
        try verifyClientFinished(client_finished, expected_client_verify_data);
        break;
    }

    const app_secrets = tls13_native.deriveApplicationTrafficSecrets(traffic.master_secret, application_hash);
    return .{
        .channel = .{
            .stream = stream,
            .allocator = allocator,
            .client_application_keys = tls13_native.deriveTlsRecordKeys(app_secrets.client_application_traffic_secret),
            .server_application_keys = tls13_native.deriveTlsRecordKeys(app_secrets.server_application_traffic_secret),
            .raw_read = raw_read,
            .raw_write_all = raw_write_all,
        },
        .alpn = alpn,
    };
}
