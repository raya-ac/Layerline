const std = @import("std");
const tls13_native = @import("tls13_native.zig");

const EC_PUBLIC_KEY_OID = "\x2a\x86\x48\xce\x3d\x02\x01";
const PRIME256V1_OID = "\x2a\x86\x48\xce\x3d\x03\x01\x07";
const RSA_ENCRYPTION_OID = "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01";

pub const ConfiguredPrivateKey = union(enum) {
    ecdsa_p256: tls13_native.EcdsaP256Sha256.KeyPair,
    rsa: tls13_native.RsaPrivateKey,

    pub fn deinit(self: *ConfiguredPrivateKey, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .ecdsa_p256 => {},
            .rsa => |*key| key.deinit(allocator),
        }
        self.* = undefined;
    }
};

pub const ConfiguredTlsMaterial = struct {
    certificate_chain: []const []const u8,
    private_key: ConfiguredPrivateKey,

    pub fn deinit(self: *ConfiguredTlsMaterial, allocator: std.mem.Allocator) void {
        for (self.certificate_chain) |cert| allocator.free(cert);
        allocator.free(self.certificate_chain);
        self.private_key.deinit(allocator);
        self.* = undefined;
    }
};

const DerTlv = struct {
    tag: u8,
    value: []const u8,
};

const DerReader = struct {
    bytes: []const u8,
    offset: usize = 0,

    fn done(self: *const DerReader) bool {
        return self.offset >= self.bytes.len;
    }

    fn readTlv(self: *DerReader) !DerTlv {
        if (self.offset >= self.bytes.len) return error.TruncatedDer;
        const tag = self.bytes[self.offset];
        self.offset += 1;
        const len = try self.readLength();
        if (len > self.bytes.len or self.offset > self.bytes.len - len) return error.TruncatedDer;
        const value = self.bytes[self.offset .. self.offset + len];
        self.offset += len;
        return .{ .tag = tag, .value = value };
    }

    fn readExpected(self: *DerReader, tag: u8) ![]const u8 {
        const tlv = try self.readTlv();
        if (tlv.tag != tag) return error.UnexpectedDerTag;
        return tlv.value;
    }

    fn readLength(self: *DerReader) !usize {
        if (self.offset >= self.bytes.len) return error.TruncatedDer;
        const first = self.bytes[self.offset];
        self.offset += 1;
        if ((first & 0x80) == 0) return first;

        const count = first & 0x7f;
        if (count == 0 or count > @sizeOf(usize)) return error.UnsupportedDerLength;
        if (self.bytes.len < self.offset + count) return error.TruncatedDer;

        var len: usize = 0;
        var i: usize = 0;
        while (i < count) : (i += 1) {
            len = (len << 8) | self.bytes[self.offset + i];
        }
        self.offset += count;
        return len;
    }
};

pub fn decodeCertificateChainPem(allocator: std.mem.Allocator, pem: []const u8) ![]const []const u8 {
    var chain = std.ArrayList([]const u8).empty;
    errdefer {
        for (chain.items) |cert| allocator.free(cert);
        chain.deinit(allocator);
    }

    var start_index: usize = 0;
    while (findPemBlock(pem, "CERTIFICATE", start_index)) |block| {
        const cert = try decodeBase64PemBody(allocator, block.body);
        try chain.append(allocator, cert);
        start_index = block.next_index;
    }

    if (chain.items.len == 0) return error.MissingCertificatePemBlock;
    return chain.toOwnedSlice(allocator);
}

pub fn decodePrivateKeyPem(
    allocator: std.mem.Allocator,
    pem: []const u8,
) !ConfiguredPrivateKey {
    if (findPemBlock(pem, "EC PRIVATE KEY", 0)) |block| {
        const decoded = try decodeBase64PemBody(allocator, block.body);
        defer allocator.free(decoded);
        return .{ .ecdsa_p256 = try parseSec1EcPrivateKey(decoded) };
    }
    if (findPemBlock(pem, "RSA PRIVATE KEY", 0)) |block| {
        const decoded = try decodeBase64PemBody(allocator, block.body);
        defer allocator.free(decoded);
        return .{ .rsa = try parsePkcs1RsaPrivateKey(allocator, decoded) };
    }
    if (findPemBlock(pem, "PRIVATE KEY", 0)) |block| {
        const decoded = try decodeBase64PemBody(allocator, block.body);
        defer allocator.free(decoded);
        return parsePkcs8PrivateKey(allocator, decoded);
    }
    return error.MissingPrivateKeyPemBlock;
}

pub fn loadMaterialFromPem(
    allocator: std.mem.Allocator,
    cert_pem: []const u8,
    key_pem: []const u8,
) !ConfiguredTlsMaterial {
    const chain = try decodeCertificateChainPem(allocator, cert_pem);
    errdefer {
        for (chain) |cert| allocator.free(cert);
        allocator.free(chain);
    }

    var private_key = try decodePrivateKeyPem(allocator, key_pem);
    errdefer private_key.deinit(allocator);
    switch (private_key) {
        .ecdsa_p256 => |key_pair| {
            const public_key_sec1 = key_pair.public_key.toUncompressedSec1();
            if (std.mem.indexOf(u8, chain[0], &public_key_sec1) == null) return error.CertificateKeyMismatch;
        },
        .rsa => |key| {
            if (std.mem.indexOf(u8, chain[0], key.modulus) == null) return error.CertificateKeyMismatch;
        },
    }

    return .{
        .certificate_chain = chain,
        .private_key = private_key,
    };
}

const PemBlock = struct {
    body: []const u8,
    next_index: usize,
};

fn findPemBlock(bytes: []const u8, label: []const u8, start_index: usize) ?PemBlock {
    var begin_buf: [96]u8 = undefined;
    var end_buf: [96]u8 = undefined;
    const begin_marker = std.fmt.bufPrint(&begin_buf, "-----BEGIN {s}-----", .{label}) catch return null;
    const end_marker = std.fmt.bufPrint(&end_buf, "-----END {s}-----", .{label}) catch return null;

    const begin = std.mem.indexOfPos(u8, bytes, start_index, begin_marker) orelse return null;
    const body_start = begin + begin_marker.len;
    const end = std.mem.indexOfPos(u8, bytes, body_start, end_marker) orelse return null;
    return .{
        .body = bytes[body_start..end],
        .next_index = end + end_marker.len,
    };
}

fn decodeBase64PemBody(allocator: std.mem.Allocator, body: []const u8) ![]u8 {
    const decoder = std.base64.standard.decoderWithIgnore(" \t\r\n");
    const decoded = try allocator.alloc(u8, decoder.calcSizeUpperBound(body.len));
    errdefer allocator.free(decoded);
    const len = try decoder.decode(decoded, body);
    return allocator.realloc(decoded, len);
}

fn parseSec1EcPrivateKey(der: []const u8) !tls13_native.EcdsaP256Sha256.KeyPair {
    var reader = DerReader{ .bytes = der };
    var seq = DerReader{ .bytes = try reader.readExpected(0x30) };
    if (!reader.done()) return error.TrailingDerData;

    _ = try seq.readExpected(0x02);
    const private_key = try seq.readExpected(0x04);
    if (private_key.len != tls13_native.EcdsaP256Sha256.SecretKey.encoded_length) {
        return error.UnsupportedEcPrivateKeyLength;
    }

    const secret = try tls13_native.EcdsaP256Sha256.SecretKey.fromBytes(private_key[0..32].*);
    return tls13_native.EcdsaP256Sha256.KeyPair.fromSecretKey(secret);
}

fn parsePkcs1RsaPrivateKey(allocator: std.mem.Allocator, der: []const u8) !tls13_native.RsaPrivateKey {
    var reader = DerReader{ .bytes = der };
    var seq = DerReader{ .bytes = try reader.readExpected(0x30) };
    if (!reader.done()) return error.TrailingDerData;

    _ = try seq.readExpected(0x02);
    const modulus = try allocator.dupe(u8, trimDerInteger(try seq.readExpected(0x02)));
    errdefer allocator.free(modulus);
    const public_exponent = try allocator.dupe(u8, trimDerInteger(try seq.readExpected(0x02)));
    errdefer allocator.free(public_exponent);
    const private_exponent = try allocator.dupe(u8, trimDerInteger(try seq.readExpected(0x02)));
    errdefer allocator.free(private_exponent);

    if (modulus.len < 64 or modulus.len > 512) return error.UnsupportedRsaModulusLength;
    if (private_exponent.len == 0 or private_exponent.len > modulus.len) return error.InvalidRsaPrivateExponent;
    if (public_exponent.len == 0 or public_exponent.len > 4) return error.InvalidRsaPublicExponent;

    return .{
        .modulus = modulus,
        .public_exponent = public_exponent,
        .private_exponent = private_exponent,
    };
}

fn parsePkcs8PrivateKey(allocator: std.mem.Allocator, der: []const u8) !ConfiguredPrivateKey {
    var reader = DerReader{ .bytes = der };
    var seq = DerReader{ .bytes = try reader.readExpected(0x30) };
    if (!reader.done()) return error.TrailingDerData;

    _ = try seq.readExpected(0x02);
    var algorithm = DerReader{ .bytes = try seq.readExpected(0x30) };
    const algorithm_oid = try algorithm.readExpected(0x06);
    const wrapped_private_key = try seq.readExpected(0x04);

    if (std.mem.eql(u8, algorithm_oid, EC_PUBLIC_KEY_OID)) {
        const curve_oid = try algorithm.readExpected(0x06);
        if (!std.mem.eql(u8, curve_oid, PRIME256V1_OID)) return error.UnsupportedPrivateKeyCurve;
        return .{ .ecdsa_p256 = try parseSec1EcPrivateKey(wrapped_private_key) };
    }

    if (std.mem.eql(u8, algorithm_oid, RSA_ENCRYPTION_OID)) {
        return .{ .rsa = try parsePkcs1RsaPrivateKey(allocator, wrapped_private_key) };
    }

    return error.UnsupportedPrivateKeyAlgorithm;
}

fn trimDerInteger(value: []const u8) []const u8 {
    var offset: usize = 0;
    while (offset + 1 < value.len and value[offset] == 0) {
        offset += 1;
    }
    return value[offset..];
}

fn appendDerLength(allocator: std.mem.Allocator, out: *std.ArrayList(u8), len: usize) !void {
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
    try out.append(allocator, 0x80 | @as(u8, @intCast(buf.len - i)));
    try out.appendSlice(allocator, buf[i..]);
}

fn appendTlv(allocator: std.mem.Allocator, out: *std.ArrayList(u8), tag: u8, value: []const u8) !void {
    try out.append(allocator, tag);
    try appendDerLength(allocator, out, value.len);
    try out.appendSlice(allocator, value);
}

test "decodes certificate PEM blocks" {
    const pem =
        \\-----BEGIN CERTIFICATE-----
        \\YWJj
        \\-----END CERTIFICATE-----
        \\-----BEGIN CERTIFICATE-----
        \\ZGVm
        \\-----END CERTIFICATE-----
    ;
    const chain = try decodeCertificateChainPem(std.testing.allocator, pem);
    defer {
        for (chain) |cert| std.testing.allocator.free(cert);
        std.testing.allocator.free(chain);
    }
    try std.testing.expectEqual(@as(usize, 2), chain.len);
    try std.testing.expectEqualStrings("abc", chain[0]);
    try std.testing.expectEqualStrings("def", chain[1]);
}

test "parses SEC1 ECDSA P-256 private keys" {
    const kp = try tls13_native.EcdsaP256Sha256.KeyPair.generateDeterministic([_]u8{0x24} ** 32);
    const secret = kp.secret_key.toBytes();

    var body = std.ArrayList(u8).empty;
    defer body.deinit(std.testing.allocator);
    try appendTlv(std.testing.allocator, &body, 0x02, "\x01");
    try appendTlv(std.testing.allocator, &body, 0x04, &secret);

    var der = std.ArrayList(u8).empty;
    defer der.deinit(std.testing.allocator);
    try appendTlv(std.testing.allocator, &der, 0x30, body.items);

    const parsed = try parseSec1EcPrivateKey(der.items);
    try std.testing.expectEqualSlices(u8, &kp.public_key.toUncompressedSec1(), &parsed.public_key.toUncompressedSec1());
}

test "parses PKCS1 RSA private keys" {
    var modulus = [_]u8{0x55} ** 128;
    modulus[0] = 0x7f;
    var private_exponent = [_]u8{0x33} ** 128;
    private_exponent[0] = 0x11;

    var body = std.ArrayList(u8).empty;
    defer body.deinit(std.testing.allocator);
    try appendTlv(std.testing.allocator, &body, 0x02, "\x00");
    try appendTlv(std.testing.allocator, &body, 0x02, &modulus);
    try appendTlv(std.testing.allocator, &body, 0x02, "\x01\x00\x01");
    try appendTlv(std.testing.allocator, &body, 0x02, &private_exponent);

    var der = std.ArrayList(u8).empty;
    defer der.deinit(std.testing.allocator);
    try appendTlv(std.testing.allocator, &der, 0x30, body.items);

    var parsed = try parsePkcs1RsaPrivateKey(std.testing.allocator, der.items);
    defer parsed.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(u8, &modulus, parsed.modulus);
    try std.testing.expectEqualStrings("\x01\x00\x01", parsed.public_exponent);
    try std.testing.expectEqualSlices(u8, &private_exponent, parsed.private_exponent);
}
