const std = @import("std");

pub const max_certificate_bytes = 128 * 1024;
pub const ec_oid = "\x2a\x86\x48\xce\x3d\x02\x01";
pub const p256_oid = "\x2a\x86\x48\xce\x3d\x03\x01\x07";
pub const rsa_oid = "\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01";

const Node = struct { tag: u8, value: []const u8, encoded: []const u8 };
const Cursor = struct {
    bytes: []const u8,
    offset: usize = 0,

    fn next(self: *Cursor, tag: ?u8) !Node {
        const start = self.offset;
        if (start >= self.bytes.len or self.bytes[start] & 31 == 31) return error.CertificateMalformed;
        const element = std.crypto.codecs.asn1.Element.decode(self.bytes, @intCast(start)) catch return error.CertificateMalformed;
        if (tag) |expected| if (self.bytes[start] != expected) return error.CertificateMalformed;
        if (self.bytes[start + 1] > 0x80 and self.bytes[start + 2] == 0) return error.CertificateMalformed;
        self.offset = element.slice.end;
        return .{ .tag = self.bytes[start], .value = element.slice.view(self.bytes), .encoded = self.bytes[start..self.offset] };
    }

    fn end(self: Cursor) !void {
        if (self.offset != self.bytes.len) return error.CertificateMalformed;
    }
};

fn only(bytes: []const u8, tag: u8) !Node {
    var cursor: Cursor = .{ .bytes = bytes };
    const result = try cursor.next(tag);
    try cursor.end();
    return result;
}

pub fn positive(bytes: []const u8) ![]const u8 {
    if (bytes.len == 0 or bytes[0] & 0x80 != 0) return error.CertificateMalformed;
    if (bytes.len > 1 and bytes[0] == 0) {
        if (bytes[1] & 0x80 == 0) return error.CertificateMalformed;
        return bytes[1..];
    }
    return bytes;
}

fn oid(bytes: []const u8) !void {
    if (bytes.len == 0 or bytes[bytes.len - 1] & 0x80 != 0) return error.CertificateMalformed;
    var first = true;
    for (bytes) |byte| {
        if (first and byte == 0x80) return error.CertificateMalformed;
        first = byte & 0x80 == 0;
    }
}

fn bits(bytes: []const u8) ![]const u8 {
    if (bytes.len == 0 or bytes[0] > 7) return error.CertificateMalformed;
    if (bytes.len == 1 and bytes[0] != 0) return error.CertificateMalformed;
    if (bytes.len > 1 and bytes[bytes.len - 1] & ((@as(u8, 1) << @as(u3, @intCast(bytes[0]))) - 1) != 0) return error.CertificateMalformed;
    return bytes[1..];
}

fn tree(bytes: []const u8, depth: usize, remaining: *usize) error{CertificateMalformed}!void {
    if (depth == 16) return error.CertificateMalformed;
    var cursor: Cursor = .{ .bytes = bytes };
    while (cursor.offset < bytes.len) {
        if (remaining.* == 0) return error.CertificateMalformed;
        remaining.* -= 1;
        const node = try cursor.next(null);
        if (node.tag & 0xc0 == 0) switch (node.tag & 31) {
            0, 15 => return error.CertificateMalformed,
            8, 11, 16, 17, 29 => if (node.tag & 0x20 == 0) return error.CertificateMalformed,
            else => if (node.tag & 0x20 != 0) return error.CertificateMalformed,
        };
        if (node.tag & 0x20 != 0) {
            try tree(node.value, depth + 1, remaining);
        } else switch (node.tag) {
            0x01 => if (node.value.len != 1 or (node.value[0] != 0 and node.value[0] != 0xff)) return error.CertificateMalformed,
            0x02 => {
                if (node.value.len == 0) return error.CertificateMalformed;
                if (node.value.len > 1 and ((node.value[0] == 0 and node.value[1] & 0x80 == 0) or
                    (node.value[0] == 0xff and node.value[1] & 0x80 != 0))) return error.CertificateMalformed;
            },
            0x03 => _ = try bits(node.value),
            0x05 => if (node.value.len != 0) return error.CertificateMalformed,
            0x06 => try oid(node.value),
            else => {},
        }
    }
}

fn name(bytes: []const u8) !void {
    var rdns: Cursor = .{ .bytes = bytes };
    while (rdns.offset < bytes.len) {
        var attributes: Cursor = .{ .bytes = (try rdns.next(0x31)).value };
        if (attributes.bytes.len == 0) return error.CertificateMalformed;
        var previous: []const u8 = "";
        while (attributes.offset < attributes.bytes.len) {
            const attribute = try attributes.next(0x30);
            if (std.mem.order(u8, previous, attribute.encoded) == .gt) return error.CertificateMalformed;
            previous = attribute.encoded;
            var fields: Cursor = .{ .bytes = attribute.value };
            _ = try fields.next(0x06);
            _ = try fields.next(null);
            try fields.end();
        }
    }
}

const Algorithm = struct { id: []const u8, parameters: ?Node };

fn algorithm(bytes: []const u8) !Algorithm {
    var cursor: Cursor = .{ .bytes = bytes };
    const id = (try cursor.next(0x06)).value;
    try oid(id);
    const parameters = if (cursor.offset < bytes.len) try cursor.next(null) else null;
    try cursor.end();
    return .{ .id = id, .parameters = parameters };
}

fn time(node: Node) ![6]u16 {
    const value = node.value;
    const years: usize = switch (node.tag) {
        0x17 => if (value.len == 13) 2 else return error.CertificateMalformed,
        0x18 => if (value.len == 15) 4 else return error.CertificateMalformed,
        else => return error.CertificateMalformed,
    };
    if (value[value.len - 1] != 'Z') return error.CertificateMalformed;
    for (value[0 .. value.len - 1]) |byte| if (!std.ascii.isDigit(byte)) return error.CertificateMalformed;
    var fields: [6]u16 = undefined;
    fields[0] = try std.fmt.parseInt(u16, value[0..years], 10);
    if (years == 2) fields[0] += if (fields[0] >= 50) @as(u16, 1900) else 2000;
    for (fields[1..], 0..) |*field, index| field.* = try std.fmt.parseInt(u16, value[years + index * 2 ..][0..2], 10);
    if (fields[0] == 0 or fields[1] < 1 or fields[1] > 12 or fields[3] > 23 or fields[4] > 59 or fields[5] > 59) return error.CertificateMalformed;
    if (fields[2] < 1 or fields[2] > std.time.epoch.getDaysInMonth(fields[0], @enumFromInt(fields[1]))) return error.CertificateMalformed;
    return fields;
}

fn extensions(bytes: []const u8) !void {
    var cursor: Cursor = .{ .bytes = (try only(bytes, 0x30)).value };
    var seen: [64][]const u8 = undefined;
    var count: usize = 0;
    while (cursor.offset < cursor.bytes.len) {
        if (count == seen.len) return error.CertificateMalformed;
        var extension: Cursor = .{ .bytes = (try cursor.next(0x30)).value };
        const id = (try extension.next(0x06)).value;
        for (seen[0..count]) |previous| if (std.mem.eql(u8, previous, id)) return error.CertificateMalformed;
        seen[count] = id;
        count += 1;
        var value = try extension.next(null);
        if (value.tag == 0x01) {
            if (!std.mem.eql(u8, value.value, "\xff")) return error.CertificateMalformed;
            value = try extension.next(0x04);
        }
        if (value.tag != 0x04) return error.CertificateMalformed;
        try extension.end();
    }
    if (count == 0) return error.CertificateMalformed;
}

pub const PublicKey = struct {
    algorithm: Algorithm,
    bytes: []const u8,

    pub fn rsa(self: PublicKey) !struct { modulus: []const u8, exponent: []const u8 } {
        if (!std.mem.eql(u8, self.algorithm.id, rsa_oid)) return error.CertificateKeyMismatch;
        if (self.algorithm.parameters) |params| if (params.tag != 0x05 or params.value.len != 0) return error.CertificateMalformed;
        var cursor: Cursor = .{ .bytes = (try only(self.bytes, 0x30)).value };
        const modulus = try positive((try cursor.next(0x02)).value);
        const exponent = try positive((try cursor.next(0x02)).value);
        try cursor.end();
        if (modulus.len < 256 or modulus.len > 512 or modulus[0] == 0) return error.CertificateWeakKey;
        if (modulus.len * 8 - @clz(modulus[0]) < 2048 or modulus[modulus.len - 1] & 1 == 0) return error.CertificateWeakKey;
        if (exponent.len == 0 or exponent.len > 4) return error.CertificateWeakKey;
        const e = std.mem.readVarInt(u32, exponent, .big);
        if (e < 3 or e & 1 == 0) return error.CertificateWeakKey;
        return .{ .modulus = modulus, .exponent = exponent };
    }

    pub fn p256(self: PublicKey) ![]const u8 {
        if (!std.mem.eql(u8, self.algorithm.id, ec_oid)) return error.CertificateKeyMismatch;
        const curve = self.algorithm.parameters orelse return error.CertificateMalformed;
        if (curve.tag != 0x06 or !std.mem.eql(u8, curve.value, p256_oid)) return error.CertificateKeyMismatch;
        if (self.bytes.len != 65 or self.bytes[0] != 4) return error.CertificateMalformed;
        return self.bytes;
    }
};

// Read the certificate envelope, not its issuer's trust policy. Extensions and
// signature algorithms may belong to client profiles that Layerline does not use.
pub fn parse(bytes: []const u8) !PublicKey {
    if (bytes.len > max_certificate_bytes) return error.CertificateMalformed;
    var remaining: usize = 4096;
    try tree(bytes, 0, &remaining);
    var certificate: Cursor = .{ .bytes = (try only(bytes, 0x30)).value };
    const tbs = (try certificate.next(0x30)).value;
    const signature_algorithm = try certificate.next(0x30);
    _ = try algorithm(signature_algorithm.value);
    const signature = (try certificate.next(0x03)).value;
    if (signature.len < 2 or signature[0] != 0) return error.CertificateMalformed;
    try certificate.end();
    var fields: Cursor = .{ .bytes = tbs };
    var first = try fields.next(null);
    var version: u8 = 0;
    if (first.tag == 0xa0) {
        const value = (try only(first.value, 0x02)).value;
        if (value.len != 1 or value[0] < 1 or value[0] > 2) return error.CertificateMalformed;
        version = value[0];
        first = try fields.next(0x02);
    }
    if (first.tag != 0x02) return error.CertificateMalformed;
    _ = try positive(first.value);
    if (!std.mem.eql(u8, (try fields.next(0x30)).encoded, signature_algorithm.encoded)) return error.CertificateMalformed;
    try name((try fields.next(0x30)).value);
    var validity: Cursor = .{ .bytes = (try fields.next(0x30)).value };
    const before = try time(try validity.next(null));
    const after = try time(try validity.next(null));
    if (std.mem.order(u16, &before, &after) == .gt) return error.CertificateMalformed;
    try validity.end();
    try name((try fields.next(0x30)).value);
    var spki: Cursor = .{ .bytes = (try fields.next(0x30)).value };
    const key_algorithm = try algorithm((try spki.next(0x30)).value);
    const key = (try spki.next(0x03)).value;
    if (key.len < 2 or key[0] != 0) return error.CertificateMalformed;
    try spki.end();
    var last: u8 = 0x80;
    while (fields.offset < fields.bytes.len) {
        const optional = try fields.next(null);
        if (optional.tag <= last) return error.CertificateMalformed;
        switch (optional.tag) {
            0x81, 0x82 => {
                if (version == 0) return error.CertificateMalformed;
                _ = try bits(optional.value);
            },
            0xa3 => {
                if (version != 2) return error.CertificateMalformed;
                try extensions(optional.value);
            },
            else => return error.CertificateMalformed,
        }
        last = optional.tag;
    }
    return .{ .algorithm = key_algorithm, .bytes = key[1..] };
}

test "certificate key extraction owns no storage and rejects truncated or trailing envelopes" {
    const tls = @import("tls13_native.zig");
    const pair = try tls.EcdsaP256Sha256.KeyPair.generateDeterministic(@splat(0x27));
    const cert = try tls.buildSelfSignedEcdsaP256Sha256Certificate(std.testing.allocator, pair, "localhost");
    defer std.testing.allocator.free(cert);
    const key = try parse(cert);
    try std.testing.expectEqualSlices(u8, &pair.public_key.toUncompressedSec1(), try key.p256());
    try std.testing.expectError(error.CertificateKeyMismatch, key.rsa());
    for (0..cert.len) |size| try std.testing.expectError(error.CertificateMalformed, parse(cert[0..size]));
    const extra = try std.mem.concat(std.testing.allocator, u8, &.{ cert, "\x05\x00" });
    defer std.testing.allocator.free(extra);
    try std.testing.expectError(error.CertificateMalformed, parse(extra));
}

test "RSA listener keys require complete positive components and actual 2048 bit strength" {
    var modulus: [256]u8 = @splat(0x55);
    modulus[0] = 0x80;
    var encoded = [_]u8{ 0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00 } ++ modulus ++ [_]u8{ 0x02, 0x03, 0x01, 0x00, 0x01 };
    var key: PublicKey = .{ .algorithm = .{ .id = rsa_oid, .parameters = null }, .bytes = &encoded };
    const components = try key.rsa();
    try std.testing.expectEqualSlices(u8, &modulus, components.modulus);
    try std.testing.expectEqualStrings("\x01\x00\x01", components.exponent);
    encoded[encoded.len - 1] = 0;
    try std.testing.expectError(error.CertificateWeakKey, key.rsa());
    encoded[encoded.len - 1] = 1;
    encoded[encoded.len - 6] &= 0xfe;
    try std.testing.expectError(error.CertificateWeakKey, key.rsa());
    modulus[0] = 0x7f;
    const short = [_]u8{ 0x30, 0x82, 0x01, 0x09, 0x02, 0x82, 0x01, 0x00 } ++ modulus ++ [_]u8{ 0x02, 0x03, 0x01, 0x00, 0x01 };
    key.bytes = &short;
    try std.testing.expectError(error.CertificateWeakKey, key.rsa());
    for (0..short.len) |size| {
        key.bytes = short[0..size];
        try std.testing.expectError(error.CertificateMalformed, key.rsa());
    }
}

test "certificate structure has bounded depth element work and input size" {
    var nested: [64]u8 = @splat(0);
    var size: usize = 0;
    for (0..17) |_| {
        std.mem.copyBackwards(u8, nested[2..][0..size], nested[0..size]);
        nested[0] = 0x30;
        nested[1] = @intCast(size);
        size += 2;
    }
    var budget: usize = 4096;
    try std.testing.expectError(error.CertificateMalformed, tree(nested[0..size], 0, &budget));
    budget = 0;
    try std.testing.expectError(error.CertificateMalformed, tree("\x05\x00", 0, &budget));
    const huge = try std.testing.allocator.alloc(u8, max_certificate_bytes + 1);
    defer std.testing.allocator.free(huge);
    try std.testing.expectError(error.CertificateMalformed, parse(huge));
    for ([_][]const u8{ "\x00\x00", "\x22\x00", "\x10\x00", "\x30\x81\x00", "\x30\x82\x00\x80" }) |bad| {
        budget = 4096;
        try std.testing.expectError(error.CertificateMalformed, tree(bad, 0, &budget));
    }
}

test "hostile certificate bytes cannot escape the bounded parser" {
    var random = std.Random.DefaultPrng.init(0x51c71);
    var bytes: [256]u8 = undefined;
    for (0..4096) |index| {
        const value = bytes[0 .. index % bytes.len];
        random.random().bytes(value);
        _ = parse(value) catch continue;
    }
}
