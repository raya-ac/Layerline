const std = @import("std");
const X509 = std.crypto.Certificate;

pub const max_chain = 16;
pub const max_certificate_bytes = 128 * 1024;
pub const max_anchors = 1024;
pub const max_signature_checks = 64;

const Node = struct { tag: u8, value: []const u8, encoded: []const u8 };
const Cursor = struct {
    bytes: []const u8,
    offset: usize = 0,

    fn done(self: Cursor) bool {
        return self.offset == self.bytes.len;
    }

    fn next(self: *Cursor, expected: ?u8) !Node {
        if (self.offset >= self.bytes.len or self.bytes[self.offset] & 31 == 31) return error.CertificateMalformed;
        const start = self.offset;
        const element = std.crypto.codecs.asn1.Element.decode(self.bytes, @intCast(start)) catch return error.CertificateMalformed;
        const tag = self.bytes[start];
        if (expected) |wanted| if (tag != wanted) return error.CertificateMalformed;
        // Reject a padded length even when the decoded size needs long form.
        if (self.bytes[start + 1] > 0x80 and self.bytes[start + 2] == 0) return error.CertificateMalformed;
        self.offset = element.slice.end;
        return .{ .tag = tag, .value = element.slice.view(self.bytes), .encoded = self.bytes[start..self.offset] };
    }

    fn end(self: Cursor) !void {
        if (!self.done()) return error.CertificateMalformed;
    }
};

fn only(bytes: []const u8, tag: u8) !Node {
    var cursor: Cursor = .{ .bytes = bytes };
    const node = try cursor.next(tag);
    try cursor.end();
    return node;
}

fn positive(bytes: []const u8) ![]const u8 {
    if (bytes.len == 0 or bytes[0] & 0x80 != 0) return error.CertificateMalformed;
    if (bytes.len > 1 and bytes[0] == 0) {
        if (bytes[1] & 0x80 == 0) return error.CertificateMalformed;
        return bytes[1..];
    }
    return bytes;
}

fn smallInteger(bytes: []const u8) !u32 {
    const value = try positive(bytes);
    if (value.len > 4) return error.CertificateMalformed;
    return std.mem.readVarInt(u32, value, .big);
}

fn bitString(bytes: []const u8) ![]const u8 {
    if (bytes.len == 0 or bytes[0] > 7) return error.CertificateMalformed;
    if (bytes.len == 1 and bytes[0] != 0) return error.CertificateMalformed;
    if (bytes.len > 1 and bytes[bytes.len - 1] & ((@as(u8, 1) << @as(u3, @intCast(bytes[0]))) - 1) != 0) return error.CertificateMalformed;
    return bytes[1..];
}

fn boolean(bytes: []const u8) !bool {
    if (bytes.len != 1 or (bytes[0] != 0 and bytes[0] != 0xff)) return error.CertificateMalformed;
    return bytes[0] == 0xff;
}

fn oid(bytes: []const u8) !void {
    if (bytes.len == 0 or bytes[bytes.len - 1] & 0x80 != 0) return error.CertificateMalformed;
    var start = true;
    for (bytes) |byte| {
        if (start and byte == 0x80) return error.CertificateMalformed;
        start = byte & 0x80 == 0;
    }
}

fn slice(whole: []const u8, part: []const u8) X509.der.Element.Slice {
    const start = @intFromPtr(part.ptr) - @intFromPtr(whole.ptr);
    return .{ .start = @intCast(start), .end = @intCast(start + part.len) };
}

fn decimal(bytes: []const u8) !u16 {
    for (bytes) |byte| if (!std.ascii.isDigit(byte)) return error.CertificateMalformed;
    return std.fmt.parseInt(u16, bytes, 10) catch error.CertificateMalformed;
}

fn calendarTime(node: Node) !i64 {
    const text = node.value;
    const year_bytes: usize = switch (node.tag) {
        0x17 => if (text.len == 13) 2 else return error.CertificateMalformed,
        0x18 => if (text.len == 15) 4 else return error.CertificateMalformed,
        else => return error.CertificateMalformed,
    };
    if (text[text.len - 1] != 'Z') return error.CertificateMalformed;
    var year = try decimal(text[0..year_bytes]);
    if (year_bytes == 2) year += if (year >= 50) @as(u16, 1900) else 2000;
    if (year == 0) return error.CertificateMalformed;
    const month = try decimal(text[year_bytes..][0..2]);
    const day = try decimal(text[year_bytes + 2 ..][0..2]);
    const hour = try decimal(text[year_bytes + 4 ..][0..2]);
    const minute = try decimal(text[year_bytes + 6 ..][0..2]);
    const second = try decimal(text[year_bytes + 8 ..][0..2]);
    if (month < 1 or month > 12 or hour > 23 or minute > 59 or second > 59) return error.CertificateMalformed;
    if (day < 1 or day > std.time.epoch.getDaysInMonth(year, @enumFromInt(month))) return error.CertificateMalformed;
    var days: i64 = 0;
    if (year >= 1970) {
        for (1970..year) |value| days += std.time.epoch.getDaysInYear(@intCast(value));
    } else {
        for (year..1970) |value| days -= std.time.epoch.getDaysInYear(@intCast(value));
    }
    for (1..month) |value| days += std.time.epoch.getDaysInMonth(year, @enumFromInt(value));
    return (days + day - 1) * 86400 + @as(i64, hour) * 3600 + @as(i64, minute) * 60 + second;
}

fn name(bytes: []const u8) !void {
    var rdns: Cursor = .{ .bytes = bytes };
    var count: usize = 0;
    while (!rdns.done()) {
        count += 1;
        if (count > 128) return error.CertificateMalformed;
        var attributes: Cursor = .{ .bytes = (try rdns.next(0x31)).value };
        if (attributes.done()) return error.CertificateMalformed;
        while (!attributes.done()) {
            var attribute: Cursor = .{ .bytes = (try attributes.next(0x30)).value };
            try oid((try attribute.next(0x06)).value);
            const value = try attribute.next(null);
            if (value.tag & 0x20 != 0) return error.CertificateMalformed;
            try attribute.end();
        }
    }
}

const Extensions = struct {
    basic: bool = false,
    basic_critical: bool = false,
    ca: bool = false,
    path_length: ?u32 = null,
    usage: ?u16 = null,
    server_auth: ?bool = null,
    subject_key_id: []const u8 = "",
    authority_key_id: []const u8 = "",
    san: []const u8 = "",
    san_critical: bool = false,
    constraints: []const u8 = "",
};

fn extensions(bytes: []const u8) !Extensions {
    var result: Extensions = .{};
    var cursor: Cursor = .{ .bytes = (try only(bytes, 0x30)).value };
    var seen: [64][]const u8 = undefined;
    var count: usize = 0;
    while (!cursor.done()) {
        if (count == seen.len) return error.CertificateMalformed;
        var extension: Cursor = .{ .bytes = (try cursor.next(0x30)).value };
        const id = (try extension.next(0x06)).value;
        try oid(id);
        for (seen[0..count]) |previous| if (std.mem.eql(u8, previous, id)) return error.CertificateMalformed;
        seen[count] = id;
        count += 1;
        var node = try extension.next(null);
        var critical = false;
        if (node.tag == 0x01) {
            critical = try boolean(node.value);
            node = try extension.next(0x04);
        } else if (node.tag != 0x04) return error.CertificateMalformed;
        try extension.end();
        if (std.mem.eql(u8, id, "\x55\x1d\x13")) {
            result.basic = true;
            result.basic_critical = critical;
            var basic: Cursor = .{ .bytes = (try only(node.value, 0x30)).value };
            if (!basic.done()) {
                const first = try basic.next(null);
                if (first.tag == 0x01) {
                    result.ca = try boolean(first.value);
                    if (!basic.done()) result.path_length = try smallInteger((try basic.next(0x02)).value);
                } else if (first.tag == 0x02) {
                    result.path_length = try smallInteger(first.value);
                } else return error.CertificateMalformed;
            }
            if (!result.ca and result.path_length != null) return error.CertificateMalformed;
            try basic.end();
        } else if (std.mem.eql(u8, id, "\x55\x1d\x0f")) {
            const usage = try bitString((try only(node.value, 0x03)).value);
            if (usage.len == 0 or usage.len > 2) return error.CertificateMalformed;
            result.usage = @as(u16, usage[0]) << 8 | (if (usage.len == 2) @as(u16, usage[1]) else 0);
            if (result.usage.? & 0x007f != 0 or result.usage.? == 0) return error.CertificateMalformed;
            if (result.usage.? & 0x0180 != 0 and result.usage.? & 0x0800 == 0) return error.CertificateKeyUsage;
        } else if (std.mem.eql(u8, id, "\x55\x1d\x25")) {
            var usages: Cursor = .{ .bytes = (try only(node.value, 0x30)).value };
            result.server_auth = false;
            if (usages.done()) return error.CertificateMalformed;
            while (!usages.done()) {
                const usage = (try usages.next(0x06)).value;
                try oid(usage);
                if (std.mem.eql(u8, usage, "\x2b\x06\x01\x05\x05\x07\x03\x01") or std.mem.eql(u8, usage, "\x55\x1d\x25\x00")) result.server_auth = true;
            }
        } else if (std.mem.eql(u8, id, "\x55\x1d\x11")) {
            result.san = (try only(node.value, 0x30)).value;
            result.san_critical = critical;
            try validateNames(result.san);
        } else if (std.mem.eql(u8, id, "\x55\x1d\x0e")) {
            if (critical) return error.CertificateMalformed;
            result.subject_key_id = (try only(node.value, 0x04)).value;
            if (result.subject_key_id.len == 0) return error.CertificateMalformed;
        } else if (std.mem.eql(u8, id, "\x55\x1d\x23")) {
            if (critical) return error.CertificateMalformed;
            var authority: Cursor = .{ .bytes = (try only(node.value, 0x30)).value };
            result.authority_key_id = (try authority.next(0x80)).value;
            if (result.authority_key_id.len == 0) return error.CertificateMalformed;
            if (!authority.done()) {
                try validateNames((try authority.next(0xa1)).value);
                _ = try positive((try authority.next(0x82)).value);
            }
            try authority.end();
        } else if (std.mem.eql(u8, id, "\x55\x1d\x1e")) {
            if (!critical) return error.CertificateMalformed;
            result.constraints = (try only(node.value, 0x30)).value;
            try validateConstraints(result.constraints);
        } else if (std.mem.eql(u8, id, "\x2b\x06\x01\x05\x05\x07\x01\x01")) {
            if (critical) return error.CertificateMalformed;
            var descriptions: Cursor = .{ .bytes = (try only(node.value, 0x30)).value };
            if (descriptions.done()) return error.CertificateMalformed;
            var description_count: usize = 0;
            while (!descriptions.done()) {
                description_count += 1;
                if (description_count > 64) return error.CertificateMalformed;
                var description: Cursor = .{ .bytes = (try descriptions.next(0x30)).value };
                try oid((try description.next(0x06)).value);
                const location = try description.next(null);
                try validateNames(location.encoded);
                try description.end();
            }
        } else if (critical) return error.CertificateUnsupportedCriticalExtension;
    }
    return result;
}

pub const Certificate = struct {
    parsed: X509.Parsed,
    serial_zero: bool,
    not_before: i64,
    not_after: i64,
    policy: Extensions,

    pub fn checkTime(self: Certificate, now: i64) !void {
        if (now < self.not_before) return error.CertificateNotYetValid;
        if (now > self.not_after) return error.CertificateExpired;
    }
};

fn publicKey(algorithm: Node, key: []const u8) !X509.Parsed.PubKeyAlgo {
    var cursor: Cursor = .{ .bytes = algorithm.value };
    const id = (try cursor.next(0x06)).value;
    const category = X509.AlgorithmCategory.map.get(id) orelse return error.CertificatePublicKeyUnsupported;
    const result: X509.Parsed.PubKeyAlgo = switch (category) {
        .rsaEncryption => blk: {
            if (!cursor.done()) if ((try cursor.next(0x05)).value.len != 0) return error.CertificateMalformed;
            var rsa: Cursor = .{ .bytes = (try only(key, 0x30)).value };
            const modulus = try positive((try rsa.next(0x02)).value);
            const exponent = try positive((try rsa.next(0x02)).value);
            try rsa.end();
            if (modulus.len < 256 or modulus.len > 512 or modulus[0] == 0 or exponent.len > 8) return error.CertificateWeakKey;
            const bits = modulus.len * 8 - @clz(modulus[0]);
            if (bits < 2048) return error.CertificateWeakKey;
            const exp = std.mem.readVarInt(u64, exponent, .big);
            if (exp < 3 or exp & 1 == 0) return error.CertificateWeakKey;
            break :blk .rsaEncryption;
        },
        .X9_62_id_ecPublicKey => blk: {
            const curve = X509.NamedCurve.map.get((try cursor.next(0x06)).value) orelse return error.CertificatePublicKeyUnsupported;
            const length: usize = switch (curve) {
                .X9_62_prime256v1 => 65,
                .secp384r1 => 97,
                .secp521r1 => return error.CertificatePublicKeyUnsupported,
            };
            if (key.len != length or key[0] != 4) return error.CertificateMalformed;
            break :blk .{ .X9_62_id_ecPublicKey = curve };
        },
        .curveEd25519 => blk: {
            if (key.len != 32) return error.CertificateMalformed;
            break :blk .curveEd25519;
        },
        .rsassa_pss => return error.CertificatePublicKeyUnsupported,
    };
    try cursor.end();
    return result;
}

fn signatureAlgorithm(node: Node) !X509.Algorithm {
    var cursor: Cursor = .{ .bytes = node.value };
    const result = X509.Algorithm.map.get((try cursor.next(0x06)).value) orelse return error.CertificateSignatureAlgorithmUnsupported;
    if (!cursor.done()) {
        if ((try cursor.next(0x05)).value.len != 0) return error.CertificateMalformed;
        switch (result) {
            .curveEd25519, .ecdsa_with_SHA224, .ecdsa_with_SHA256, .ecdsa_with_SHA384, .ecdsa_with_SHA512 => return error.CertificateMalformed,
            else => {},
        }
    }
    try cursor.end();
    return result;
}

// Build the signature verifier's slices only after validating each enclosing
// structure. The legacy certificate parser is not a hostile-input boundary.
pub fn parse(bytes: []const u8) !Certificate {
    if (bytes.len > max_certificate_bytes) return error.CertificateMalformed;
    var certificate: Cursor = .{ .bytes = (try only(bytes, 0x30)).value };
    const tbs = try certificate.next(0x30);
    const algorithm = try certificate.next(0x30);
    const signature_node = try certificate.next(0x03);
    const signature = try bitString(signature_node.value);
    if (signature.len == 0 or signature_node.value[0] != 0) return error.CertificateMalformed;
    try certificate.end();
    const signature_algorithm = try signatureAlgorithm(algorithm);
    switch (signature_algorithm) {
        .ecdsa_with_SHA224, .ecdsa_with_SHA256, .ecdsa_with_SHA384, .ecdsa_with_SHA512 => {
            var parts: Cursor = .{ .bytes = (try only(signature, 0x30)).value };
            _ = try positive((try parts.next(0x02)).value);
            _ = try positive((try parts.next(0x02)).value);
            try parts.end();
        },
        else => {},
    }
    var fields: Cursor = .{ .bytes = tbs.value };
    var first = try fields.next(null);
    var version: X509.Version = .v1;
    if (first.tag == 0xa0) {
        if (try smallInteger((try only(first.value, 0x02)).value) != 2) return error.CertificateUnsupportedVersion;
        version = .v3;
        first = try fields.next(0x02);
    } else if (first.tag != 0x02) return error.CertificateMalformed;
    const serial = try positive(first.value);
    if (first.value.len > 20) return error.CertificateMalformed;
    const tbs_algorithm = try fields.next(0x30);
    if (!std.mem.eql(u8, tbs_algorithm.encoded, algorithm.encoded)) return error.CertificateSignatureAlgorithmMismatch;
    const issuer = try fields.next(0x30);
    try name(issuer.value);
    if (issuer.value.len == 0) return error.CertificateMalformed;
    var validity: Cursor = .{ .bytes = (try fields.next(0x30)).value };
    const not_before = try calendarTime(try validity.next(null));
    const not_after = try calendarTime(try validity.next(null));
    if (not_before > not_after) return error.CertificateMalformed;
    try validity.end();
    const subject = try fields.next(0x30);
    try name(subject.value);
    var spki: Cursor = .{ .bytes = (try fields.next(0x30)).value };
    const key_algorithm = try spki.next(0x30);
    const key_node = try spki.next(0x03);
    const key = try bitString(key_node.value);
    if (key_node.value[0] != 0) return error.CertificateMalformed;
    const key_kind = try publicKey(key_algorithm, key);
    try spki.end();
    const policy = if (!fields.done()) blk: {
        if (version != .v3) return error.CertificateMalformed;
        break :blk try extensions((try fields.next(0xa3)).value);
    } else Extensions{};
    try fields.end();
    if (subject.value.len == 0 and (!policy.san_critical or policy.ca)) return error.CertificateMalformed;
    if (policy.ca and (!policy.basic_critical or policy.subject_key_id.len == 0)) return error.CertificateNotCA;
    if (!policy.ca and policy.constraints.len != 0) return error.CertificateNameConstraint;
    if (!policy.ca and (policy.usage orelse 0) & 0x0400 != 0) return error.CertificateKeyUsage;
    return .{ .serial_zero = std.mem.allEqual(u8, serial, 0), .not_before = not_before, .not_after = not_after, .policy = policy, .parsed = .{
        .certificate = .{ .buffer = bytes, .index = 0 },
        .issuer_slice = slice(bytes, issuer.value),
        .subject_slice = slice(bytes, subject.value),
        .common_name_slice = .empty,
        .signature_slice = slice(bytes, signature),
        .signature_algorithm = signature_algorithm,
        .pub_key_algo = key_kind,
        .pub_key_slice = slice(bytes, key),
        .message_slice = slice(bytes, tbs.encoded),
        .subject_alt_name_slice = .empty,
        .validity = .{ .not_before = @intCast(@max(0, not_before)), .not_after = @intCast(@max(0, not_after)) },
        .version = version,
    } };
}

fn dnsValid(value: []const u8, wildcard: bool) bool {
    const text = if (wildcard and std.mem.startsWith(u8, value, "*.")) value[2..] else value;
    if (text.len == 0 or text.len > 253) return false;
    var labels = std.mem.splitScalar(u8, text, '.');
    while (labels.next()) |label| {
        if (label.len == 0 or label.len > 63 or label[0] == '-' or label[label.len - 1] == '-') return false;
        for (label) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '-') return false;
    }
    return true;
}

fn dnsMatch(reference: []const u8, presented: []const u8) bool {
    if (!dnsValid(reference, false) or !dnsValid(presented, true)) return false;
    if (std.ascii.eqlIgnoreCase(reference, presented)) return true;
    if (!std.mem.startsWith(u8, presented, "*.")) return false;
    const dot = std.mem.indexOfScalar(u8, reference, '.') orelse return false;
    return std.ascii.eqlIgnoreCase(reference[dot + 1 ..], presented[2..]);
}

fn validateNames(bytes: []const u8) !void {
    var names: Cursor = .{ .bytes = bytes };
    if (names.done()) return error.CertificateMalformed;
    var count: usize = 0;
    while (!names.done()) {
        count += 1;
        if (count > 256) return error.CertificateMalformed;
        const item = try names.next(null);
        switch (item.tag) {
            0x82 => if (!dnsValid(item.value, true)) return error.CertificateMalformed,
            0x87 => if (item.value.len != 4 and item.value.len != 16) return error.CertificateMalformed,
            0x81, 0x86 => for (item.value) |byte| {
                if (byte == 0 or byte > 127) return error.CertificateMalformed;
            },
            0xa0 => try otherName(item.value),
            0xa3, 0xa4, 0xa5, 0x88 => {},
            else => return error.CertificateMalformed,
        }
    }
}

fn otherName(bytes: []const u8) !void {
    var fields: Cursor = .{ .bytes = bytes };
    try oid((try fields.next(0x06)).value);
    var value: Cursor = .{ .bytes = (try fields.next(0xa0)).value };
    _ = try value.next(null);
    try value.end();
    try fields.end();
}

pub fn referenceName(reference_input: []const u8) ![]const u8 {
    const reference = if (std.mem.endsWith(u8, reference_input, ".")) reference_input[0 .. reference_input.len - 1] else reference_input;
    const address = std.Io.net.IpAddress.parse(reference, 0) catch null;
    if (address == null and !dnsValid(reference, false)) return error.CertificateHostMismatch;
    return reference;
}

pub fn verifyIdentity(san: []const u8, reference_input: []const u8) !void {
    if (san.len == 0) return error.CertificateHostMismatch;
    try validateNames(san);
    const reference = try referenceName(reference_input);
    const address = std.Io.net.IpAddress.parse(reference, 0) catch null;
    var names: Cursor = .{ .bytes = san };
    while (!names.done()) {
        const item = try names.next(null);
        if (address) |ip| {
            const matches = switch (ip) {
                .ip4 => |value| item.tag == 0x87 and std.mem.eql(u8, item.value, &value.bytes),
                .ip6 => |value| item.tag == 0x87 and std.mem.eql(u8, item.value, &value.bytes),
            };
            if (matches) return;
        } else if (item.tag == 0x82 and dnsMatch(reference, item.value)) return;
    }
    return error.CertificateHostMismatch;
}

fn validateConstraints(bytes: []const u8) !void {
    var fields: Cursor = .{ .bytes = bytes };
    var seen: u2 = 0;
    if (fields.done()) return error.CertificateMalformed;
    while (!fields.done()) {
        const group = try fields.next(null);
        const bit: u2 = switch (group.tag) {
            0xa0 => 1,
            0xa1 => 2,
            else => return error.CertificateMalformed,
        };
        if (seen & bit != 0) return error.CertificateMalformed;
        seen |= bit;
        var subtrees: Cursor = .{ .bytes = group.value };
        if (subtrees.done()) return error.CertificateMalformed;
        while (!subtrees.done()) {
            var tree: Cursor = .{ .bytes = (try subtrees.next(0x30)).value };
            const base = try tree.next(null);
            switch (base.tag) {
                0xa0 => try otherName(base.value),
                0x82 => {
                    if (!dnsValid(base.value, false)) return error.CertificateMalformed;
                },
                0x87 => if (base.value.len != 8 and base.value.len != 32) return error.CertificateMalformed,
                else => return error.CertificateUnsupportedNameConstraint,
            }
            if (!tree.done()) {
                const minimum = try tree.next(0x80);
                if (try smallInteger(minimum.value) != 0) return error.CertificateUnsupportedNameConstraint;
                if (!tree.done()) return error.CertificateUnsupportedNameConstraint;
            }
        }
    }
}

fn dnsWithin(value: []const u8, subtree: []const u8) bool {
    if (std.ascii.eqlIgnoreCase(value, subtree)) return true;
    return value.len > subtree.len and value[value.len - subtree.len - 1] == '.' and std.ascii.endsWithIgnoreCase(value, subtree);
}

fn dnsExcluded(value: []const u8, subtree: []const u8) bool {
    if (dnsWithin(value, subtree)) return true;
    if (!std.mem.startsWith(u8, value, "*.")) return false;
    return dnsMatch(subtree, value);
}

fn within(item: Node, base: Node, excluded: bool) bool {
    if (item.tag == 0x82) return if (excluded) dnsExcluded(item.value, base.value) else dnsWithin(item.value, base.value);
    if (item.value.len * 2 != base.value.len) return false;
    for (item.value, 0..) |byte, index| {
        const mask = base.value[item.value.len + index];
        if (byte & mask != base.value[index] & mask) return false;
    }
    return true;
}

fn checkConstraints(constraints: []const u8, san: []const u8) !void {
    var names: Cursor = .{ .bytes = san };
    while (!names.done()) {
        const item = try names.next(null);
        var groups: Cursor = .{ .bytes = constraints };
        while (!groups.done()) {
            const group = try groups.next(null);
            var subtrees: Cursor = .{ .bytes = group.value };
            var restricted = false;
            var permitted = false;
            while (!subtrees.done()) {
                var tree: Cursor = .{ .bytes = (try subtrees.next(0x30)).value };
                const base = try tree.next(null);
                if (item.tag != base.tag) continue;
                if (item.tag != 0x82 and item.tag != 0x87) return error.CertificateUnsupportedNameConstraint;
                restricted = true;
                if (within(item, base, group.tag == 0xa1)) {
                    if (group.tag == 0xa1) return error.CertificateNameConstraint;
                    permitted = true;
                }
            }
            if (group.tag == 0xa0 and restricted and !permitted) return error.CertificateNameConstraint;
        }
    }
}

fn checkUsage(certificate: Certificate, issuer: bool) !void {
    if (issuer and (!certificate.policy.basic or !certificate.policy.ca)) return error.CertificateNotCA;
    if (certificate.policy.usage) |bits| if (bits & (if (issuer) @as(u16, 0x0400) else @as(u16, 0x8000)) == 0) return error.CertificateKeyUsage;
    if (certificate.policy.server_auth) |allowed| if (!allowed) return error.CertificateExtendedKeyUsage;
}

fn strongSignature(certificate: Certificate) !void {
    switch (certificate.parsed.signature_algorithm) {
        .md2WithRSAEncryption, .md5WithRSAEncryption, .sha1WithRSAEncryption, .sha224WithRSAEncryption, .ecdsa_with_SHA224 => return error.CertificateWeakSignature,
        else => {},
    }
}

fn issuerPolicy(issuer: Certificate, descendants: []const Certificate, now: i64) !void {
    try issuer.checkTime(now);
    try checkUsage(issuer, true);
    var ca_below: usize = 0;
    for (descendants, 0..) |certificate, index| {
        const self_issued = std.mem.eql(u8, certificate.parsed.subject(), certificate.parsed.issuer());
        if (index != 0 and !self_issued) ca_below += 1;
        if (index == 0 or !self_issued) try checkConstraints(issuer.policy.constraints, certificate.policy.san);
    }
    if (issuer.policy.path_length) |limit| if (ca_below > limit) return error.CertificatePathLength;
}

const Search = struct {
    peers: []const Certificate,
    anchors: []const Certificate,
    now: i64,
    visited: [max_chain]bool = @splat(false),
    path: [max_chain]Certificate = undefined,
    signature_checks: usize = 0,

    fn verifySignature(self: *Search, certificate: Certificate, issuer: Certificate) !bool {
        if (self.signature_checks == max_signature_checks) return error.CertificateSearchLimit;
        self.signature_checks += 1;
        certificate.parsed.verify(issuer.parsed, self.now) catch return false;
        return true;
    }

    fn walk(self: *Search, index: usize, depth: usize) error{CertificateSearchLimit}!bool {
        const certificate = self.peers[index];
        certificate.checkTime(self.now) catch return false;
        self.path[depth] = certificate;
        for (self.anchors) |anchor| {
            if (std.mem.eql(u8, certificate.parsed.certificate.buffer, anchor.parsed.certificate.buffer)) return true;
        }
        if (certificate.serial_zero) return false;
        if (!std.mem.eql(u8, certificate.parsed.issuer(), certificate.parsed.subject()) and certificate.policy.authority_key_id.len == 0) return false;
        strongSignature(certificate) catch return false;
        const descendants = self.path[0 .. depth + 1];
        for (self.anchors) |anchor| {
            if (!std.mem.eql(u8, certificate.parsed.issuer(), anchor.parsed.subject())) continue;
            issuerPolicy(anchor, descendants, self.now) catch continue;
            if (try self.verifySignature(certificate, anchor)) return true;
        }
        if (depth + 1 == max_chain) return false;
        // Untrusted certificates can offer issuer candidates, never trust. A
        // bounded search handles alternate chains without cycling forever.
        for (self.peers, 0..) |issuer, next_index| {
            if (self.visited[next_index] or !std.mem.eql(u8, certificate.parsed.issuer(), issuer.parsed.subject())) continue;
            issuerPolicy(issuer, descendants, self.now) catch continue;
            if (!try self.verifySignature(certificate, issuer)) continue;
            self.visited[next_index] = true;
            defer self.visited[next_index] = false;
            if (try self.walk(next_index, depth + 1)) return true;
        }
        return false;
    }
};

/// Inputs borrow immutable, pre-parsed certificate bytes. The leaf comes first;
/// remaining candidates need not be ordered. No network fetches, implicit roots
/// or issuer promotion. Unsupported policy and exhausted work limits fail closed.
pub fn verifyChain(peers: []const Certificate, anchors: []const Certificate, reference: []const u8, now: i64) !void {
    if (peers.len == 0 or peers.len > max_chain or anchors.len > max_anchors or now < 0) return error.CertificateMalformed;
    try verifyIdentity(peers[0].policy.san, reference);
    try checkUsage(peers[0], false);
    try peers[0].checkTime(now);
    if (peers[0].serial_zero) return error.CertificateMalformed;
    var search: Search = .{ .peers = peers, .anchors = anchors, .now = now };
    search.visited[0] = true;
    if (!try search.walk(0, 0)) return error.CertificateUntrusted;
}

test "service identities use SAN DNS and exact IP bytes, not common names" {
    const san = "\x82\x0e*.example.test\x87\x04\x7f\x00\x00\x01";
    try verifyIdentity(san, "API.EXAMPLE.TEST.");
    try verifyIdentity(san, "127.0.0.1");
    for ([_][]const u8{ "example.test", "a.b.example.test", "evil.test", "127.0.0.2", "" }) |reference| {
        try std.testing.expectError(error.CertificateHostMismatch, verifyIdentity(san, reference));
    }
    try std.testing.expectError(error.CertificateHostMismatch, verifyIdentity("\x82\x09127.0.0.1", "127.0.0.1"));
    try std.testing.expectError(error.CertificateHostMismatch, verifyIdentity("", "common-name.test"));
}

test "calendar validation handles the UTC pivot and rejects impossible dates" {
    try std.testing.expectEqual(-631152000, try calendarTime(.{ .tag = 0x17, .value = "500101000000Z", .encoded = "" }));
    try std.testing.expectEqual(2524608000, try calendarTime(.{ .tag = 0x18, .value = "20500101000000Z", .encoded = "" }));
    try std.testing.expectError(error.CertificateMalformed, calendarTime(.{ .tag = 0x17, .value = "250229000000Z", .encoded = "" }));
    try std.testing.expectError(error.CertificateMalformed, calendarTime(.{ .tag = 0x18, .value = "20250101000000X", .encoded = "" }));
}

test "bounded DER rejects missing lengths oversized elements and trailing data" {
    for ([_][]const u8{ "", "\x30", "\x30\x80", "\x30\x82\x00\x80", "\x30\x7f", "\x30\x00\x00", "\x30\x02\x30\x00" }) |bytes| {
        try std.testing.expectError(error.CertificateMalformed, parse(bytes));
    }
}

test "wildcard exclusions include every possible presented identity" {
    try std.testing.expect(dnsExcluded("*.example.test", "blocked.example.test"));
    try std.testing.expect(!dnsExcluded("*.example.test", "a.blocked.example.test"));
    try std.testing.expect(dnsWithin("*.example.test", "example.test"));
    try std.testing.expect(!dnsWithin("*.example.test", "only.example.test"));
}

test "an early identity match does not hide malformed or oversized SAN lists" {
    const valid = "\x82\x0capi.test.dev";
    try std.testing.expectError(error.CertificateMalformed, verifyIdentity(valid ++ "\x82\x01*", "api.test.dev"));
    try std.testing.expectError(error.CertificateMalformed, verifyIdentity(valid ++ "\x87\x01\x7f", "api.test.dev"));
    try std.testing.expectError(error.CertificateMalformed, verifyIdentity("\x82\x01a" ** 257, "a"));
}

test "DER parser rejects bounded deterministic hostile byte strings" {
    var prng = std.Random.DefaultPrng.init(0x4c617965726c696e);
    const random = prng.random();
    var bytes: [2048]u8 = undefined;
    for (0..8192) |_| {
        const length = random.uintLessThan(usize, bytes.len + 1);
        random.bytes(bytes[0..length]);
        if (parse(bytes[0..length])) |_| return error.RandomCertificateAccepted else |_| {}
    }
}
