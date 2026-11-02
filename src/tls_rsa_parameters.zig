const std = @import("std");

pub const Components = struct {
    n: []const u8,
    e: []const u8,
    d: []const u8,
    p: []const u8,
    q: []const u8,
    dp: []const u8,
    dq: []const u8,
    q_inverse: []const u8,
};

pub fn validate(parts: Components) error{InvalidRsaPrivateKey}!void {
    for ([_][]const u8{ parts.n, parts.e, parts.d, parts.p, parts.q, parts.dp, parts.dq, parts.q_inverse }) |bytes| {
        if (bytes.len == 0 or bytes.len > 512) return error.InvalidRsaPrivateKey;
    }
    if (parts.e.len > 4) return error.InvalidRsaPrivateKey;
    var values = struct {
        n: u4096,
        e: u4096,
        d: u4096,
        p: u4096,
        q: u4096,
        dp: u4096,
        dq: u4096,
        q_inverse: u4096,
        p_minus_one: u4096 = 0,
        q_minus_one: u4096 = 0,
        product: u8192 = 0,
    }{
        .n = std.mem.readVarInt(u4096, parts.n, .big),
        .e = std.mem.readVarInt(u4096, parts.e, .big),
        .d = std.mem.readVarInt(u4096, parts.d, .big),
        .p = std.mem.readVarInt(u4096, parts.p, .big),
        .q = std.mem.readVarInt(u4096, parts.q, .big),
        .dp = std.mem.readVarInt(u4096, parts.dp, .big),
        .dq = std.mem.readVarInt(u4096, parts.dq, .big),
        .q_inverse = std.mem.readVarInt(u4096, parts.q_inverse, .big),
    };
    defer std.crypto.secureZero(u8, std.mem.asBytes(&values));
    if (values.n < 3 or values.e < 3 or values.e & 1 == 0 or values.e >= values.n or values.d == 0 or values.d >= values.n) return error.InvalidRsaPrivateKey;
    if (values.p < 3 or values.q < 3 or values.p & 1 == 0 or values.q & 1 == 0 or values.p == values.q) return error.InvalidRsaPrivateKey;
    if (values.dp == 0 or values.dq == 0 or values.q_inverse == 0 or values.q_inverse >= values.p) return error.InvalidRsaPrivateKey;

    // The signer keeps only n/e/d. Check the complete supplied tuple first,
    // rather than accepting a matching public key with an unusable secret.
    values.product = @as(u8192, values.p) * values.q;
    if (values.product != values.n) return error.InvalidRsaPrivateKey;
    values.p_minus_one = values.p - 1;
    values.q_minus_one = values.q - 1;
    values.product = @as(u8192, values.e) * values.d;
    if (values.product % values.p_minus_one != 1 or values.product % values.q_minus_one != 1) return error.InvalidRsaPrivateKey;
    if (values.d % values.p_minus_one != values.dp or values.d % values.q_minus_one != values.dq) return error.InvalidRsaPrivateKey;
    values.product = @as(u8192, values.q) * values.q_inverse;
    if (values.product % values.p != 1) return error.InvalidRsaPrivateKey;
}

const toy: Components = .{ .n = "\x0c\xa1", .e = "\x11", .d = "\x0a\xc1", .p = "\x3d", .q = "\x35", .dp = "\x35", .dq = "\x31", .q_inverse = "\x26" };

test "RSA algebraic admission checks every supplied component" {
    try validate(toy);
    inline for (std.meta.fields(Components)) |field| {
        var changed = toy;
        var bytes: [2]u8 = @splat(0);
        const original = @field(toy, field.name);
        @memcpy(bytes[0..original.len], original);
        bytes[original.len - 1] ^= 1;
        @field(changed, field.name) = bytes[0..original.len];
        try std.testing.expectError(error.InvalidRsaPrivateKey, validate(changed));
    }
}

test "RSA admission bounds integers and rejects zero and repeated factors" {
    inline for (std.meta.fields(Components)) |field| {
        var changed = toy;
        @field(changed, field.name) = "";
        try std.testing.expectError(error.InvalidRsaPrivateKey, validate(changed));
        @field(changed, field.name) = "\x00";
        try std.testing.expectError(error.InvalidRsaPrivateKey, validate(changed));
        @field(changed, field.name) = &(@as([513]u8, @splat(0xff)));
        try std.testing.expectError(error.InvalidRsaPrivateKey, validate(changed));
    }
    var changed = toy;
    changed.q = changed.p;
    try std.testing.expectError(error.InvalidRsaPrivateKey, validate(changed));
    changed = toy;
    changed.e = "\x01\x00\x00\x00\x01";
    try std.testing.expectError(error.InvalidRsaPrivateKey, validate(changed));
}
