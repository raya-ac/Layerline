const std = @import("std");
const policy = @import("upstream_certificate.zig");

pub const max_file_bytes = 8 * 1024 * 1024;
pub const Store = struct {
    allocator: std.mem.Allocator,
    anchors: []const policy.Certificate,
    skipped: usize,

    pub fn deinit(self: *Store) void {
        for (self.anchors) |anchor| self.allocator.free(anchor.parsed.certificate.buffer);
        self.allocator.free(self.anchors);
        self.* = undefined;
    }
};

pub const Snapshot = struct {
    allocator: std.mem.Allocator,
    entries: std.ArrayList(Entry) = .empty,
    const Entry = struct { path: ?[]const u8, store: *Store };

    pub fn create(allocator: std.mem.Allocator) !*Snapshot {
        const self = try allocator.create(Snapshot);
        self.* = .{ .allocator = allocator };
        return self;
    }

    pub fn get(self: *Snapshot, io: std.Io, path: ?[]const u8) !*Store {
        for (self.entries.items) |entry| {
            if (path == null and entry.path == null) return entry.store;
            if (path != null and entry.path != null and std.mem.eql(u8, path.?, entry.path.?)) return entry.store;
        }
        var store = if (path) |file| try load(io, self.allocator, file, false) else try loadSystem(io, self.allocator);
        errdefer store.deinit();
        const owned_path = if (path) |file| try self.allocator.dupe(u8, file) else null;
        errdefer if (owned_path) |file| self.allocator.free(file);
        const stable = try self.allocator.create(Store);
        errdefer self.allocator.destroy(stable);
        stable.* = store;
        try self.entries.append(self.allocator, .{ .path = owned_path, .store = stable });
        if (!@import("builtin").is_test) std.debug.print("{{\"event\":\"server.upstream_trust_loaded\",\"system\":{},\"anchors\":{d},\"skipped\":{d}}}\n", .{ path == null, store.anchors.len, store.skipped });
        return stable;
    }

    pub fn destroy(self: *Snapshot) void {
        const allocator = self.allocator;
        for (self.entries.items) |entry| {
            entry.store.deinit();
            allocator.destroy(entry.store);
            if (entry.path) |path| allocator.free(path);
        }
        self.entries.deinit(allocator);
        allocator.destroy(self);
    }
};

pub fn fromPem(allocator: std.mem.Allocator, pem: []const u8, skip_unusable: bool) !Store {
    if (pem.len > max_file_bytes) return error.TrustFileTooLarge;
    const begin = "-----BEGIN CERTIFICATE-----";
    const end = "-----END CERTIFICATE-----";
    const decoder = std.base64.standard.decoderWithIgnore(" \t\r\n");
    var anchors: std.ArrayList(policy.Certificate) = .empty;
    errdefer {
        for (anchors.items) |anchor| allocator.free(anchor.parsed.certificate.buffer);
        anchors.deinit(allocator);
    }
    var offset: usize = 0;
    var count: usize = 0;
    var skipped: usize = 0;
    while (std.mem.indexOfPos(u8, pem, offset, begin)) |start| {
        if (count == policy.max_anchors) return error.TooManyTrustAnchors;
        count += 1;
        const body_start = start + begin.len;
        const body_end = std.mem.indexOfPos(u8, pem, body_start, end) orelse return error.MalformedTrustPem;
        const body = pem[body_start..body_end];
        offset = body_end + end.len;
        var characters: usize = 0;
        for (body) |byte| if (std.mem.indexOfScalar(u8, " \t\r\n", byte) == null) {
            characters += 1;
        };
        if (characters == 0 or characters > (policy.max_certificate_bytes + 2) / 3 * 4) return error.MalformedTrustPem;
        var bytes = try allocator.alloc(u8, decoder.calcSizeUpperBound(characters));
        errdefer allocator.free(bytes);
        const size = decoder.decode(bytes, body) catch return error.MalformedTrustPem;
        if (size == 0 or size > policy.max_certificate_bytes) return error.MalformedTrustPem;
        bytes = try allocator.realloc(bytes, size);
        const certificate = policy.parse(bytes) catch |err| {
            if (!skip_unusable) return err;
            allocator.free(bytes);
            skipped += 1;
            continue;
        };
        try anchors.append(allocator, certificate);
    }
    if (anchors.items.len == 0) return error.NoTrustAnchors;
    return .{ .allocator = allocator, .anchors = try anchors.toOwnedSlice(allocator), .skipped = skipped };
}

pub fn load(io: std.Io, allocator: std.mem.Allocator, path: []const u8, system: bool) !Store {
    const bytes = try std.Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(max_file_bytes));
    defer allocator.free(bytes);
    defer std.crypto.secureZero(u8, bytes);
    return fromPem(allocator, bytes, system);
}

pub fn loadSystem(io: std.Io, allocator: std.mem.Allocator) !Store {
    const paths: []const []const u8 = switch (@import("builtin").os.tag) {
        .macos => &.{"/etc/ssl/cert.pem"},
        .linux => &.{ "/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/ca-bundle.pem", "/etc/pki/tls/cacert.pem", "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", "/etc/ssl/cert.pem" },
        else => return error.SystemTrustUnsupported,
    };
    for (paths) |path| return load(io, allocator, path, true) catch |err| switch (err) {
        error.FileNotFound => continue,
        else => return err,
    };
    return error.NoSystemTrustBundle;
}

test "trust imports reject empty malformed oversized and missing certificate data" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.NoTrustAnchors, fromPem(allocator, "not a certificate", false));
    try std.testing.expectError(error.MalformedTrustPem, fromPem(allocator, "-----BEGIN CERTIFICATE-----", false));
    try std.testing.expectError(error.MalformedTrustPem, fromPem(allocator, "-----BEGIN CERTIFICATE-----!!-----END CERTIFICATE-----", false));
    try std.testing.expectError(error.CertificateMalformed, fromPem(allocator, "-----BEGIN CERTIFICATE-----MAA=-----END CERTIFICATE-----", false));
    try std.testing.expectError(error.NoTrustAnchors, fromPem(allocator, "-----BEGIN CERTIFICATE-----MAA=-----END CERTIFICATE-----", true));
    const too_large = try allocator.alloc(u8, max_file_bytes + 1);
    defer allocator.free(too_large);
    @memset(too_large, ' ');
    try std.testing.expectError(error.TrustFileTooLarge, fromPem(allocator, too_large, false));
}

test "trust owns decoded bytes and cleans up every allocation failure" {
    const allocator = std.testing.allocator;
    const pair = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(0x39));
    const der = try @import("tls13_native.zig").buildSelfSignedEd25519Certificate(allocator, pair, "localhost");
    defer allocator.free(der);
    const encoder = std.base64.standard.Encoder;
    const encoded = try allocator.alloc(u8, encoder.calcSize(der.len));
    defer allocator.free(encoded);
    _ = encoder.encode(encoded, der);
    const pem = try std.fmt.allocPrint(allocator, "-----BEGIN CERTIFICATE-----\n{s}\n-----END CERTIFICATE-----\n", .{encoded});
    defer allocator.free(pem);
    const Check = struct {
        fn load(failing: std.mem.Allocator, source: []const u8, expected: []const u8) !void {
            var store = try fromPem(failing, source, false);
            defer store.deinit();
            try std.testing.expectEqual(1, store.anchors.len);
            try std.testing.expectEqualSlices(u8, expected, store.anchors[0].parsed.certificate.buffer);
            try std.testing.expectEqual(0, store.skipped);
        }
    };
    try std.testing.checkAllAllocationFailures(allocator, Check.load, .{ pem, der });
    const mixed = try std.mem.concat(allocator, u8, &.{ "-----BEGIN CERTIFICATE-----MAA=-----END CERTIFICATE-----\n", pem });
    defer allocator.free(mixed);
    try std.testing.expectError(error.CertificateMalformed, fromPem(allocator, mixed, false));
    var store = try fromPem(allocator, mixed, true);
    defer store.deinit();
    @memset(mixed, 0);
    try std.testing.expectEqual(1, store.skipped);
    try std.testing.expectEqualSlices(u8, der, store.anchors[0].parsed.certificate.buffer);
    const excess = try allocator.alloc(u8, pem.len * (policy.max_anchors + 1));
    defer allocator.free(excess);
    for (0..policy.max_anchors + 1) |index| @memcpy(excess[index * pem.len ..][0..pem.len], pem);
    try std.testing.expectError(error.TooManyTrustAnchors, fromPem(allocator, excess, false));
}

test "trust snapshots deduplicate paths without moving borrowed stores" {
    const allocator = std.testing.allocator;
    const pair = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(@splat(0x58));
    const der = try @import("tls13_native.zig").buildSelfSignedEd25519Certificate(allocator, pair, "localhost");
    defer allocator.free(der);
    const encoded = try allocator.alloc(u8, std.base64.standard.Encoder.calcSize(der.len));
    defer allocator.free(encoded);
    _ = std.base64.standard.Encoder.encode(encoded, der);
    const pem = try std.fmt.allocPrint(allocator, "-----BEGIN CERTIFICATE-----\n{s}\n-----END CERTIFICATE-----\n", .{encoded});
    defer allocator.free(pem);
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.writeFile(std.testing.io, .{ .sub_path = "one.pem", .data = pem });
    try temporary.dir.writeFile(std.testing.io, .{ .sub_path = "two.pem", .data = pem });
    const one = try temporary.dir.realPathFileAlloc(std.testing.io, "one.pem", allocator);
    defer allocator.free(one);
    const two = try temporary.dir.realPathFileAlloc(std.testing.io, "two.pem", allocator);
    defer allocator.free(two);
    const Check = struct {
        fn load(failing: std.mem.Allocator, first: []const u8, second: []const u8) !void {
            const snapshot = try Snapshot.create(failing);
            defer snapshot.destroy();
            const a = try snapshot.get(std.testing.io, first);
            const b = try snapshot.get(std.testing.io, second);
            try std.testing.expect(a != b);
            try std.testing.expect(a == try snapshot.get(std.testing.io, first));
            try std.testing.expectEqual(2, snapshot.entries.items.len);
            try std.testing.expectEqualSlices(u8, a.anchors[0].parsed.certificate.buffer, b.anchors[0].parsed.certificate.buffer);
        }
    };
    try std.testing.checkAllAllocationFailures(allocator, Check.load, .{ one, two });
}
