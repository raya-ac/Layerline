const std = @import("std");
const candidate_mod = @import("config_candidate.zig");
const config = @import("config.zig");
const store_mod = @import("config_store.zig");
const tls = @import("tls13_native.zig");
const tls_material = @import("tls_material.zig");
const upstream_material = @import("upstream_material.zig");

const Candidate = candidate_mod.Candidate;
const rsa_secret: [64]u8 = @splat(0xd3);

const WipeAllocator = struct {
    backing: std.mem.Allocator,
    ec_secret: [32]u8,
    checked_frees: usize = 0,

    fn allocator(self: *WipeAllocator) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }

    fn alloc(context: *anyopaque, len: usize, alignment: std.mem.Alignment, address: usize) ?[*]u8 {
        const self: *WipeAllocator = @ptrCast(@alignCast(context));
        return self.backing.rawAlloc(len, alignment, address);
    }

    fn resize(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) bool {
        return false;
    }

    fn remap(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) ?[*]u8 {
        return null;
    }

    fn free(context: *anyopaque, memory: []u8, alignment: std.mem.Alignment, address: usize) void {
        const self: *WipeAllocator = @ptrCast(@alignCast(context));
        // Arena.deinit calls rawFree before any allocator poisoning. Reading
        // after backing.free would hide the bug and access released storage.
        if (std.mem.indexOf(u8, memory, &self.ec_secret) != null or std.mem.indexOf(u8, memory, &rsa_secret) != null) @panic("arena released with signing key bytes");
        self.checked_frees += 1;
        self.backing.rawFree(memory, alignment, address);
    }
};

const Fixture = struct {
    temporary: std.testing.TmpDir,
    root: []const u8,
    path: []const u8,
    empty_path: []const u8,
    secret: [32]u8,

    fn init() !Fixture {
        const allocator = std.testing.allocator;
        var temporary = std.testing.tmpDir(.{});
        errdefer temporary.cleanup();
        var buffer: [4096]u8 = undefined;
        const size = try temporary.dir.realPath(std.testing.io, &buffer);
        const root = try allocator.dupe(u8, buffer[0..size]);
        errdefer allocator.free(root);
        const path = try std.fmt.allocPrint(allocator, "{s}/server.conf", .{root});
        errdefer allocator.free(path);
        const empty_path = try std.fmt.allocPrint(allocator, "{s}/empty.conf", .{root});
        errdefer allocator.free(empty_path);
        const pair = try tls.EcdsaP256Sha256.KeyPair.generateDeterministic(@splat(0x27));
        const cert = try tls.buildSelfSignedEcdsaP256Sha256Certificate(allocator, pair, "localhost");
        defer allocator.free(cert);
        try pem(temporary.dir, "cert.pem", "CERTIFICATE", cert);
        const key = [_]u8{ 0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20 } ++ pair.secret_key.toBytes();
        try pem(temporary.dir, "key.pem", "EC PRIVATE KEY", &key);
        try temporary.dir.writeFile(std.testing.io, .{ .sub_path = "empty.conf", .data = "admin = false\nhttp3 = false\n" });
        var fixture: Fixture = .{ .temporary = temporary, .root = root, .path = path, .empty_path = empty_path, .secret = pair.secret_key.toBytes() };
        try fixture.write("");
        return fixture;
    }

    fn pem(dir: std.Io.Dir, name: []const u8, label: []const u8, der: []const u8) !void {
        const allocator = std.testing.allocator;
        const encoded = try allocator.alloc(u8, std.base64.standard.Encoder.calcSize(der.len));
        defer allocator.free(encoded);
        _ = std.base64.standard.Encoder.encode(encoded, der);
        const contents = try std.fmt.allocPrint(allocator, "-----BEGIN {s}-----\n{s}\n-----END {s}-----\n", .{ label, encoded, label });
        defer allocator.free(contents);
        try dir.writeFile(std.testing.io, .{ .sub_path = name, .data = contents });
    }

    fn write(self: *Fixture, extra: []const u8) !void {
        const contents = try std.fmt.allocPrint(std.testing.allocator, "host = 127.0.0.1\nport = 8080\nadmin = false\nhttp3 = false\ntls = true\ntls_cert = {s}/cert.pem\ntls_key = {s}/key.pem\nserver = secure\nserver_name.secure = secure.test\nserver_tls_cert.secure = {s}/cert.pem\nserver_tls_key.secure = {s}/key.pem\nproxy = https://localhost:8443 tls_ca_file={s}/cert.pem\n{s}", .{ self.root, self.root, self.root, self.root, self.root, extra });
        defer std.testing.allocator.free(contents);
        try self.temporary.dir.writeFile(std.testing.io, .{ .sub_path = "server.conf", .data = contents });
    }

    fn deinit(self: *Fixture) void {
        std.testing.allocator.free(self.root);
        std.testing.allocator.free(self.path);
        std.testing.allocator.free(self.empty_path);
        self.temporary.cleanup();
    }
};

fn addRsa(value: *Candidate) !void {
    const allocator = value.arena.?.allocator();
    var domain = try config.initDomainConfig(allocator, "rsa-cleanup");
    domain.tls_material = .{ .certificate_chain = &.{}, .private_key = .{ .rsa = .{
        .modulus = try allocator.dupe(u8, "public modulus"),
        .public_exponent = try allocator.dupe(u8, "public exponent"),
        .private_exponent = try allocator.dupe(u8, &rsa_secret),
    } } };
    try value.cfg.domains.append(allocator, domain);
}

fn expectLive(value: *const Candidate, secret: [32]u8) !void {
    const key = value.cfg.tls_material.?.private_key.ecdsa_p256.secret_key.toBytes();
    try std.testing.expectEqualSlices(u8, &secret, &key);
    try std.testing.expect(std.mem.indexOf(u8, std.mem.asBytes(&value.cfg.tls_material.?.private_key.ecdsa_p256), &secret) != null);
    try std.testing.expect(value.cfg.domains.items[0].tls_material != null);
    try std.testing.expect(value.cfg.upstream_trust_snapshot != null);
    try std.testing.expect(value.cfg.upstream.?.targets.items[0].tls_trust != null);
}

fn retire(cfg: *config.ServerConfig) void {
    upstream_material.deinitAll(cfg);
    tls_material.wipeAll(cfg);
}

test "validation candidates erase global domain and RSA keys before freeing their arena" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var watch: WipeAllocator = .{ .backing = std.testing.allocator, .ec_secret = fixture.secret };
    var value = try Candidate.load(std.testing.io, watch.allocator(), fixture.path, null);
    defer value.deinit();
    try expectLive(&value, fixture.secret);
    try addRsa(&value);
    value.deinit();
    value.deinit();
    try std.testing.expect(value.arena == null);
    try std.testing.expect(watch.checked_frees > 0);
}

test "canceled stale overflowing absent and allocation-failed publications retain candidate cleanup" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    for (0..5) |mode| {
        var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        var store: store_mod.Store = .{};
        defer store.deinit();
        var initial = config.defaultServerConfig();
        if (mode != 3) try store.installInitial(failing.allocator(), &initial, retire);
        var watch: WipeAllocator = .{ .backing = std.testing.allocator, .ec_secret = fixture.secret };
        var value = try Candidate.load(std.testing.io, watch.allocator(), fixture.path, null);
        defer value.deinit();
        try addRsa(&value);
        var shutdown: std.atomic.Value(bool) = .init(mode == 0);
        if (mode == 2) store.generation = std.math.maxInt(u64);
        if (mode == 4) failing.fail_index = failing.alloc_index;
        const expected = [_]anyerror{ error.Canceled, error.ConfigChangedDuringReload, error.Overflow, error.ConfigNotInstalled, error.OutOfMemory };
        try std.testing.expectError(expected[mode], value.publish(&store, if (mode == 1) 0 else 1, &shutdown));
        try std.testing.expect(value.arena != null);
        try expectLive(&value, fixture.secret);
        value.deinit();
        try std.testing.expect(watch.checked_frees > 0);
    }
}

test "real snapshot backpressure rejects a loaded candidate without losing its secrets cleanup" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var store: store_mod.Store = .{};
    defer store.deinit();
    var initial = config.defaultServerConfig();
    try store.installInitial(std.testing.allocator, &initial, retire);
    var leases: [store_mod.Store.max_snapshots - 1]?store_mod.Lease = @splat(null);
    defer for (&leases) |*item| if (item.*) |*lease| lease.deinit();
    var shutdown: std.atomic.Value(bool) = .init(false);
    for (&leases, 1..) |*lease, generation| {
        lease.* = store.acquire().?;
        var next = try Candidate.load(std.testing.io, std.testing.allocator, fixture.empty_path, null);
        defer next.deinit();
        try next.publish(&store, generation, &shutdown);
    }
    var watch: WipeAllocator = .{ .backing = std.testing.allocator, .ec_secret = fixture.secret };
    var value = try Candidate.load(std.testing.io, watch.allocator(), fixture.path, null);
    defer value.deinit();
    try addRsa(&value);
    try std.testing.expectError(error.TooManyLiveConfigGenerations, value.publish(&store, store_mod.Store.max_snapshots, &shutdown));
    try expectLive(&value, fixture.secret);
    value.deinit();
    try std.testing.expect(watch.checked_frees > 0);
}

test "successful publication keeps keys and trust until its last reader retires" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var watch: WipeAllocator = .{ .backing = std.testing.allocator, .ec_secret = fixture.secret };
    var store: store_mod.Store = .{};
    defer store.deinit();
    var initial = config.defaultServerConfig();
    try store.installInitial(std.testing.allocator, &initial, retire);
    var value = try Candidate.load(std.testing.io, watch.allocator(), fixture.path, null);
    defer value.deinit();
    try addRsa(&value);
    const cfg = value.cfg;
    var shutdown: std.atomic.Value(bool) = .init(false);
    try value.publish(&store, 1, &shutdown);
    try std.testing.expect(value.arena == null);
    try std.testing.expectError(error.ConfigCandidateConsumed, value.publish(&store, 1, &shutdown));
    value.deinit();
    try std.testing.expectEqualSlices(u8, &fixture.secret, &cfg.tls_material.?.private_key.ecdsa_p256.secret_key.toBytes());
    var held = store.acquire().?;
    defer held.deinit();
    var next = try Candidate.load(std.testing.io, std.testing.allocator, fixture.empty_path, null);
    defer next.deinit();
    try next.publish(&store, 2, &shutdown);
    try std.testing.expectEqualSlices(u8, &rsa_secret, cfg.domains.items[1].tls_material.?.private_key.rsa.private_exponent);
    try std.testing.expect(cfg.upstream_trust_snapshot != null);
    const before = watch.checked_frees;
    held.deinit();
    try std.testing.expect(watch.checked_frees > before);
    try std.testing.expectEqual(1, store.stats().snapshots);
}

test "later TLS and root loading failures erase previously loaded signing keys" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    for ([_][]const u8{ "server_tls_cert.secure = /missing-layerline-fixture-cert.pem\n", "proxy = https://localhost:8443 tls_ca_file=/missing-layerline-fixture-ca.pem\n" }) |extra| {
        try fixture.write(extra);
        var watch: WipeAllocator = .{ .backing = std.testing.allocator, .ec_secret = fixture.secret };
        try std.testing.expectError(error.FileNotFound, Candidate.load(std.testing.io, watch.allocator(), fixture.path, null));
        try std.testing.expect(watch.checked_frees > 0);
    }
}

fn allocationFailure(backing: std.mem.Allocator, path: []const u8, secret: [32]u8) !void {
    var watch: WipeAllocator = .{ .backing = backing, .ec_secret = secret };
    var value = try Candidate.load(std.testing.io, watch.allocator(), path, null);
    defer value.deinit();
    try expectLive(&value, secret);
}

test "candidate config key and trust allocations clean up every failed allocation" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationFailure, .{ fixture.path, fixture.secret });
}

test "reload compatibility is checked before reading changed key files" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var active = try Candidate.load(std.testing.io, std.testing.allocator, fixture.path, null);
    defer active.deinit();
    try fixture.write("port = 8081\ntls_cert = /missing-layerline-fixture-cert.pem\n");
    try std.testing.expectError(error.ReloadRequiresRestart, Candidate.load(std.testing.io, std.testing.allocator, fixture.path, active.cfg));
}
