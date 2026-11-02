const std = @import("std");
const tls = @import("tls13_native.zig");

pub const Algorithm = enum { ecdsa, ed25519 };
pub const max_identities = 64;
const max_cached_name = 253;

pub const Identity = struct {
    name: []u8,
    certificate: []u8,
    key: union(Algorithm) {
        ecdsa: tls.EcdsaP256Sha256.KeyPair,
        ed25519: tls.Ed25519.KeyPair,
    },

    pub fn create(io: std.Io, allocator: std.mem.Allocator, name: []const u8, algorithm: Algorithm) !*Identity {
        var seed: [32]u8 = undefined;
        defer std.crypto.secureZero(u8, &seed);
        try io.randomSecure(&seed);
        const identity = try allocator.create(Identity);
        errdefer allocator.destroy(identity);
        identity.name = try allocator.dupe(u8, name);
        errdefer allocator.free(identity.name);
        identity.key = switch (algorithm) {
            .ecdsa => .{ .ecdsa = try tls.EcdsaP256Sha256.KeyPair.generateDeterministic(seed) },
            .ed25519 => .{ .ed25519 = try tls.Ed25519.KeyPair.generateDeterministic(seed) },
        };
        errdefer std.crypto.secureZero(u8, std.mem.asBytes(&identity.key));
        identity.certificate = switch (identity.key) {
            .ecdsa => |key| try tls.buildSelfSignedEcdsaP256Sha256Certificate(allocator, key, name),
            .ed25519 => |key| try tls.buildSelfSignedEd25519Certificate(allocator, key, name),
        };
        return identity;
    }

    pub fn destroy(self: *Identity, allocator: std.mem.Allocator) void {
        std.crypto.secureZero(u8, std.mem.asBytes(&self.key));
        if (@import("builtin").is_test) std.debug.assert(std.mem.allEqual(u8, std.mem.asBytes(&self.key), 0));
        allocator.free(self.certificate);
        allocator.free(self.name);
        allocator.destroy(self);
    }
};

pub const Reference = struct {
    identity: *const Identity,
    owner: ?std.mem.Allocator = null,

    pub fn deinit(self: *Reference) void {
        if (self.owner) |allocator| @constCast(self.identity).destroy(allocator);
        self.* = undefined;
    }
};

// Published identities never move or evict. The process owner destroys them only
// after all connection workers join, independently of config reload lifetimes.
pub const Store = struct {
    allocator: ?std.mem.Allocator = null,
    mutex: std.Io.Mutex = .init,
    entries: [max_identities]?*Identity = @splat(null),
    count: usize = 0,

    fn find(self: *Store, name: []const u8, algorithm: Algorithm) ?*const Identity {
        for (self.entries[0..self.count]) |entry| {
            const identity = entry.?;
            if (std.meta.activeTag(identity.key) == algorithm and std.ascii.eqlIgnoreCase(identity.name, name)) return identity;
        }
        return null;
    }

    pub fn acquire(self: *Store, io: std.Io, fallback: std.mem.Allocator, name: []const u8, algorithm: Algorithm) !Reference {
        return self.acquireUsing(io, fallback, name, algorithm, Identity.create);
    }

    fn acquireUsing(self: *Store, io: std.Io, fallback: std.mem.Allocator, name: []const u8, algorithm: Algorithm, comptime create: anytype) !Reference {
        const allocator = self.allocator orelse return .{ .identity = try create(io, fallback, name, algorithm), .owner = fallback };
        if (name.len > max_cached_name) return .{ .identity = try create(io, fallback, name, algorithm), .owner = fallback };
        self.mutex.lockUncancelable(io);
        const existing = self.find(name, algorithm);
        self.mutex.unlock(io);
        if (existing) |identity| return .{ .identity = identity };

        // Key generation and allocation stay outside the registry lock. A second
        // creator may win; erase our duplicate rather than replacing its pointer.
        const fresh = try create(io, allocator, name, algorithm);
        self.mutex.lockUncancelable(io);
        const winner = self.find(name, algorithm);
        if (winner == null and self.count < self.entries.len) {
            self.entries[self.count] = fresh;
            self.count += 1;
            self.mutex.unlock(io);
            return .{ .identity = fresh };
        }
        self.mutex.unlock(io);
        if (winner) |identity| {
            fresh.destroy(allocator);
            return .{ .identity = identity };
        }
        return .{ .identity = fresh, .owner = allocator };
    }

    pub fn warm(self: *Store, io: std.Io) !void {
        const allocator = self.allocator orelse return error.DevelopmentTlsNotInitialized;
        for ([_]Algorithm{ .ecdsa, .ed25519 }) |algorithm| {
            var identity = try self.acquire(io, allocator, "localhost", algorithm);
            identity.deinit();
        }
    }

    pub fn deinit(self: *Store) void {
        const allocator = self.allocator orelse return;
        for (self.entries[0..self.count]) |identity| identity.?.destroy(allocator);
        self.* = .{};
    }
};

test "development identities reuse host and algorithm without moving borrowed data" {
    var store = Store{ .allocator = std.testing.allocator };
    defer store.deinit();
    var first = try store.acquire(std.testing.io, std.testing.allocator, "localhost", .ecdsa);
    defer first.deinit();
    var second = try store.acquire(std.testing.io, std.testing.allocator, "LOCALHOST", .ecdsa);
    defer second.deinit();
    try std.testing.expect(first.identity == second.identity);
    var other = try store.acquire(std.testing.io, std.testing.allocator, "other.test", .ed25519);
    defer other.deinit();
    try std.testing.expect(first.identity != other.identity);
    try std.testing.expectEqualStrings("localhost", first.identity.name);
    const certificate = try @import("tls_certificate_key.zig").parse(first.identity.certificate);
    try std.testing.expectEqualSlices(u8, &first.identity.key.ecdsa.public_key.toUncompressedSec1(), try certificate.p256());
}

test "full or uninitialized development stores retain owned uncached fallback" {
    const Fake = struct {
        var key: tls.EcdsaP256Sha256.KeyPair = undefined;
        fn create(_: std.Io, allocator: std.mem.Allocator, name: []const u8, _: Algorithm) !*Identity {
            const result = try allocator.create(Identity);
            errdefer allocator.destroy(result);
            const owned_name = try allocator.dupe(u8, name);
            errdefer allocator.free(owned_name);
            result.* = .{ .name = owned_name, .certificate = try allocator.dupe(u8, "fixture"), .key = .{ .ecdsa = key } };
            return result;
        }
    };
    Fake.key = try tls.EcdsaP256Sha256.KeyPair.generateDeterministic(@splat(0x13));
    defer std.crypto.secureZero(u8, std.mem.asBytes(&Fake.key));
    var store = Store{ .allocator = std.testing.allocator };
    defer store.deinit();
    var first: ?*const Identity = null;
    for (0..max_identities + 2) |index| {
        var buffer: [32]u8 = undefined;
        const name = try std.fmt.bufPrint(&buffer, "fixture-{d}.test", .{index});
        var ref = try store.acquireUsing(std.testing.io, std.testing.allocator, name, .ecdsa, Fake.create);
        defer ref.deinit();
        try std.testing.expectEqual(index >= max_identities, ref.owner != null);
        if (first == null) first = ref.identity;
        try std.testing.expectEqualStrings("fixture-0.test", first.?.name);
    }
    try std.testing.expectEqual(max_identities, store.count);
    var long = try store.acquireUsing(std.testing.io, std.testing.allocator, &(@as([254]u8, @splat('x'))), .ecdsa, Fake.create);
    defer long.deinit();
    try std.testing.expect(long.owner != null);
    var empty = Store{};
    var uncached = try empty.acquireUsing(std.testing.io, std.testing.allocator, "localhost", .ecdsa, Fake.create);
    defer uncached.deinit();
    try std.testing.expect(uncached.owner != null);
}

test "development identity allocation failures release their key and owned storage" {
    const Fake = struct {
        fn create(allocator: std.mem.Allocator) !void {
            const identity = try Identity.create(std.testing.io, allocator, "localhost", .ed25519);
            defer identity.destroy(allocator);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Fake.create, .{});
}

test "concurrent development creators publish one stable identity" {
    const Fake = struct {
        const Generator = @This();
        var key: tls.EcdsaP256Sha256.KeyPair = undefined;
        var started = std.atomic.Value(usize).init(0);
        fn create(io: std.Io, allocator: std.mem.Allocator, name: []const u8, _: Algorithm) !*Identity {
            _ = started.fetchAdd(1, .acq_rel);
            const until = std.Io.Timestamp.now(io, .awake).addDuration(.fromMilliseconds(3000));
            while (started.load(.acquire) < 2) {
                if (std.Io.Timestamp.now(io, .awake).nanoseconds >= until.nanoseconds) return error.FixtureGenerationBlocked;
                try io.sleep(.fromMilliseconds(1), .awake);
            }
            const identity = try allocator.create(Identity);
            errdefer allocator.destroy(identity);
            const owned_name = try allocator.dupe(u8, name);
            errdefer allocator.free(owned_name);
            identity.* = .{ .name = owned_name, .certificate = try allocator.dupe(u8, "fixture"), .key = .{ .ecdsa = key } };
            return identity;
        }
        const Worker = struct {
            store: *Store,
            result: ?Reference = null,
            failure: ?anyerror = null,
            fn run(self: *@This()) void {
                self.result = self.store.acquireUsing(std.testing.io, std.testing.allocator, "localhost", .ecdsa, Generator.create) catch |err| {
                    self.failure = err;
                    return;
                };
            }
        };
    };
    Fake.started.store(0, .release);
    Fake.key = try tls.EcdsaP256Sha256.KeyPair.generateDeterministic(@splat(0x17));
    defer std.crypto.secureZero(u8, std.mem.asBytes(&Fake.key));
    var store = Store{ .allocator = std.testing.allocator };
    defer store.deinit();
    var left = Fake.Worker{ .store = &store };
    var right = Fake.Worker{ .store = &store };
    const one = try std.Thread.spawn(.{}, Fake.Worker.run, .{&left});
    const two = std.Thread.spawn(.{}, Fake.Worker.run, .{&right}) catch |err| {
        Fake.started.store(2, .release);
        one.join();
        if (left.result) |*result| result.deinit();
        return err;
    };
    two.join();
    one.join();
    if (left.failure) |err| return err;
    if (right.failure) |err| return err;
    try std.testing.expect(left.result.?.identity == right.result.?.identity);
    try std.testing.expectEqual(1, store.count);
    left.result.?.deinit();
    right.result.?.deinit();
}
