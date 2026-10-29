const std = @import("std");
const config_mod = @import("config.zig");
const ServerConfig = config_mod.ServerConfig;

const Snapshot = struct {
    cfg: *ServerConfig,
    arena: ?*std.heap.ArenaAllocator,
    readers: usize = 0,
};

// Transfer a lease to a worker by value, but release it exactly once. Config
// pointers borrowed from it must not outlive the lease (including TLS/tasks).
pub const Lease = struct {
    store: *Store,
    snapshot: ?*Snapshot,
    cfg: *ServerConfig,

    pub fn deinit(self: *Lease) void {
        const snapshot = self.snapshot orelse return;
        self.snapshot = null;
        self.store.release(snapshot);
    }
};

pub const Stats = struct {
    generation: u64,
    snapshots: usize,
    readers: usize,
    owned_bytes: usize,
};

pub const Store = struct {
    mutex: std.atomic.Mutex = .unlocked,
    active: ?*Snapshot = null,
    allocator: ?std.mem.Allocator = null,
    snapshots: std.ArrayList(*Snapshot) = .empty,
    generation: u64 = 0,
    retire: ?*const fn (*ServerConfig) void = null,
    retiring: usize = 0,
    retiring_bytes: usize = 0,
    closing: bool = false,
    pub const max_snapshots = 32;

    pub fn installInitial(self: *Store, allocator: std.mem.Allocator, cfg: *ServerConfig, retire: ?*const fn (*ServerConfig) void) !void {
        self.lock();
        defer self.mutex.unlock();
        if (self.closing) return error.ConfigStoreStopping;
        if (self.active != null) return error.ConfigAlreadyInstalled;
        const generation = try std.math.add(u64, self.generation, 1);
        const snapshot = try allocator.create(Snapshot);
        errdefer allocator.destroy(snapshot);
        snapshot.* = .{ .cfg = cfg, .arena = null };
        try self.snapshots.append(allocator, snapshot);
        self.allocator = allocator;
        self.retire = retire;
        self.generation = generation;
        cfg.cache_generation = generation;
        self.active = snapshot;
    }

    pub fn acquire(self: *Store) ?Lease {
        self.lock();
        defer self.mutex.unlock();
        const snapshot = self.active orelse return null;
        snapshot.readers += 1;
        return .{ .store = self, .snapshot = snapshot, .cfg = snapshot.cfg };
    }

    // Failure leaves ownership with the builder. A stale builder cannot replace
    // a newer publication, and unleased retired arenas never accumulate.
    pub fn activateOwned(self: *Store, arena: *std.heap.ArenaAllocator, cfg: *ServerConfig, expected_generation: u64) !void {
        self.lock();
        const previous = self.active orelse {
            self.mutex.unlock();
            return error.ConfigNotInstalled;
        };
        if (previous.cfg.cache_generation != expected_generation) {
            self.mutex.unlock();
            return error.ConfigChangedDuringReload;
        }
        if (self.snapshots.items.len + self.retiring >= max_snapshots) {
            self.mutex.unlock();
            return error.TooManyLiveConfigGenerations;
        }
        const generation = std.math.add(u64, self.generation, 1) catch |err| {
            self.mutex.unlock();
            return err;
        };
        const allocator = self.allocator.?;
        const snapshot = allocator.create(Snapshot) catch |err| {
            self.mutex.unlock();
            return err;
        };
        snapshot.* = .{ .cfg = cfg, .arena = arena };
        if (previous.readers == 0) {
            self.snapshots.items[self.indexOf(previous)] = snapshot;
        } else {
            self.snapshots.append(allocator, snapshot) catch |err| {
                allocator.destroy(snapshot);
                self.mutex.unlock();
                return err;
            };
        }
        self.generation = generation;
        cfg.cache_generation = generation;
        self.active = snapshot;
        const dispose_previous = previous.readers == 0;
        if (dispose_previous) self.beginRetirement(previous);
        self.mutex.unlock();
        if (dispose_previous) self.dispose(previous);
    }

    fn release(self: *Store, snapshot: *Snapshot) void {
        self.lock();
        std.debug.assert(snapshot.readers > 0);
        snapshot.readers -= 1;
        const retired = snapshot != self.active and snapshot.readers == 0;
        if (retired) {
            _ = self.snapshots.swapRemove(self.indexOf(snapshot));
            self.beginRetirement(snapshot);
        }
        self.mutex.unlock();
        if (retired) self.dispose(snapshot);
    }

    fn indexOf(self: *Store, snapshot: *Snapshot) usize {
        for (self.snapshots.items, 0..) |item, index| if (item == snapshot) return index;
        unreachable;
    }

    fn beginRetirement(self: *Store, snapshot: *Snapshot) void {
        self.retiring += 1;
        if (snapshot.arena) |arena| self.retiring_bytes += arena.queryCapacity();
    }

    fn dispose(self: *Store, snapshot: *Snapshot) void {
        // Socket cleanup can wait on IO and inspect metrics/config state. Keep
        // it outside the publication mutex, before freeing the arena.
        const bytes = if (snapshot.arena) |arena| arena.queryCapacity() else 0;
        if (self.retire) |retire| retire(snapshot.cfg);
        if (snapshot.arena) |arena| {
            const owner = arena.child_allocator;
            arena.deinit();
            owner.destroy(arena);
        }
        self.allocator.?.destroy(snapshot);
        self.lock();
        self.retiring -= 1;
        self.retiring_bytes -= bytes;
        self.mutex.unlock();
    }

    pub fn stats(self: *Store) Stats {
        self.lock();
        defer self.mutex.unlock();
        var result = Stats{ .generation = self.generation, .snapshots = self.snapshots.items.len + self.retiring, .readers = 0, .owned_bytes = self.retiring_bytes };
        for (self.snapshots.items) |snapshot| {
            result.readers += snapshot.readers;
            if (snapshot.arena) |arena| result.owned_bytes += arena.queryCapacity();
        }
        return result;
    }

    // The runtime joins all workers and drains connection leases first.
    pub fn deinit(self: *Store) void {
        self.lock();
        const allocator = self.allocator orelse {
            self.mutex.unlock();
            return;
        };
        if (self.retiring != 0) @panic("config store shutdown during retirement");
        self.closing = true;
        for (self.snapshots.items) |snapshot| {
            if (snapshot.readers != 0) @panic("config store shutdown with live readers");
            self.beginRetirement(snapshot);
        }
        var snapshots = self.snapshots;
        self.snapshots = .empty;
        self.active = null;
        self.mutex.unlock();
        for (snapshots.items) |snapshot| self.dispose(snapshot);
        snapshots.deinit(allocator);
        self.lock();
        self.allocator = null;
        self.retire = null;
        self.closing = false;
        self.mutex.unlock();
    }

    fn lock(self: *Store) void {
        while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
    }
};

fn candidate(allocator: std.mem.Allocator) !struct { arena: *std.heap.ArenaAllocator, cfg: *ServerConfig } {
    const arena = try allocator.create(std.heap.ArenaAllocator);
    errdefer allocator.destroy(arena);
    arena.* = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const cfg = try arena.allocator().create(ServerConfig);
    cfg.* = config_mod.defaultServerConfig();
    cfg.static_dir = try arena.allocator().dupe(u8, "safe snapshot");
    return .{ .arena = arena, .cfg = cfg };
}

fn freeCandidate(value: anytype) void {
    const allocator = value.arena.child_allocator;
    value.arena.deinit();
    allocator.destroy(value.arena);
}

fn publish(store: *Store, allocator: std.mem.Allocator, expected: u64) !*ServerConfig {
    const value = try candidate(allocator);
    errdefer freeCandidate(value);
    try store.activateOwned(value.arena, value.cfg, expected);
    return value.cfg;
}

test "unleased reloads reclaim arenas instead of imposing a lifetime reload cap" {
    var store = Store{};
    defer store.deinit();
    var initial = config_mod.defaultServerConfig();
    try store.installInitial(std.testing.allocator, &initial, null);
    for (1..1001) |generation| {
        _ = try publish(&store, std.testing.allocator, generation);
        const info = store.stats();
        try std.testing.expectEqual(generation + 1, info.generation);
        try std.testing.expectEqual(1, info.snapshots);
        try std.testing.expect(info.owned_bytes > 0 and info.owned_bytes < 64 * 1024);
    }
}

test "retired data survives until its last reader exits" {
    var store = Store{};
    defer store.deinit();
    var initial = config_mod.defaultServerConfig();
    try store.installInitial(std.testing.allocator, &initial, null);
    const value = try candidate(std.testing.allocator);
    try store.activateOwned(value.arena, value.cfg, 1);
    var first = store.acquire().?;
    defer first.deinit();
    var second = store.acquire().?;
    defer second.deinit();
    const next = try candidate(std.testing.allocator);
    try store.activateOwned(next.arena, next.cfg, 2);
    try std.testing.expectEqualStrings("safe snapshot", first.cfg.static_dir);
    try std.testing.expectEqual(2, store.stats().snapshots);
    first.deinit();
    try std.testing.expectEqual(2, store.stats().snapshots);
    second.deinit();
    try std.testing.expectEqual(1, store.stats().snapshots);
}

test "only simultaneously leased generations apply reload backpressure" {
    var store = Store{};
    defer store.deinit();
    var initial = config_mod.defaultServerConfig();
    try store.installInitial(std.testing.allocator, &initial, null);
    var leases: [Store.max_snapshots]?Lease = @splat(null);
    defer for (&leases) |*item| if (item.*) |*lease| lease.deinit();
    for (0..Store.max_snapshots) |index| {
        leases[index] = store.acquire().?;
        if (index + 1 == Store.max_snapshots) break;
        const value = try candidate(std.testing.allocator);
        try store.activateOwned(value.arena, value.cfg, index + 1);
    }
    const rejected = try candidate(std.testing.allocator);
    defer freeCandidate(rejected);
    try std.testing.expectError(error.TooManyLiveConfigGenerations, store.activateOwned(rejected.arena, rejected.cfg, Store.max_snapshots));
    try std.testing.expectEqual(0, rejected.cfg.cache_generation);
    leases[0].?.deinit();
    const accepted = try candidate(std.testing.allocator);
    try store.activateOwned(accepted.arena, accepted.cfg, Store.max_snapshots);
    try std.testing.expectEqual(Store.max_snapshots, store.stats().snapshots);
}

test "stale builders cannot overwrite a newer publication" {
    var store = Store{};
    defer store.deinit();
    var initial = config_mod.defaultServerConfig();
    try store.installInitial(std.testing.allocator, &initial, null);
    const value = try candidate(std.testing.allocator);
    try store.activateOwned(value.arena, value.cfg, 1);
    const stale = try candidate(std.testing.allocator);
    defer freeCandidate(stale);
    try std.testing.expectError(error.ConfigChangedDuringReload, store.activateOwned(stale.arena, stale.cfg, 1));
    try std.testing.expectEqual(2, store.stats().generation);
    try std.testing.expectEqual(0, stale.cfg.cache_generation);
}

fn allocationCheck(allocator: std.mem.Allocator) !void {
    var store = Store{};
    defer store.deinit();
    var initial = config_mod.defaultServerConfig();
    try store.installInitial(allocator, &initial, null);
    var held = store.acquire().?;
    defer held.deinit();
    const value = try candidate(allocator);
    errdefer freeCandidate(value);
    try store.activateOwned(value.arena, value.cfg, 1);
}

test "failed publication preserves caller ownership without leaks" {
    try std.testing.checkAllAllocationFailures(std.testing.allocator, allocationCheck, .{});
}

test "retirement callbacks run without the store mutex" {
    const Fake = struct {
        var store: *Store = undefined;
        var calls: usize = 0;
        fn retire(_: *ServerConfig) void {
            _ = store.stats();
            calls += 1;
        }
    };
    var store = Store{};
    Fake.store = &store;
    Fake.calls = 0;
    var initial = config_mod.defaultServerConfig();
    try store.installInitial(std.testing.allocator, &initial, Fake.retire);
    const value = try candidate(std.testing.allocator);
    try store.activateOwned(value.arena, value.cfg, 1);
    try std.testing.expectEqual(1, Fake.calls);
    store.deinit();
    try std.testing.expectEqual(2, Fake.calls);
    try std.testing.expect(store.acquire() == null);
}

test "snapshot metadata and candidate arenas keep their respective allocators" {
    var store = Store{};
    defer store.deinit();
    var initial = config_mod.defaultServerConfig();
    try store.installInitial(std.testing.allocator, &initial, null);
    const cfg = try publish(&store, std.heap.page_allocator, 1);
    var lease = store.acquire().?;
    defer lease.deinit();
    try std.testing.expect(lease.cfg == cfg);
}

test "concurrent readers survive publication and retirement churn" {
    const Readers = struct {
        fn run(store: *Store, stop: *std.atomic.Value(bool), count: *std.atomic.Value(usize)) void {
            while (!stop.load(.acquire)) {
                var lease = store.acquire().?;
                std.debug.assert(lease.cfg.cache_generation > 0);
                std.debug.assert(std.mem.eql(u8, lease.cfg.static_dir, "safe snapshot"));
                _ = count.fetchAdd(1, .monotonic);
                lease.deinit();
            }
        }
    };
    var store = Store{};
    defer store.deinit();
    var initial = config_mod.defaultServerConfig();
    initial.static_dir = "safe snapshot";
    try store.installInitial(std.testing.allocator, &initial, null);
    var stop = std.atomic.Value(bool).init(false);
    var count = std.atomic.Value(usize).init(0);
    var threads: [4]?std.Thread = @splat(null);
    defer {
        stop.store(true, .release);
        for (threads) |thread| if (thread) |worker| worker.join();
    }
    for (&threads) |*thread| thread.* = try std.Thread.spawn(.{}, Readers.run, .{ &store, &stop, &count });
    for (1..501) |generation| _ = try publish(&store, std.testing.allocator, generation);
    stop.store(true, .release);
    for (&threads) |*thread| {
        thread.*.?.join();
        thread.* = null;
    }
    try std.testing.expect(count.load(.acquire) > 0);
    try std.testing.expectEqual(1, store.stats().snapshots);
    try std.testing.expectEqual(0, store.stats().readers);
}

test "retiring generations stay accounted while cleanup runs outside the lock" {
    const Fake = struct {
        var entered: std.atomic.Value(bool) = .init(false);
        var release_cleanup: std.atomic.Value(bool) = .init(false);
        var failed: std.atomic.Value(bool) = .init(false);
        fn retire(cfg: *ServerConfig) void {
            if (cfg.cache_generation != 1) return;
            entered.store(true, .release);
            while (!release_cleanup.load(.acquire)) std.atomic.spinLoopHint();
        }
        fn writer(store: *Store) void {
            _ = publish(store, std.testing.allocator, 1) catch {
                failed.store(true, .release);
                entered.store(true, .release);
            };
        }
    };
    Fake.entered.store(false, .release);
    Fake.release_cleanup.store(false, .release);
    Fake.failed.store(false, .release);
    var store = Store{};
    defer store.deinit();
    var initial = config_mod.defaultServerConfig();
    try store.installInitial(std.testing.allocator, &initial, Fake.retire);
    const worker = try std.Thread.spawn(.{}, Fake.writer, .{&store});
    defer {
        Fake.release_cleanup.store(true, .release);
        worker.join();
    }
    while (!Fake.entered.load(.acquire)) std.atomic.spinLoopHint();
    try std.testing.expect(!Fake.failed.load(.acquire));
    try std.testing.expectEqual(2, store.stats().snapshots);
    var lease = store.acquire().?;
    defer lease.deinit();
    try std.testing.expectEqual(2, lease.cfg.cache_generation);
}

test "concurrent builders cannot overwrite a newer publication" {
    const Writers = struct {
        fn run(store: *Store, go: *std.atomic.Value(bool), ready: *std.atomic.Value(usize), published: *std.atomic.Value(usize), stale: *std.atomic.Value(usize), failed: *std.atomic.Value(bool)) void {
            const value = candidate(std.testing.allocator) catch {
                failed.store(true, .release);
                _ = ready.fetchAdd(1, .release);
                return;
            };
            _ = ready.fetchAdd(1, .release);
            while (!go.load(.acquire)) std.atomic.spinLoopHint();
            store.activateOwned(value.arena, value.cfg, 1) catch |err| {
                freeCandidate(value);
                if (err == error.ConfigChangedDuringReload) {
                    _ = stale.fetchAdd(1, .monotonic);
                } else failed.store(true, .release);
                return;
            };
            _ = published.fetchAdd(1, .monotonic);
        }
    };
    var store = Store{};
    defer store.deinit();
    var initial = config_mod.defaultServerConfig();
    try store.installInitial(std.testing.allocator, &initial, null);
    var go = std.atomic.Value(bool).init(false);
    var ready = std.atomic.Value(usize).init(0);
    var published = std.atomic.Value(usize).init(0);
    var stale = std.atomic.Value(usize).init(0);
    var failed = std.atomic.Value(bool).init(false);
    var threads: [2]?std.Thread = @splat(null);
    defer {
        go.store(true, .release);
        for (threads) |thread| if (thread) |worker| worker.join();
    }
    for (&threads) |*thread| thread.* = try std.Thread.spawn(.{}, Writers.run, .{ &store, &go, &ready, &published, &stale, &failed });
    while (ready.load(.acquire) != 2) std.atomic.spinLoopHint();
    go.store(true, .release);
    for (&threads) |*thread| {
        thread.*.?.join();
        thread.* = null;
    }
    try std.testing.expect(!failed.load(.acquire));
    try std.testing.expectEqual(1, published.load(.acquire));
    try std.testing.expectEqual(1, stale.load(.acquire));
    try std.testing.expectEqual(2, store.stats().generation);
    try std.testing.expectEqual(1, store.stats().snapshots);
}
