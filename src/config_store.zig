const std = @import("std");

const config_mod = @import("config.zig");

const ServerConfig = config_mod.ServerConfig;

const Snapshot = struct {
    cfg: *ServerConfig,
    arena: ?*std.heap.ArenaAllocator,
};

pub const Store = struct {
    mutex: std.atomic.Mutex = .unlocked,
    active: std.atomic.Value(usize) = std.atomic.Value(usize).init(0),
    allocator: ?std.mem.Allocator = null,
    snapshots: std.ArrayList(*Snapshot) = .empty,
    generation: u64 = 0,
    // Readers currently retain raw pointers for connection lifetimes. Bound
    // retention until that API has leases; never reclaim a possibly live arena.
    pub const max_snapshots = 32;

    pub fn installInitial(self: *Store, allocator: std.mem.Allocator, cfg: *ServerConfig) !void {
        self.lock();
        defer self.mutex.unlock();

        if (self.snapshots.items.len != 0) return error.ConfigAlreadyInstalled;
        if (self.allocator == null) self.allocator = allocator;
        const snapshot = try allocator.create(Snapshot);
        errdefer allocator.destroy(snapshot);
        snapshot.* = .{ .cfg = cfg, .arena = null };
        try self.snapshots.append(allocator, snapshot);
        self.generation += 1;
        cfg.cache_generation = self.generation;
        self.active.store(@intFromPtr(cfg), .release);
    }

    pub fn current(self: *Store) *ServerConfig {
        const raw = self.active.load(.acquire);
        return @ptrFromInt(raw);
    }

    pub fn activateOwned(self: *Store, allocator: std.mem.Allocator, arena: *std.heap.ArenaAllocator, cfg: *ServerConfig) !void {
        self.lock();
        defer self.mutex.unlock();

        if (self.snapshots.items.len >= max_snapshots) return error.ReloadLimitRequiresRestart;
        if (self.allocator == null) self.allocator = allocator;
        const snapshot = try allocator.create(Snapshot);
        errdefer allocator.destroy(snapshot);
        snapshot.* = .{ .cfg = cfg, .arena = arena };
        try self.snapshots.append(allocator, snapshot);
        self.generation += 1;
        cfg.cache_generation = self.generation;
        self.active.store(@intFromPtr(cfg), .release);
    }

    pub fn deinit(self: *Store) void {
        self.lock();
        defer self.mutex.unlock();

        const allocator = self.allocator orelse return;
        for (self.snapshots.items) |snapshot| {
            if (snapshot.arena) |arena| {
                arena.deinit();
                allocator.destroy(arena);
            }
            allocator.destroy(snapshot);
        }
        self.snapshots.deinit(allocator);
        self.active.store(0, .release);
        self.allocator = null;
    }

    fn lock(self: *Store) void {
        while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
    }
};

test "reload snapshots have a hard cap and distinct cache generations" {
    const allocator = std.testing.allocator;
    var store = Store{};
    defer store.deinit();
    var initial = config_mod.defaultServerConfig();
    try store.installInitial(allocator, &initial);
    for (1..Store.max_snapshots) |i| {
        const arena = try allocator.create(std.heap.ArenaAllocator);
        arena.* = std.heap.ArenaAllocator.init(allocator);
        const cfg = try arena.allocator().create(ServerConfig);
        cfg.* = config_mod.defaultServerConfig();
        try store.activateOwned(allocator, arena, cfg);
        try std.testing.expectEqual(i + 1, cfg.cache_generation);
    }
    const previous = store.current();
    const rejected = try allocator.create(std.heap.ArenaAllocator);
    rejected.* = std.heap.ArenaAllocator.init(allocator);
    defer {
        rejected.deinit();
        allocator.destroy(rejected);
    }
    var cfg = config_mod.defaultServerConfig();
    try std.testing.expectError(error.ReloadLimitRequiresRestart, store.activateOwned(allocator, rejected, &cfg));
    try std.testing.expect(previous == store.current());
    try std.testing.expectEqual(0, cfg.cache_generation);
}
