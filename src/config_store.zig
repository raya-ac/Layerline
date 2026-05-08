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

    pub fn installInitial(self: *Store, allocator: std.mem.Allocator, cfg: *ServerConfig) !void {
        self.lock();
        defer self.mutex.unlock();

        if (self.allocator == null) self.allocator = allocator;
        const snapshot = try allocator.create(Snapshot);
        snapshot.* = .{ .cfg = cfg, .arena = null };
        try self.snapshots.append(allocator, snapshot);
        self.active.store(@intFromPtr(cfg), .release);
    }

    pub fn current(self: *Store) *ServerConfig {
        const raw = self.active.load(.acquire);
        return @ptrFromInt(raw);
    }

    pub fn activateOwned(self: *Store, allocator: std.mem.Allocator, arena: *std.heap.ArenaAllocator, cfg: *ServerConfig) !void {
        self.lock();
        defer self.mutex.unlock();

        if (self.allocator == null) self.allocator = allocator;
        const snapshot = try allocator.create(Snapshot);
        snapshot.* = .{ .cfg = cfg, .arena = arena };
        try self.snapshots.append(allocator, snapshot);
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
