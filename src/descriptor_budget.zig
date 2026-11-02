const std = @import("std");
const builtin = @import("builtin");

pub const supported = builtin.os.tag == .linux or builtin.os.tag == .macos;
pub const default_limit = 4096;
pub const minimum_limit = 32;
pub const maximum_limit = 1024 * 1024;
pub const kernel_headroom = 32;
pub const resolver_allowance = 8;
pub const Class = enum { normal, control, emergency };
pub threadlocal var current_class: Class = .normal;
var enabled = false;

pub const Scope = struct {
    previous: Class,

    pub fn enter(class: Class) Scope {
        const previous = current_class;
        current_class = class;
        return .{ .previous = previous };
    }

    pub fn deinit(self: Scope) void {
        current_class = self.previous;
    }
};

pub const Snapshot = struct {
    enabled: bool = false,
    configured: usize = default_limit,
    effective: usize = 0,
    kernel_limit: usize = 0,
    inherited: usize = 0,
    owned: usize = 0,
    owned_by_class: [3]usize = @splat(0),
    used: [3]usize = @splat(0),
    limits: [3]usize = @splat(0),
    peak: [3]usize = @splat(0),
    rejected: [3]usize = @splat(0),
};

// Reservations precede syscalls; a returned handle keeps its reservation until
// close finishes. The registry is cleared first so FD reuse cannot remove the
// next owner's entry while the previous close is releasing its counter.
fn Registry(comptime capacity: usize) type {
    return struct {
        const Self = @This();
        mutex: std.atomic.Mutex = .unlocked,
        masks: [3][(capacity + @bitSizeOf(usize) - 1) / @bitSizeOf(usize)]usize = @splat(@splat(0)),
        stats: Snapshot = .{},

        fn bits(self: *Self, class: Class) std.DynamicBitSetUnmanaged {
            // StaticBitSet.isSet takes its receiver by value in Zig 0.16.
            // A pointer-backed view keeps large registry copies off worker stacks.
            return .{ .bit_length = capacity, .masks = &self.masks[@intFromEnum(class)] };
        }

        fn lock(self: *Self) void {
            while (!self.mutex.tryLock()) std.atomic.spinLoopHint();
        }

        fn setLimit(self: *Self, requested: usize, kernel: usize, inherited: usize) !void {
            try validate(requested);
            const effective = @min(requested, kernel -| inherited -| kernel_headroom);
            if (effective < minimum_limit) return error.DescriptorLimitTooLow;
            const control = @min(32, effective / 4);
            const limits = [3]usize{ effective - control - 2, control, 2 };
            self.lock();
            defer self.mutex.unlock();
            for (self.stats.used, limits) |used, limit| if (used > limit) return error.DescriptorBudgetAlreadyExceeded;
            self.stats.configured = requested;
            self.stats.effective = effective;
            self.stats.kernel_limit = kernel;
            self.stats.inherited = inherited;
            self.stats.limits = limits;
        }

        pub const Ticket = struct {
            owner: ?*Self = null,
            class: Class = .normal,
            count: usize = 0,

            pub fn adopt(self: *@This(), handle: std.posix.fd_t) !void {
                return self.adoptAll(&.{handle});
            }

            pub fn adoptAll(self: *@This(), handles: []const std.posix.fd_t) !void {
                const owner = self.owner orelse return;
                std.debug.assert(self.count >= handles.len);
                owner.lock();
                defer owner.mutex.unlock();
                for (handles, 0..) |handle, offset| {
                    const index = std.math.cast(usize, handle) orelse return error.ProcessFdQuotaExceeded;
                    if (index >= capacity or owner.classOf(index) != null) {
                        owner.stats.rejected[@intFromEnum(self.class)] += 1;
                        return error.ProcessFdQuotaExceeded;
                    }
                    for (handles[0..offset]) |previous| if (handle == previous) return error.ProcessFdQuotaExceeded;
                }
                var slots = owner.bits(self.class);
                for (handles) |handle| slots.set(@intCast(handle));
                owner.stats.owned += handles.len;
                owner.stats.owned_by_class[@intFromEnum(self.class)] += handles.len;
                self.count -= handles.len;
            }

            pub fn deinit(self: *@This()) void {
                if (self.owner) |owner| owner.release(self.class, self.count);
                self.* = .{};
            }
        };

        fn reserve(self: *Self, class: Class, count: usize) !Self.Ticket {
            self.lock();
            defer self.mutex.unlock();
            const index = @intFromEnum(class);
            if (count > self.stats.limits[index] -| self.stats.used[index]) {
                self.stats.rejected[index] += 1;
                return error.ProcessFdQuotaExceeded;
            }
            self.stats.used[index] += count;
            self.stats.peak[index] = @max(self.stats.peak[index], self.stats.used[index]);
            return .{ .owner = self, .class = class, .count = count };
        }

        fn release(self: *Self, class: Class, count: usize) void {
            if (count == 0) return;
            self.lock();
            defer self.mutex.unlock();
            const index = @intFromEnum(class);
            std.debug.assert(self.stats.used[index] >= count);
            self.stats.used[index] -= count;
        }

        fn classOf(self: *Self, index: usize) ?Class {
            inline for (std.meta.tags(Class)) |class| if (self.bits(class).isSet(index)) return class;
            return null;
        }

        fn take(self: *Self, handle: std.posix.fd_t) ?Class {
            const index = std.math.cast(usize, handle) orelse return null;
            if (index >= capacity) return null;
            self.lock();
            defer self.mutex.unlock();
            const class = self.classOf(index) orelse return null;
            var slots = self.bits(class);
            slots.unset(index);
            self.stats.owned -= 1;
            self.stats.owned_by_class[@intFromEnum(class)] -= 1;
            return class;
        }

        fn snapshot(self: *Self) Snapshot {
            self.lock();
            defer self.mutex.unlock();
            return self.stats;
        }
    };
}

var registry: Registry(maximum_limit) = .{};
pub const Ticket = Registry(maximum_limit).Ticket;

pub fn validate(limit: usize) !void {
    if (limit < minimum_limit or limit > maximum_limit) return error.InvalidConfigValue;
}

pub fn install(kernel: usize, inherited: usize) !void {
    if (enabled) return error.DescriptorBudgetAlreadyInstalled;
    try registry.setLimit(default_limit, kernel, inherited);
    enabled = true;
}

pub fn uninstall() void {
    enabled = false;
}

pub fn configure(limit: usize) !void {
    try validate(limit);
    if (!supported) return;
    if (!enabled) return error.DescriptorBudgetUnavailable;
    const old = registry.snapshot();
    try registry.setLimit(limit, old.kernel_limit, old.inherited);
}

pub fn acquireClass(class: Class, count: usize) error{ProcessFdQuotaExceeded}!Ticket {
    if (!enabled) return .{};
    return registry.reserve(class, count);
}

pub fn acquire(count: usize) error{ProcessFdQuotaExceeded}!Ticket {
    return acquireClass(current_class, count);
}

pub fn beforeClose(handle: std.posix.fd_t) ?Class {
    return if (enabled) registry.take(handle) else null;
}

pub fn afterClose(class: ?Class) void {
    if (class) |owned| registry.release(owned, 1);
}

pub fn closeNative(handle: std.posix.fd_t) void {
    const class = beforeClose(handle);
    _ = std.posix.system.close(handle);
    afterClose(class);
}

pub fn emergency(handle: std.posix.fd_t) bool {
    if (!enabled) return false;
    const index = std.math.cast(usize, handle) orelse return false;
    if (index >= maximum_limit) return false;
    registry.lock();
    defer registry.mutex.unlock();
    return registry.classOf(index) == .emergency;
}

pub fn snapshot() Snapshot {
    var result = registry.snapshot();
    result.enabled = enabled;
    return result;
}

pub fn capacityError(err: anyerror) bool {
    return switch (err) {
        error.ProcessFdQuotaExceeded, error.SystemFdQuotaExceeded, error.SystemResources => true,
        else => false,
    };
}

test "descriptor partitions preserve control and emergency admission" {
    var state: Registry(64) = .{};
    try state.setLimit(32, 256, 3);
    var normal = try state.reserve(.normal, 22);
    defer normal.deinit();
    try std.testing.expectError(error.ProcessFdQuotaExceeded, state.reserve(.normal, 1));
    var control = try state.reserve(.control, 8);
    defer control.deinit();
    var rejection = try state.reserve(.emergency, 2);
    defer rejection.deinit();
    try std.testing.expectEqual([3]usize{ 22, 8, 2 }, state.snapshot().used);
    try std.testing.expectError(error.ProcessFdQuotaExceeded, state.reserve(.control, 1));
}

test "descriptor ownership survives reuse between unregister and release" {
    var state: Registry(16) = .{};
    try state.setLimit(32, 256, 3);
    var first = try state.reserve(.normal, 2);
    try first.adopt(5);
    first.deinit();
    const old = state.take(5).?;
    var next = try state.reserve(.control, 1);
    try next.adopt(5);
    next.deinit();
    state.release(old, 1);
    try std.testing.expectEqual(.control, state.classOf(5).?);
    try std.testing.expectEqual([3]usize{ 0, 1, 0 }, state.snapshot().used);
    state.release(state.take(5).?, 1);
    try std.testing.expectEqual(0, state.snapshot().owned);
}

test "descriptor failure rolls back reservations and invalid handles cannot overwrite owners" {
    var state: Registry(16) = .{};
    try state.setLimit(32, 256, 3);
    var ticket = try state.reserve(.normal, 2);
    defer ticket.deinit();
    try ticket.adopt(5);
    try std.testing.expectError(error.ProcessFdQuotaExceeded, ticket.adopt(5));
    try std.testing.expectError(error.ProcessFdQuotaExceeded, ticket.adopt(16));
    try std.testing.expectError(error.ProcessFdQuotaExceeded, ticket.adopt(-1));
    state.release(state.take(5).?, 1);
    ticket.deinit();
    try std.testing.expectEqual([3]usize{ 0, 0, 0 }, state.snapshot().used);
}

test "descriptor configuration clamps to inherited handles and kernel headroom" {
    var state: Registry(16) = .{};
    try state.setLimit(4096, 128, 5);
    try std.testing.expectEqual(91, state.snapshot().effective);
    try std.testing.expectError(error.DescriptorLimitTooLow, state.setLimit(4096, 64, 5));
    try std.testing.expectEqual(91, state.snapshot().effective);
    for ([_]usize{ 0, 31, maximum_limit + 1 }) |limit| try std.testing.expectError(error.InvalidConfigValue, validate(limit));
}

test "paired descriptor adoption is atomic on partial validation failure" {
    var state: Registry(16) = .{};
    try state.setLimit(32, 256, 3);
    var ticket = try state.reserve(.normal, 2);
    defer ticket.deinit();
    try std.testing.expectError(error.ProcessFdQuotaExceeded, ticket.adoptAll(&.{ 4, 16 }));
    try std.testing.expectEqual(0, state.snapshot().owned);
    try std.testing.expectEqual(2, ticket.count);
    try std.testing.expectError(error.ProcessFdQuotaExceeded, ticket.adoptAll(&.{ 4, 4 }));
    try ticket.adoptAll(&.{ 4, 5 });
    try std.testing.expectEqual(2, state.snapshot().owned);
    state.release(state.take(4).?, 1);
    state.release(state.take(5).?, 1);
}

test "concurrent descriptor reservations never exceed their partition" {
    const State = Registry(64);
    const Worker = struct {
        fn run(state: *State, index: usize) void {
            for (0..500) |_| {
                var ticket = state.reserve(.normal, 4) catch continue;
                const base: std.posix.fd_t = @intCast(index * 4);
                const handles = [_]std.posix.fd_t{ base, base + 1, base + 2, base + 3 };
                ticket.adoptAll(&handles) catch unreachable;
                ticket.deinit();
                for (handles) |fd| state.release(state.take(fd).?, 1);
            }
        }
    };
    var state: State = .{};
    try state.setLimit(32, 256, 3);
    var workers: [8]std.Thread = undefined;
    var started: usize = 0;
    defer for (workers[0..started]) |worker| worker.join();
    for (&workers, 0..) |*worker, index| {
        worker.* = try std.Thread.spawn(.{}, Worker.run, .{ &state, index });
        started += 1;
    }
    for (workers) |worker| worker.join();
    started = 0;
    const result = state.snapshot();
    try std.testing.expectEqual(0, result.owned);
    try std.testing.expectEqual(0, result.used[0]);
    try std.testing.expect(result.peak[0] <= result.limits[0]);
}

test "full descriptor registry fits on a small worker stack" {
    const State = Registry(maximum_limit);
    const state = try std.testing.allocator.create(State);
    defer std.testing.allocator.destroy(state);
    state.* = .{};
    try state.setLimit(32, 256, 3);
    const Worker = struct {
        fn run(value: *State) void {
            var ticket = value.reserve(.normal, 2) catch unreachable;
            ticket.adoptAll(&.{ 5, maximum_limit - 1 }) catch unreachable;
            ticket.deinit();
            value.release(value.take(5).?, 1);
            value.release(value.take(maximum_limit - 1).?, 1);
        }
    };
    const worker = try std.Thread.spawn(.{ .stack_size = 65536 }, Worker.run, .{state});
    worker.join();
    try std.testing.expectEqual(0, state.snapshot().owned);
}
