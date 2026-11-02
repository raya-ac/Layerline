const std = @import("std");

pub const default_limit = 512 * 1024 * 1024;
pub const minimum_limit = 8 * 1024 * 1024;
pub const maximum_control_reserve = 16 * 1024 * 1024;

// These tiers account for the same pages, not additional memory. Keep enough
// outside the request pool to inspect an overloaded server and reject work.
pub var total: Budget = .{ .backing = std.heap.page_allocator, .limit = default_limit, .page_accounting = true };
pub var normal: Budget = .{ .backing = total.allocator(), .limit = default_limit - maximum_control_reserve, .page_accounting = true, .pressure = &pressure };
pub var control: Budget = .{ .backing = total.allocator(), .limit = maximum_control_reserve, .page_accounting = true };
pub var pressure = std.atomic.Value(bool).init(false);
pub var overload_responses = std.atomic.Value(usize).init(0);
pub threadlocal var emergency_write: bool = false;
pub var http2: Budget = .{ .backing = normal.allocator(), .limit = 256 * 1024 * 1024 };
pub var http3: Budget = .{ .backing = normal.allocator(), .limit = 64 * 1024 * 1024 };
pub var io: Budget = .{ .backing = normal.allocator(), .limit = 16 * 1024 * 1024 };
pub const max_http2_jobs = 64;
pub var http2_jobs = std.atomic.Value(usize).init(0);

pub fn allocator() std.mem.Allocator {
    return normal.allocator();
}

// Startup only: callers must not change limits while workers are running.
pub fn configure(limit: usize) !void {
    if (limit < minimum_limit) return error.InvalidMemoryBudget;
    const reserve = @min(maximum_control_reserve, limit / 8);
    if (normal.used.load(.acquire) > limit - reserve or control.used.load(.acquire) > reserve or total.used.load(.acquire) > limit) return error.MemoryBudgetAlreadyExceeded;
    total.limit = limit;
    normal.limit = limit - reserve;
    control.limit = reserve;
}

pub const Budget = struct {
    backing: std.mem.Allocator,
    limit: usize,
    used: std.atomic.Value(usize) = .init(0),
    peak: std.atomic.Value(usize) = .init(0),
    rejected: std.atomic.Value(usize) = .init(0),
    page_accounting: bool = false,
    pressure: ?*std.atomic.Value(bool) = null,

    pub fn allocator(self: *Budget) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }

    pub fn reserve(self: *Budget, count: usize) bool {
        var current = self.used.load(.acquire);
        while (true) {
            if (count > self.limit -| current) {
                self.reject();
                return false;
            }
            if (self.used.cmpxchgWeak(current, current + count, .acq_rel, .acquire)) |changed| {
                current = changed;
            } else {
                var peak = self.peak.load(.acquire);
                while (peak < current + count) {
                    peak = self.peak.cmpxchgWeak(peak, current + count, .acq_rel, .acquire) orelse break;
                }
                return true;
            }
        }
    }

    fn reject(self: *Budget) void {
        _ = self.rejected.fetchAdd(1, .monotonic);
        if (self.pressure) |flag| flag.store(true, .release);
    }

    fn charge(self: *Budget, len: usize) ?usize {
        if (!self.page_accounting) return len;
        const page = std.heap.pageSize();
        const padded = std.math.add(usize, len, page - 1) catch {
            self.reject();
            return null;
        };
        return padded & ~(page - 1);
    }

    pub fn release(self: *Budget, count: usize) void {
        const previous = self.used.fetchSub(count, .acq_rel);
        std.debug.assert(previous >= count);
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, address: usize) ?[*]u8 {
        const self: *Budget = @ptrCast(@alignCast(ctx));
        const charged = self.charge(len) orelse return null;
        if (!self.reserve(charged)) return null;
        return self.backing.rawAlloc(len, alignment, address) orelse {
            self.release(charged);
            self.reject();
            return null;
        };
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, address: usize) bool {
        const self: *Budget = @ptrCast(@alignCast(ctx));
        const old_charge = self.charge(memory.len).?;
        const new_charge = self.charge(new_len) orelse return false;
        const growth = new_charge -| old_charge;
        if (!self.reserve(growth)) return false;
        if (!self.backing.rawResize(memory, alignment, new_len, address)) {
            self.release(growth);
            return false;
        }
        self.release(old_charge -| new_charge);
        return true;
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, address: usize) ?[*]u8 {
        const self: *Budget = @ptrCast(@alignCast(ctx));
        const old_charge = self.charge(memory.len).?;
        const new_charge = self.charge(new_len) orelse return null;
        const growth = new_charge -| old_charge;
        if (!self.reserve(growth)) return null;
        const result = self.backing.rawRemap(memory, alignment, new_len, address) orelse {
            self.release(growth);
            return null;
        };
        self.release(old_charge -| new_charge);
        return result;
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, address: usize) void {
        const self: *Budget = @ptrCast(@alignCast(ctx));
        self.backing.rawFree(memory, alignment, address);
        self.release(self.charge(memory.len).?);
    }
};

test "shared allocator caps allocations and reclaims failed growth" {
    var budget: Budget = .{ .backing = std.testing.allocator, .limit = 64 };
    const a = budget.allocator();
    const first = try a.alloc(u8, 32);
    try std.testing.expectError(error.OutOfMemory, a.alloc(u8, 33));
    try std.testing.expectEqual(32, budget.used.load(.acquire));
    try std.testing.expect(!a.resize(first, 65));
    a.free(first);
    try std.testing.expectEqual(0, budget.used.load(.acquire));
    const second = try a.alloc(u8, 64);
    a.free(second);
    try std.testing.expectEqual(0, budget.used.load(.acquire));
    var empty: [0]u8 = .{};
    var buffer = std.heap.FixedBufferAllocator.init(&empty);
    var failing: Budget = .{ .backing = buffer.allocator(), .limit = 64 };
    try std.testing.expectError(error.OutOfMemory, failing.allocator().alloc(u8, 1));
    try std.testing.expectEqual(0, failing.used.load(.acquire));
}

test "page accounting caps tiny allocations and preserves the control partition" {
    const page = std.heap.pageSize();
    var parent: Budget = .{ .backing = std.heap.page_allocator, .limit = page * 4, .page_accounting = true };
    var flag = std.atomic.Value(bool).init(false);
    var requests: Budget = .{ .backing = parent.allocator(), .limit = page * 3, .page_accounting = true, .pressure = &flag };
    var reserved: Budget = .{ .backing = parent.allocator(), .limit = page, .page_accounting = true };
    const a = requests.allocator();
    const held = try a.alloc(u8, page * 2 + 1);
    try std.testing.expectEqual(page * 3, parent.used.load(.acquire));
    try std.testing.expectError(error.OutOfMemory, a.alloc(u8, 1));
    try std.testing.expect(flag.load(.acquire));
    const command = try reserved.allocator().alloc(u8, 1);
    try std.testing.expectEqual(page * 4, parent.used.load(.acquire));
    try std.testing.expect(!a.resize(held, page * 3 + 1));
    try std.testing.expect(a.resize(held, page + 1));
    a.free(@as([]u8, held[0 .. page + 1]));
    reserved.allocator().free(command);
    try std.testing.expectEqual(0, parent.used.load(.acquire));
    try std.testing.expectEqual(page * 4, parent.peak.load(.acquire));
    try std.testing.expect(requests.rejected.load(.acquire) >= 2);
    const recovered = try a.alloc(u8, 1);
    a.free(recovered);
}

test "budget rolls back parent failures and remap growth with page rounding" {
    const page = std.heap.pageSize();
    var parent: Budget = .{ .backing = std.heap.page_allocator, .limit = page, .page_accounting = true };
    var child: Budget = .{ .backing = parent.allocator(), .limit = page * 4, .page_accounting = true };
    const a = child.allocator();
    const bytes = try a.alloc(u8, 1);
    try std.testing.expect(a.remap(bytes, page + 1) == null);
    try std.testing.expectEqual(page, child.used.load(.acquire));
    try std.testing.expectError(error.OutOfMemory, a.alloc(u8, 1));
    try std.testing.expectEqual(page, child.used.load(.acquire));
    try std.testing.expect(child.charge(std.math.maxInt(usize)) == null);
    a.free(bytes);
    try std.testing.expectEqual(0, parent.used.load(.acquire));
}

test "concurrent allocators never exceed a shared parent cap" {
    const Worker = struct {
        fn run(budget: *Budget) void {
            for (0..1000) |_| {
                const bytes = budget.allocator().alloc(u8, 1) catch continue;
                budget.allocator().free(bytes);
            }
        }
    };
    const page = std.heap.pageSize();
    var parent: Budget = .{ .backing = std.heap.page_allocator, .limit = page * 4, .page_accounting = true };
    var child: Budget = .{ .backing = parent.allocator(), .limit = page * 4, .page_accounting = true };
    var threads: [8]std.Thread = undefined;
    var started: usize = 0;
    defer for (threads[0..started]) |thread| thread.join();
    for (&threads) |*thread| {
        thread.* = try std.Thread.spawn(.{}, Worker.run, .{&child});
        started += 1;
    }
    for (threads) |thread| thread.join();
    started = 0;
    try std.testing.expectEqual(0, child.used.load(.acquire));
    try std.testing.expectEqual(0, parent.used.load(.acquire));
    try std.testing.expect(parent.peak.load(.acquire) <= parent.limit);
}
