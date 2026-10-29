const std = @import("std");

// Shared by HTTP/2 connection state and routing arenas. This accounts for
// allocator requests, not RSS, kernel buffers, thread stacks or other protocols.
pub var http2: Budget = .{ .backing = std.heap.page_allocator, .limit = 256 * 1024 * 1024 };
pub const max_http2_jobs = 64;
pub var http2_jobs = std.atomic.Value(usize).init(0);

pub const Budget = struct {
    backing: std.mem.Allocator,
    limit: usize,
    used: std.atomic.Value(usize) = .init(0),

    pub fn allocator(self: *Budget) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }

    pub fn reserve(self: *Budget, count: usize) bool {
        var current = self.used.load(.acquire);
        while (true) {
            if (count > self.limit -| current) return false;
            current = self.used.cmpxchgWeak(current, current + count, .acq_rel, .acquire) orelse return true;
        }
    }

    pub fn release(self: *Budget, count: usize) void {
        const previous = self.used.fetchSub(count, .acq_rel);
        std.debug.assert(previous >= count);
    }

    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, address: usize) ?[*]u8 {
        const self: *Budget = @ptrCast(@alignCast(ctx));
        if (!self.reserve(len)) return null;
        return self.backing.rawAlloc(len, alignment, address) orelse {
            self.release(len);
            return null;
        };
    }

    fn resize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, address: usize) bool {
        const self: *Budget = @ptrCast(@alignCast(ctx));
        const growth = new_len -| memory.len;
        if (!self.reserve(growth)) return false;
        if (!self.backing.rawResize(memory, alignment, new_len, address)) {
            self.release(growth);
            return false;
        }
        self.release(memory.len -| new_len);
        return true;
    }

    fn remap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, address: usize) ?[*]u8 {
        const self: *Budget = @ptrCast(@alignCast(ctx));
        const growth = new_len -| memory.len;
        if (!self.reserve(growth)) return null;
        const result = self.backing.rawRemap(memory, alignment, new_len, address) orelse {
            self.release(growth);
            return null;
        };
        self.release(memory.len -| new_len);
        return result;
    }

    fn free(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, address: usize) void {
        const self: *Budget = @ptrCast(@alignCast(ctx));
        self.backing.rawFree(memory, alignment, address);
        self.release(memory.len);
    }
};

test "shared allocator caps allocations and reclaims failed growth" {
    var budget: Budget = .{ .backing = std.testing.allocator, .limit = 64 };
    const allocator = budget.allocator();
    const first = try allocator.alloc(u8, 32);
    try std.testing.expectError(error.OutOfMemory, allocator.alloc(u8, 33));
    try std.testing.expectEqual(32, budget.used.load(.acquire));
    try std.testing.expect(!allocator.resize(first, 65));
    allocator.free(first);
    try std.testing.expectEqual(0, budget.used.load(.acquire));
    const second = try allocator.alloc(u8, 64);
    allocator.free(second);
    try std.testing.expectEqual(0, budget.used.load(.acquire));
    var empty: [0]u8 = .{};
    var buffer = std.heap.FixedBufferAllocator.init(&empty);
    var failing: Budget = .{ .backing = buffer.allocator(), .limit = 64 };
    try std.testing.expectError(error.OutOfMemory, failing.allocator().alloc(u8, 1));
    try std.testing.expectEqual(0, failing.used.load(.acquire));
}
