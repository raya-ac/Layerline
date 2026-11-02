const std = @import("std");

// Record helpers free their temporary buffers out of order. Reclaim the whole
// bounded workspace only when its last live slice is gone, then erase it.
// Each instance belongs to one reader or to the channel's locked writer.
pub const Workspace = struct {
    backing: std.mem.Allocator,
    fixed: std.heap.FixedBufferAllocator,
    live: usize = 0,
    high_water: usize = 0,

    pub fn init(backing: std.mem.Allocator, size: usize) !Workspace {
        return .{ .backing = backing, .fixed = .init(try backing.alloc(u8, size)) };
    }

    pub fn deinit(self: *Workspace) void {
        std.debug.assert(self.live == 0);
        std.crypto.secureZero(u8, self.fixed.buffer);
        self.backing.free(self.fixed.buffer);
        self.* = undefined;
    }

    pub fn allocator(self: *Workspace) std.mem.Allocator {
        // Allocator handles borrow this address; obtain them after moving us.
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = std.mem.Allocator.noResize, .remap = std.mem.Allocator.noRemap, .free = free } };
    }

    fn alloc(context: *anyopaque, size: usize, alignment: std.mem.Alignment, address: usize) ?[*]u8 {
        const self: *Workspace = @ptrCast(@alignCast(context));
        const bytes = self.fixed.allocator().rawAlloc(size, alignment, address) orelse return null;
        self.live += 1;
        self.high_water = @max(self.high_water, self.fixed.end_index);
        return bytes;
    }

    fn free(context: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, address: usize) void {
        const self: *Workspace = @ptrCast(@alignCast(context));
        std.debug.assert(self.live > 0);
        self.fixed.allocator().rawFree(bytes, alignment, address);
        self.live -= 1;
        if (self.live == 0) {
            std.crypto.secureZero(u8, self.fixed.buffer[0..self.high_water]);
            self.fixed.reset();
            self.high_water = 0;
        }
    }
};

test "record workspace waits for non-LIFO slices then erases and reuses storage" {
    var workspace = try Workspace.init(std.testing.allocator, 64);
    defer workspace.deinit();
    const allocator = workspace.allocator();
    for (0..32) |_| {
        const first = try allocator.alloc(u8, 16);
        const second = try allocator.alloc(u8, 16);
        const last = try allocator.alloc(u8, 16);
        @memset(first, 0x11);
        @memset(second, 0x22);
        @memset(last, 0x33);
        allocator.free(second);
        allocator.free(first);
        try std.testing.expectEqual(1, workspace.live);
        try std.testing.expect(std.mem.allEqual(u8, last, 0x33));
        allocator.free(last);
        try std.testing.expectEqual(0, workspace.live);
        try std.testing.expectEqual(0, workspace.fixed.end_index);
        try std.testing.expect(std.mem.allEqual(u8, workspace.fixed.buffer[0..48], 0));
    }
}

test "record workspace exhaustion cannot fall back to its backing heap" {
    var workspace = try Workspace.init(std.testing.allocator, 32);
    defer workspace.deinit();
    const allocator = workspace.allocator();
    const bytes = try allocator.alloc(u8, 32);
    @memset(bytes, 0x55);
    try std.testing.expectError(error.OutOfMemory, allocator.alloc(u8, 1));
    try std.testing.expect(std.mem.allEqual(u8, bytes, 0x55));
    allocator.free(bytes);
    const again = try allocator.alloc(u8, 32);
    allocator.free(again);
}

test "record workspace admission propagates backing allocation failure" {
    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, Workspace.init(failing.allocator(), 32));
}
