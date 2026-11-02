const std = @import("std");
const resource_budget = @import("resource_budget.zig");

pub const default_thread_limit = 128;
pub const minimum_thread_limit = 8;
pub const maximum_thread_limit = 4096;
pub const default_stack_size = 1024 * 1024;
pub const maximum_stack_size = 64 * 1024 * 1024;

var active: ?*std.Io.Threaded = null;

pub fn validate(limit: usize, stack_size: usize) !void {
    if (limit < minimum_thread_limit or limit > maximum_thread_limit or
        stack_size < default_stack_size or stack_size > maximum_stack_size)
        return error.InvalidConfigValue;
    _ = std.math.mul(usize, limit, stack_size) catch return error.InvalidConfigValue;
}

// Called once after configuration, before certificate work or server workers.
pub fn configure(io: std.Io, limit: usize, stack_size: usize) !void {
    try validate(limit, stack_size);
    const runtime = active orelse return error.IoRuntimeUnavailable;
    runtime.mutex.lockUncancelable(io);
    defer runtime.mutex.unlock(io);
    if (runtime.worker_threads.load(.acquire) != null or runtime.busy_count != 0) return error.IoRuntimeAlreadyStarted;
    runtime.async_limit = .limited(limit);
    runtime.concurrent_limit = .limited(limit);
    runtime.stack_size = stack_size;
}

pub const Snapshot = struct {
    limit: usize = default_thread_limit,
    stack_size: usize = default_stack_size,
    threads: usize = 0,
    busy: usize = 0,
};

pub fn snapshot() Snapshot {
    const runtime = active orelse return .{};
    const io = runtime.io();
    runtime.mutex.lockUncancelable(io);
    defer runtime.mutex.unlock(io);
    return .{ .limit = @intFromEnum(runtime.concurrent_limit), .stack_size = runtime.stack_size, .threads = threadCount(runtime), .busy = runtime.busy_count };
}

fn threadCount(runtime: *std.Io.Threaded) usize {
    var count: usize = 0;
    var cursor = runtime.worker_threads.load(.acquire);
    while (cursor) |thread| : (cursor = thread.next) count += 1;
    return count;
}

pub fn run(minimal: std.process.Init.Minimal, comptime app: fn (std.process.Init) anyerror!void) !void {
    // Init.Minimal avoids the standard unbounded I/O pool and allocator roots.
    // Environment/bootstrap storage lives in the same parent budget as requests.
    const allocator = resource_budget.allocator();
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    var runtime: std.Io.Threaded = .init(resource_budget.io.allocator(), .{
        .argv0 = .init(minimal.args),
        .environ = minimal.environ,
        .stack_size = default_stack_size,
        .async_limit = .limited(default_thread_limit),
        .concurrent_limit = .limited(default_thread_limit),
    });
    defer runtime.deinit();
    active = &runtime;
    defer active = null;
    var environment = try minimal.environ.createMap(arena.allocator());
    defer environment.deinit();
    const preopens = try std.process.Preopens.init(arena.allocator());
    try app(.{ .minimal = minimal, .arena = &arena, .gpa = allocator, .io = runtime.io(), .environ_map = &environment, .preopens = preopens });
}

test "runtime limits reject unsafe stacks and unbounded thread settings" {
    try validate(default_thread_limit, default_stack_size);
    for ([_]usize{ 0, minimum_thread_limit - 1, maximum_thread_limit + 1, std.math.maxInt(usize) }) |limit|
        try std.testing.expectError(error.InvalidConfigValue, validate(limit, default_stack_size));
    for ([_]usize{ 0, default_stack_size - 1, maximum_stack_size + 1, std.math.maxInt(usize) }) |stack|
        try std.testing.expectError(error.InvalidConfigValue, validate(default_thread_limit, stack));
}

test "bounded I/O admission rejects work rather than running it inline" {
    var runtime: std.Io.Threaded = .init(std.testing.allocator, .{ .async_limit = .limited(2), .concurrent_limit = .limited(2), .stack_size = default_stack_size });
    defer runtime.deinit();
    const io = runtime.io();
    const Worker = struct {
        fn wait(task_io: std.Io) !void {
            try task_io.sleep(.fromSeconds(60), .awake);
        }
    };
    var first = try io.concurrent(Worker.wait, .{io});
    defer first.cancel(io) catch {};
    var second = try io.concurrent(Worker.wait, .{io});
    defer second.cancel(io) catch {};
    try std.testing.expectError(error.ConcurrencyUnavailable, io.concurrent(Worker.wait, .{io}));
    try std.testing.expect(threadCount(&runtime) <= 2);
}
