const std = @import("std");
const builtin = @import("builtin");
const Deadline = @import("read_deadline.zig").Deadline;
const native_spawn = @import("native_spawn.zig");

pub const Options = struct {
    argv: []const []const u8,
    environ_map: ?*const std.process.Environ.Map = null,
    input: []const u8 = "",
    timeout_ms: u32,
    stdout_limit: usize,
    stderr_limit: usize,
    shutdown: ?*const std.atomic.Value(bool) = null,
};

pub const max_children = native_spawn.max_children;
var active_children = std.atomic.Value(usize).init(0);

fn reserve() !void {
    if (active_children.fetchAdd(1, .acq_rel) >= max_children) {
        _ = active_children.fetchSub(1, .acq_rel);
        return error.ChildCapacity;
    }
}

// WNOWAIT keeps the leader's PID reserved until its process group has been
// stopped. Reaping first would let a later group signal race PID reuse.
extern "c" fn waitid(kind: c_uint, id: c_uint, info: *std.c.siginfo_t, flags: c_int) c_int;

fn exited(pid: std.posix.pid_t) !bool {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        var info = std.mem.zeroes(linux.siginfo_t);
        return switch (linux.errno(linux.waitid(.PID, pid, &info, linux.W.EXITED | linux.W.NOWAIT | linux.W.NOHANG, null))) {
            .SUCCESS => info.fields.common.first.piduid.pid != 0,
            .INTR => false,
            else => error.ChildWaitFailed,
        };
    }
    var info = std.mem.zeroes(std.c.siginfo_t);
    // Darwin sys/wait.h: P_PID, WEXITED | WNOWAIT | WNOHANG.
    return switch (std.posix.errno(waitid(1, @intCast(pid), &info, 4 | 32 | 1))) {
        .SUCCESS => info.pid != 0,
        .INTR => false,
        else => error.ChildWaitFailed,
    };
}

fn signal(pid: std.posix.pid_t) !void {
    while (true) switch (std.posix.errno(std.posix.system.kill(pid, .KILL))) {
        .SUCCESS, .SRCH => return,
        .INTR => continue,
        .PERM => {
            // Darwin skips zombies during group delivery and reports EPERM
            // when no signalable members remain. Our unreaped leader anchors
            // this group ID; commands that change credentials are not sandboxed.
            if (builtin.os.tag == .macos and pid < -1 and try exited(-pid)) return;
            return error.ChildSignalFailed;
        },
        else => return error.ChildSignalFailed,
    };
}

fn reap(pid: std.posix.pid_t) !std.process.Child.Term {
    var status: if (builtin.link_libc) c_int else u32 = undefined;
    while (true) switch (std.posix.errno(std.posix.system.waitpid(pid, &status, 0))) {
        .SUCCESS => return std.Io.Threaded.statusToTerm(@bitCast(status)),
        .INTR => continue,
        else => return error.ChildWaitFailed,
    };
}

fn close(io: std.Io, pipe: *?std.Io.File) void {
    if (pipe.*) |file| file.close(io);
    pipe.* = null;
}

fn cleanup(io: std.Io, child: *std.process.Child) void {
    if (child.id) |pid| {
        std.debug.assert(pid > 1);
        native_spawn.stopOwned(io, pid);
        if (reap(pid)) |_| {} else |err| {
            std.debug.print("{{\"event\":\"server.child_cleanup_error\",\"phase\":\"reap\",\"error\":\"{s}\"}}\n", .{@errorName(err)});
        }
        child.id = null;
    }
    close(io, &child.stdin);
    close(io, &child.stdout);
    close(io, &child.stderr);
}

fn nonblocking(file: std.Io.File) !void {
    const flags = while (true) {
        const result = std.posix.system.fcntl(file.handle, std.posix.F.GETFL, @as(usize, 0));
        switch (std.posix.errno(result)) {
            .SUCCESS => break @as(usize, @intCast(result)),
            .INTR => continue,
            else => return error.ChildPipeFailed,
        }
    };
    while (true) switch (std.posix.errno(std.posix.system.fcntl(file.handle, std.posix.F.SETFL, flags | (1 << @bitOffsetOf(std.posix.O, "NONBLOCK"))))) {
        .SUCCESS => return,
        .INTR => continue,
        else => return error.ChildPipeFailed,
    };
}

fn append(allocator: std.mem.Allocator, output: *std.ArrayList(u8), bytes: []const u8, limit: usize, overflow: anyerror) !void {
    if (bytes.len > limit - output.items.len) return overflow;
    try output.appendSlice(allocator, bytes);
}

fn read(io: std.Io, allocator: std.mem.Allocator, pipe: *?std.Io.File, output: *std.ArrayList(u8), limit: usize, overflow: anyerror) !bool {
    const file = pipe.* orelse return false;
    var buffer: [8192]u8 = undefined;
    const n = std.posix.system.read(file.handle, &buffer, buffer.len);
    switch (std.posix.errno(n)) {
        .SUCCESS => {
            if (n == 0) close(io, pipe) else try append(allocator, output, buffer[0..@intCast(n)], limit, overflow);
            return true;
        },
        .INTR, .AGAIN => return false,
        else => return error.ChildPipeFailed,
    }
}

fn check(io: std.Io, options: Options, deadline: Deadline) !void {
    try io.checkCancel();
    if (native_spawn.isStopping()) return error.Canceled;
    if (options.shutdown) |requested| if (requested.load(.acquire)) return error.Canceled;
    _ = try deadline.remaining(.now(io, .awake));
}

pub fn run(io: std.Io, allocator: std.mem.Allocator, options: Options) !std.process.RunResult {
    if (comptime builtin.os.tag != .linux and builtin.os.tag != .macos) return error.OperationUnsupported;
    const deadline: Deadline = .after(.now(io, .awake), options.timeout_ms);
    try check(io, options, deadline);
    try reserve();
    // Keep the slot until cleanup has reaped the child, not just until EOF.
    defer _ = active_children.fetchSub(1, .acq_rel);
    const started = try native_spawn.start(io, allocator, options.argv, options.environ_map, deadline, options.shutdown);
    var child = started.child;
    defer cleanup(io, &child);
    var exec_status: ?std.Io.File = started.exec_status;
    defer close(io, &exec_status);
    try nonblocking(exec_status.?);
    if (child.stdin) |file| try nonblocking(file);
    if (options.input.len == 0) close(io, &child.stdin);
    try nonblocking(child.stdout.?);
    try nonblocking(child.stderr.?);
    var out = std.ArrayList(u8).empty;
    defer out.deinit(allocator);
    var err = std.ArrayList(u8).empty;
    defer err.deinit(allocator);
    var input_offset: usize = 0;
    var group_stopped = false;
    while (true) {
        try check(io, options, deadline);
        if (exec_status) |file| {
            var byte: [1]u8 = undefined;
            const n = std.posix.system.read(file.handle, &byte, 1);
            switch (std.posix.errno(n)) {
                .SUCCESS => {
                    if (n == 0) close(io, &exec_status) else return (std.enums.fromInt(native_spawn.ExecFailure, byte[0]) orelse return error.ChildSetupFailed).err();
                },
                .AGAIN, .INTR => {},
                else => return error.ChildSetupFailed,
            }
        }
        var progress = try read(io, allocator, &child.stdout, &out, options.stdout_limit, error.StdoutTooLong);
        progress = (try read(io, allocator, &child.stderr, &err, options.stderr_limit, error.StderrTooLong)) or progress;
        if (child.stdin) |file| {
            const remaining = options.input[input_offset..];
            const n = std.posix.system.write(file.handle, remaining.ptr, @min(remaining.len, 16384));
            switch (std.posix.errno(n)) {
                .SUCCESS => {
                    if (n == 0) return error.ChildPipeFailed;
                    input_offset += @intCast(n);
                    progress = true;
                    if (input_offset == options.input.len) close(io, &child.stdin);
                },
                .PIPE => close(io, &child.stdin),
                .INTR, .AGAIN => {},
                else => return error.ChildPipeFailed,
            }
        }
        if (!group_stopped and try exited(child.id.?)) {
            try signal(-child.id.?);
            group_stopped = true;
            close(io, &child.stdin);
        }
        try check(io, options, deadline);
        if (group_stopped and child.stdout == null and child.stderr == null and exec_status == null) break;
        if (progress) continue;
        var fds: [4]std.posix.pollfd = undefined;
        var count: usize = 0;
        for ([_]?std.Io.File{ child.stdout, child.stderr, child.stdin, exec_status }, 0..) |pipe, index| {
            if (pipe) |file| {
                fds[count] = .{ .fd = file.handle, .events = if (index == 2) std.posix.POLL.OUT else std.posix.POLL.IN, .revents = 0 };
                count += 1;
            }
        }
        const ms: i32 = @intCast(@min(try deadline.remaining(.now(io, .awake)) orelse 25, 25));
        switch (std.posix.errno(std.posix.system.poll(&fds, @intCast(count), ms))) {
            .SUCCESS, .INTR => {},
            else => return error.ChildPipeFailed,
        }
    }
    const term = try native_spawn.reapExited(io, &child);
    const stdout = try out.toOwnedSlice(allocator);
    errdefer allocator.free(stdout);
    return .{ .term = term, .stdout = stdout, .stderr = try err.toOwnedSlice(allocator) };
}

test "child output caps include the final read and allocation failures release buffers" {
    var output = std.ArrayList(u8).empty;
    defer output.deinit(std.testing.allocator);
    try append(std.testing.allocator, &output, "abc", 3, error.StdoutTooLong);
    try std.testing.expectError(error.StdoutTooLong, append(std.testing.allocator, &output, "d", 3, error.StdoutTooLong));
    try std.testing.expectEqualStrings("abc", output.items);
    const Case = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var out = std.ArrayList(u8).empty;
            defer out.deinit(allocator);
            try append(allocator, &out, "bounded output", 20, error.StdoutTooLong);
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Case.run, .{});
}

test "child budgets and shutdown are checked before spawning or accepting more progress" {
    var shutdown = std.atomic.Value(bool).init(false);
    const options: Options = .{ .argv = &.{"unused"}, .timeout_ms = 1, .stdout_limit = 1, .stderr_limit = 1, .shutdown = &shutdown };
    try std.testing.expectError(error.RequestTimeout, check(std.testing.io, options, .after(.zero, 1)));
    try check(std.testing.io, options, .{});
    shutdown.store(true, .release);
    try std.testing.expectError(error.Canceled, run(std.testing.io, std.testing.allocator, options));
}

test "child admission counts cleanup and rejects excess work without consuming slots" {
    try std.testing.expectEqual(0, active_children.load(.acquire));
    for (0..max_children) |_| try reserve();
    defer active_children.store(0, .release);
    try std.testing.expectError(error.ChildCapacity, reserve());
    try std.testing.expectEqual(max_children, active_children.load(.acquire));
    _ = active_children.fetchSub(1, .acq_rel);
    try reserve();
}

test "child capture releases its process and buffers at every allocation failure" {
    if (builtin.os.tag != .macos and builtin.os.tag != .linux) return error.SkipZigTest;
    const Case = struct {
        fn exercise(allocator: std.mem.Allocator) !void {
            const result = try runForTest(allocator);
            defer allocator.free(result.stdout);
            defer allocator.free(result.stderr);
            try std.testing.expectEqualStrings("ok", result.stdout);
        }
        fn runForTest(allocator: std.mem.Allocator) !std.process.RunResult {
            return run(std.testing.io, allocator, .{ .argv = &.{ "/bin/sh", "-c", "printf ok" }, .timeout_ms = 2000, .stdout_limit = 10, .stderr_limit = 10 });
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Case.exercise, .{});
    try std.testing.expectEqual(0, active_children.load(.acquire));
}
