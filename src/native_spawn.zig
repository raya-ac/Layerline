const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const Deadline = @import("read_deadline.zig").Deadline;

// Darwin cannot create CLOEXEC pipes atomically. Serialize their creation and
// fork so another command cannot inherit an intermediate pipe endpoint.
var launch_mutex: std.Io.Mutex = .init;
pub const max_children = 64;
var children: [max_children]posix.pid_t = @splat(0);
var stopping = std.atomic.Value(bool).init(false);

pub fn isStopping() bool {
    return stopping.load(.acquire);
}

fn terminate(pid: posix.pid_t) void {
    std.debug.assert(pid > 1);
    for ([_]posix.pid_t{ -pid, pid }) |target| {
        while (true) switch (posix.errno(posix.system.kill(target, .KILL))) {
            .SUCCESS, .SRCH => break,
            .INTR => continue,
            .PERM => {
                if (target > 0) std.debug.print("{{\"event\":\"server.child_cleanup_error\",\"phase\":\"leader\",\"errno\":\"PERM\"}}\n", .{});
                break;
            },
            else => |cause| {
                std.debug.print("{{\"event\":\"server.child_cleanup_error\",\"phase\":\"signal\",\"errno\":\"{s}\"}}\n", .{@tagName(cause)});
                break;
            },
        };
    }
}

fn remove(pid: posix.pid_t) void {
    for (&children) |*owned| if (owned.* == pid) {
        owned.* = 0;
        return;
    };
    std.debug.assert(false);
}

pub fn stopOwned(io: std.Io, pid: posix.pid_t) void {
    launch_mutex.lockUncancelable(io);
    defer launch_mutex.unlock(io);
    terminate(pid);
    remove(pid);
}

pub fn reapExited(io: std.Io, child: *std.process.Child) !std.process.Child.Term {
    const pid = child.id.?;
    launch_mutex.lockUncancelable(io);
    defer launch_mutex.unlock(io);
    defer {
        remove(pid);
        child.id = null;
    }
    var status: if (builtin.link_libc) c_int else u32 = undefined;
    // WNOWAIT already proved termination. Reap under the registry lock so a
    // shutdown scan cannot signal a PID after the kernel has reused it.
    while (true) switch (posix.errno(posix.system.waitpid(pid, &status, 0))) {
        .SUCCESS => return std.Io.Threaded.statusToTerm(@bitCast(status)),
        .INTR => continue,
        else => return error.ChildWaitFailed,
    };
}

pub fn tryStopAll(io: std.Io) bool {
    stopping.store(true, .release);
    if (!launch_mutex.tryLock()) return false;
    defer launch_mutex.unlock(io);
    // Owners cannot reap/reuse these PIDs until they remove them under this
    // same lock. Shutdown signals never act on a stale saved PID.
    for (children) |pid| if (pid != 0) terminate(pid);
    return true;
}

pub const Spawned = struct {
    child: std.process.Child,
    exec_status: std.Io.File,
};

pub const ExecFailure = enum(u8) {
    not_found = 1,
    denied,
    invalid_executable,
    setup,

    pub fn err(self: ExecFailure) anyerror {
        return switch (self) {
            .not_found => error.FileNotFound,
            .denied => error.AccessDenied,
            .invalid_executable => error.InvalidExecutable,
            .setup => error.ChildSetupFailed,
        };
    }
};

fn close(handle: posix.fd_t) void {
    _ = posix.system.close(handle);
}

fn systemFailure(cause: posix.E) anyerror {
    return switch (cause) {
        .MFILE => error.ProcessFdQuotaExceeded,
        .NFILE => error.SystemFdQuotaExceeded,
        .NOMEM, .NOBUFS, .AGAIN => error.SystemResources,
        else => error.ChildPipeFailed,
    };
}

fn control(handle: posix.fd_t, command: i32, value: usize) !usize {
    while (true) {
        const result = posix.system.fcntl(handle, command, value);
        switch (posix.errno(result)) {
            .SUCCESS => return @intCast(result),
            .INTR => continue,
            else => |cause| return systemFailure(cause),
        }
    }
}

fn pipe() ![2]posix.fd_t {
    var ends: [2]posix.fd_t = undefined;
    while (true) {
        const result = if (builtin.os.tag == .linux) posix.system.pipe2(&ends, .{ .CLOEXEC = true }) else std.c.pipe(&ends);
        switch (posix.errno(result)) {
            .SUCCESS => break,
            .INTR => continue,
            else => |cause| return systemFailure(cause),
        }
    }
    errdefer for (ends) |fd| close(fd);
    for (&ends) |*fd| {
        if (fd.* < 3) {
            const replacement: posix.fd_t = @intCast(try control(fd.*, posix.F.DUPFD_CLOEXEC, 3));
            close(fd.*);
            fd.* = replacement;
        }
        _ = try control(fd.*, posix.F.SETFD, posix.FD_CLOEXEC);
    }
    return ends;
}

fn report(fd: posix.fd_t, failure: ExecFailure) noreturn {
    const byte = [_]u8{@intFromEnum(failure)};
    while (posix.errno(posix.system.write(fd, &byte, 1)) == .INTR) {}
    if (builtin.link_libc) std.c._exit(127);
    std.os.linux.exit_group(127);
}

fn redirect(source: posix.fd_t, target: posix.fd_t, error_fd: posix.fd_t) void {
    while (true) switch (posix.errno(posix.system.dup2(source, target))) {
        .SUCCESS => return,
        .INTR => continue,
        else => report(error_fd, .setup),
    };
}

fn check(io: std.Io, deadline: Deadline, shutdown: ?*const std.atomic.Value(bool)) !void {
    try io.checkCancel();
    if (isStopping()) return error.Canceled;
    if (shutdown) |requested| if (requested.load(.acquire)) return error.Canceled;
    _ = try deadline.remaining(.now(io, .awake));
}

pub fn start(io: std.Io, allocator: std.mem.Allocator, argv: []const []const u8, environment: ?*const std.process.Environ.Map, deadline: Deadline, shutdown: ?*const std.atomic.Value(bool)) !Spawned {
    try check(io, deadline, shutdown);
    if (argv.len == 0 or argv[0].len == 0) return error.InvalidArgument;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const temporary = arena.allocator();
    const arguments = try temporary.allocSentinel(?[*:0]const u8, argv.len, null);
    for (argv, arguments) |value, *argument| {
        if (std.mem.indexOfScalar(u8, value, 0) != null) return error.InvalidArgument;
        argument.* = (try temporary.dupeZ(u8, value)).ptr;
    }
    const empty = [_:null]?[*:0]const u8{};
    const envp: [*:null]const ?[*:0]const u8 = if (environment) |env| @ptrCast((try env.createPosixBlock(temporary, .{ .zig_progress_fd = -1 })).slice.ptr) else &empty;
    var paths = std.ArrayList([:0]const u8).empty;
    if (std.mem.indexOfScalar(u8, argv[0], '/') != null) {
        try paths.append(temporary, try temporary.dupeZ(u8, argv[0]));
    } else {
        const path = if (environment) |env| env.get("PATH") orelse "/usr/local/bin:/usr/bin:/bin" else "/usr/local/bin:/usr/bin:/bin";
        var entries = std.mem.splitScalar(u8, path, ':');
        while (entries.next()) |entry| {
            const candidate = try std.fmt.allocPrintSentinel(temporary, "{s}/{s}", .{ if (entry.len == 0) "." else entry, argv[0] }, 0);
            try paths.append(temporary, candidate);
        }
    }
    while (!launch_mutex.tryLock()) {
        try check(io, deadline, shutdown);
        try io.sleep(.fromMilliseconds(1), .awake);
    }
    defer launch_mutex.unlock(io);
    try check(io, deadline, shutdown);
    const slot = for (&children) |*owned| {
        if (owned.* == 0) break owned;
    } else return error.ChildCapacity;
    var pipes: [4][2]posix.fd_t = undefined;
    var made: usize = 0;
    errdefer for (pipes[0..made]) |ends| for (ends) |fd| close(fd);
    while (made < pipes.len) : (made += 1) pipes[made] = try pipe();
    try check(io, deadline, shutdown);
    const pid: posix.pid_t = while (true) {
        const result = posix.system.fork();
        switch (posix.errno(result)) {
            .SUCCESS => break @intCast(result),
            .INTR => try io.checkCancel(),
            .AGAIN, .NOMEM => return error.SystemResources,
            else => return error.ChildForkFailed,
        }
    };
    if (pid == 0) {
        const error_fd = pipes[3][1];
        // Only async-signal-safe syscalls below: no allocator, IO runtime,
        // logging, or locks from the multithreaded parent may run after fork.
        while (true) switch (posix.errno(posix.system.setpgid(0, 0))) {
            .SUCCESS => break,
            .INTR => continue,
            else => report(error_fd, .setup),
        };
        redirect(pipes[0][0], 0, error_fd);
        redirect(pipes[1][1], 1, error_fd);
        redirect(pipes[2][1], 2, error_fd);
        for (pipes) |ends| for (ends) |fd| if (fd != error_fd) close(fd);
        var failure: ExecFailure = .not_found;
        for (paths.items) |path| {
            while (true) switch (posix.errno(posix.system.execve(path.ptr, arguments.ptr, envp))) {
                .NOENT, .NOTDIR => break,
                .ACCES => {
                    failure = .denied;
                    break;
                },
                .INTR => continue,
                .NOEXEC => report(error_fd, .invalid_executable),
                else => report(error_fd, .setup),
            };
        }
        report(error_fd, failure);
    }
    close(pipes[0][0]);
    close(pipes[1][1]);
    close(pipes[2][1]);
    close(pipes[3][1]);
    slot.* = pid;
    if (isStopping()) terminate(pid);
    return .{
        .child = .{
            .id = pid,
            .thread_handle = {},
            .stdin = .{ .handle = pipes[0][1], .flags = .{ .nonblocking = false } },
            .stdout = .{ .handle = pipes[1][0], .flags = .{ .nonblocking = false } },
            .stderr = .{ .handle = pipes[2][0], .flags = .{ .nonblocking = false } },
            .request_resource_usage_statistics = false,
        },
        .exec_status = .{ .handle = pipes[3][0], .flags = .{ .nonblocking = false } },
    };
}
