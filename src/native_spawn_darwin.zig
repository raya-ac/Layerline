const std = @import("std");
const posix = std.posix;

extern "c" fn posix_spawnattr_setpgroup(attr: *std.c.posix_spawnattr_t, group: posix.pid_t) c_int;

fn failure(code: c_int) anyerror {
    if (code < 0) return error.ChildSetupFailed;
    return switch (@as(posix.E, @enumFromInt(code))) {
        .NOENT, .NOTDIR => error.FileNotFound,
        .ACCES, .PERM => error.AccessDenied,
        .NOEXEC => error.InvalidExecutable,
        .MFILE => error.ProcessFdQuotaExceeded,
        .NFILE => error.SystemFdQuotaExceeded,
        .AGAIN, .NOMEM => error.SystemResources,
        .INTR => error.Interrupted,
        else => error.ChildSetupFailed,
    };
}

fn check(code: c_int) !void {
    if (code != 0) return failure(code);
}

pub const Prepared = struct {
    actions: std.c.posix_spawn_file_actions_t,
    attributes: std.c.posix_spawnattr_t,

    pub fn init(pipes: *const [3][2]posix.fd_t) !Prepared {
        var actions: std.c.posix_spawn_file_actions_t = undefined;
        try check(std.c.posix_spawn_file_actions_init(&actions));
        errdefer _ = std.c.posix_spawn_file_actions_destroy(&actions);
        var attributes: std.c.posix_spawnattr_t = undefined;
        try check(std.c.posix_spawnattr_init(&attributes));
        errdefer _ = std.c.posix_spawnattr_destroy(&attributes);
        try check(std.c.posix_spawnattr_setflags(&attributes, .{ .SETPGROUP = true, .CLOEXEC_DEFAULT = true }));
        try check(posix_spawnattr_setpgroup(&attributes, 0));
        // CLOEXEC_DEFAULT lets only these dup2 targets survive, even if another
        // parent thread is between creating a handle and setting its CLOEXEC bit.
        try check(std.c.posix_spawn_file_actions_adddup2(&actions, pipes[0][0], 0));
        try check(std.c.posix_spawn_file_actions_adddup2(&actions, pipes[1][1], 1));
        try check(std.c.posix_spawn_file_actions_adddup2(&actions, pipes[2][1], 2));
        return .{ .actions = actions, .attributes = attributes };
    }

    pub fn deinit(self: *Prepared) void {
        _ = std.c.posix_spawn_file_actions_destroy(&self.actions);
        _ = std.c.posix_spawnattr_destroy(&self.attributes);
    }

    pub fn spawn(self: *const Prepared, path: [*:0]const u8, argv: [*:null]const ?[*:0]const u8, envp: [*:null]const ?[*:0]const u8) !posix.pid_t {
        var pid: posix.pid_t = undefined;
        // Darwin reports failed execs synchronously and reaps them in the kernel.
        // On success the caller takes PID ownership before releasing its lock.
        try check(std.c.posix_spawn(&pid, path, &self.actions, &self.attributes, argv, envp));
        return pid;
    }
};

test "Darwin spawn flags match the kernel descriptor allowlist and group ABI" {
    if (comptime @import("builtin").os.tag != .macos) return error.SkipZigTest;
    const flags: std.c.POSIX_SPAWN = .{ .SETPGROUP = true, .CLOEXEC_DEFAULT = true };
    try std.testing.expectEqual(@as(c_short, 0x4002), @as(c_short, @bitCast(flags)));
    try std.testing.expectEqual(error.FileNotFound, failure(@intFromEnum(posix.E.NOENT)));
    try std.testing.expectEqual(error.SystemResources, failure(@intFromEnum(posix.E.AGAIN)));
}
