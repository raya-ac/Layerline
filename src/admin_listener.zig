const std = @import("std");
const builtin = @import("builtin");
const native_accept = @import("native_accept.zig");
const posix = std.posix;

const Identity = struct {
    inode: u64,
    device: u64,
    uid: u32,
    mode: u32,
    links: u64,

    fn same(self: Identity, other: Identity) bool {
        return self.inode == other.inode and self.device == other.device and self.uid == other.uid;
    }
};

fn identity(fd: posix.fd_t, name: [:0]const u8) !Identity {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        var stat: linux.Statx = undefined;
        while (true) switch (linux.errno(linux.statx(fd, name, linux.AT.SYMLINK_NOFOLLOW | if (name.len == 0) @as(u32, linux.AT.EMPTY_PATH) else 0, .{ .TYPE = true, .MODE = true, .UID = true, .INO = true, .NLINK = true }, &stat))) {
            .SUCCESS => {
                if (!stat.mask.TYPE or !stat.mask.MODE or !stat.mask.UID or !stat.mask.INO or !stat.mask.NLINK) return error.SocketIdentityUnavailable;
                return .{ .inode = stat.ino, .device = (@as(u64, stat.dev_major) << 32) | stat.dev_minor, .uid = stat.uid, .mode = stat.mode, .links = stat.nlink };
            },
            .INTR => continue,
            .NOENT => return error.FileNotFound,
            else => return error.SocketIdentityUnavailable,
        };
    }
    if (builtin.os.tag == .macos) {
        var stat: std.c.Stat = undefined;
        while (true) {
            const rc = if (name.len == 0) std.c.fstat(fd, &stat) else std.c.fstatat(fd, name, &stat, posix.AT.SYMLINK_NOFOLLOW);
            switch (posix.errno(rc)) {
                .SUCCESS => return .{ .inode = stat.ino, .device = @as(u32, @bitCast(stat.dev)), .uid = stat.uid, .mode = stat.mode, .links = stat.nlink },
                .INTR => continue,
                .NOENT => return error.FileNotFound,
                else => return error.SocketIdentityUnavailable,
            }
        }
    }
    return error.OperationUnsupported;
}

fn owner() u32 {
    return posix.system.geteuid();
}

fn checkParent(value: Identity) !void {
    if (value.uid != owner() and value.uid != 0) return error.UnsafeAdminSocketDirectory;
    // Sticky directories such as /tmp protect an existing owner's entries.
    if (value.mode & 0o022 != 0 and value.mode & 0o1000 == 0) return error.UnsafeAdminSocketDirectory;
}

fn checkSocket(value: Identity) !void {
    if (value.uid != owner() or value.mode & posix.S.IFMT != posix.S.IFSOCK or value.links != 1)
        return error.SocketIdentityUnavailable;
}

fn openParent(io: std.Io, canonical: []const u8) !std.Io.Dir {
    var directory = try std.Io.Dir.openDirAbsolute(io, "/", .{});
    errdefer directory.close(io);
    try checkParent(try identity(directory.handle, ""));
    var parts = std.mem.tokenizeScalar(u8, canonical, '/');
    while (parts.next()) |part| {
        const next = try directory.openDir(io, part, .{ .follow_symlinks = false });
        directory.close(io);
        directory = next;
        try checkParent(try identity(directory.handle, ""));
    }
    return directory;
}

fn stale(io: std.Io, path: []const u8) !bool {
    const flags = posix.SOCK.STREAM | if (builtin.os.tag == .linux) posix.SOCK.CLOEXEC | posix.SOCK.NONBLOCK else @as(u32, 0);
    const fd = posix.system.socket(posix.AF.UNIX, @intCast(flags), 0);
    if (posix.errno(fd) != .SUCCESS) return error.SocketProbeFailed;
    const stream = std.Io.net.Stream{ .socket = .{ .handle = @intCast(fd), .address = .{ .ip4 = .loopback(0) } } };
    defer stream.close(io);
    if (builtin.os.tag == .macos) {
        if (posix.errno(posix.system.fcntl(stream.socket.handle, posix.F.SETFD, @as(usize, posix.FD_CLOEXEC))) != .SUCCESS or
            posix.errno(posix.system.fcntl(stream.socket.handle, posix.F.SETFL, @as(usize, 1 << @bitOffsetOf(posix.O, "NONBLOCK")))) != .SUCCESS)
            return error.SocketProbeFailed;
    }
    var address = std.mem.zeroes(posix.sockaddr.un);
    address.family = posix.AF.UNIX;
    if (path.len >= address.path.len) return error.NameTooLong;
    @memcpy(address.path[0..path.len], path);
    const length: posix.socklen_t = @intCast(@offsetOf(posix.sockaddr.un, "path") + path.len + 1);
    // A full backlog is busy, not stale. Never wait for or send a command to
    // another server while deciding whether an abandoned socket can be removed.
    return switch (posix.errno(posix.system.connect(stream.socket.handle, @ptrCast(&address), length))) {
        .CONNREFUSED => true,
        .SUCCESS, .ISCONN, .INPROGRESS, .ALREADY, .AGAIN, .INTR => false,
        else => error.SocketProbeFailed,
    };
}

pub const Listener = struct {
    server: std.Io.net.Server,
    parent: std.Io.Dir,
    lock: std.Io.File,
    path: [:0]u8,
    name: [:0]u8,
    owned: Identity,
    allocator: std.mem.Allocator,
    cleanup_claimed: std.atomic.Value(bool) = .init(false),

    pub fn init(io: std.Io, allocator: std.mem.Allocator, path: []const u8) !Listener {
        if (comptime builtin.os.tag != .linux and builtin.os.tag != .macos) return error.OperationUnsupported;
        if (path.len == 0 or std.mem.indexOfScalar(u8, path, 0) != null) return error.InvalidAdminSocketPath;
        const canonical = try std.Io.Dir.cwd().realPathFileAlloc(io, std.fs.path.dirname(path) orelse ".", allocator);
        defer allocator.free(canonical);
        var parent = try openParent(io, canonical);
        errdefer parent.close(io);
        const name = try allocator.dupeZ(u8, std.fs.path.basename(path));
        errdefer allocator.free(name);
        if (name.len == 0 or std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return error.InvalidAdminSocketPath;
        // Keep the caller's shorter spelling for sockaddr_un (for example
        // /var instead of /private/var on macOS). Ownership checks and cleanup
        // still use the verified canonical parent handle above.
        const full_path = try allocator.dupeZ(u8, path);
        errdefer allocator.free(full_path);
        if (full_path.len >= @sizeOf(@FieldType(posix.sockaddr.un, "path"))) return error.NameTooLong;
        const address = try std.Io.net.UnixAddress.init(full_path);
        const lock_name = try std.mem.concatWithSentinel(allocator, u8, &.{ name, ".lock" }, 0);
        defer allocator.free(lock_name);
        const lock = parent.createFile(io, lock_name, .{ .read = true, .truncate = false, .exclusive = true, .permissions = @enumFromInt(0o600) }) catch |err| switch (err) {
            error.PathAlreadyExists => try parent.openFile(io, lock_name, .{ .mode = .read_write, .allow_directory = false, .follow_symlinks = false }),
            else => return err,
        };
        errdefer lock.close(io);
        const lock_id = try identity(lock.handle, "");
        if (lock_id.uid != owner() or lock_id.mode & posix.S.IFMT != posix.S.IFREG or lock_id.mode & 0o077 != 0 or lock_id.links != 1)
            return error.UnsafeAdminSocketLock;
        if (!try lock.tryLock(io, .exclusive)) return error.AddressInUse;
        // Keep the lock file after close: unlinking a locked file would let a
        // competing process obtain a different lock inode for the same socket.
        if (identity(parent.handle, name)) |existing| {
            if (existing.uid != owner() or existing.mode & posix.S.IFMT != posix.S.IFSOCK or !try stale(io, full_path)) return error.AddressInUse;
            if (!existing.same(try identity(parent.handle, name))) return error.AddressInUse;
            try parent.deleteFile(io, name);
        } else |err| if (err != error.FileNotFound) return err;
        var server = try address.listen(io, .{ .kernel_backlog = 16 });
        errdefer server.deinit(io);
        const owned = try identity(parent.handle, name);
        try checkSocket(owned);
        var result: Listener = .{ .server = server, .parent = parent, .lock = lock, .path = full_path, .name = name, .owned = owned, .allocator = allocator };
        errdefer result.removePath(io);
        try parent.setFilePermissions(io, name, @enumFromInt(0o600), .{ .follow_symlinks = false });
        try native_accept.prepare(&result.server);
        return result;
    }

    pub fn removePath(self: *Listener, io: std.Io) void {
        if (self.cleanup_claimed.swap(true, .acq_rel)) return;
        const current = identity(self.parent.handle, self.name) catch return;
        if (self.owned.same(current) and current.mode & posix.S.IFMT == posix.S.IFSOCK)
            self.parent.deleteFile(io, self.name) catch {};
    }

    pub fn deinit(self: *Listener, io: std.Io) void {
        self.server.deinit(io);
        self.removePath(io);
        self.lock.close(io);
        self.parent.close(io);
        self.allocator.free(self.path);
        self.allocator.free(self.name);
    }
};

extern "c" fn getpeereid(fd: c_int, uid: *u32, gid: *u32) c_int;

pub fn authorized(stream: std.Io.net.Stream) !bool {
    if (builtin.os.tag == .linux) {
        var credentials: extern struct { pid: c_int, uid: u32, gid: u32 } = undefined;
        var size: posix.socklen_t = @sizeOf(@TypeOf(credentials));
        while (true) switch (posix.errno(posix.system.getsockopt(stream.socket.handle, posix.SOL.SOCKET, posix.SO.PEERCRED, @ptrCast(&credentials), &size))) {
            .SUCCESS => {
                if (size != @sizeOf(@TypeOf(credentials))) return error.PeerCredentialsUnavailable;
                return credentials.uid == owner() or credentials.uid == 0;
            },
            .INTR => continue,
            else => return error.PeerCredentialsUnavailable,
        };
    }
    if (builtin.os.tag == .macos) {
        var uid: u32 = undefined;
        var gid: u32 = undefined;
        while (true) switch (posix.errno(getpeereid(stream.socket.handle, &uid, &gid))) {
            .SUCCESS => return uid == owner() or uid == 0,
            .INTR => continue,
            else => return error.PeerCredentialsUnavailable,
        };
    }
    return error.OperationUnsupported;
}

test "admin socket parents need a trusted owner and protected directory entries" {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos) return error.SkipZigTest;
    var value: Identity = .{ .inode = 1, .device = 2, .uid = owner(), .mode = 0o700, .links = 1 };
    try checkParent(value);
    value.mode = 0o777;
    try std.testing.expectError(error.UnsafeAdminSocketDirectory, checkParent(value));
    value.mode = 0o1777;
    try checkParent(value);
    value.uid = owner() + 1;
    try std.testing.expectError(error.UnsafeAdminSocketDirectory, checkParent(value));
    value.uid = 0;
    try checkParent(value);
    var changed = value;
    changed.device += 1;
    try std.testing.expect(!value.same(changed));
    changed = value;
    changed.inode += 1;
    try std.testing.expect(!value.same(changed));
}

test "post-bind identity must still name an owned socket before permission changes" {
    if (builtin.os.tag != .linux and builtin.os.tag != .macos) return error.SkipZigTest;
    var value: Identity = .{ .inode = 1, .device = 2, .uid = owner(), .mode = posix.S.IFSOCK | 0o600, .links = 1 };
    try checkSocket(value);
    for ([_]u32{ posix.S.IFREG, posix.S.IFLNK, posix.S.IFDIR }) |kind| {
        value.mode = kind | 0o600;
        try std.testing.expectError(error.SocketIdentityUnavailable, checkSocket(value));
    }
    value.mode = posix.S.IFSOCK | 0o600;
    value.uid += 1;
    try std.testing.expectError(error.SocketIdentityUnavailable, checkSocket(value));
    value.uid = owner();
    value.links = 2;
    try std.testing.expectError(error.SocketIdentityUnavailable, checkSocket(value));
}
