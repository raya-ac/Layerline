const std = @import("std");
const builtin = @import("builtin");
const budget = @import("descriptor_budget.zig");
const Io = std.Io;
const Dir = Io.Dir;
const File = Io.File;
const net = Io.net;

// One adapter belongs to the process-owned Threaded runtime. Its userdata stays
// unchanged, so untouched vtable entries still receive their original backend.
var original: *const Io.VTable = undefined;
var table: Io.VTable = undefined;
var installed = false;

fn inheritedHandles(io: Io) !usize {
    var dir = try Dir.cwd().openDir(io, if (builtin.os.tag == .linux) "/proc/self/fd" else "/dev/fd", .{ .iterate = true });
    defer dir.close(io);
    var iterator = dir.iterate();
    var count: usize = 0;
    while (try iterator.next(io)) |entry| {
        const handle = std.fmt.parseInt(usize, entry.name, 10) catch continue;
        if (handle != dir.handle) count += 1;
    }
    return count;
}

pub fn install(io: Io) !Io {
    if (!budget.supported) return io;
    if (installed) return error.DescriptorBudgetAlreadyInstalled;
    const limits = try std.posix.getrlimit(.NOFILE);
    const inherited = try inheritedHandles(io);
    try budget.install(std.math.cast(usize, limits.cur) orelse std.math.maxInt(usize), inherited);
    original = io.vtable;
    table = original.*;
    table.dirOpenDir = dirOpenDir;
    table.dirCreateDirPathOpen = dirCreateDirPathOpen;
    table.dirCreateDirPath = dirCreateDirPath;
    table.dirOpenFile = dirOpenFile;
    table.dirCreateFile = dirCreateFile;
    table.dirCreateFileAtomic = dirCreateFileAtomic;
    table.dirRealPathFile = dirRealPathFile;
    table.dirClose = dirClose;
    table.fileClose = fileClose;
    table.processExecutableOpen = processExecutableOpen;
    table.netListenIp = netListenIp;
    table.netAccept = netAccept;
    table.netBindIp = netBindIp;
    table.netConnectIp = netConnectIp;
    table.netListenUnix = netListenUnix;
    table.netConnectUnix = netConnectUnix;
    table.netSocketCreatePair = netSocketCreatePair;
    table.netLookup = netLookup;
    table.netClose = netClose;
    installed = true;
    return .{ .userdata = io.userdata, .vtable = &table };
}

pub fn uninstall() void {
    if (!installed) return;
    budget.uninstall();
    installed = false;
}

fn dirOpenDir(data: ?*anyopaque, dir: Dir, path: []const u8, options: Dir.OpenOptions) Dir.OpenError!Dir {
    var ticket = try budget.acquire(1);
    defer ticket.deinit();
    const result = try original.dirOpenDir(data, dir, path, options);
    errdefer original.dirClose(data, &.{result});
    try ticket.adopt(result.handle);
    return result;
}

fn dirCreateDirPathOpen(data: ?*anyopaque, dir: Dir, path: []const u8, permissions: Dir.Permissions, options: Dir.OpenOptions) Dir.CreateDirPathOpenError!Dir {
    var ticket = try budget.acquire(3);
    defer ticket.deinit();
    const result = try original.dirCreateDirPathOpen(data, dir, path, permissions, options);
    errdefer original.dirClose(data, &.{result});
    try ticket.adopt(result.handle);
    return result;
}

fn dirCreateDirPath(data: ?*anyopaque, dir: Dir, path: []const u8, permissions: Dir.Permissions) Dir.CreateDirPathError!Dir.CreatePathStatus {
    var ticket = try budget.acquire(2);
    defer ticket.deinit();
    return original.dirCreateDirPath(data, dir, path, permissions);
}

fn dirRealPathFile(data: ?*anyopaque, dir: Dir, path: []const u8, buffer: []u8) Dir.RealPathFileError!usize {
    var ticket = try budget.acquire(2);
    defer ticket.deinit();
    return original.dirRealPathFile(data, dir, path, buffer);
}

fn dirOpenFile(data: ?*anyopaque, dir: Dir, path: []const u8, options: Dir.OpenFileOptions) File.OpenError!File {
    var ticket = try budget.acquire(1);
    defer ticket.deinit();
    const result = try original.dirOpenFile(data, dir, path, options);
    errdefer original.fileClose(data, &.{result});
    try ticket.adopt(result.handle);
    return result;
}

fn dirCreateFile(data: ?*anyopaque, dir: Dir, path: []const u8, options: Dir.CreateFileOptions) File.OpenError!File {
    var ticket = try budget.acquire(1);
    defer ticket.deinit();
    const result = try original.dirCreateFile(data, dir, path, options);
    errdefer original.fileClose(data, &.{result});
    try ticket.adopt(result.handle);
    return result;
}

fn dirCreateFileAtomic(data: ?*anyopaque, dir: Dir, path: []const u8, options: Dir.CreateFileAtomicOptions) Dir.CreateFileAtomicError!File.Atomic {
    const io: Io = .{ .userdata = data, .vtable = &table };
    var parent = dir;
    var owns_parent = false;
    // Open the parent ourselves. The backend's nested-path atomic helper can
    // otherwise lose that directory handle when creating its temp file fails.
    if (Dir.path.dirname(path)) |dirname| {
        parent = if (options.make_path)
            dir.createDirPathOpen(io, dirname, .{}) catch |err| switch (err) {
                error.IsDir, error.Streaming, error.DiskQuota, error.PathAlreadyExists, error.LinkQuotaExceeded, error.PipeBusy, error.FileTooBig, error.FileLocksUnsupported, error.DeviceBusy => return error.Unexpected,
                else => |other| return other,
            }
        else
            try dir.openDir(io, dirname, .{});
        owns_parent = true;
    }
    errdefer if (owns_parent) parent.close(io);
    var ticket = try budget.acquire(1);
    defer ticket.deinit();
    var result = try original.dirCreateFileAtomic(data, parent, Dir.path.basename(path), options);
    errdefer result.deinit(.{ .userdata = data, .vtable = original });
    try ticket.adopt(result.file.handle);
    result.close_dir_on_deinit = owns_parent;
    return result;
}

fn processExecutableOpen(data: ?*anyopaque, options: Dir.OpenFileOptions) std.process.OpenExecutableError!File {
    var ticket = try budget.acquire(1);
    defer ticket.deinit();
    const result = try original.processExecutableOpen(data, options);
    errdefer original.fileClose(data, &.{result});
    try ticket.adopt(result.handle);
    return result;
}

fn fileClose(data: ?*anyopaque, files: []const File) void {
    for (files) |file| {
        const class = budget.beforeClose(file.handle);
        original.fileClose(data, &.{file});
        budget.afterClose(class);
    }
}

fn dirClose(data: ?*anyopaque, dirs: []const Dir) void {
    for (dirs) |dir| {
        const class = budget.beforeClose(dir.handle);
        original.dirClose(data, &.{dir});
        budget.afterClose(class);
    }
}

fn netListenIp(data: ?*anyopaque, address: *const net.IpAddress, options: net.IpAddress.ListenOptions) net.IpAddress.ListenError!net.Socket {
    var ticket = try budget.acquire(1);
    defer ticket.deinit();
    const result = try original.netListenIp(data, address, options);
    errdefer original.netClose(data, &.{result.handle});
    try ticket.adopt(result.handle);
    return result;
}

fn netAccept(data: ?*anyopaque, server: net.Socket.Handle, options: net.Server.AcceptOptions) net.Server.AcceptError!net.Socket {
    var ticket = try budget.acquire(1);
    defer ticket.deinit();
    const result = try original.netAccept(data, server, options);
    errdefer original.netClose(data, &.{result.handle});
    try ticket.adopt(result.handle);
    return result;
}

fn netBindIp(data: ?*anyopaque, address: *const net.IpAddress, options: net.IpAddress.BindOptions) net.IpAddress.BindError!net.Socket {
    var ticket = try budget.acquire(1);
    defer ticket.deinit();
    const result = try original.netBindIp(data, address, options);
    errdefer original.netClose(data, &.{result.handle});
    try ticket.adopt(result.handle);
    return result;
}

fn netConnectIp(data: ?*anyopaque, address: *const net.IpAddress, options: net.IpAddress.ConnectOptions) net.IpAddress.ConnectError!net.Socket {
    var ticket = try budget.acquire(1);
    defer ticket.deinit();
    const result = try original.netConnectIp(data, address, options);
    errdefer original.netClose(data, &.{result.handle});
    try ticket.adopt(result.handle);
    return result;
}

fn netListenUnix(data: ?*anyopaque, address: *const net.UnixAddress, options: net.UnixAddress.ListenOptions) net.UnixAddress.ListenError!net.Socket.Handle {
    var ticket = try budget.acquire(1);
    defer ticket.deinit();
    const result = try original.netListenUnix(data, address, options);
    errdefer original.netClose(data, &.{result});
    try ticket.adopt(result);
    return result;
}

fn netConnectUnix(data: ?*anyopaque, address: *const net.UnixAddress) net.UnixAddress.ConnectError!net.Socket.Handle {
    var ticket = try budget.acquire(1);
    defer ticket.deinit();
    const result = try original.netConnectUnix(data, address);
    errdefer original.netClose(data, &.{result});
    try ticket.adopt(result);
    return result;
}

fn netSocketCreatePair(data: ?*anyopaque, options: net.Socket.CreatePairOptions) net.Socket.CreatePairError![2]net.Socket {
    var ticket = try budget.acquire(2);
    defer ticket.deinit();
    const result = try original.netSocketCreatePair(data, options);
    errdefer original.netClose(data, &.{ result[0].handle, result[1].handle });
    try ticket.adoptAll(&.{ result[0].handle, result[1].handle });
    return result;
}

fn netLookup(data: ?*anyopaque, host: net.HostName, results: *Io.Queue(net.HostName.LookupResult), options: net.HostName.LookupOptions) net.HostName.LookupError!void {
    // Resolver internals use the backend's own IO handle. Charge a bounded
    // transient allowance even though those private descriptors are not returned.
    var ticket = budget.acquire(budget.resolver_allowance) catch |err| {
        results.close(.{ .userdata = data, .vtable = original });
        return err;
    };
    defer ticket.deinit();
    return original.netLookup(data, host, results, options);
}

fn netClose(data: ?*anyopaque, handles: []const net.Socket.Handle) void {
    for (handles) |handle| {
        const class = budget.beforeClose(handle);
        original.netClose(data, &.{handle});
        budget.afterClose(class);
    }
}

test "IO adapter releases failed opens and preserves reserved control capacity" {
    if (!budget.supported) return error.SkipZigTest;
    const io = try install(std.testing.io);
    defer uninstall();
    try budget.configure(32);
    const initial = budget.snapshot();
    try std.testing.expectError(error.FileNotFound, Dir.cwd().openFile(io, "/layerline-descriptor-fixture-does-not-exist", .{}));
    try std.testing.expectEqual(initial.used, budget.snapshot().used);
    var files: [22]File = undefined;
    var count: usize = 0;
    defer for (files[0..count]) |file| file.close(io);
    for (&files) |*file| {
        file.* = try Dir.cwd().openFile(io, "/dev/null", .{});
        count += 1;
    }
    try std.testing.expectError(error.ProcessFdQuotaExceeded, Dir.cwd().openFile(io, "/dev/null", .{}));
    const scope = budget.Scope.enter(.control);
    defer scope.deinit();
    const control = try Dir.cwd().openFile(io, "/dev/null", .{});
    control.close(io);
    for (files[0..count]) |file| file.close(io);
    count = 0;
    try std.testing.expectEqual(initial.used, budget.snapshot().used);
    try std.testing.expectEqual(initial.owned, budget.snapshot().owned);
}

test "atomic file ownership includes its parent and rolls back failed temp creation" {
    if (!budget.supported) return error.SkipZigTest;
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    try temporary.dir.createDir(std.testing.io, "parent", .default_dir);
    const io = try install(std.testing.io);
    var active = true;
    defer if (active) uninstall();
    try budget.configure(32);
    const initial = budget.snapshot();
    {
        var file = try temporary.dir.createFileAtomic(io, "parent/created", .{ .replace = true });
        defer file.deinit(io);
        try std.testing.expectEqual(initial.owned + 2, budget.snapshot().owned);
        try file.replace(io);
    }
    try std.testing.expectEqual(initial.owned, budget.snapshot().owned);
    try std.testing.expectEqual(initial.used, budget.snapshot().used);
    uninstall();
    active = false;

    const Fake = struct {
        fn fail(_: ?*anyopaque, _: Dir, _: []const u8, _: Dir.CreateFileAtomicOptions) Dir.CreateFileAtomicError!File.Atomic {
            return error.AccessDenied;
        }
    };
    var fake = std.testing.io.vtable.*;
    fake.dirCreateFileAtomic = Fake.fail;
    const failing = try install(.{ .userdata = std.testing.io.userdata, .vtable = &fake });
    defer uninstall();
    const before = budget.snapshot();
    try std.testing.expectError(error.AccessDenied, temporary.dir.createFileAtomic(failing, "parent/denied", .{}));
    try std.testing.expectEqual(before.owned, budget.snapshot().owned);
    try std.testing.expectEqual(before.used, budget.snapshot().used);
}
