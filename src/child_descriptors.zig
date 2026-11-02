const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const fd_t = std.posix.fd_t;

fn range(first: fd_t, last: fd_t) bool {
    while (true) switch (linux.errno(linux.close_range(first, last, .{ .UNSHARE = false, .CLOEXEC = false }))) {
        .SUCCESS => return true,
        .INTR => continue,
        else => return false,
    };
}

const Entry = struct { length: usize, handle: ?fd_t };

fn entry(bytes: []const u8) !Entry {
    if (bytes.len < @sizeOf(linux.dirent64)) return error.InvalidDescriptorDirectory;
    const header = std.mem.bytesAsValue(linux.dirent64, bytes[0..@sizeOf(linux.dirent64)]);
    const length: usize = header.reclen;
    const name_start = @offsetOf(linux.dirent64, "name");
    if (length < @sizeOf(linux.dirent64) or length > bytes.len) return error.InvalidDescriptorDirectory;
    const names = bytes[name_start..length];
    const end = std.mem.indexOfScalar(u8, names, 0) orelse return error.InvalidDescriptorDirectory;
    const name = names[0..end];
    if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return .{ .length = length, .handle = null };
    if (name.len == 0) return error.InvalidDescriptorDirectory;
    for (name) |byte| if (!std.ascii.isDigit(byte)) return error.InvalidDescriptorDirectory;
    const handle = std.fmt.parseInt(fd_t, name, 10) catch return error.InvalidDescriptorDirectory;
    return .{ .length = length, .handle = handle };
}

fn fromProc(keep: fd_t, path: [*:0]const u8) bool {
    // This runs after fork: only raw syscalls and fixed-size stack storage.
    // Scan the child's table, not a racy parent snapshot or the soft nofile limit.
    const scanner: fd_t = while (true) {
        const result = linux.openat(linux.AT.FDCWD, path, .{ .ACCMODE = .RDONLY, .DIRECTORY = true, .CLOEXEC = true }, 0);
        switch (linux.errno(result)) {
            .SUCCESS => break @intCast(result),
            .INTR => continue,
            else => return false,
        }
    };
    defer _ = linux.close(scanner);
    var bytes: [4096]u8 = undefined;
    while (true) {
        const size = linux.getdents64(scanner, &bytes, bytes.len);
        switch (linux.errno(size)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return false,
        }
        if (size == 0) return true;
        if (size > bytes.len) return false;
        var offset: usize = 0;
        while (offset < size) {
            const next = entry(bytes[offset..size]) catch return false;
            if (next.handle) |handle| if (handle > 2 and handle != keep and handle != scanner) {
                _ = linux.close(handle);
            };
            offset += next.length;
        }
    }
}

pub fn closeExcept(keep: fd_t) bool {
    if (comptime builtin.os.tag != .linux) return false;
    if (keep < 3) return false;
    // fork gave this child a private table. Zero flags avoid changing the
    // parent's descriptors and need only the original Linux 5.9 operation.
    const lower = keep == 3 or range(3, keep - 1);
    const upper = keep == std.math.maxInt(fd_t) or range(keep + 1, -1);
    if (lower and upper) return true;
    // Older kernels and restricted close_range policies can still enumerate
    // /proc safely. If that fails too, the caller reports setup failure, not exec.
    return fromProc(keep, "/proc/self/fd");
}

test "descriptor directory records reject truncation and invalid names" {
    var bytes: [32]u8 = @splat(0);
    const header = std.mem.bytesAsValue(linux.dirent64, bytes[0..@sizeOf(linux.dirent64)]);
    header.reclen = bytes.len;
    const name = @offsetOf(linux.dirent64, "name");
    @memcpy(bytes[name..][0..4], "4096");
    try std.testing.expectEqual(@as(?fd_t, 4096), (try entry(&bytes)).handle);
    try std.testing.expectError(error.InvalidDescriptorDirectory, entry(bytes[0..20]));
    header.reclen = 0;
    try std.testing.expectError(error.InvalidDescriptorDirectory, entry(&bytes));
    header.reclen = bytes.len + 1;
    try std.testing.expectError(error.InvalidDescriptorDirectory, entry(&bytes));
    header.reclen = bytes.len;
    bytes[name] = '-';
    try std.testing.expectError(error.InvalidDescriptorDirectory, entry(&bytes));
    @memset(bytes[name..], '9');
    try std.testing.expectError(error.InvalidDescriptorDirectory, entry(&bytes));
}

test "descriptor fallback fails closed if its directory cannot be opened" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    try std.testing.expect(!fromProc(3, ""));
}
