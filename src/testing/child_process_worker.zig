const std = @import("std");
const builtin = @import("builtin");
const allocator = std.heap.page_allocator;
const header = "Content-Type: text/plain\r\n\r\n";

extern "c" fn getpgrp() c_int;

fn now() !u64 {
    var value: std.c.timespec = undefined;
    // Match Python's monotonic_ns so the verifier can measure actual child time.
    const clock: std.c.CLOCK = if (builtin.os.tag == .macos) .UPTIME_RAW else .MONOTONIC;
    if (std.c.clock_gettime(clock, &value) != 0) return error.ClockFailed;
    return @as(u64, @intCast(value.sec)) * std.time.ns_per_s + @as(u64, @intCast(value.nsec));
}

fn sleep(ms: u32) !void {
    var remaining: std.c.timespec = .{ .sec = ms / 1000, .nsec = (ms % 1000) * std.time.ns_per_ms };
    while (std.c.nanosleep(&remaining, &remaining) != 0) {
        if (std.posix.errno(-1) != .INTR) return error.SleepFailed;
    }
}

fn write(fd: c_int, bytes: []const u8) !void {
    var offset: usize = 0;
    while (offset < bytes.len) {
        const count = std.c.write(fd, bytes.ptr + offset, bytes.len - offset);
        if (count < 0) {
            if (std.posix.errno(count) == .INTR) continue;
            return error.WriteFailed;
        }
        if (count == 0) return error.WriteFailed;
        offset += @intCast(count);
    }
}

fn record(folder: []const u8, kind: []const u8, phase: []const u8, started_ns: u64) !void {
    const path = try std.fmt.allocPrintSentinel(allocator, "{s}/pids/{d}", .{ folder, std.c.getpid() }, 0);
    defer allocator.free(path);
    const temporary = try std.fmt.allocPrintSentinel(allocator, "{s}.tmp", .{path}, 0);
    defer allocator.free(temporary);
    const json = try std.json.Stringify.valueAlloc(allocator, .{
        .kind = kind,
        .phase = phase,
        .pgid = getpgrp(),
        .started_ns = started_ns,
    }, .{});
    defer allocator.free(json);
    const file = std.c.fopen(temporary, "wb") orelse return error.RecordFailed;
    const count = std.c.fwrite(json.ptr, 1, json.len, file);
    const closed = std.c.fclose(file);
    if (count != json.len or closed != 0) return error.RecordFailed;
    if (std.c.rename(temporary, path) != 0) return error.RecordFailed;
}

fn worker(folder: []const u8, kind: []const u8) !void {
    const started_ns = try now();
    try record(folder, kind, "started", started_ns);
    if (std.mem.eql(u8, kind, "hang") or std.mem.eql(u8, kind, "descendant")) {
        // This executable starts without a threaded I/O runtime, so fork has no
        // inherited allocator or runtime locks from other threads.
        const child = std.c.fork();
        if (child < 0) return error.ForkFailed;
        if (child == 0) {
            worker(folder, "sleeper") catch std.c._exit(1);
            std.c._exit(0);
        }
        const path = try std.fmt.allocPrintSentinel(allocator, "{s}/pids/{d}", .{ folder, child }, 0);
        defer allocator.free(path);
        const until = try now() + std.time.ns_per_s;
        while (std.c.access(path, 0) != 0) {
            if (try now() >= until) return error.ChildDidNotStart;
            try sleep(2);
        }
    }
    if (std.mem.eql(u8, kind, "hang") or std.mem.eql(u8, kind, "noinput") or
        std.mem.eql(u8, kind, "sleeper") or std.mem.eql(u8, kind, "renew"))
    {
        try sleep(8000);
    } else if (std.mem.eql(u8, kind, "closed")) {
        _ = std.c.close(1);
        _ = std.c.close(2);
        try record(folder, kind, "closed", started_ns);
        try sleep(8000);
    } else if (std.mem.eql(u8, kind, "trickle")) {
        try write(1, header);
        try write(1, "x");
        try record(folder, kind, "trickling", started_ns);
        for (1..100) |_| {
            try sleep(50);
            try write(1, "x");
        }
        try sleep(50);
    } else if (std.mem.eql(u8, kind, "duplex")) {
        try write(1, header);
        try write(1, &@as([65536]u8, @splat('x')));
        for (0..1800) |_| try write(2, "diagnostic fixture\n");
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        var buffer: [8192]u8 = undefined;
        while (true) {
            const count = std.c.read(0, &buffer, buffer.len);
            if (count < 0) {
                if (std.posix.errno(count) == .INTR) continue;
                return error.ReadFailed;
            }
            if (count == 0) break;
            hash.update(buffer[0..@intCast(count)]);
        }
        var digest: [32]u8 = undefined;
        hash.final(&digest);
        try write(1, &std.fmt.bytesToHex(digest, .lower));
    } else if (std.mem.eql(u8, kind, "overflow")) {
        for (0..4) |_| try write(1, &@as([65536]u8, @splat('x')));
        try sleep(8000);
    } else if (std.mem.eql(u8, kind, "stderr")) {
        for (0..8192) |_| try write(2, "private-child-marker\n");
        try sleep(8000);
    } else if (std.mem.eql(u8, kind, "earlyinput")) {
        _ = std.c.close(0);
        try write(1, header ++ "ok");
    } else if (std.mem.eql(u8, kind, "exit")) {
        try write(1, header ++ "not a successful reply");
        std.c._exit(7);
    } else {
        if (std.mem.eql(u8, kind, "slow")) try sleep(600);
        try write(1, header ++ "ok");
    }
}

pub fn main(init: std.process.Init.Minimal) !void {
    var args = std.process.Args.iterate(init.args);
    _ = args.next();
    const mode = args.next() orelse return error.MissingMode;
    const folder = args.next() orelse return error.MissingFolder;
    const ignored: std.posix.Sigaction = .{
        .handler = .{ .handler = std.posix.SIG.IGN },
        .mask = std.posix.sigemptyset(),
        .flags = 0,
    };
    std.posix.sigaction(.TERM, &ignored, null);
    std.posix.sigaction(.PIPE, &ignored, null);
    if (std.mem.eql(u8, mode, "--cgi")) {
        return worker(folder, init.environ.getPosix("QUERY_STRING") orelse "okay");
    }
    if (!std.mem.eql(u8, mode, "--command")) return error.InvalidMode;
    try write(2, "private-child-marker\n");
    const path = try std.fmt.allocPrintSentinel(allocator, "{s}/command-mode", .{folder}, 0);
    defer allocator.free(path);
    const file = std.c.fopen(path, "rb") orelse return error.CommandModeFailed;
    var buffer: [64]u8 = undefined;
    const size = std.c.fread(&buffer, 1, buffer.len, file);
    if (std.c.fclose(file) != 0 or size == buffer.len) return error.CommandModeFailed;
    var kind: []const u8 = buffer[0..size];
    while (args.next()) |arg| if (std.mem.eql(u8, arg, "renew")) {
        kind = "renew";
    };
    try worker(folder, kind);
}
