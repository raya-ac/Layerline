const std = @import("std");
const builtin = @import("builtin");
const socket_io = @import("socket_io.zig");
const Stream = std.Io.net.Stream;
const IpAddress = std.Io.net.IpAddress;
const HostName = std.Io.net.HostName;
const ResultQueue = std.Io.Queue(anyerror!Stream);

fn failure(err: std.posix.E) anyerror {
    return switch (err) {
        .CONNREFUSED => error.ConnectionRefused,
        .CONNRESET => error.ConnectionResetByPeer,
        .CONNABORTED => error.ConnectionAborted,
        .TIMEDOUT => error.RequestTimeout,
        .ADDRNOTAVAIL, .ADDRINUSE => error.AddressUnavailable,
        .HOSTUNREACH => error.HostUnreachable,
        .NETUNREACH => error.NetworkUnreachable,
        .NETDOWN => error.NetworkDown,
        .MFILE => error.ProcessFdQuotaExceeded,
        .NFILE => error.SystemFdQuotaExceeded,
        .NOMEM, .NOBUFS => error.SystemResources,
        .ACCES, .PERM => error.AccessDenied,
        .BADF, .NOTSOCK => error.SocketClosed,
        .AFNOSUPPORT => error.AddressFamilyUnsupported,
        .PROTONOSUPPORT, .PROTOTYPE => error.ProtocolUnsupportedByAddressFamily,
        .NOENT => error.FileNotFound,
        .NOTDIR => error.NotDir,
        .LOOP => error.SymLinkLoop,
        .ROFS => error.ReadOnlyFileSystem,
        .AGAIN => error.WouldBlock,
        else => blk: {
            if (!builtin.is_test) std.debug.print("{{\"event\":\"server.connect_syscall_error\",\"errno\":\"{s}\"}}\n", .{@tagName(err)});
            break :blk error.UnexpectedConnect;
        },
    };
}

const Native = struct {
    fn start(handle: std.Io.net.Socket.Handle, address: *const std.posix.sockaddr, len: std.posix.socklen_t) std.posix.E {
        return std.posix.errno(std.posix.system.connect(handle, address, len));
    }
    fn wait(io: std.Io, stream: Stream) !void {
        try socket_io.waitWritable(io, stream);
    }
    fn pending(handle: std.Io.net.Socket.Handle) !std.posix.E {
        var value: c_int = 0;
        var len: std.posix.socklen_t = @sizeOf(c_int);
        while (true) switch (std.posix.errno(std.posix.system.getsockopt(handle, std.posix.SOL.SOCKET, std.posix.SO.ERROR, @ptrCast(&value), &len))) {
            .SUCCESS => {
                if (len != @sizeOf(c_int)) return error.InvalidSocketOption;
                return @enumFromInt(value);
            },
            .INTR => continue,
            else => |err| return failure(err),
        };
    }
};

fn finish(io: std.Io, stream: Stream, address: *const std.posix.sockaddr, len: std.posix.socklen_t, comptime Ops: type) !void {
    while (true) {
        try io.checkCancel();
        switch (Ops.start(stream.socket.handle, address, len)) {
            // A successful handshake can finish while an interrupted connect
            // is returning. Retrying that syscall then reports ISCONN.
            .SUCCESS, .ISCONN => return,
            .INTR => continue,
            .INPROGRESS, .ALREADY => break,
            else => |err| return failure(err),
        }
    }
    while (true) {
        try Ops.wait(io, stream);
        switch (try Ops.pending(stream.socket.handle)) {
            .SUCCESS, .ISCONN => return,
            .INPROGRESS, .ALREADY => continue,
            else => |err| return failure(err),
        }
    }
}

fn connectAddress(io: std.Io, family: std.posix.sa_family_t, address: *const std.posix.sockaddr, len: std.posix.socklen_t) !Stream {
    try io.checkCancel();
    const flags: u32 = std.posix.SOCK.STREAM | if (builtin.os.tag == .linux) std.posix.SOCK.CLOEXEC | std.posix.SOCK.NONBLOCK else 0;
    const protocol: u32 = if (family == std.posix.AF.UNIX) 0 else std.posix.IPPROTO.TCP;
    const handle = while (true) {
        const result = std.posix.system.socket(family, @intCast(flags), @intCast(protocol));
        switch (std.posix.errno(result)) {
            .SUCCESS => break @as(std.Io.net.Socket.Handle, @intCast(result)),
            .INTR => try io.checkCancel(),
            else => |err| return failure(err),
        }
    };
    var stream = Stream{ .socket = .{ .handle = handle, .address = .{ .ip4 = .loopback(0) } } };
    errdefer stream.close(io);
    if (builtin.os.tag != .linux) {
        const options = [_]struct { command: i32, value: usize }{
            .{ .command = std.posix.F.SETFD, .value = std.posix.FD_CLOEXEC },
            .{ .command = std.posix.F.SETFL, .value = 1 << @bitOffsetOf(std.posix.O, "NONBLOCK") },
        };
        for (options) |option| {
            while (true) switch (std.posix.errno(std.posix.system.fcntl(handle, option.command, option.value))) {
                .SUCCESS => break,
                .INTR => try io.checkCancel(),
                else => |err| return failure(err),
            };
        }
    }
    try finish(io, stream, address, len, Native);
    if (family != std.posix.AF.UNIX) {
        var storage: std.Io.Threaded.PosixAddress = undefined;
        var local_len: std.posix.socklen_t = @sizeOf(@TypeOf(storage));
        while (true) switch (std.posix.errno(std.posix.system.getsockname(handle, &storage.any, &local_len))) {
            .SUCCESS => break,
            .INTR => try io.checkCancel(),
            else => |err| return failure(err),
        };
        stream.socket.address = std.Io.Threaded.addressFromPosix(&storage);
    }
    return stream;
}

pub fn connectIp(address: *const IpAddress, io: std.Io) !Stream {
    if (builtin.os.tag == .windows) return address.connect(io, .{ .mode = .stream });
    var storage: std.Io.Threaded.PosixAddress = undefined;
    const len = std.Io.Threaded.addressToPosix(address, &storage);
    return connectAddress(io, std.Io.Threaded.posixAddressFamily(address), &storage.any, len);
}

pub fn connectUnix(address: *const std.Io.net.UnixAddress, io: std.Io) !Stream {
    if (builtin.os.tag == .windows) return address.connect(io);
    var storage: std.posix.sockaddr.un = std.mem.zeroes(std.posix.sockaddr.un);
    storage.family = std.posix.AF.UNIX;
    if (address.path.len > storage.path.len) return error.NameTooLong;
    @memcpy(storage.path[0..address.path.len], address.path);
    const length = address.path.len + @as(usize, @intFromBool(address.path.len < storage.path.len));
    return connectAddress(io, std.posix.AF.UNIX, @ptrCast(&storage), @intCast(@offsetOf(std.posix.sockaddr.un, "path") + length));
}

fn enqueueAddress(io: std.Io, address: IpAddress, results: *ResultQueue) void {
    publishResult(io, results, connectIp(&address, io));
}

fn publishResult(io: std.Io, results: *ResultQueue, result: anyerror!Stream) void {
    // Publishing must stay cancelable if a host has more addresses than the
    // result buffer. Close a successful socket if its recipient has gone away.
    results.putOne(io, result) catch {
        if (result) |stream| stream.close(io) else |_| {}
    };
}

fn connectMany(host: HostName, io: std.Io, port: u16, results: *ResultQueue) !void {
    defer results.close(io);
    var buffer: [32]HostName.LookupResult = undefined;
    var resolved: std.Io.Queue(HostName.LookupResult) = .init(&buffer);
    var lookup = io.async(HostName.lookup, .{ host, io, &resolved, HostName.LookupOptions{ .port = port } });
    defer lookup.cancel(io) catch {};
    var group: std.Io.Group = .init;
    defer group.cancel(io);
    while (resolved.getOne(io)) |result| switch (result) {
        .address => |address| group.async(io, enqueueAddress, .{ io, address, results }),
        .canonical_name => {},
    } else |err| switch (err) {
        error.Canceled => return err,
        error.Closed => {},
    }
    try group.await(io);
    try lookup.await(io);
}

pub fn connectHost(host: HostName, io: std.Io, port: u16) !Stream {
    if (builtin.os.tag == .windows) return host.connect(io, port, .{ .mode = .stream });
    var buffer: [32]anyerror!Stream = undefined;
    var results: ResultQueue = .init(&buffer);
    var producer = io.async(connectMany, .{ host, io, port, &results });
    defer {
        producer.cancel(io) catch {};
        while (results.getOneUncancelable(io)) |result| {
            if (result) |stream| stream.close(io) else |_| {}
        } else |_| {}
    }
    var last_error: anyerror = error.UnknownHostName;
    while (results.getOne(io)) |result| {
        if (result) |stream| return stream else |err| switch (err) {
            error.SystemResources, error.ProcessFdQuotaExceeded, error.SystemFdQuotaExceeded => return err,
            error.Canceled => {},
            else => last_error = err,
        }
    } else |err| switch (err) {
        error.Canceled => return err,
        error.Closed => {},
    }
    try producer.await(io);
    return last_error;
}

test "interrupted connects accept ISCONN on the same descriptor and verify pending results" {
    const Fake = struct {
        var calls: usize = 0;
        var waits: usize = 0;
        var pending_count: usize = 0;
        var mode: u8 = 0;
        fn start(_: std.Io.net.Socket.Handle, _: *const std.posix.sockaddr, _: std.posix.socklen_t) std.posix.E {
            calls += 1;
            if (mode == 0) return if (calls == 1) .INTR else .ISCONN;
            if (mode == 4) return .ISCONN;
            return .INPROGRESS;
        }
        fn wait(_: std.Io, _: Stream) !void {
            waits += 1;
        }
        fn pending(_: std.Io.net.Socket.Handle) !std.posix.E {
            pending_count += 1;
            if (mode == 3) return if (pending_count == 1) .INPROGRESS else .SUCCESS;
            return if (mode == 1) .SUCCESS else .CONNREFUSED;
        }
    };
    const stream = Stream{ .socket = .{ .handle = 123, .address = undefined } };
    const address = std.mem.zeroes(std.posix.sockaddr);
    for (0..5) |mode| {
        Fake.calls = 0;
        Fake.waits = 0;
        Fake.pending_count = 0;
        Fake.mode = @intCast(mode);
        if (mode == 2) {
            try std.testing.expectError(error.ConnectionRefused, finish(std.testing.io, stream, &address, @sizeOf(@TypeOf(address)), Fake));
        } else try finish(std.testing.io, stream, &address, @sizeOf(@TypeOf(address)), Fake);
        try std.testing.expectEqual(if (mode == 0) @as(usize, 2) else 1, Fake.calls);
        const waits: usize = if (mode == 0 or mode == 4) 0 else if (mode == 3) 2 else 1;
        try std.testing.expectEqual(waits, Fake.waits);
        try std.testing.expectEqual(Fake.waits, Fake.pending_count);
    }
}

test "closed or canceled DNS result queues close successful unpublished sockets exactly once" {
    const Fake = struct {
        var closed: std.atomic.Value(usize) = .init(0);
        var finished: std.atomic.Value(bool) = .init(false);
        var entered: std.Io.Event = .unset;
        fn close(_: ?*anyopaque, handles: []const std.Io.net.Socket.Handle) void {
            std.debug.assert(handles.len == 1 and handles[0] == 123);
            _ = closed.fetchAdd(1, .acq_rel);
        }
        fn run(io: std.Io, results: *ResultQueue) void {
            defer finished.store(true, .release);
            entered.set(io);
            publishResult(io, results, Stream{ .socket = .{ .handle = 123, .address = undefined } });
        }
    };
    var vtable = std.testing.io.vtable.*;
    vtable.netClose = Fake.close;
    const io: std.Io = .{ .userdata = std.testing.io.userdata, .vtable = &vtable };
    for ([_]bool{ false, true }) |cancel| {
        Fake.closed.store(0, .release);
        Fake.finished.store(false, .release);
        Fake.entered = .unset;
        var buffer: [1]anyerror!Stream = undefined;
        var results: ResultQueue = .init(&buffer);
        defer results.close(io);
        if (cancel) {
            try results.putOne(io, error.Seed);
            var task = try io.concurrent(Fake.run, .{ io, &results });
            defer task.cancel(io);
            try Fake.entered.wait(io);
            task.cancel(io);
        } else {
            results.close(io);
            Fake.run(io, &results);
        }
        try std.testing.expectEqual(1, Fake.closed.load(.acquire));
        try std.testing.expect(Fake.finished.load(.acquire));
    }
}
