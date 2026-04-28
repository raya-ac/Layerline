const std = @import("std");
const builtin = @import("builtin");

pub const Fd = std.posix.fd_t;
pub const Token = usize;

pub const is_darwin = switch (builtin.os.tag) {
    .driverkit, .ios, .maccatalyst, .macos, .tvos, .visionos, .watchos => true,
    else => false,
};

pub const Interest = packed struct {
    read: bool = false,
    write: bool = false,

    pub const none = Interest{};
    pub const readable = Interest{ .read = true };
    pub const writable = Interest{ .write = true };
    pub const read_write = Interest{ .read = true, .write = true };

    pub fn isEmpty(self: Interest) bool {
        return !self.read and !self.write;
    }

    pub fn contains(self: Interest, other: Interest) bool {
        return (!other.read or self.read) and (!other.write or self.write);
    }

    pub fn merge(a: Interest, b: Interest) Interest {
        return .{
            .read = a.read or b.read,
            .write = a.write or b.write,
        };
    }
};

pub const TriggerMode = enum {
    level,
    edge,
};

pub const Operation = enum {
    add,
    modify,
    delete,
};

pub const Registration = struct {
    fd: Fd,
    token: Token,
    interest: Interest,
    trigger: TriggerMode = .level,
};

pub const Event = struct {
    fd: Fd,
    token: Token,
    readiness: Interest,
    eof: bool = false,
    error_code: ?i32 = null,
    data: isize = 0,
};

pub const Error = error{
    AccessDenied,
    EventNotFound,
    Interrupted,
    InvalidFileDescriptor,
    InvalidInterest,
    Overflow,
    ProcessNotFound,
    SystemResources,
    UnsupportedEvent,
    UnsupportedPlatform,
    Unexpected,
};

pub const Reactor = if (is_darwin) DarwinReactor else UnsupportedReactor;

pub const UnsupportedReactor = struct {
    pub fn init() Error!UnsupportedReactor {
        return error.UnsupportedPlatform;
    }

    pub fn deinit(_: *UnsupportedReactor) void {}

    pub fn register(_: *UnsupportedReactor, _: Registration) Error!void {
        return error.UnsupportedPlatform;
    }

    pub fn reregister(_: *UnsupportedReactor, _: Registration) Error!void {
        return error.UnsupportedPlatform;
    }

    pub fn deregister(_: *UnsupportedReactor, _: Fd) Error!void {
        return error.UnsupportedPlatform;
    }

    pub fn poll(_: *UnsupportedReactor, _: []Event, _: ?u64) Error!usize {
        return error.UnsupportedPlatform;
    }
};

pub const DarwinReactor = struct {
    kq: Fd,

    pub fn init() Error!DarwinReactor {
        const rc = std.c.kqueue();
        if (std.c.errno(rc) != .SUCCESS) return mapErrno(std.c.errno(rc));
        return .{ .kq = @intCast(rc) };
    }

    pub fn deinit(self: *DarwinReactor) void {
        if (self.kq >= 0) {
            _ = std.c.close(self.kq);
            self.kq = -1;
        }
    }

    pub fn register(self: *DarwinReactor, registration: Registration) Error!void {
        try self.apply(registration, .add);
    }

    pub fn reregister(self: *DarwinReactor, registration: Registration) Error!void {
        // kqueue has no single "replace this interest mask" operation. Clear the
        // old filters first so a read-only reregister does not leave writes armed.
        try self.deregister(registration.fd);
        try self.apply(registration, .add);
    }

    pub fn deregister(self: *DarwinReactor, fd: Fd) Error!void {
        var first_error: ?Error = null;
        for ([_]EventInterest{ .read, .write }) |interest| {
            const change = DarwinKqueue.changeFor(
                .{
                    .fd = fd,
                    .token = 0,
                    .interest = .read_write,
                },
                interest,
                .delete,
            );
            _ = DarwinKqueue.kevent(self.kq, &.{change}, &.{}, null) catch |err| switch (err) {
                error.EventNotFound => continue,
                else => {
                    if (first_error == null) first_error = err;
                    continue;
                },
            };
        }
        if (first_error) |err| return err;
    }

    pub fn poll(self: *DarwinReactor, out: []Event, timeout_ns: ?u64) Error!usize {
        if (out.len == 0) return 0;

        var raw_events: [64]std.c.Kevent = undefined;
        const raw_out = raw_events[0..@min(out.len, raw_events.len)];
        var timeout_storage: std.c.timespec = undefined;
        const timeout = if (timeout_ns) |ns| blk: {
            timeout_storage = nanosToTimespec(ns);
            break :blk &timeout_storage;
        } else null;

        const n = try DarwinKqueue.kevent(self.kq, &.{}, raw_out, timeout);
        for (raw_out[0..n], 0..) |raw, i| {
            out[i] = try DarwinKqueue.eventFromKevent(raw);
        }
        return n;
    }

    fn apply(self: *DarwinReactor, registration: Registration, operation: Operation) Error!void {
        var changes: [2]std.c.Kevent = undefined;
        const n = try DarwinKqueue.buildChanges(&changes, registration, operation);
        _ = try DarwinKqueue.kevent(self.kq, changes[0..n], &.{}, null);
    }
};

pub const DarwinKqueue = struct {
    pub fn buildChanges(
        out: []std.c.Kevent,
        registration: Registration,
        operation: Operation,
    ) Error!usize {
        if (!is_darwin) return error.UnsupportedPlatform;
        if (registration.interest.isEmpty()) return error.InvalidInterest;
        if (out.len < 2) return error.Overflow;

        var n: usize = 0;
        if (registration.interest.read) {
            out[n] = changeFor(registration, .read, operation);
            n += 1;
        }
        if (registration.interest.write) {
            out[n] = changeFor(registration, .write, operation);
            n += 1;
        }
        return n;
    }

    pub fn changeFor(
        registration: Registration,
        interest: EventInterest,
        operation: Operation,
    ) std.c.Kevent {
        var flags: u16 = switch (operation) {
            .add, .modify => std.c.EV.ADD | std.c.EV.ENABLE,
            .delete => std.c.EV.DELETE,
        };
        if (operation != .delete and registration.trigger == .edge) {
            flags |= std.c.EV.CLEAR;
        }

        return .{
            .ident = @intCast(registration.fd),
            .filter = filterFor(interest),
            .flags = flags,
            .fflags = 0,
            .data = 0,
            .udata = registration.token,
        };
    }

    pub fn eventFromKevent(raw: std.c.Kevent) Error!Event {
        const readiness = interestFor(raw.filter) orelse return error.UnsupportedEvent;
        return .{
            .fd = @intCast(raw.ident),
            .token = raw.udata,
            .readiness = readiness,
            .eof = (raw.flags & std.c.EV.EOF) != 0,
            .error_code = if ((raw.flags & std.c.EV.ERROR) != 0) @intCast(raw.data) else null,
            .data = raw.data,
        };
    }

    pub fn filterFor(interest: EventInterest) i16 {
        return switch (interest) {
            .read => std.c.EVFILT.READ,
            .write => std.c.EVFILT.WRITE,
        };
    }

    pub fn interestFor(filter: i16) ?Interest {
        return if (filter == std.c.EVFILT.READ)
            .readable
        else if (filter == std.c.EVFILT.WRITE)
            .writable
        else
            null;
    }

    pub fn kevent(
        kq: Fd,
        changelist: []const std.c.Kevent,
        eventlist: []std.c.Kevent,
        timeout: ?*const std.c.timespec,
    ) Error!usize {
        const rc = std.c.kevent(
            kq,
            changelist.ptr,
            std.math.cast(c_int, changelist.len) orelse return error.Overflow,
            eventlist.ptr,
            std.math.cast(c_int, eventlist.len) orelse return error.Overflow,
            timeout,
        );
        if (std.c.errno(rc) != .SUCCESS) return mapErrno(std.c.errno(rc));
        return @intCast(rc);
    }
};

pub const EventInterest = enum {
    read,
    write,
};

fn nanosToTimespec(ns: u64) std.c.timespec {
    const ns_per_s = std.time.ns_per_s;
    return .{
        .sec = @intCast(ns / ns_per_s),
        .nsec = @intCast(ns % ns_per_s),
    };
}

fn mapErrno(err: std.c.E) Error {
    return switch (err) {
        .SUCCESS => unreachable,
        .ACCES => error.AccessDenied,
        .BADF => error.InvalidFileDescriptor,
        .INTR => error.Interrupted,
        .INVAL => error.InvalidInterest,
        .NOENT => error.EventNotFound,
        .NOMEM => error.SystemResources,
        .SRCH => error.ProcessNotFound,
        else => error.Unexpected,
    };
}

test "interest masks merge and contain flags" {
    try std.testing.expect(Interest.none.isEmpty());
    try std.testing.expect(!Interest.readable.isEmpty());
    try std.testing.expect(Interest.read_write.contains(.readable));
    try std.testing.expect(Interest.read_write.contains(.writable));
    try std.testing.expect(!Interest.readable.contains(.writable));
    try std.testing.expectEqual(Interest.read_write, Interest.merge(.readable, .writable));
}

test "Darwin kevent changes map read and write interests" {
    if (!is_darwin) return error.SkipZigTest;

    var changes: [2]std.c.Kevent = undefined;
    const n = try DarwinKqueue.buildChanges(
        &changes,
        .{
            .fd = 7,
            .token = 0xfeed,
            .interest = .read_write,
            .trigger = .edge,
        },
        .add,
    );

    try std.testing.expectEqual(@as(usize, 2), n);
    try std.testing.expectEqual(@as(usize, 7), changes[0].ident);
    try std.testing.expectEqual(@as(i16, std.c.EVFILT.READ), changes[0].filter);
    try std.testing.expectEqual(@as(usize, 0xfeed), changes[0].udata);
    try std.testing.expect((changes[0].flags & std.c.EV.ADD) != 0);
    try std.testing.expect((changes[0].flags & std.c.EV.ENABLE) != 0);
    try std.testing.expect((changes[0].flags & std.c.EV.CLEAR) != 0);
    try std.testing.expectEqual(@as(i16, std.c.EVFILT.WRITE), changes[1].filter);
}

test "Darwin raw events map back to portable readiness" {
    if (!is_darwin) return error.SkipZigTest;

    const raw = std.c.Kevent{
        .ident = 11,
        .filter = std.c.EVFILT.READ,
        .flags = std.c.EV.EOF,
        .fflags = 0,
        .data = 23,
        .udata = 0xbeef,
    };
    const event = try DarwinKqueue.eventFromKevent(raw);

    try std.testing.expectEqual(@as(Fd, 11), event.fd);
    try std.testing.expectEqual(@as(usize, 0xbeef), event.token);
    try std.testing.expect(event.readiness.contains(.readable));
    try std.testing.expect(!event.readiness.contains(.writable));
    try std.testing.expect(event.eof);
    try std.testing.expectEqual(@as(isize, 23), event.data);
}

test "Darwin reactor reports pipe read readiness" {
    if (!is_darwin) return error.SkipZigTest;

    var pipe_fds: [2]std.c.fd_t = undefined;
    if (std.c.errno(std.c.pipe(&pipe_fds)) != .SUCCESS) {
        return mapErrno(std.c.errno(-1));
    }
    defer _ = std.c.close(pipe_fds[0]);
    defer _ = std.c.close(pipe_fds[1]);

    var reactor = try Reactor.init();
    defer reactor.deinit();

    try reactor.register(.{
        .fd = pipe_fds[0],
        .token = 0x1234,
        .interest = .readable,
    });

    var events: [4]Event = undefined;
    try std.testing.expectEqual(@as(usize, 0), try reactor.poll(&events, 0));

    const byte = [_]u8{'x'};
    if (std.c.errno(std.c.write(pipe_fds[1], &byte, byte.len)) != .SUCCESS) {
        return mapErrno(std.c.errno(-1));
    }

    const n = try reactor.poll(&events, 100 * std.time.ns_per_ms);
    try std.testing.expect(n >= 1);
    try std.testing.expectEqual(@as(usize, 0x1234), events[0].token);
    try std.testing.expect(events[0].readiness.contains(.readable));
    try reactor.deregister(pipe_fds[0]);
}
