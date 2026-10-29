const std = @import("std");
const builtin = @import("builtin");

pub fn reusable(stream: std.Io.net.Stream) bool {
    if (builtin.os.tag == .windows) return false;
    if (stream.socket.handle < 0) return false;
    var fds = [_]std.posix.pollfd{.{ .fd = stream.socket.handle, .events = std.posix.POLL.IN, .revents = 0 }};
    const result = std.posix.system.poll(&fds, fds.len, 0);
    // An idle HTTP socket has nothing to read. EOF, errors and unsolicited
    // bytes all make it unsafe to assign to the next request.
    return std.posix.errno(result) == .SUCCESS and result == 0;
}

test "idle descriptors reject EOF errors and unexpected bytes without consuming them" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    const system = std.posix.system;
    const fds = try std.Io.Threaded.pipe2(.{ .CLOEXEC = true, .NONBLOCK = true });
    defer _ = system.close(fds[0]);
    var writer_open = true;
    defer if (writer_open) {
        _ = system.close(fds[1]);
    };
    const stream: std.Io.net.Stream = .{ .socket = .{ .handle = fds[0], .address = undefined } };
    try std.testing.expect(reusable(stream));
    const byte = [_]u8{'x'};
    try std.testing.expect(system.write(fds[1], &byte, 1) == 1);
    try std.testing.expect(!reusable(stream));
    var data: [1]u8 = undefined;
    try std.testing.expect(system.read(fds[0], &data, 1) == 1);
    try std.testing.expectEqualStrings("x", &data);
    try std.testing.expect(reusable(stream));
    _ = system.close(fds[1]);
    writer_open = false;
    try std.testing.expect(!reusable(stream));
    try std.testing.expect(!reusable(.{ .socket = .{ .handle = -1, .address = undefined } }));
}
