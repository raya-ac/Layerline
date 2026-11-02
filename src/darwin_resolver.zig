const std = @import("std");
const builtin = @import("builtin");
const HostName = std.Io.net.HostName;
const IpAddress = std.Io.net.IpAddress;
const child_process = @import("child_process.zig");

const worker_argument = "--layerline-resolver-v1";
const max_addresses = 128;
const header_size = 7;
const record_size = 25;
const max_packet = header_size + max_addresses * record_size;
const Status = enum(u8) { resolved, unknown, failed, resources, family, too_many };

const Packet = struct {
    bytes: [max_packet]u8 = @splat(0),
    count: u16 = 0,

    fn add(self: *Packet, address: IpAddress) !void {
        if (self.count == max_addresses) return error.ResolverCapacity;
        const record = self.bytes[header_size + @as(usize, self.count) * record_size ..][0..record_size];
        switch (address) {
            .ip4 => |ip| {
                record[0] = 4;
                @memcpy(record[1..5], &ip.bytes);
            },
            .ip6 => |ip| {
                record[0] = 6;
                @memcpy(record[1..17], &ip.bytes);
                std.mem.writeInt(u32, record[17..21], ip.interface.index, .big);
                std.mem.writeInt(u32, record[21..25], ip.flow, .big);
            },
        }
        self.count += 1;
    }

    fn finish(self: *Packet, status: Status) []const u8 {
        if (status != .resolved) self.count = 0;
        self.bytes[0..4].* = "LND1".*;
        self.bytes[4] = @intFromEnum(status);
        std.mem.writeInt(u16, self.bytes[5..7], self.count, .big);
        return self.bytes[0 .. header_size + @as(usize, self.count) * record_size];
    }
};

fn decode(bytes: []const u8, port: u16, addresses: *[max_addresses]IpAddress) ![]IpAddress {
    if (bytes.len < header_size or !std.mem.eql(u8, bytes[0..4], "LND1")) return error.InvalidResolverReply;
    const status = std.enums.fromInt(Status, bytes[4]) orelse return error.InvalidResolverReply;
    const count = std.mem.readInt(u16, bytes[5..7], .big);
    if (count > max_addresses or bytes.len != header_size + @as(usize, count) * record_size or
        (status != .resolved and count != 0)) return error.InvalidResolverReply;
    switch (status) {
        .resolved => if (count == 0) return error.NoAddressReturned,
        .unknown => return error.UnknownHostName,
        .failed, .too_many => return error.NameServerFailure,
        .resources => return error.SystemResources,
        .family => return error.AddressFamilyUnsupported,
    }
    for (addresses[0..count], 0..) |*address, index| {
        const record = bytes[header_size + index * record_size ..][0..record_size];
        address.* = switch (record[0]) {
            4 => blk: {
                if (!std.mem.allEqual(u8, record[5..], 0)) return error.InvalidResolverReply;
                break :blk .{ .ip4 = .{ .bytes = record[1..5].*, .port = port } };
            },
            6 => .{ .ip6 = .{
                .bytes = record[1..17].*,
                .port = port,
                .interface = .{ .index = std.mem.readInt(u32, record[17..21], .big) },
                .flow = std.mem.readInt(u32, record[21..25], .big),
            } },
            else => return error.InvalidResolverReply,
        };
    }
    return addresses[0..count];
}

// Run before config/environment bootstrap. The helper only resolves its two
// arguments and writes a bounded binary reply; it cannot start a server.
pub fn serve(minimal: std.process.Init.Minimal) !bool {
    if (comptime builtin.os.tag != .macos) return false;
    var args = std.process.Args.iterate(minimal.args);
    _ = args.next();
    const mode = args.next() orelse return false;
    if (!std.mem.eql(u8, mode, worker_argument)) return false;
    const name = args.next() orelse return error.InvalidResolverArguments;
    const service = args.next() orelse return error.InvalidResolverArguments;
    if (args.next() != null or name.len > HostName.max_len + 1) return error.InvalidResolverArguments;
    HostName.validate(name) catch return error.InvalidResolverArguments;
    _ = std.fmt.parseInt(u16, service, 10) catch return error.InvalidResolverArguments;
    var name_buffer: [HostName.max_len + 2]u8 = undefined;
    @memcpy(name_buffer[0..name.len], name);
    name_buffer[name.len] = 0;
    var service_buffer: [6:0]u8 = undefined;
    if (service.len == 0 or service.len > 5) return error.InvalidResolverArguments;
    @memcpy(service_buffer[0..service.len], service);
    service_buffer[service.len] = 0;
    const hints: std.posix.addrinfo = .{
        .flags = .{ .NUMERICSERV = true },
        .family = std.posix.AF.UNSPEC,
        .socktype = std.posix.SOCK.STREAM,
        .protocol = std.posix.IPPROTO.TCP,
        .canonname = null,
        .addr = null,
        .addrlen = 0,
        .next = null,
    };
    var result: ?*std.posix.addrinfo = null;
    const code = std.c.getaddrinfo(@ptrCast(&name_buffer), @ptrCast(&service_buffer), &hints, &result);
    defer if (result) |list| std.c.freeaddrinfo(list);
    var packet: Packet = .{};
    const status: Status = if (@intFromEnum(code) == 0) collect: {
        var cursor = result;
        while (cursor) |info| : (cursor = info.next) {
            const address = info.addr orelse continue;
            if (info.family != std.posix.AF.INET and info.family != std.posix.AF.INET6) continue;
            const size: usize = if (info.family == std.posix.AF.INET) @sizeOf(std.posix.sockaddr.in) else @sizeOf(std.posix.sockaddr.in6);
            if (info.addrlen < size) break :collect .failed;
            const ip = std.Io.Threaded.addressFromPosix(@alignCast(@fieldParentPtr("any", address)));
            packet.add(ip) catch break :collect .too_many;
        }
        break :collect if (packet.count == 0) .unknown else .resolved;
    } else switch (code) {
        .NONAME, .NODATA => .unknown,
        .MEMORY => .resources,
        .FAMILY, .ADDRFAMILY => .family,
        else => .failed,
    };
    var bytes = packet.finish(status);
    while (bytes.len != 0) {
        const written = std.c.write(1, bytes.ptr, bytes.len);
        switch (std.posix.errno(written)) {
            .SUCCESS => {
                if (written == 0) return error.ResolverPipeFailed;
                bytes = bytes[@intCast(written)..];
            },
            .INTR => continue,
            else => return error.ResolverPipeFailed,
        }
    }
    return true;
}

pub fn lookup(host: HostName, io: std.Io, resolved: *std.Io.Queue(HostName.LookupResult), port: u16) !void {
    defer resolved.close(io);
    try io.checkCancel();
    const allocator = @import("resource_budget.zig").allocator();
    const executable = try std.process.executablePathAlloc(io, allocator);
    defer allocator.free(executable);
    var service: [6]u8 = undefined;
    const port_text = try std.fmt.bufPrint(&service, "{d}", .{port});
    // No inherited environment, shell, PATH search or new timeout. The outer
    // backend-attempt timer cancels this owner, which kills and reaps the helper.
    const result = child_process.run(io, allocator, .{
        .argv = &.{ executable, worker_argument, host.bytes, port_text },
        .timeout_ms = 0,
        .stdout_limit = max_packet,
        .stderr_limit = 1024,
    }) catch |err| switch (err) {
        error.ChildCapacity, error.OutOfMemory => return error.BackendCapacity,
        else => return err,
    };
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    if (result.term != .exited or result.term.exited != 0) return error.NameServerFailure;
    var addresses: [max_addresses]IpAddress = undefined;
    for (try decode(result.stdout, port, &addresses)) |address| {
        try resolved.putOne(io, .{ .address = address });
    }
}

test "resolver packets preserve ordered IPv4 and scoped IPv6 addresses" {
    var packet: Packet = .{};
    try packet.add(.{ .ip4 = .loopback(42) });
    var ip6: std.Io.net.Ip6Address = .loopback(42);
    ip6.interface.index = 17;
    ip6.flow = 19;
    try packet.add(.{ .ip6 = ip6 });
    var buffer: [max_addresses]IpAddress = undefined;
    const addresses = try decode(packet.finish(.resolved), 443, &buffer);
    try std.testing.expectEqual(2, addresses.len);
    try std.testing.expectEqualDeep(IpAddress{ .ip4 = .loopback(443) }, addresses[0]);
    ip6.port = 443;
    try std.testing.expectEqualDeep(IpAddress{ .ip6 = ip6 }, addresses[1]);
}

test "resolver packets reject truncation, surplus bytes, bad tags and unsafe counts" {
    var packet: Packet = .{};
    try packet.add(.{ .ip4 = .loopback(1) });
    const bytes = packet.finish(.resolved);
    var buffer: [max_addresses]IpAddress = undefined;
    for (0..bytes.len) |length| try std.testing.expectError(error.InvalidResolverReply, decode(bytes[0..length], 1, &buffer));
    try std.testing.expectError(error.InvalidResolverReply, decode(packet.bytes[0 .. bytes.len + 1], 1, &buffer));
    for ([_]usize{ 0, 4, 5, 6, 7, 12, 31 }) |index| {
        packet.bytes[index] = 255;
        try std.testing.expectError(error.InvalidResolverReply, decode(bytes, 1, &buffer));
        packet = .{};
        try packet.add(.{ .ip4 = .loopback(1) });
        _ = packet.finish(.resolved);
    }
    for (0..max_addresses - 1) |_| try packet.add(.{ .ip4 = .loopback(1) });
    try std.testing.expectError(error.ResolverCapacity, packet.add(.{ .ip4 = .loopback(1) }));
    try std.testing.expectEqual(max_addresses, (try decode(packet.finish(.resolved), 1, &buffer)).len);
    try std.testing.expectError(error.NameServerFailure, decode(packet.finish(.too_many), 1, &buffer));
    try std.testing.expectError(error.SystemResources, decode(packet.finish(.resources), 1, &buffer));
    try std.testing.expectError(error.UnknownHostName, decode(packet.finish(.unknown), 1, &buffer));
    try std.testing.expectError(error.AddressFamilyUnsupported, decode(packet.finish(.family), 1, &buffer));
    try std.testing.expectError(error.NoAddressReturned, decode(packet.finish(.resolved), 1, &buffer));
}
