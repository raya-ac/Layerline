//! Test-only real TLS transport probe. Not installed with the web server.
const std = @import("std");
const runtime = @import("stream_runtime.zig");
const deadline = @import("backend_deadline.zig");
const origin_tls = @import("upstream_tls.zig");
const trust = @import("upstream_trust.zig");
const upstream_reader = @import("upstream_reader.zig");

pub fn main(init: std.process.Init) void {
    start(init) catch |err| {
        std.debug.print("rejected:{s}\n", .{@errorName(err)});
        std.process.exit(1);
    };
}

fn start(init: std.process.Init) !void {
    if (try @import("darwin_resolver.zig").serve(init.minimal)) return;
    try onWorker(init);
}

fn onWorker(init: std.process.Init) !void {
    const Task = struct {
        init: std.process.Init,
        failure: ?anyerror = null,
        fn work(self: *@This()) void {
            run(self.init) catch |err| {
                self.failure = err;
            };
        }
    };
    var task: Task = .{ .init = init };
    const worker = try std.Thread.spawn(.{ .stack_size = origin_tls.handshake_stack_bytes }, Task.work, .{&task});
    worker.join();
    if (task.failure) |err| return err;
}

fn run(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    if (args.len != 6) return error.InvalidArguments;
    const port = try std.fmt.parseInt(u16, args[2], 10);
    const timeout = try std.fmt.parseInt(u32, args[5], 10);
    var roots = if (std.mem.eql(u8, args[4], "system")) try trust.loadSystem(init.io, allocator) else try trust.load(init.io, allocator, args[4], false);
    defer roots.deinit();
    runtime.bindThreadIo(init.io);
    const previous = deadline.push(init.io, timeout);
    defer deadline.restore(previous);
    const stream = try runtime.connectTcpHost(allocator, args[1], port);
    defer runtime.streamClose(stream);
    try runtime.setStreamTimeouts(stream, timeout, timeout);
    try deadline.attach(stream);
    const channel = try origin_tls.Channel.create(allocator, init.io, stream, args[3], roots.anchors, runtime.rawStreamRead, runtime.rawStreamWriteAll, deadline.checkReadCompletion);
    defer channel.destroy();
    const previous_channel = origin_tls.bind(channel);
    defer _ = origin_tls.bind(previous_channel);
    const request = try std.fmt.allocPrint(allocator, "GET / HTTP/1.1\r\nHost: {s}\r\nConnection: close\r\n\r\n", .{args[3]});
    var accepted: usize = 0;
    try channel.write(request, &accepted);
    const reader = try upstream_reader.Reader.create(allocator, stream, read);
    defer allocator.destroy(reader);
    const head = final: while (true) {
        const head = try reader.nextHead();
        if (head.framing.status_code.? == 101) return error.BadGateway;
        if (head.framing.status_code.? >= 200) break :final head;
    };
    try reader.beginBody("GET", head.framing, 1024 * 1024);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var bytes: usize = 0;
    while (try reader.nextData()) |data| {
        hash.update(data);
        bytes += data.len;
    }
    try channel.end();
    std.debug.print("accepted status={d} bytes={d} sha256={s}\n", .{ head.framing.status_code.?, bytes, std.fmt.bytesToHex(hash.finalResult(), .lower) });
}

fn read(stream: std.Io.net.Stream, output: []u8) !usize {
    return (origin_tls.forStream(stream) orelse return error.MissingTlsChannel).read(output);
}
