//! Test-only entry point; not linked into Layerline or exposed as a server mode.
const std = @import("std");
const policy = @import("upstream_certificate.zig");

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const args = try init.minimal.args.toSlice(allocator);
    if (args.len < 6 or args.len > 5 + policy.max_chain) return error.InvalidArguments;
    const primitive = std.mem.eql(u8, args[1], "primitive");
    if (!primitive and !std.mem.eql(u8, args[1], "strict")) return error.InvalidArguments;
    const now = try std.fmt.parseInt(i64, args[3], 10);
    const root_bytes = try std.Io.Dir.cwd().readFileAlloc(init.io, args[4], allocator, .limited(policy.max_certificate_bytes));
    const root = policy.parse(root_bytes) catch |err| fail(err);
    var peers: [policy.max_chain]policy.Certificate = undefined;
    var count: usize = 0;
    for (args[5..], 0..) |path, index| {
        const bytes = try std.Io.Dir.cwd().readFileAlloc(init.io, path, allocator, .limited(policy.max_certificate_bytes));
        const certificate = policy.parse(bytes) catch |err| {
            if (index == 0 or primitive) fail(err);
            continue;
        };
        peers[count] = certificate;
        count += 1;
    }
    const chain = peers[0..count];
    if (primitive) {
        // This negative control proves why signature verification alone is not
        // issuer authorization. It still parses through the bounded decoder.
        policy.verifyIdentity(chain[0].policy.san, args[2]) catch |err| fail(err);
        for (chain, 0..) |certificate, index| {
            const issuer = if (index + 1 < chain.len) chain[index + 1] else root;
            certificate.parsed.verify(issuer.parsed, now) catch |err| fail(err);
        }
    } else policy.verifyChain(chain, &.{root}, args[2], now) catch |err| fail(err);
    std.debug.print("accepted\n", .{});
}

fn fail(err: anyerror) noreturn {
    std.debug.print("rejected:{s}\n", .{@errorName(err)});
    std.process.exit(1);
}
