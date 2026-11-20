const std = @import("std");
const config = @import("config.zig");
const routing = @import("routing.zig");
const tls_pem = @import("tls_pem.zig");
const certificate = @import("upstream_certificate.zig");
const field = @import("tls_log_field.zig").field;

fn checkName(io: std.Io, allocator: std.mem.Allocator, path: ?[]const u8, name: []const u8, now: i64) !void {
    const pem = try std.Io.Dir.cwd().readFileAlloc(io, path orelse return error.NoConfiguredCertificate, allocator, .limited(512 * 1024));
    defer allocator.free(pem);
    const chain = try tls_pem.decodeCertificateChainPem(allocator, pem);
    defer {
        for (chain) |der| allocator.free(der);
        allocator.free(chain);
    }
    const leaf = try certificate.parse(chain[0]);
    try leaf.checkTime(now);
    try leaf.checkConfiguredName(name);
}

pub fn run(io: std.Io, allocator: std.mem.Allocator, cfg: *const config.ServerConfig) !void {
    if (!cfg.tls_enabled) {
        std.debug.print("fail: no TCP TLS listener configured\n", .{});
        return error.CertificateNameCheckFailed;
    }
    const now = std.Io.Timestamp.now(io, .real).toSeconds();
    var checked: usize = 0;
    var failures: usize = 0;
    for (cfg.domains.items) |*domain| {
        for (domain.server_names.items) |name| {
            if (std.mem.eql(u8, name, "_") or std.ascii.eqlIgnoreCase(name, "default")) continue;
            const selected = routing.findDomainForHost(cfg, name) orelse domain;
            const reference = if (name.len > 2 and name[0] == '[' and name[name.len - 1] == ']')
                name[1 .. name.len - 1]
            else
                name;
            // clients connecting by IP don't send SNI.
            const path = if (std.Io.net.IpAddress.parse(reference, 0)) |_|
                cfg.tls_cert
            else |_|
                selected.tls_cert orelse cfg.tls_cert;
            checked += 1;
            checkName(io, allocator, path, reference, now) catch |err| {
                std.debug.print("fail: certificate name={f} error={s}\n", .{ field(name), @errorName(err) });
                failures += 1;
                continue;
            };
            const scope = if (std.mem.startsWith(u8, name, "*.")) " (one label only)" else "";
            std.debug.print("ok: certificate name={f}{s}\n", .{ field(name), scope });
        }
    }
    if (checked == 0) {
        std.debug.print("fail: no named TLS sites to check (catch-all names are skipped)\n", .{});
        return error.CertificateNameCheckFailed;
    }
    std.debug.print("certificate names: checked={d} failed={d}\n", .{ checked, failures });
    if (failures != 0) return error.CertificateNameCheckFailed;
}
