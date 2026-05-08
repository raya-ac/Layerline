const std = @import("std");

const config_mod = @import("config.zig");
const tls_pem = @import("tls_pem.zig");

const ServerConfig = config_mod.ServerConfig;

pub fn loadFromPaths(
    io: std.Io,
    allocator: std.mem.Allocator,
    cert_path: []const u8,
    key_path: []const u8,
) !tls_pem.ConfiguredTlsMaterial {
    const cert_pem = try std.Io.Dir.cwd().readFileAlloc(io, cert_path, allocator, .limited(512 * 1024));
    defer allocator.free(cert_pem);
    const key_pem = try std.Io.Dir.cwd().readFileAlloc(io, key_path, allocator, .limited(128 * 1024));
    defer allocator.free(key_pem);
    return tls_pem.loadMaterialFromPem(allocator, cert_pem, key_pem);
}

pub fn loadAll(io: std.Io, allocator: std.mem.Allocator, cfg: *ServerConfig) !void {
    if (cfg.tls_enabled) {
        if (cfg.tls_cert == null and cfg.tls_key == null) {
            std.debug.print("TLS enabled without cert/key; native TLS will use an ephemeral self-signed certificate.\n", .{});
        } else if (cfg.tls_cert == null or cfg.tls_key == null) {
            return error.InvalidTlsConfig;
        } else {
            cfg.tls_material = try loadFromPaths(io, allocator, cfg.tls_cert.?, cfg.tls_key.?);
            std.debug.print("Native TLS certificate loaded from {s}\n", .{cfg.tls_cert.?});
        }
    }

    for (cfg.domains.items) |*domain| {
        if (domain.tls_cert == null and domain.tls_key == null) continue;
        if (domain.tls_cert == null or domain.tls_key == null) return error.InvalidTlsConfig;
        domain.tls_material = try loadFromPaths(io, allocator, domain.tls_cert.?, domain.tls_key.?);
        std.debug.print("Native TLS certificate loaded for {s} from {s}\n", .{ domain.name, domain.tls_cert.? });
    }
}

pub fn deinitAll(allocator: std.mem.Allocator, cfg: *ServerConfig) void {
    if (cfg.tls_material) |*material| material.deinit(allocator);
    cfg.tls_material = null;
    for (cfg.domains.items) |*domain| {
        if (domain.tls_material) |*material| material.deinit(allocator);
        domain.tls_material = null;
    }
}
