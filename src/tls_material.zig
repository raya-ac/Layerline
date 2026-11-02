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
    defer std.crypto.secureZero(u8, cert_pem);
    const key_pem = try std.Io.Dir.cwd().readFileAlloc(io, key_path, allocator, .limited(128 * 1024));
    defer allocator.free(key_pem);
    defer std.crypto.secureZero(u8, key_pem);
    return tls_pem.loadMaterialFromPem(allocator, cert_pem, key_pem);
}

fn validatePair(io: std.Io, allocator: std.mem.Allocator, cert: ?[]const u8, key: ?[]const u8, allow_missing: bool) !void {
    if (cert == null and key == null) return;
    if (cert == null or key == null) return error.InvalidTlsConfig;
    var material = loadFromPaths(io, allocator, cert.?, key.?) catch |err| {
        if (allow_missing and err == error.FileNotFound) return;
        return err;
    };
    material.deinit(allocator);
}

pub fn validateFiles(io: std.Io, allocator: std.mem.Allocator, cfg: *const ServerConfig) !void {
    // Validation never invokes ACME. On first issuance its files may not exist yet.
    if (cfg.tls_enabled) try validatePair(io, allocator, cfg.tls_cert, cfg.tls_key, cfg.tls_auto);
    for (cfg.domains.items) |domain| try validatePair(io, allocator, domain.tls_cert, domain.tls_key, cfg.tls_auto);
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

// Retired reloads live in an arena. Erase secrets before that arena is released,
// without guessing whether its individual allocations can be freed here.
pub fn wipeAll(cfg: *ServerConfig) void {
    if (cfg.tls_material) |*material| material.private_key.wipe();
    for (cfg.domains.items) |*domain| {
        if (domain.tls_material) |*material| material.private_key.wipe();
    }
}
