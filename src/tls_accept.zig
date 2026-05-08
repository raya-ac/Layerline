const std = @import("std");

const config_mod = @import("config.zig");
const native_tls = @import("native_tls_runtime.zig");
const tls_client_hello = @import("tls_client_hello.zig");

const ServerConfig = config_mod.ServerConfig;

pub const Callbacks = struct {
    active_io: *const fn () std.Io,
    clear_tls_channel: *const fn () void,
    handle_http1_connection: *const fn (std.Io, std.Io.net.Stream, *ServerConfig, std.mem.Allocator, *const std.process.Environ.Map) anyerror!void,
    handle_http2_preface: *const fn (std.Io, std.Io.net.Stream, std.mem.Allocator, *ServerConfig, []const u8, *const std.process.Environ.Map) anyerror!void,
    raw_stream_read: *const fn (std.Io.net.Stream, []u8) anyerror!usize,
    raw_stream_write_all: *const fn (std.Io.net.Stream, []const u8) anyerror!void,
    set_tls_channel: *const fn (?*native_tls.Channel) void,
};

pub fn handleClientHelloProbe(
    io: std.Io,
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    cfg: *ServerConfig,
    prefill: []const u8,
    process_env: *const std.process.Environ.Map,
    callbacks: Callbacks,
) anyerror!void {
    const record = try native_tls.readClientHelloRecord(stream, allocator, prefill, callbacks.raw_stream_read);
    defer allocator.free(record);
    var info = tls_client_hello.parse(allocator, record) catch |err| {
        std.debug.print("TLS ClientHello parse failed before native TLS termination: {}\n", .{err});
        try native_tls.sendFatalAlert(stream, native_tls.ALERT_HANDSHAKE_FAILURE, callbacks.raw_stream_write_all);
        return;
    };
    defer info.deinit(allocator);

    std.debug.print(
        "TLS ClientHello sni={s} alpn={s} tls13={} aes128gcm={} ecdsa_p256={} rsa_pss={} ed25519={} h2={} http11={} tls_configured={}\n",
        .{
            info.sni orelse "(none)",
            info.alpn orelse "(none)",
            info.supports_tls13,
            info.offers_aes_128_gcm_sha256,
            info.offers_ecdsa_secp256r1_sha256,
            info.offers_rsa_pss_rsae_sha256,
            info.offers_ed25519,
            info.offers_h2,
            info.offers_http11,
            cfg.tls_enabled,
        },
    );

    var established = native_tls.establishTls13(stream, allocator, cfg, record, info, callbacks.active_io(), callbacks.raw_stream_read, callbacks.raw_stream_write_all) catch |err| {
        std.debug.print("Native TLS 1.3 handshake failed: {}\n", .{err});
        const alert = switch (err) {
            error.NoApplicationProtocol => native_tls.ALERT_NO_APPLICATION_PROTOCOL,
            else => native_tls.ALERT_HANDSHAKE_FAILURE,
        };
        try native_tls.sendFatalAlert(stream, alert, callbacks.raw_stream_write_all);
        return;
    };
    defer established.channel.deinit();

    callbacks.set_tls_channel(&established.channel);
    defer callbacks.clear_tls_channel();

    std.debug.print(
        "TLS 1.3 native connection accepted sni={s} alpn={s}\n",
        .{ info.sni orelse "(none)", established.alpn orelse "(none)" },
    );

    if (established.alpn) |alpn| {
        if (std.mem.eql(u8, alpn, "h2")) {
            try callbacks.handle_http2_preface(io, stream, allocator, cfg, "", process_env);
            return;
        }
    }

    try callbacks.handle_http1_connection(io, stream, cfg, allocator, process_env);
}
