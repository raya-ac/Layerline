const std = @import("std");

const config_mod = @import("config.zig");
const h3_native = @import("h3_native.zig");
const h3_state = @import("h3_state.zig");
const http2_content = @import("http2_content.zig");
const http2_support = @import("http2_support.zig");
const http_response = @import("http_response.zig");
const metrics_mod = @import("metrics.zig");
const quic_native = @import("quic_native.zig");
const request_mod = @import("request.zig");
const routing_mod = @import("routing.zig");
const server_identity = @import("server_identity.zig");
const tls13_native = @import("tls13_native.zig");

const DomainConfig = config_mod.DomainConfig;
const H2BufferedResponse = http2_support.BufferedResponse;
const HttpRequest = request_mod.HttpRequest;
const ServerConfig = config_mod.ServerConfig;
const ServerMetrics = metrics_mod.ServerMetrics;

pub const Callbacks = struct {
    build_response_for_request: *const fn (std.Io, std.mem.Allocator, *ServerConfig, HttpRequest, *const std.process.Environ.Map) anyerror!H2BufferedResponse,
};

const HTTP3_INITIAL_PADDING_BYTES = 600;
const HTTP3_MAX_DATAGRAM_BYTES = 1200;
const HTTP3_CONNECTION_TABLE_CAPACITY = 1024;
const QUIC_SHORT_PACKET_NUMBER_BYTES = 4;
const QUIC_AEAD_TAG_BYTES = 16;
const HTTP3_MAX_REQUEST_STREAM_BYTES = config_mod.DEFAULT_MAX_BODY_BYTES + config_mod.DEFAULT_MAX_REQUEST_BYTES;

const Http3InitialAssembly = struct {
    has_scid: bool = false,
    scid: quic_native.ConnectionId = .{},
    has_original_dcid: bool = false,
    original_dcid: quic_native.ConnectionId = .{},
    has_server_cid: bool = false,
    server_cid: quic_native.ConnectionId = .{},
    crypto: std.ArrayListUnmanaged(u8) = .empty,
    server_flight_sent: bool = false,
    client_handshake_crypto: std.ArrayListUnmanaged(u8) = .empty,
    has_handshake_keys: bool = false,
    client_handshake_keys: quic_native.PacketKeys = undefined,
    server_handshake_keys: quic_native.PacketKeys = undefined,
    traffic: tls13_native.TrafficSecrets = undefined,
    application_transcript_hash: [32]u8 = undefined,
    handshake_done: bool = false,
    has_application_keys: bool = false,
    client_application_keys: quic_native.PacketKeys = undefined,
    server_application_keys: quic_native.PacketKeys = undefined,
    server_handshake_packets: h3_state.PacketNumberSpace(16) = h3_state.PacketNumberSpace(16).init(),
    server_application_packets: h3_state.PacketNumberSpace(64) = h3_state.PacketNumberSpace(64).init(),
    h3_response_sent: bool = false,
    has_request_stream: bool = false,
    request_stream_id: u64 = 0,
    request_stream_finished: bool = false,
    request_stream: std.ArrayListUnmanaged(u8) = .empty,
    request_stream_filled: std.ArrayListUnmanaged(u8) = .empty,
    request_stream_contiguous_len: usize = 0,
    request_stream_fin_seen: bool = false,
    request_stream_final_size: usize = 0,

    fn matches(self: *const Http3InitialAssembly, scid: []const u8) bool {
        return self.has_scid and std.mem.eql(u8, self.scid.slice(), scid);
    }

    fn matchesServerCid(self: *const Http3InitialAssembly, dcid: []const u8) bool {
        return self.has_server_cid and std.mem.eql(u8, self.server_cid.slice(), dcid);
    }

    fn deinit(self: *Http3InitialAssembly, allocator: std.mem.Allocator) void {
        self.crypto.deinit(allocator);
        self.client_handshake_crypto.deinit(allocator);
        self.request_stream.deinit(allocator);
        self.request_stream_filled.deinit(allocator);
        self.* = .{};
    }

    fn reset(self: *Http3InitialAssembly, allocator: std.mem.Allocator, original_dcid: []const u8, scid: []const u8) !void {
        self.crypto.clearRetainingCapacity();
        self.client_handshake_crypto.clearRetainingCapacity();
        self.original_dcid = try quic_native.ConnectionId.init(original_dcid);
        self.has_original_dcid = true;
        self.scid = try quic_native.ConnectionId.init(scid);
        self.has_scid = true;
        self.has_server_cid = false;
        self.server_flight_sent = false;
        self.has_handshake_keys = false;
        self.handshake_done = false;
        self.has_application_keys = false;
        self.server_handshake_packets = h3_state.PacketNumberSpace(16).init();
        self.server_application_packets = h3_state.PacketNumberSpace(64).init();
        self.h3_response_sent = false;
        self.has_request_stream = false;
        self.request_stream_id = 0;
        self.request_stream_finished = false;
        self.request_stream.clearRetainingCapacity();
        self.request_stream_filled.clearRetainingCapacity();
        self.request_stream_contiguous_len = 0;
        self.request_stream_fin_seen = false;
        self.request_stream_final_size = 0;
        _ = allocator;
    }

    fn rememberServerCid(self: *Http3InitialAssembly, server_cid: []const u8) !void {
        self.server_cid = try quic_native.ConnectionId.init(server_cid);
        self.has_server_cid = true;
    }
};

const Http3ConnectionTable = struct {
    allocator: std.mem.Allocator,
    entries: []Http3InitialAssembly,
    active: []bool,
    active_count: usize = 0,

    fn init(allocator: std.mem.Allocator, capacity: usize) !Http3ConnectionTable {
        const entries = try allocator.alloc(Http3InitialAssembly, capacity);
        errdefer allocator.free(entries);
        const active = try allocator.alloc(bool, capacity);
        @memset(active, false);
        return .{
            .allocator = allocator,
            .entries = entries,
            .active = active,
        };
    }

    fn deinit(self: *Http3ConnectionTable) void {
        for (self.entries, self.active) |*entry, is_active| {
            if (is_active) entry.deinit(self.allocator);
        }
        self.allocator.free(self.entries);
        self.allocator.free(self.active);
        self.* = undefined;
    }

    fn findByClientScid(self: *Http3ConnectionTable, scid: []const u8) ?*Http3InitialAssembly {
        for (self.entries, self.active) |*entry, is_active| {
            if (is_active and entry.matches(scid)) return entry;
        }
        return null;
    }

    fn findByServerCid(self: *Http3ConnectionTable, dcid: []const u8) ?*Http3InitialAssembly {
        for (self.entries, self.active) |*entry, is_active| {
            if (is_active and entry.matchesServerCid(dcid)) return entry;
        }
        return null;
    }

    fn findByShortPacketDcid(self: *Http3ConnectionTable, packet: []const u8) ?*Http3InitialAssembly {
        if (packet.len <= 1) return null;
        for (self.entries, self.active) |*entry, is_active| {
            if (!is_active or !entry.has_server_cid) continue;
            const cid = entry.server_cid.slice();
            if (packet.len >= 1 + cid.len and std.mem.eql(u8, packet[1 .. 1 + cid.len], cid)) return entry;
        }
        return null;
    }

    fn acquire(self: *Http3ConnectionTable) !*Http3InitialAssembly {
        for (self.active, 0..) |is_active, i| {
            if (!is_active) {
                self.entries[i] = .{};
                self.active[i] = true;
                self.active_count += 1;
                return &self.entries[i];
            }
        }
        return error.Http3ConnectionCapacityExceeded;
    }
};

fn packetKeysFromTls(keys: tls13_native.QuicPacketKeys) quic_native.PacketKeys {
    return .{ .key = keys.key, .iv = keys.iv, .hp = keys.hp };
}

fn findTlsFinishedVerifyData(handshake_messages: []const u8) !?[32]u8 {
    var offset: usize = 0;
    while (offset < handshake_messages.len) {
        if (handshake_messages.len < offset + 4) return error.Truncated;
        const kind = handshake_messages[offset];
        const len = (@as(usize, handshake_messages[offset + 1]) << 16) |
            (@as(usize, handshake_messages[offset + 2]) << 8) |
            @as(usize, handshake_messages[offset + 3]);
        offset += 4;
        if (handshake_messages.len < offset + len) return error.Truncated;
        if (kind == 0x14) {
            if (len != 32) return error.InvalidFinished;
            return handshake_messages[offset..][0..32].*;
        }
        offset += len;
    }
    return null;
}

fn skipAckFrame(plaintext: []const u8, offset: *usize, with_ecn: bool) !void {
    const largest = try h3_native.decodeVarInt(plaintext[offset.*..]);
    offset.* += largest.len;
    const delay = try h3_native.decodeVarInt(plaintext[offset.*..]);
    offset.* += delay.len;
    const range_count = try h3_native.decodeVarInt(plaintext[offset.*..]);
    offset.* += range_count.len;
    const first_range = try h3_native.decodeVarInt(plaintext[offset.*..]);
    offset.* += first_range.len;
    var i: u64 = 0;
    while (i < range_count.value) : (i += 1) {
        const gap = try h3_native.decodeVarInt(plaintext[offset.*..]);
        offset.* += gap.len;
        const range = try h3_native.decodeVarInt(plaintext[offset.*..]);
        offset.* += range.len;
    }
    if (with_ecn) {
        const ect0 = try h3_native.decodeVarInt(plaintext[offset.*..]);
        offset.* += ect0.len;
        const ect1 = try h3_native.decodeVarInt(plaintext[offset.*..]);
        offset.* += ect1.len;
        const ce = try h3_native.decodeVarInt(plaintext[offset.*..]);
        offset.* += ce.len;
    }
}

const Http3Request = struct {
    stream_id: u64,
    method: []const u8 = "GET",
    path: []const u8 = "/",
    authority: ?[]const u8 = null,
    headers: []const u8 = "",
    body: []const u8 = "",
    body_available: bool = false,
};

fn http3PathOnly(path: []const u8) []const u8 {
    const split = std.mem.indexOfScalar(u8, path, '?') orelse return path;
    return path[0..split];
}

fn http3QueryOnly(path: []const u8) []const u8 {
    const split = std.mem.indexOfScalar(u8, path, '?') orelse return "";
    return path[split + 1 ..];
}

fn parseHttp3RequestStreamPayload(allocator: std.mem.Allocator, stream_id: u64, payload: []const u8) !?Http3Request {
    var offset: usize = 0;
    var request = Http3Request{ .stream_id = stream_id };
    var saw_headers = false;
    var raw_headers = std.ArrayList(u8).empty;
    errdefer raw_headers.deinit(allocator);
    var body = std.ArrayList(u8).empty;
    errdefer body.deinit(allocator);

    while (offset < payload.len) {
        const frame_header = try h3_native.decodeFrameHeader(payload[offset..]);
        offset += frame_header.len;
        if (frame_header.length > std.math.maxInt(usize)) return error.InvalidFrame;
        const frame_len: usize = @intCast(frame_header.length);
        if (payload.len < offset + frame_len) return error.Truncated;
        const frame_payload = payload[offset .. offset + frame_len];
        offset += frame_len;

        if (frame_header.frame_type == @intFromEnum(h3_native.FrameType.headers)) {
            if (saw_headers) continue;
            const headers = try h3_native.decodeHeaderBlock(allocator, frame_payload);
            defer allocator.free(headers);

            for (headers) |header| {
                if (std.mem.eql(u8, header.name, ":method")) {
                    request.method = header.value;
                } else if (std.mem.eql(u8, header.name, ":path")) {
                    request.path = header.value;
                } else if (std.mem.eql(u8, header.name, ":authority")) {
                    request.authority = header.value;
                } else if (header.name.len > 0 and header.name[0] != ':' and !std.ascii.eqlIgnoreCase(header.name, "connection")) {
                    try raw_headers.print(allocator, "{s}: {s}\r\n", .{ header.name, header.value });
                }
            }
            saw_headers = true;
            continue;
        }

        if (frame_header.frame_type == @intFromEnum(h3_native.FrameType.data)) {
            request.body_available = true;
            if (frame_payload.len > 0) try body.appendSlice(allocator, frame_payload);
            continue;
        }
    }

    if (!saw_headers) return null;
    if (raw_headers.items.len > 0) {
        request.headers = try raw_headers.toOwnedSlice(allocator);
    } else {
        raw_headers.deinit(allocator);
    }
    if (request.body_available) {
        request.body = try body.toOwnedSlice(allocator);
    } else {
        body.deinit(allocator);
    }
    return request;
}

fn appendHttp3RequestStreamData(
    allocator: std.mem.Allocator,
    assembly: *Http3InitialAssembly,
    stream_id: u64,
    stream_offset: usize,
    data: []const u8,
    fin: bool,
) !void {
    if (!assembly.has_request_stream) {
        assembly.has_request_stream = true;
        assembly.request_stream_id = stream_id;
        assembly.request_stream.clearRetainingCapacity();
        assembly.request_stream_filled.clearRetainingCapacity();
        assembly.request_stream_finished = false;
        assembly.request_stream_contiguous_len = 0;
        assembly.request_stream_fin_seen = false;
        assembly.request_stream_final_size = 0;
    }
    if (assembly.request_stream_id != stream_id or assembly.request_stream_finished) return;

    if (stream_offset > HTTP3_MAX_REQUEST_STREAM_BYTES) return error.Http3RequestStreamTooLarge;
    const end = std.math.add(usize, stream_offset, data.len) catch return error.InvalidFrame;
    if (end > HTTP3_MAX_REQUEST_STREAM_BYTES) return error.Http3RequestStreamTooLarge;

    if (end > assembly.request_stream.items.len) {
        const old_len = assembly.request_stream.items.len;
        try assembly.request_stream.resize(allocator, end);
        @memset(assembly.request_stream.items[old_len..end], 0);
        try assembly.request_stream_filled.resize(allocator, end);
        @memset(assembly.request_stream_filled.items[old_len..end], 0);
    }

    for (data, 0..) |byte, i| {
        const index = stream_offset + i;
        if (assembly.request_stream_filled.items[index] == 0) {
            assembly.request_stream.items[index] = byte;
            assembly.request_stream_filled.items[index] = 1;
        } else if (assembly.request_stream.items[index] != byte) {
            return error.Http3StreamDataConflict;
        }
    }

    while (assembly.request_stream_contiguous_len < assembly.request_stream_filled.items.len and
        assembly.request_stream_filled.items[assembly.request_stream_contiguous_len] != 0)
    {
        assembly.request_stream_contiguous_len += 1;
    }

    if (fin) {
        if (assembly.request_stream_fin_seen and assembly.request_stream_final_size != end) return error.Http3InvalidStreamFinalSize;
        assembly.request_stream_fin_seen = true;
        assembly.request_stream_final_size = end;
    }
    assembly.request_stream_finished = assembly.request_stream_fin_seen and assembly.request_stream_contiguous_len >= assembly.request_stream_final_size;
}

fn findHttp3Request(allocator: std.mem.Allocator, assembly: *Http3InitialAssembly, plaintext: []const u8) !?Http3Request {
    var offset: usize = 0;
    while (offset < plaintext.len) {
        const frame_type_vi = try h3_native.decodeVarInt(plaintext[offset..]);
        offset += frame_type_vi.len;
        const frame_type = frame_type_vi.value;

        switch (frame_type) {
            0x00, 0x01, 0x1e => {},
            0x02 => try skipAckFrame(plaintext, &offset, false),
            0x03 => try skipAckFrame(plaintext, &offset, true),
            0x06 => {
                const crypto_offset = try h3_native.decodeVarInt(plaintext[offset..]);
                offset += crypto_offset.len;
                const len = try h3_native.decodeVarInt(plaintext[offset..]);
                offset += len.len + @as(usize, @intCast(len.value));
                if (offset > plaintext.len) return error.Truncated;
            },
            0x08...0x0f => {
                const stream_id = try h3_native.decodeVarInt(plaintext[offset..]);
                offset += stream_id.len;
                var stream_offset: usize = 0;
                if ((frame_type & 0x04) != 0) {
                    const stream_offset_vi = try h3_native.decodeVarInt(plaintext[offset..]);
                    offset += stream_offset_vi.len;
                    if (stream_offset_vi.value > std.math.maxInt(usize)) return error.InvalidFrame;
                    stream_offset = @intCast(stream_offset_vi.value);
                }
                const data_len = if ((frame_type & 0x02) != 0) len: {
                    const len_vi = try h3_native.decodeVarInt(plaintext[offset..]);
                    offset += len_vi.len;
                    break :len @as(usize, @intCast(len_vi.value));
                } else plaintext.len - offset;
                if (plaintext.len < offset + data_len) return error.Truncated;
                if ((stream_id.value & 0x03) == 0) {
                    const fin = (frame_type & 0x01) != 0;
                    try appendHttp3RequestStreamData(
                        allocator,
                        assembly,
                        stream_id.value,
                        stream_offset,
                        plaintext[offset .. offset + data_len],
                        fin,
                    );
                    if (assembly.request_stream_finished) {
                        if (try parseHttp3RequestStreamPayload(allocator, stream_id.value, assembly.request_stream.items[0..assembly.request_stream_final_size])) |request| {
                            return request;
                        }
                    }
                }
                offset += data_len;
            },
            0x10, 0x12, 0x13, 0x14, 0x16, 0x17, 0x19 => {
                const ignored = try h3_native.decodeVarInt(plaintext[offset..]);
                offset += ignored.len;
            },
            0x11, 0x15 => {
                const stream_id = try h3_native.decodeVarInt(plaintext[offset..]);
                offset += stream_id.len;
                const value = try h3_native.decodeVarInt(plaintext[offset..]);
                offset += value.len;
            },
            0x18 => {
                const sequence = try h3_native.decodeVarInt(plaintext[offset..]);
                offset += sequence.len;
                const retire_prior = try h3_native.decodeVarInt(plaintext[offset..]);
                offset += retire_prior.len;
                if (plaintext.len < offset + 1) return error.Truncated;
                const cid_len = plaintext[offset];
                offset += 1;
                if (plaintext.len < offset + cid_len + 16) return error.Truncated;
                offset += cid_len + 16;
            },
            0x1a, 0x1b => {
                if (plaintext.len < offset + 8) return error.Truncated;
                offset += 8;
            },
            0x1c, 0x1d => {
                const error_code = try h3_native.decodeVarInt(plaintext[offset..]);
                offset += error_code.len;
                if (frame_type == 0x1c) {
                    const failed_frame = try h3_native.decodeVarInt(plaintext[offset..]);
                    offset += failed_frame.len;
                }
                const reason_len = try h3_native.decodeVarInt(plaintext[offset..]);
                offset += reason_len.len + @as(usize, @intCast(reason_len.value));
                if (offset > plaintext.len) return error.Truncated;
            },
            else => return error.UnsupportedFrame,
        }
    }

    return null;
}

fn buildHttp3ControlStreamData(allocator: std.mem.Allocator) ![]u8 {
    var out = std.ArrayListUnmanaged(u8).empty;
    errdefer out.deinit(allocator);

    var stream_type_buf: [8]u8 = undefined;
    const stream_type_len = try h3_native.encodeVarInt(&stream_type_buf, 0x00);
    try out.appendSlice(allocator, stream_type_buf[0..stream_type_len]);

    var settings_buf: [16]u8 = undefined;
    const settings_len = try h3_native.encodeFrameHeader(&settings_buf, @intFromEnum(h3_native.FrameType.settings), 0);
    try out.appendSlice(allocator, settings_buf[0..settings_len]);

    return out.toOwnedSlice(allocator);
}

fn buildHttp3ResponseData(allocator: std.mem.Allocator, head: http_response.ResponseHead, body: []const u8, extra_headers: []const h3_native.Header) ![]u8 {
    var status_buf: [8]u8 = undefined;
    const status = try std.fmt.bufPrint(&status_buf, "{d}", .{head.status_code});
    var length_buf: [32]u8 = undefined;
    const content_length = try std.fmt.bufPrint(&length_buf, "{d}", .{head.content_length});
    const headers = try allocator.alloc(h3_native.Header, 4 + extra_headers.len);
    defer allocator.free(headers);
    headers[0] = .{ .name = ":status", .value = status };
    headers[1] = .{ .name = "server", .value = head.server };
    headers[2] = .{ .name = "content-type", .value = head.content_type };
    headers[3] = .{ .name = "content-length", .value = content_length };
    if (extra_headers.len > 0) @memcpy(headers[4..], extra_headers);

    const headers_frame = try h3_native.buildHeadersFrame(allocator, headers);
    defer allocator.free(headers_frame);
    const data_frame = try h3_native.buildDataFrame(allocator, body);
    defer allocator.free(data_frame);

    var out = std.ArrayListUnmanaged(u8).empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, headers_frame);
    try out.appendSlice(allocator, data_frame);
    return out.toOwnedSlice(allocator);
}

fn buildHttp3DefaultResponseData(allocator: std.mem.Allocator, server_header: []const u8, is_head: bool) ![]u8 {
    const body =
        \\<!doctype html>
        \\<html lang="en">
        \\<head>
        \\<meta charset="utf-8">
        \\<meta name="viewport" content="width=device-width, initial-scale=1">
        \\<title>Layerline</title>
        \\<style>
        \\body{margin:0;min-height:100vh;background:linear-gradient(180deg,#f7f4ed,#e9e3d6);color:#11110f;font:16px/1.5 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
        \\main{min-height:100vh;display:grid;grid-template-columns:minmax(0,1fr) minmax(260px,.7fr);gap:48px;align-items:center;padding:48px}
        \\section{max-width:820px}
        \\h1{margin:0;font-size:clamp(68px,14vw,148px);line-height:.82;letter-spacing:0}
        \\p{max-width:48ch;color:#5d5e58;font-size:20px}
        \\code,.tag{font:14px ui-monospace,SFMono-Regular,Menlo,monospace}
        \\.tag{display:inline-block;margin:0 0 18px;color:#77786f;text-transform:uppercase}
        \\ul{display:grid;gap:12px;margin:0;padding:0;list-style:none}
        \\li{border-top:1px solid rgba(17,17,15,.16);padding-top:12px;font:14px ui-monospace,SFMono-Regular,Menlo,monospace}
        \\@media(max-width:760px){main{grid-template-columns:1fr;padding:28px}}
        \\</style>
        \\</head>
        \\<body><main><section><div class="tag">native QUIC response</div><h1>HTTP/3</h1><p>Served by Layerline from the Zig QUIC path after TLS 1.3 Finished, 1-RTT packet protection, QPACK headers, and an HTTP/3 DATA frame.</p><code>HTTP/3 200</code></section><ul><li>QUIC v1</li><li>TLS 1.3</li><li>1-RTT</li><li>QPACK</li></ul></main></body>
        \\</html>
    ;

    return buildHttp3ResponseData(allocator, .{
        .status_code = 200,
        .status_text = "OK",
        .server = server_header,
        .content_type = "text/html; charset=utf-8",
        .content_length = if (is_head) 0 else body.len,
        .close_connection = true,
    }, if (is_head) "" else body, &.{});
}

fn statusText(status_code: u16) []const u8 {
    return switch (status_code) {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        501 => "Not Implemented",
        else => "OK",
    };
}

fn skipForwardedH3Header(name: []const u8) bool {
    return std.mem.startsWith(u8, name, ":") or
        std.ascii.eqlIgnoreCase(name, "server") or
        std.ascii.eqlIgnoreCase(name, "content-type") or
        std.ascii.eqlIgnoreCase(name, "content-length");
}

fn buildHttp3BufferedResponseData(
    allocator: std.mem.Allocator,
    server_header: []const u8,
    response: H2BufferedResponse,
    is_head: bool,
) ![]u8 {
    const extra_headers = try allocator.alloc(h3_native.Header, response.headers.len);
    defer allocator.free(extra_headers);
    var extra_len: usize = 0;
    for (response.headers) |header| {
        if (skipForwardedH3Header(header.name)) continue;
        extra_headers[extra_len] = .{ .name = header.name, .value = header.value };
        extra_len += 1;
    }

    const body = if (http_response.canSendBody(response.status_code, is_head)) response.body else "";
    return buildHttp3ResponseData(allocator, .{
        .status_code = response.status_code,
        .status_text = statusText(response.status_code),
        .server = server_header,
        .content_type = response.content_type,
        .content_length = body.len,
        .close_connection = true,
    }, body, extra_headers[0..extra_len]);
}

fn buildHttp3ErrorResponseData(
    allocator: std.mem.Allocator,
    server_header: []const u8,
    status_code: u16,
    status_text: []const u8,
    detail: []const u8,
    is_head: bool,
) ![]u8 {
    const response = try http2_content.coolErrorResponse(allocator, server_identity.name, server_identity.tagline, status_code, status_text, detail);
    return buildHttp3BufferedResponseData(allocator, server_header, response, is_head);
}

fn http3MethodCanUseBufferedRouter(method: []const u8, body_available: bool, declared_content_length: ?usize) bool {
    return std.mem.eql(u8, method, "GET") or
        std.mem.eql(u8, method, "HEAD") or
        std.mem.eql(u8, method, "OPTIONS") or
        std.mem.eql(u8, method, "DELETE") or
        body_available or
        (declared_content_length != null and declared_content_length.? == 0);
}

fn http3ToHttpRequest(allocator: std.mem.Allocator, request: Http3Request) !HttpRequest {
    const path = http3PathOnly(request.path);
    const query = http3QueryOnly(request.path);

    var headers = std.ArrayList(u8).empty;
    errdefer headers.deinit(allocator);
    if (request.authority) |authority| {
        if (authority.len > 0) try headers.print(allocator, "Host: {s}\r\n", .{authority});
    }
    if (request.headers.len > 0) try headers.appendSlice(allocator, request.headers);

    return .{
        .method = try allocator.dupe(u8, request.method),
        .path = try allocator.dupe(u8, path),
        .query = try allocator.dupe(u8, query),
        .headers = try headers.toOwnedSlice(allocator),
        .version = "HTTP/3",
        .body = request.body,
        .close_connection = true,
    };
}

fn buildHttp3RoutedResponseData(
    io: std.Io,
    allocator: std.mem.Allocator,
    cfg: *ServerConfig,
    process_env: *const std.process.Environ.Map,
    server_header: []const u8,
    request: Http3Request,
    callbacks: Callbacks,
) ![]u8 {
    const is_head = std.mem.eql(u8, request.method, "HEAD");
    const request_path = http3PathOnly(request.path);
    const domain = if (request.authority) |authority| routing_mod.findDomainForHost(cfg, authority) else null;

    if (std.mem.eql(u8, request_path, "/") and !routing_mod.domainServeStaticRoot(cfg, domain)) {
        return buildHttp3DefaultResponseData(allocator, server_header, is_head);
    }

    const req = try http3ToHttpRequest(allocator, request);
    if (req.body.len > cfg.max_body_bytes) {
        return buildHttp3ErrorResponseData(allocator, server_header, 413, "Payload Too Large", "Request body exceeds configured limit.", is_head);
    }
    const declared_content_length = http2_support.parseRequestContentLength(req.headers) catch {
        return buildHttp3ErrorResponseData(allocator, server_header, 400, "Bad Request", "HTTP/3 Content-Length was invalid.", is_head);
    };
    if (declared_content_length) |content_length| {
        if (content_length != req.body.len) {
            return buildHttp3ErrorResponseData(allocator, server_header, 400, "Bad Request", "HTTP/3 Content-Length did not match the received request body.", is_head);
        }
    }
    if (!http3MethodCanUseBufferedRouter(request.method, request.body_available, declared_content_length)) {
        return buildHttp3ErrorResponseData(allocator, server_header, 501, "Not Implemented", "HTTP/3 request body routing is still on the roadmap for this method.", is_head);
    }
    const response = callbacks.build_response_for_request(io, allocator, cfg, req, process_env) catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => return buildHttp3ErrorResponseData(allocator, server_header, 500, "Internal Server Error", "Internal server error while routing HTTP/3 request.", is_head),
    };
    return buildHttp3BufferedResponseData(allocator, server_header, response, is_head);
}

fn maxHttp3ShortPlaintextBytes(dcid_len: usize) !usize {
    // Stay inside QUIC's conservative 1200-byte datagram floor until path MTU
    // discovery exists. Bigger responses should split, not gamble on UDP.
    const packet_overhead = 1 + dcid_len + QUIC_SHORT_PACKET_NUMBER_BYTES + QUIC_AEAD_TAG_BYTES;
    if (HTTP3_MAX_DATAGRAM_BYTES <= packet_overhead + 16) return error.PacketBudgetTooSmall;
    return HTTP3_MAX_DATAGRAM_BYTES - packet_overhead;
}

fn h3StreamFramePrefixLen(stream_id: u64, stream_offset: u64, data_len: usize) !usize {
    const has_offset = stream_offset != 0;
    const frame_type = 0x08 | 0x02 | (if (has_offset) @as(u64, 0x04) else @as(u64, 0));
    return (try h3_native.varIntLen(frame_type)) +
        (try h3_native.varIntLen(stream_id)) +
        (if (has_offset) try h3_native.varIntLen(stream_offset) else 0) +
        (try h3_native.varIntLen(@intCast(data_len)));
}

fn maxHttp3StreamChunkLen(available_plaintext: usize, stream_id: u64, stream_offset: u64, remaining: usize) !usize {
    if (remaining == 0) return 0;

    var chunk_len = @min(available_plaintext, remaining);
    while (chunk_len > 0) {
        const prefix_len = try h3StreamFramePrefixLen(stream_id, stream_offset, chunk_len);
        if (prefix_len >= available_plaintext) return error.PacketBudgetTooSmall;

        const next = @min(available_plaintext - prefix_len, remaining);
        if (next == chunk_len) return chunk_len;
        chunk_len = next;
    }

    return error.PacketBudgetTooSmall;
}

fn sendHttp3ShortPlaintext(
    io: std.Io,
    socket: anytype,
    peer: *const std.Io.net.IpAddress,
    assembly: *Http3InitialAssembly,
    plaintext: []const u8,
) !void {
    var padded: ?[]u8 = null;
    defer if (padded) |buf| std.heap.page_allocator.free(buf);

    var packet_plaintext = plaintext;
    if (packet_plaintext.len < 16) {
        const buf = try std.heap.page_allocator.alloc(u8, 16);
        @memcpy(buf[0..packet_plaintext.len], packet_plaintext);
        @memset(buf[packet_plaintext.len..], 0);
        padded = buf;
        packet_plaintext = buf;
    }

    const packet_number = try assembly.server_application_packets.takeNext();
    const packet = try quic_native.buildProtectedShortPacket(std.heap.page_allocator, .{
        .dcid = assembly.scid.slice(),
        .packet_number = packet_number,
        .keys = assembly.server_application_keys,
        .plaintext = packet_plaintext,
    });
    defer std.heap.page_allocator.free(packet);

    try socket.send(io, peer, packet);
}

fn sendHttp3ResponsePacket(
    io: std.Io,
    socket: anytype,
    peer: *const std.Io.net.IpAddress,
    assembly: *Http3InitialAssembly,
    largest_client_packet_number: u64,
    request: Http3Request,
    cfg: *ServerConfig,
    process_env: *const std.process.Environ.Map,
    server_header: []const u8,
    callbacks: Callbacks,
) !usize {
    const ack_frame = try quic_native.buildAckFrame(std.heap.page_allocator, largest_client_packet_number, 0);
    defer std.heap.page_allocator.free(ack_frame);
    const control_data = try buildHttp3ControlStreamData(std.heap.page_allocator);
    defer std.heap.page_allocator.free(control_data);
    const control_stream = try quic_native.buildStreamFrame(std.heap.page_allocator, 3, control_data, false);
    defer std.heap.page_allocator.free(control_stream);
    var response_arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer response_arena.deinit();
    const response_data = try buildHttp3RoutedResponseData(io, response_arena.allocator(), cfg, process_env, server_header, request, callbacks);

    const max_plaintext = try maxHttp3ShortPlaintextBytes(assembly.scid.slice().len);
    var response_offset: usize = 0;
    var include_control = true;
    var packet_count: usize = 0;

    // STREAM offsets are byte offsets into the HTTP/3 stream. The client sees
    // one ordered response even though we ship it as multiple QUIC packets.
    while (include_control or response_offset < response_data.len) {
        var plaintext = std.ArrayListUnmanaged(u8).empty;
        defer plaintext.deinit(std.heap.page_allocator);

        if (include_control) {
            try plaintext.appendSlice(std.heap.page_allocator, ack_frame);
            try plaintext.appendSlice(std.heap.page_allocator, control_stream);
            include_control = false;
        }

        if (plaintext.items.len > max_plaintext) return error.PacketBudgetTooSmall;

        if (response_offset < response_data.len and plaintext.items.len < max_plaintext) {
            const remaining = response_data.len - response_offset;
            const available = max_plaintext - plaintext.items.len;
            const chunk_len = try maxHttp3StreamChunkLen(available, request.stream_id, @intCast(response_offset), remaining);
            const fin = chunk_len == remaining;
            const response_stream = try quic_native.buildStreamFrameAt(
                std.heap.page_allocator,
                request.stream_id,
                @intCast(response_offset),
                response_data[response_offset .. response_offset + chunk_len],
                fin,
            );
            defer std.heap.page_allocator.free(response_stream);
            try plaintext.appendSlice(std.heap.page_allocator, response_stream);
            response_offset += chunk_len;
        }

        try sendHttp3ShortPlaintext(io, socket, peer, assembly, plaintext.items);
        packet_count += 1;
    }

    return packet_count;
}

test "extracts HTTP/3 request path from a request stream" {
    const header_block = "\x00\x00\xd1\x51\x07/health";
    var frame_header: [16]u8 = undefined;
    const frame_header_len = try h3_native.encodeFrameHeader(&frame_header, @intFromEnum(h3_native.FrameType.headers), header_block.len);
    var h3_payload = std.ArrayListUnmanaged(u8).empty;
    defer h3_payload.deinit(std.testing.allocator);
    try h3_payload.appendSlice(std.testing.allocator, frame_header[0..frame_header_len]);
    try h3_payload.appendSlice(std.testing.allocator, header_block);

    const stream_frame = try quic_native.buildStreamFrame(std.testing.allocator, 0, h3_payload.items, true);
    defer std.testing.allocator.free(stream_frame);

    var assembly = Http3InitialAssembly{};
    defer assembly.deinit(std.testing.allocator);
    const request = (try findHttp3Request(std.testing.allocator, &assembly, stream_frame)).?;
    try std.testing.expectEqual(@as(u64, 0), request.stream_id);
    try std.testing.expectEqualStrings("GET", request.method);
    try std.testing.expectEqualStrings("/health", request.path);
}

test "HTTP/3 path helpers split query strings" {
    try std.testing.expectEqualStrings("/assets/app.css", http3PathOnly("/assets/app.css?v=1"));
    try std.testing.expectEqualStrings("v=1", http3QueryOnly("/assets/app.css?v=1"));
    try std.testing.expectEqualStrings("/health", http3PathOnly("/health"));
    try std.testing.expectEqualStrings("", http3QueryOnly("/health"));
}

test "HTTP/3 request conversion carries host and query into common router shape" {
    const req = try http3ToHttpRequest(std.testing.allocator, .{
        .stream_id = 0,
        .method = "GET",
        .path = "/api/echo?msg=layerline",
        .authority = "example.test:8443",
        .headers = "accept: text/plain\r\n",
        .body = "ignored for get",
    });
    defer {
        std.testing.allocator.free(req.method);
        std.testing.allocator.free(req.path);
        std.testing.allocator.free(req.query);
        std.testing.allocator.free(req.headers);
    }

    try std.testing.expectEqualStrings("GET", req.method);
    try std.testing.expectEqualStrings("/api/echo", req.path);
    try std.testing.expectEqualStrings("msg=layerline", req.query);
    try std.testing.expectEqualStrings("Host: example.test:8443\r\naccept: text/plain\r\n", req.headers);
    try std.testing.expectEqualStrings("HTTP/3", req.version);
    try std.testing.expectEqualStrings("ignored for get", req.body);
}

test "HTTP/3 buffered router is gated to methods without DATA bodies" {
    try std.testing.expect(http3MethodCanUseBufferedRouter("GET", false, null));
    try std.testing.expect(http3MethodCanUseBufferedRouter("HEAD", false, null));
    try std.testing.expect(http3MethodCanUseBufferedRouter("OPTIONS", false, null));
    try std.testing.expect(http3MethodCanUseBufferedRouter("DELETE", false, null));
    try std.testing.expect(http3MethodCanUseBufferedRouter("POST", true, 5));
    try std.testing.expect(http3MethodCanUseBufferedRouter("POST", false, 0));
    try std.testing.expect(!http3MethodCanUseBufferedRouter("POST", false, null));
    try std.testing.expect(!http3MethodCanUseBufferedRouter("PATCH", false, null));
}

test "extracts HTTP/3 DATA frames from a request stream" {
    const headers = [_]h3_native.Header{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/api/echo" },
        .{ .name = ":authority", .value = "example.test" },
        .{ .name = "content-length", .value = "5" },
        .{ .name = "content-type", .value = "text/plain" },
    };
    const header_block = try h3_native.encodeLiteralHeaders(std.testing.allocator, &headers);
    defer std.testing.allocator.free(header_block);

    var h3_payload = std.ArrayListUnmanaged(u8).empty;
    defer h3_payload.deinit(std.testing.allocator);
    try h3_native.appendFrame(std.testing.allocator, &h3_payload, .headers, header_block);
    try h3_native.appendFrame(std.testing.allocator, &h3_payload, .data, "hello");

    const request = (try parseHttp3RequestStreamPayload(std.testing.allocator, 0, h3_payload.items)).?;
    defer {
        std.testing.allocator.free(request.headers);
        std.testing.allocator.free(request.body);
    }

    try std.testing.expectEqualStrings("POST", request.method);
    try std.testing.expectEqualStrings("/api/echo", request.path);
    try std.testing.expectEqualStrings("example.test", request.authority.?);
    try std.testing.expectEqualStrings("content-length: 5\r\ncontent-type: text/plain\r\n", request.headers);
    try std.testing.expect(request.body_available);
    try std.testing.expectEqualStrings("hello", request.body);
}

test "reassembles ordered HTTP/3 request stream data across packets" {
    const headers = [_]h3_native.Header{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/api/echo" },
        .{ .name = ":authority", .value = "example.test" },
        .{ .name = "content-length", .value = "5" },
    };
    const header_block = try h3_native.encodeLiteralHeaders(std.testing.allocator, &headers);
    defer std.testing.allocator.free(header_block);

    var first_payload = std.ArrayListUnmanaged(u8).empty;
    defer first_payload.deinit(std.testing.allocator);
    try h3_native.appendFrame(std.testing.allocator, &first_payload, .headers, header_block);
    var second_payload = std.ArrayListUnmanaged(u8).empty;
    defer second_payload.deinit(std.testing.allocator);
    try h3_native.appendFrame(std.testing.allocator, &second_payload, .data, "hello");

    const first_stream = try quic_native.buildStreamFrameAt(std.testing.allocator, 0, 0, first_payload.items, false);
    defer std.testing.allocator.free(first_stream);
    const second_stream = try quic_native.buildStreamFrameAt(std.testing.allocator, 0, first_payload.items.len, second_payload.items, true);
    defer std.testing.allocator.free(second_stream);

    var assembly = Http3InitialAssembly{};
    defer assembly.deinit(std.testing.allocator);

    try std.testing.expect((try findHttp3Request(std.testing.allocator, &assembly, first_stream)) == null);
    const request = (try findHttp3Request(std.testing.allocator, &assembly, second_stream)).?;
    defer {
        std.testing.allocator.free(request.headers);
        std.testing.allocator.free(request.body);
    }

    try std.testing.expectEqualStrings("POST", request.method);
    try std.testing.expectEqualStrings("/api/echo", request.path);
    try std.testing.expectEqualStrings("hello", request.body);
}

test "reassembles out-of-order HTTP/3 request stream data" {
    const headers = [_]h3_native.Header{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":path", .value = "/api/echo" },
        .{ .name = ":authority", .value = "example.test" },
        .{ .name = "content-length", .value = "5" },
    };
    const header_block = try h3_native.encodeLiteralHeaders(std.testing.allocator, &headers);
    defer std.testing.allocator.free(header_block);

    var h3_payload = std.ArrayListUnmanaged(u8).empty;
    defer h3_payload.deinit(std.testing.allocator);
    try h3_native.appendFrame(std.testing.allocator, &h3_payload, .headers, header_block);
    try h3_native.appendFrame(std.testing.allocator, &h3_payload, .data, "hello");

    const split = h3_payload.items.len / 2;
    const tail_stream = try quic_native.buildStreamFrameAt(std.testing.allocator, 0, split, h3_payload.items[split..], true);
    defer std.testing.allocator.free(tail_stream);
    const head_stream = try quic_native.buildStreamFrameAt(std.testing.allocator, 0, 0, h3_payload.items[0..split], false);
    defer std.testing.allocator.free(head_stream);

    var assembly = Http3InitialAssembly{};
    defer assembly.deinit(std.testing.allocator);

    try std.testing.expect((try findHttp3Request(std.testing.allocator, &assembly, tail_stream)) == null);
    const request = (try findHttp3Request(std.testing.allocator, &assembly, head_stream)).?;
    defer {
        std.testing.allocator.free(request.headers);
        std.testing.allocator.free(request.body);
    }

    try std.testing.expectEqualStrings("POST", request.method);
    try std.testing.expectEqualStrings("/api/echo", request.path);
    try std.testing.expectEqualStrings("hello", request.body);
}

test "HTTP/3 default showcase suppresses body for HEAD" {
    const get_data = try buildHttp3DefaultResponseData(std.testing.allocator, "Layerline", false);
    defer std.testing.allocator.free(get_data);
    const head_data = try buildHttp3DefaultResponseData(std.testing.allocator, "Layerline", true);
    defer std.testing.allocator.free(head_data);

    try std.testing.expect(std.mem.indexOf(u8, get_data, "native QUIC response") != null);
    try std.testing.expect(std.mem.indexOf(u8, head_data, "native QUIC response") == null);
}

fn testHttp3BufferedRouterCallback(
    io: std.Io,
    allocator: std.mem.Allocator,
    cfg: *ServerConfig,
    req: HttpRequest,
    process_env: *const std.process.Environ.Map,
) !H2BufferedResponse {
    _ = io;
    _ = cfg;
    _ = process_env;
    try std.testing.expectEqualStrings("GET", req.method);
    try std.testing.expectEqualStrings("/from-h3", req.path);
    try std.testing.expectEqualStrings("x=1", req.query);
    try std.testing.expectEqualStrings("Host: example.test\r\n", req.headers);
    return .{
        .status_code = 200,
        .content_type = "text/plain; charset=utf-8",
        .body = try allocator.dupe(u8, "routed over h3\n"),
    };
}

fn testHttp3BodyRouterCallback(
    io: std.Io,
    allocator: std.mem.Allocator,
    cfg: *ServerConfig,
    req: HttpRequest,
    process_env: *const std.process.Environ.Map,
) !H2BufferedResponse {
    _ = io;
    _ = cfg;
    _ = process_env;
    try std.testing.expectEqualStrings("POST", req.method);
    try std.testing.expectEqualStrings("/api/echo", req.path);
    try std.testing.expectEqualStrings("Host: example.test\r\ncontent-length: 5\r\ncontent-type: text/plain\r\n", req.headers);
    try std.testing.expectEqualStrings("hello", req.body);
    return .{
        .status_code = 200,
        .content_type = "text/plain; charset=utf-8",
        .body = try allocator.dupe(u8, req.body),
    };
}

test "HTTP/3 routed responses delegate to the buffered route builder" {
    var cfg = config_mod.defaultServerConfig();
    const data = try buildHttp3RoutedResponseData(
        undefined,
        std.testing.allocator,
        &cfg,
        undefined,
        "Layerline",
        .{
            .stream_id = 0,
            .method = "GET",
            .path = "/from-h3?x=1",
            .authority = "example.test",
        },
        .{ .build_response_for_request = testHttp3BufferedRouterCallback },
    );
    defer std.testing.allocator.free(data);

    try std.testing.expect(std.mem.indexOf(u8, data, "routed over h3\n") != null);
}

test "HTTP/3 routed responses accept parsed DATA bodies" {
    var cfg = config_mod.defaultServerConfig();
    const data = try buildHttp3RoutedResponseData(
        undefined,
        std.testing.allocator,
        &cfg,
        undefined,
        "Layerline",
        .{
            .stream_id = 0,
            .method = "POST",
            .path = "/api/echo",
            .authority = "example.test",
            .headers = "content-length: 5\r\ncontent-type: text/plain\r\n",
            .body = "hello",
            .body_available = true,
        },
        .{ .build_response_for_request = testHttp3BodyRouterCallback },
    );
    defer std.testing.allocator.free(data);

    try std.testing.expect(std.mem.indexOf(u8, data, "hello") != null);
}

pub fn serveProbeTask(io: std.Io, cfg: *const ServerConfig, process_env: *const std.process.Environ.Map, metrics: *ServerMetrics, server_header: []const u8, active_config: *const fn () *ServerConfig, callbacks: Callbacks) void {
    var address = std.Io.net.IpAddress.parse(cfg.host, cfg.http3_port) catch |err| {
        std.debug.print("HTTP/3 bind address error: {}\n", .{err});
        return;
    };
    const socket = address.bind(io, .{ .mode = .dgram, .protocol = .udp }) catch |err| {
        std.debug.print("HTTP/3 UDP bind failed on {s}:{d}: {}\n", .{ cfg.host, cfg.http3_port, err });
        return;
    };
    defer socket.close(io);

    std.debug.print("HTTP/3 native UDP listener on udp://{s}:{d}\n", .{ cfg.host, cfg.http3_port });
    std.debug.print("HTTP/3 status: native QUIC/TLS handshake and buffered route response path active.\n", .{});

    var connections = Http3ConnectionTable.init(std.heap.page_allocator, HTTP3_CONNECTION_TABLE_CAPACITY) catch |err| {
        std.debug.print("HTTP/3 connection table allocation failed: {}\n", .{err});
        return;
    };
    defer connections.deinit();

    var recv_buf: [4096]u8 = undefined;

    while (true) {
        const msg = socket.receive(io, &recv_buf) catch |err| {
            std.debug.print("HTTP/3 UDP receive error: {}\n", .{err});
            continue;
        };

        if (msg.data.len == 0) continue;

        if ((msg.data[0] & 0x80) != 0) {
            const long = quic_native.parseLongHeader(msg.data) catch |err| {
                std.debug.print("HTTP/3 ignored malformed long-header datagram from {f}: {}\n", .{ msg.from, err });
                continue;
            };
            const assembly_opt = connections.findByServerCid(long.dcid.slice());
            if (long.packet_type == .handshake or (assembly_opt != null and assembly_opt.?.has_handshake_keys and assembly_opt.?.server_flight_sent)) {
                const assembly = assembly_opt orelse {
                    std.debug.print("HTTP/3 ignored Handshake packet from {f}: unknown destination CID\n", .{msg.from});
                    continue;
                };
                if (!assembly.has_handshake_keys) {
                    std.debug.print("HTTP/3 ignored early Handshake packet from {f}: no handshake keys yet\n", .{msg.from});
                    continue;
                }

                var packet_cursor: usize = 0;
                var largest_handshake_packet_number: u64 = 0;
                var saw_handshake_packet = false;
                while (packet_cursor < msg.data.len and (msg.data[packet_cursor] & 0x80) != 0) {
                    const packet = msg.data[packet_cursor..];
                    const packet_long = quic_native.parseLongHeader(packet) catch break;
                    const packet_len = quic_native.protectedLongPacketLen(packet) catch |err| {
                        std.debug.print("HTTP/3 Handshake packet length parse failed from {f}: {}\n", .{ msg.from, err });
                        break;
                    };
                    if (packet.len < packet_len) {
                        std.debug.print("HTTP/3 truncated Handshake datagram from {f}: packet_len={d}, datagram_len={d}\n", .{ msg.from, packet_len, packet.len });
                        break;
                    }
                    if (packet_long.packet_type != .handshake) {
                        packet_cursor += packet_len;
                        continue;
                    }

                    const decrypted = quic_native.decryptProtectedLongPacketWithKeys(
                        std.heap.page_allocator,
                        packet[0..packet_len],
                        assembly.client_handshake_keys,
                    ) catch |err| {
                        std.debug.print("HTTP/3 client Handshake decrypt failed from {f}: {}\n", .{ msg.from, err });
                        packet_cursor += packet_len;
                        continue;
                    };
                    defer std.heap.page_allocator.free(decrypted.plaintext);

                    quic_native.appendCryptoData(std.heap.page_allocator, decrypted.plaintext, &assembly.client_handshake_crypto) catch |err| {
                        std.debug.print("HTTP/3 client Handshake CRYPTO parse failed from {f}: {}\n", .{ msg.from, err });
                        packet_cursor += packet_len;
                        continue;
                    };
                    largest_handshake_packet_number = decrypted.packet_number;
                    saw_handshake_packet = true;
                    packet_cursor += packet_len;
                }

                if (!saw_handshake_packet) {
                    std.debug.print("HTTP/3 ignored Handshake datagram from {f}: no decryptable Handshake packet\n", .{msg.from});
                    continue;
                }

                const finished = findTlsFinishedVerifyData(assembly.client_handshake_crypto.items) catch |err| {
                    std.debug.print("HTTP/3 client Finished parse failed from {f}: {}\n", .{ msg.from, err });
                    continue;
                } orelse {
                    std.debug.print("HTTP/3 waiting for client Finished from {f}: crypto_bytes={d}\n", .{ msg.from, assembly.client_handshake_crypto.items.len });
                    continue;
                };
                const expected_finished = tls13_native.finishedVerifyData(assembly.traffic.client_finished_key, assembly.application_transcript_hash);
                if (!std.mem.eql(u8, &finished, &expected_finished)) {
                    std.debug.print("HTTP/3 client Finished verify failed from {f}\n", .{msg.from});
                    continue;
                }

                const was_handshake_done = assembly.handshake_done;
                if (!was_handshake_done) {
                    const application = tls13_native.deriveApplicationTrafficSecrets(assembly.traffic.master_secret, assembly.application_transcript_hash);
                    assembly.client_application_keys = packetKeysFromTls(tls13_native.deriveQuicPacketKeys(application.client_application_traffic_secret));
                    assembly.server_application_keys = packetKeysFromTls(tls13_native.deriveQuicPacketKeys(application.server_application_traffic_secret));
                    assembly.has_application_keys = true;
                    assembly.handshake_done = true;
                }

                const ack_frame = quic_native.buildAckFrame(std.heap.page_allocator, largest_handshake_packet_number, 0) catch |err| {
                    std.debug.print("HTTP/3 Handshake ACK frame build failed for {f}: {}\n", .{ msg.from, err });
                    continue;
                };
                defer std.heap.page_allocator.free(ack_frame);
                var handshake_ack_plaintext = std.ArrayListUnmanaged(u8).empty;
                defer handshake_ack_plaintext.deinit(std.heap.page_allocator);
                handshake_ack_plaintext.appendSlice(std.heap.page_allocator, ack_frame) catch |err| {
                    std.debug.print("HTTP/3 Handshake ACK plaintext build failed for {f}: {}\n", .{ msg.from, err });
                    continue;
                };
                handshake_ack_plaintext.appendNTimes(std.heap.page_allocator, 0, 16) catch |err| {
                    std.debug.print("HTTP/3 Handshake ACK padding build failed for {f}: {}\n", .{ msg.from, err });
                    continue;
                };
                const handshake_ack_packet_number = assembly.server_handshake_packets.takeNext() catch |err| {
                    std.debug.print("HTTP/3 Handshake ACK packet number failed for {f}: {}\n", .{ msg.from, err });
                    continue;
                };
                const ack_packet = quic_native.buildProtectedLongPacket(std.heap.page_allocator, .{
                    .packet_type = .handshake,
                    .dcid = assembly.scid.slice(),
                    .scid = assembly.server_cid.slice(),
                    .packet_number = handshake_ack_packet_number,
                    .keys = assembly.server_handshake_keys,
                    .plaintext = handshake_ack_plaintext.items,
                }) catch |err| {
                    std.debug.print("HTTP/3 Handshake ACK packet build failed for {f}: {}\n", .{ msg.from, err });
                    continue;
                };
                defer std.heap.page_allocator.free(ack_packet);
                socket.send(io, &msg.from, ack_packet) catch |err| {
                    std.debug.print("HTTP/3 Handshake ACK send failed for {f}: {}\n", .{ msg.from, err });
                    continue;
                };

                if (!was_handshake_done) {
                    std.debug.print("HTTP/3 handshake complete with {f}; 1-RTT keys ready\n", .{msg.from});
                }

                if (packet_cursor < msg.data.len and (msg.data[packet_cursor] & 0x80) == 0) {
                    const short = quic_native.decryptProtectedShortPacketWithKeys(
                        std.heap.page_allocator,
                        msg.data[packet_cursor..],
                        assembly.server_cid.len,
                        assembly.client_application_keys,
                    ) catch |err| {
                        std.debug.print("HTTP/3 coalesced 1-RTT decrypt failed from {f}: {}\n", .{ msg.from, err });
                        continue;
                    };
                    defer std.heap.page_allocator.free(short.plaintext);
                    var request_arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
                    defer request_arena.deinit();
                    const request_opt = findHttp3Request(request_arena.allocator(), assembly, short.plaintext) catch |err| {
                        if (!assembly.h3_response_sent) {
                            std.debug.print("HTTP/3 coalesced request parse failed from {f}: {}\n", .{ msg.from, err });
                        }
                        continue;
                    };
                    if (request_opt) |request| {
                        const packet_count = sendHttp3ResponsePacket(io, socket, &msg.from, assembly, short.packet_number, request, active_config(), process_env, server_header, callbacks) catch |err| {
                            std.debug.print("HTTP/3 response send failed for {f}: {}\n", .{ msg.from, err });
                            continue;
                        };
                        assembly.h3_response_sent = true;
                        metrics.h3ResponseSent(packet_count);
                        std.debug.print("HTTP/3 served {s} to {f} on stream {d} in {d} packet(s)\n", .{ request.path, msg.from, request.stream_id, packet_count });
                    }
                }
                continue;
            }
        } else {
            const assembly = connections.findByShortPacketDcid(msg.data) orelse {
                std.debug.print("HTTP/3 ignored 1-RTT packet from {f}: unknown destination CID\n", .{msg.from});
                continue;
            };
            if (!assembly.has_application_keys) {
                std.debug.print("HTTP/3 ignored 1-RTT packet from {f}: application keys not ready\n", .{msg.from});
                continue;
            }

            const decrypted = quic_native.decryptProtectedShortPacketWithKeys(
                std.heap.page_allocator,
                msg.data,
                assembly.server_cid.len,
                assembly.client_application_keys,
            ) catch |err| {
                std.debug.print("HTTP/3 1-RTT decrypt failed from {f}: {}\n", .{ msg.from, err });
                continue;
            };
            defer std.heap.page_allocator.free(decrypted.plaintext);

            var request_arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
            defer request_arena.deinit();
            const request_opt = findHttp3Request(request_arena.allocator(), assembly, decrypted.plaintext) catch |err| {
                if (!assembly.h3_response_sent) {
                    std.debug.print("HTTP/3 request parse failed from {f}: {}\n", .{ msg.from, err });
                }
                continue;
            };
            if (request_opt) |request| {
                if (!assembly.h3_response_sent) {
                    const packet_count = sendHttp3ResponsePacket(io, socket, &msg.from, assembly, decrypted.packet_number, request, active_config(), process_env, server_header, callbacks) catch |err| {
                        std.debug.print("HTTP/3 response send failed for {f}: {}\n", .{ msg.from, err });
                        continue;
                    };
                    assembly.h3_response_sent = true;
                    metrics.h3ResponseSent(packet_count);
                    std.debug.print("HTTP/3 served {s} to {f} on stream {d} in {d} packet(s)\n", .{ request.path, msg.from, request.stream_id, packet_count });
                }
            }
            continue;
        }

        const initial = quic_native.parseInitialHeader(msg.data) catch |err| {
            std.debug.print("HTTP/3 ignored non-initial datagram from {f}: {}\n", .{ msg.from, err });
            continue;
        };

        if (!quic_native.isSupportedVersion(initial.long.version)) {
            var response: [128]u8 = undefined;
            const len = quic_native.encodeVersionNegotiation(
                &response,
                initial.long.dcid.slice(),
                initial.long.scid.slice(),
                &.{ @intFromEnum(quic_native.Version.v1), @intFromEnum(quic_native.Version.v2) },
            ) catch |err| {
                std.debug.print("HTTP/3 version negotiation build failed: {}\n", .{err});
                continue;
            };
            socket.send(io, &msg.from, response[0..len]) catch |err| {
                std.debug.print("HTTP/3 version negotiation send failed: {}\n", .{err});
            };
            continue;
        }

        var used_fresh_initial_keys = false;
        const existing_assembly = connections.findByClientScid(initial.long.scid.slice());
        const decrypted = if (existing_assembly) |assembly|
            if (assembly.has_original_dcid)
                quic_native.decryptClientInitialWithOriginalDcid(
                    std.heap.page_allocator,
                    msg.data,
                    assembly.original_dcid.slice(),
                ) catch |stored_err| fresh: {
                    const fresh_decrypted = quic_native.decryptClientInitial(std.heap.page_allocator, msg.data) catch {
                        std.debug.print(
                            "HTTP/3 QUIC Initial from {f}: version=0x{x}, dcid_len={d}, scid_len={d}; decrypt failed: {}\n",
                            .{
                                msg.from,
                                initial.long.version,
                                initial.long.dcid.len,
                                initial.long.scid.len,
                                stored_err,
                            },
                        );
                        continue;
                    };
                    used_fresh_initial_keys = true;
                    break :fresh fresh_decrypted;
                }
            else
                quic_native.decryptClientInitial(std.heap.page_allocator, msg.data) catch |err| {
                    std.debug.print(
                        "HTTP/3 QUIC Initial from {f}: version=0x{x}, dcid_len={d}, scid_len={d}; decrypt failed: {}\n",
                        .{
                            msg.from,
                            initial.long.version,
                            initial.long.dcid.len,
                            initial.long.scid.len,
                            err,
                        },
                    );
                    continue;
                }
        else fresh: {
            used_fresh_initial_keys = true;
            break :fresh quic_native.decryptClientInitial(std.heap.page_allocator, msg.data) catch |err| {
                std.debug.print(
                    "HTTP/3 QUIC Initial from {f}: version=0x{x}, dcid_len={d}, scid_len={d}; decrypt failed: {}\n",
                    .{
                        msg.from,
                        initial.long.version,
                        initial.long.dcid.len,
                        initial.long.scid.len,
                        err,
                    },
                );
                continue;
            };
        };
        defer std.heap.page_allocator.free(decrypted.plaintext);

        const assembly = existing_assembly orelse (connections.acquire() catch |err| {
            std.debug.print("HTTP/3 connection table is full; dropping Initial from {f}: {}\n", .{ msg.from, err });
            continue;
        });

        if (existing_assembly == null or !assembly.has_original_dcid or used_fresh_initial_keys or (!assembly.server_flight_sent and !assembly.matches(initial.long.scid.slice()))) {
            assembly.reset(std.heap.page_allocator, initial.long.dcid.slice(), initial.long.scid.slice()) catch |err| {
                std.debug.print("HTTP/3 state reset failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };
        }

        quic_native.appendCryptoData(std.heap.page_allocator, decrypted.plaintext, &assembly.crypto) catch |err| {
            std.debug.print(
                "HTTP/3 QUIC Initial from {f}: packet_number={d}, plaintext_bytes={d}; CRYPTO reassembly failed: {}\n",
                .{ msg.from, decrypted.packet_number, decrypted.plaintext.len, err },
            );
            continue;
        };

        if (assembly.server_flight_sent) continue;

        const hello = quic_native.parseClientHello(assembly.crypto.items) catch |err| {
            if (err == error.Truncated) {
                std.debug.print(
                    "HTTP/3 waiting for complete ClientHello from {f}: packet_number={d}, crypto_bytes={d}\n",
                    .{ msg.from, decrypted.packet_number, assembly.crypto.items.len },
                );
                continue;
            }
            std.debug.print(
                "HTTP/3 QUIC Initial from {f}: packet_number={d}, crypto_bytes={d}; ClientHello parse failed: {}\n",
                .{ msg.from, decrypted.packet_number, assembly.crypto.items.len, err },
            );
            continue;
        };

        std.debug.print(
            "HTTP/3 ClientHello from {f}: packet_number={d}, alpn={s}, sni={s}, tls13={}, aes128gcm={}, ed25519={}, x25519={}, quic_transport_params={}\n",
            .{
                msg.from,
                decrypted.packet_number,
                hello.alpn orelse "(none)",
                hello.server_name orelse "(none)",
                hello.supports_tls13,
                hello.supports_aes_128_gcm_sha256,
                hello.supports_ed25519,
                hello.x25519_key_share != null,
                hello.has_quic_transport_parameters,
            },
        );

        if (hello.x25519_key_share) |client_key| {
            if (!std.mem.eql(u8, hello.alpn orelse "", "h3")) {
                std.debug.print("HTTP/3 ClientHello from {f} did not offer h3 ALPN; skipping server flight.\n", .{msg.from});
                continue;
            }

            var server_random: [32]u8 = undefined;
            io.random(&server_random);
            const server_kp = tls13_native.X25519.KeyPair.generate(io);
            const server_hello = tls13_native.buildServerHello(std.heap.page_allocator, .{
                .legacy_session_id = hello.legacy_session_id,
                .random = server_random,
                .x25519_public_key = server_kp.public_key,
            }) catch |err| {
                std.debug.print("HTTP/3 TLS ServerHello build failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };
            defer std.heap.page_allocator.free(server_hello);

            const shared = tls13_native.X25519.scalarmult(server_kp.secret_key, client_key) catch |err| {
                std.debug.print("HTTP/3 TLS X25519 shared-secret failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };
            const transcript_hash = tls13_native.transcriptHash(&.{ assembly.crypto.items, server_hello });
            const traffic = tls13_native.deriveTrafficSecrets(shared, transcript_hash);
            const client_handshake_keys = packetKeysFromTls(tls13_native.deriveQuicPacketKeys(traffic.client_handshake_traffic_secret));
            const server_handshake_keys = packetKeysFromTls(tls13_native.deriveQuicPacketKeys(traffic.server_handshake_traffic_secret));

            var server_cid: [8]u8 = undefined;
            io.random(&server_cid);
            assembly.rememberServerCid(&server_cid) catch |err| {
                std.debug.print("HTTP/3 server CID tracking failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };
            const ack_frame = quic_native.buildAckFrame(std.heap.page_allocator, decrypted.packet_number, 0) catch |err| {
                std.debug.print("HTTP/3 QUIC ACK frame build failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };
            defer std.heap.page_allocator.free(ack_frame);

            const crypto_frame = quic_native.buildCryptoFrame(std.heap.page_allocator, 0, server_hello) catch |err| {
                std.debug.print("HTTP/3 QUIC CRYPTO frame build failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };
            defer std.heap.page_allocator.free(crypto_frame);

            var initial_plaintext = std.ArrayListUnmanaged(u8).empty;
            defer initial_plaintext.deinit(std.heap.page_allocator);
            initial_plaintext.appendSlice(std.heap.page_allocator, ack_frame) catch |err| {
                std.debug.print("HTTP/3 QUIC plaintext build failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };
            initial_plaintext.appendSlice(std.heap.page_allocator, crypto_frame) catch |err| {
                std.debug.print("HTTP/3 QUIC plaintext build failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };
            // QUIC Initial datagrams are intentionally bulky. Some clients will
            // read the ServerHello from a small packet and still reject the flight.
            initial_plaintext.appendNTimes(std.heap.page_allocator, 0, HTTP3_INITIAL_PADDING_BYTES) catch |err| {
                std.debug.print("HTTP/3 QUIC Initial padding build failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };

            const initial_secrets = quic_native.deriveInitialSecrets(initial.long.dcid.slice());
            const response = quic_native.buildProtectedLongPacket(std.heap.page_allocator, .{
                .packet_type = .initial,
                .dcid = initial.long.scid.slice(),
                .scid = &server_cid,
                .packet_number = 0,
                .keys = quic_native.packetKeysFromInitialDirection(initial_secrets.server),
                .plaintext = initial_plaintext.items,
            }) catch |err| {
                std.debug.print("HTTP/3 QUIC server Initial build failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };
            defer std.heap.page_allocator.free(response);

            const transport_params = quic_native.buildDefaultTransportParameters(std.heap.page_allocator, initial.long.dcid.slice(), &server_cid) catch |err| {
                std.debug.print("HTTP/3 QUIC transport parameter build failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };
            defer std.heap.page_allocator.free(transport_params);

            const encrypted_extensions = tls13_native.buildEncryptedExtensions(std.heap.page_allocator, "h3", transport_params) catch |err| {
                std.debug.print("HTTP/3 TLS EncryptedExtensions build failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };
            defer std.heap.page_allocator.free(encrypted_extensions);

            const cert_key = tls13_native.Ed25519.KeyPair.generate(io);
            const cert_der = tls13_native.buildSelfSignedEd25519Certificate(std.heap.page_allocator, cert_key, "localhost") catch |err| {
                std.debug.print("HTTP/3 TLS self-signed certificate build failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };
            defer std.heap.page_allocator.free(cert_der);

            const certificate_msg = tls13_native.buildCertificate(std.heap.page_allocator, &.{cert_der}) catch |err| {
                std.debug.print("HTTP/3 TLS Certificate build failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };
            defer std.heap.page_allocator.free(certificate_msg);

            const cert_verify_hash = tls13_native.transcriptHash(&.{
                assembly.crypto.items,
                server_hello,
                encrypted_extensions,
                certificate_msg,
            });
            const cert_verify_signature = tls13_native.signCertificateVerifyEd25519(cert_key, cert_verify_hash) catch |err| {
                std.debug.print("HTTP/3 TLS CertificateVerify signature failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };
            const certificate_verify_msg = tls13_native.buildCertificateVerify(std.heap.page_allocator, .ed25519, &cert_verify_signature) catch |err| {
                std.debug.print("HTTP/3 TLS CertificateVerify build failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };
            defer std.heap.page_allocator.free(certificate_verify_msg);

            const finished_hash = tls13_native.transcriptHash(&.{
                assembly.crypto.items,
                server_hello,
                encrypted_extensions,
                certificate_msg,
                certificate_verify_msg,
            });
            const server_finished_msg = tls13_native.buildFinished(
                std.heap.page_allocator,
                tls13_native.finishedVerifyData(traffic.server_finished_key, finished_hash),
            ) catch |err| {
                std.debug.print("HTTP/3 TLS Finished build failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };
            defer std.heap.page_allocator.free(server_finished_msg);

            assembly.traffic = traffic;
            assembly.client_handshake_keys = client_handshake_keys;
            assembly.server_handshake_keys = server_handshake_keys;
            assembly.application_transcript_hash = tls13_native.transcriptHash(&.{
                assembly.crypto.items,
                server_hello,
                encrypted_extensions,
                certificate_msg,
                certificate_verify_msg,
                server_finished_msg,
            });
            assembly.has_handshake_keys = true;

            var server_handshake_flight = std.ArrayListUnmanaged(u8).empty;
            defer server_handshake_flight.deinit(std.heap.page_allocator);
            server_handshake_flight.appendSlice(std.heap.page_allocator, encrypted_extensions) catch |err| {
                std.debug.print("HTTP/3 TLS server flight build failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };
            server_handshake_flight.appendSlice(std.heap.page_allocator, certificate_msg) catch |err| {
                std.debug.print("HTTP/3 TLS server flight build failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };
            server_handshake_flight.appendSlice(std.heap.page_allocator, certificate_verify_msg) catch |err| {
                std.debug.print("HTTP/3 TLS server flight build failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };
            server_handshake_flight.appendSlice(std.heap.page_allocator, server_finished_msg) catch |err| {
                std.debug.print("HTTP/3 TLS server flight build failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };

            const handshake_crypto = quic_native.buildCryptoFrame(std.heap.page_allocator, 0, server_handshake_flight.items) catch |err| {
                std.debug.print("HTTP/3 QUIC Handshake CRYPTO frame build failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };
            defer std.heap.page_allocator.free(handshake_crypto);

            const server_handshake_packet_number = assembly.server_handshake_packets.takeNext() catch |err| {
                std.debug.print("HTTP/3 server Handshake packet number failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };
            const handshake_response = quic_native.buildProtectedLongPacket(std.heap.page_allocator, .{
                .packet_type = .handshake,
                .dcid = initial.long.scid.slice(),
                .scid = &server_cid,
                .packet_number = server_handshake_packet_number,
                .keys = server_handshake_keys,
                .plaintext = handshake_crypto,
            }) catch |err| {
                std.debug.print("HTTP/3 QUIC server Handshake build failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };
            defer std.heap.page_allocator.free(handshake_response);

            var server_datagram = std.ArrayListUnmanaged(u8).empty;
            defer server_datagram.deinit(std.heap.page_allocator);
            server_datagram.appendSlice(std.heap.page_allocator, response) catch |err| {
                std.debug.print("HTTP/3 QUIC server datagram build failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };
            server_datagram.appendSlice(std.heap.page_allocator, handshake_response) catch |err| {
                std.debug.print("HTTP/3 QUIC server datagram build failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };

            socket.send(io, &msg.from, server_datagram.items) catch |err| {
                std.debug.print("HTTP/3 QUIC server Initial+Handshake send failed for {f}: {}\n", .{ msg.from, err });
                continue;
            };

            std.debug.print(
                "HTTP/3 sent server Initial+Handshake to {f}: datagram_bytes={d}, initial_bytes={d}, handshake_bytes={d}, initial_padding={d}, server_hello_bytes={d}, cert_bytes={d}, finished_bytes={d}\n",
                .{ msg.from, server_datagram.items.len, response.len, handshake_response.len, HTTP3_INITIAL_PADDING_BYTES, server_hello.len, cert_der.len, server_finished_msg.len },
            );
            assembly.server_flight_sent = true;
        }
    }
}
