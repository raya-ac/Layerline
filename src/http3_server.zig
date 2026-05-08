const std = @import("std");

const config_mod = @import("config.zig");
const h3_native = @import("h3_native.zig");
const h3_state = @import("h3_state.zig");
const http_response = @import("http_response.zig");
const metrics_mod = @import("metrics.zig");
const quic_native = @import("quic_native.zig");
const tls13_native = @import("tls13_native.zig");

const ServerConfig = config_mod.ServerConfig;
const ServerMetrics = metrics_mod.ServerMetrics;

const HTTP3_INITIAL_PADDING_BYTES = 600;
const HTTP3_MAX_DATAGRAM_BYTES = 1200;
const HTTP3_CONNECTION_TABLE_CAPACITY = 1024;
const QUIC_SHORT_PACKET_NUMBER_BYTES = 4;
const QUIC_AEAD_TAG_BYTES = 16;

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

    fn matches(self: *const Http3InitialAssembly, scid: []const u8) bool {
        return self.has_scid and std.mem.eql(u8, self.scid.slice(), scid);
    }

    fn matchesServerCid(self: *const Http3InitialAssembly, dcid: []const u8) bool {
        return self.has_server_cid and std.mem.eql(u8, self.server_cid.slice(), dcid);
    }

    fn deinit(self: *Http3InitialAssembly, allocator: std.mem.Allocator) void {
        self.crypto.deinit(allocator);
        self.client_handshake_crypto.deinit(allocator);
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

fn findRequestStreamId(plaintext: []const u8) !?u64 {
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
                if ((frame_type & 0x04) != 0) {
                    const stream_offset = try h3_native.decodeVarInt(plaintext[offset..]);
                    offset += stream_offset.len;
                }
                const data_len = if ((frame_type & 0x02) != 0) len: {
                    const len_vi = try h3_native.decodeVarInt(plaintext[offset..]);
                    offset += len_vi.len;
                    break :len @as(usize, @intCast(len_vi.value));
                } else plaintext.len - offset;
                if (plaintext.len < offset + data_len) return error.Truncated;
                if ((stream_id.value & 0x03) == 0) return stream_id.value;
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

fn buildHttp3ResponseData(allocator: std.mem.Allocator, head: http_response.ResponseHead, body: []const u8) ![]u8 {
    var status_buf: [8]u8 = undefined;
    const status = try std.fmt.bufPrint(&status_buf, "{d}", .{head.status_code});
    var length_buf: [32]u8 = undefined;
    const content_length = try std.fmt.bufPrint(&length_buf, "{d}", .{head.content_length});
    const headers = [_]h3_native.Header{
        .{ .name = ":status", .value = status },
        .{ .name = "server", .value = head.server },
        .{ .name = "content-type", .value = head.content_type },
        .{ .name = "content-length", .value = content_length },
    };

    const headers_frame = try h3_native.buildHeadersFrame(allocator, &headers);
    defer allocator.free(headers_frame);
    const data_frame = try h3_native.buildDataFrame(allocator, body);
    defer allocator.free(data_frame);

    var out = std.ArrayListUnmanaged(u8).empty;
    errdefer out.deinit(allocator);
    try out.appendSlice(allocator, headers_frame);
    try out.appendSlice(allocator, data_frame);
    return out.toOwnedSlice(allocator);
}

fn buildHttp3DefaultResponseData(allocator: std.mem.Allocator, server_header: []const u8) ![]u8 {
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
        .content_length = body.len,
        .close_connection = true,
    }, body);
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
    request_stream_id: u64,
    server_header: []const u8,
) !usize {
    const ack_frame = try quic_native.buildAckFrame(std.heap.page_allocator, largest_client_packet_number, 0);
    defer std.heap.page_allocator.free(ack_frame);
    const control_data = try buildHttp3ControlStreamData(std.heap.page_allocator);
    defer std.heap.page_allocator.free(control_data);
    const control_stream = try quic_native.buildStreamFrame(std.heap.page_allocator, 3, control_data, false);
    defer std.heap.page_allocator.free(control_stream);
    const response_data = try buildHttp3DefaultResponseData(std.heap.page_allocator, server_header);
    defer std.heap.page_allocator.free(response_data);

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
            const chunk_len = try maxHttp3StreamChunkLen(available, request_stream_id, @intCast(response_offset), remaining);
            const fin = chunk_len == remaining;
            const response_stream = try quic_native.buildStreamFrameAt(
                std.heap.page_allocator,
                request_stream_id,
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

pub fn serveProbeTask(io: std.Io, cfg: *const ServerConfig, metrics: *ServerMetrics, server_header: []const u8) void {
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
    std.debug.print("HTTP/3 status: native QUIC/TLS handshake and default-page response path active.\n", .{});

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
                    const stream_id_opt = findRequestStreamId(short.plaintext) catch |err| {
                        if (!assembly.h3_response_sent) {
                            std.debug.print("HTTP/3 coalesced request parse failed from {f}: {}\n", .{ msg.from, err });
                        }
                        continue;
                    };
                    if (stream_id_opt) |stream_id| {
                        const packet_count = sendHttp3ResponsePacket(io, socket, &msg.from, assembly, short.packet_number, stream_id, server_header) catch |err| {
                            std.debug.print("HTTP/3 response send failed for {f}: {}\n", .{ msg.from, err });
                            continue;
                        };
                        assembly.h3_response_sent = true;
                        metrics.h3ResponseSent(packet_count);
                        std.debug.print("HTTP/3 served default page to {f} on stream {d} in {d} packet(s)\n", .{ msg.from, stream_id, packet_count });
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

            const stream_id_opt = findRequestStreamId(decrypted.plaintext) catch |err| {
                if (!assembly.h3_response_sent) {
                    std.debug.print("HTTP/3 request parse failed from {f}: {}\n", .{ msg.from, err });
                }
                continue;
            };
            if (stream_id_opt) |stream_id| {
                if (!assembly.h3_response_sent) {
                    const packet_count = sendHttp3ResponsePacket(io, socket, &msg.from, assembly, decrypted.packet_number, stream_id, server_header) catch |err| {
                        std.debug.print("HTTP/3 response send failed for {f}: {}\n", .{ msg.from, err });
                        continue;
                    };
                    assembly.h3_response_sent = true;
                    metrics.h3ResponseSent(packet_count);
                    std.debug.print("HTTP/3 served default page to {f} on stream {d} in {d} packet(s)\n", .{ msg.from, stream_id, packet_count });
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
