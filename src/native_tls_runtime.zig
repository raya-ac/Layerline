const std = @import("std");
const resource_budget = @import("resource_budget.zig");

const config_mod = @import("config.zig");
const routing = @import("routing.zig");
const tls13_native = @import("tls13_native.zig");
const tls_client_hello = @import("tls_client_hello.zig");
const tls_pem = @import("tls_pem.zig");

const ServerConfig = config_mod.ServerConfig;

pub const ALERT_HANDSHAKE_FAILURE: u8 = 40;
pub const ALERT_NO_APPLICATION_PROTOCOL: u8 = 120;

const MAX_INNER_PLAINTEXT_BYTES = 16 * 1024;
const MAX_RECORD_BYTES = 5 + MAX_INNER_PLAINTEXT_BYTES + 256;
const CONTENT_TYPE_CHANGE_CIPHER_SPEC: u8 = 0x14;
const CONTENT_TYPE_ALERT: u8 = 0x15;
const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const CONTENT_TYPE_APPLICATION_DATA: u8 = 0x17;

pub const RawReadFn = *const fn (std.Io.net.Stream, []u8) anyerror!usize;
pub const RawWriteAllFn = *const fn (std.Io.net.Stream, []const u8) anyerror!void;

pub const Channel = struct {
    io: std.Io,
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    client_application_keys: tls13_native.TlsRecordKeys,
    server_application_keys: tls13_native.TlsRecordKeys,
    raw_read: RawReadFn,
    raw_write_all: RawWriteAllFn,
    client_sequence: u64 = 0,
    server_sequence: u64 = 0,
    pending_plaintext: ?[]u8 = null,
    pending_offset: usize = 0,
    record_header: [5]u8 = undefined,
    record_header_used: usize = 0,
    record: ?[]u8 = null,
    record_used: usize = 0,
    write_mutex: std.Io.Mutex = .init,
    failed: std.atomic.Value(bool) = .init(false),
    sent_close_notify: bool = false,
    received_close_notify: bool = false,

    pub fn deinit(self: *Channel) void {
        if (self.pending_plaintext) |pending| self.allocator.free(pending);
        if (self.record) |record| self.allocator.free(record);
        self.pending_plaintext = null;
        self.pending_offset = 0;
        self.record = null;
        self.record_header_used = 0;
        self.record_used = 0;
        std.crypto.secureZero(u8, std.mem.asBytes(&self.client_application_keys));
        std.crypto.secureZero(u8, std.mem.asBytes(&self.server_application_keys));
    }

    fn readRecord(self: *Channel) ![]u8 {
        // Keep partial ciphertext across a stream deadline. Restarting at a new
        // record header would desynchronize TLS on the surviving HTTP/2 streams.
        while (self.record_header_used < self.record_header.len) {
            const n = try self.raw_read(self.stream, self.record_header[self.record_header_used..]);
            if (n == 0) return error.ConnectionClosed;
            self.record_header_used += n;
        }
        if (self.record == null) {
            const len = std.mem.readInt(u16, self.record_header[3..5], .big);
            if (len > MAX_RECORD_BYTES - 5) return error.RequestTooLarge;
            const record = try self.allocator.alloc(u8, 5 + @as(usize, len));
            @memcpy(record[0..5], &self.record_header);
            self.record = record;
            self.record_used = 5;
        }
        const record = self.record.?;
        while (self.record_used < record.len) {
            const n = try self.raw_read(self.stream, record[self.record_used..]);
            if (n == 0) return error.ConnectionClosed;
            self.record_used += n;
        }
        self.record = null;
        self.record_header_used = 0;
        self.record_used = 0;
        return record;
    }
};

pub const Result = struct {
    channel: Channel,
    alpn: ?[]const u8,
};

const SigningKeyKind = enum {
    configured_ecdsa,
    configured_rsa,
    generated_ecdsa,
    generated_ed25519,
};

pub fn isHttp3OverTcpProbe(bytes: []const u8) bool {
    if (bytes.len == 0) return false;
    return bytes[0] == 0x00;
}

pub fn readClientHelloRecord(stream: std.Io.net.Stream, allocator: std.mem.Allocator, prefill: []const u8, raw_read: RawReadFn) ![]u8 {
    var header: [5]u8 = undefined;
    const copied_header: usize = @min(prefill.len, header.len);
    if (copied_header > 0) @memcpy(header[0..copied_header], prefill[0..copied_header]);
    var header_used: usize = copied_header;
    while (header_used < header.len) {
        const n = try raw_read(stream, header[header_used..]);
        if (n == 0) return error.ConnectionClosed;
        header_used += n;
    }

    const record_len = try tls_client_hello.recordLength(&header);
    if (record_len > 5 + 16 * 1024) return error.RequestTooLarge;
    const record = try allocator.alloc(u8, record_len);
    errdefer allocator.free(record);
    @memcpy(record[0..header.len], &header);
    const copied_body: usize = if (prefill.len > header.len) @min(prefill.len - header.len, record_len - header.len) else 0;
    if (copied_body > 0) {
        @memcpy(record[header.len .. header.len + copied_body], prefill[header.len .. header.len + copied_body]);
    }

    var used = header.len + copied_body;
    while (used < record.len) {
        const n = try raw_read(stream, record[used..]);
        if (n == 0) return error.ConnectionClosed;
        used += n;
    }
    return record;
}

pub fn sendFatalAlert(stream: std.Io.net.Stream, description: u8, raw_write_all: RawWriteAllFn) !void {
    const alert = [_]u8{
        0x15,
        0x03,
        0x03,
        0x00,
        0x02,
        0x02,
        description,
    };
    try raw_write_all(stream, &alert);
}

fn selectedAlpn(info: tls_client_hello.ClientHelloInfo) ?[]const u8 {
    if (info.offers_h2) return "h2";
    if (info.offers_http11) return "http/1.1";
    return null;
}

fn selectedMaterialForClientHello(cfg: *const ServerConfig, info: tls_client_hello.ClientHelloInfo) ?tls_pem.ConfiguredTlsMaterial {
    if (info.sni) |server_name| {
        if (routing.findDomainForHost(cfg, server_name)) |domain| {
            if (domain.tls_material) |material| return material;
        }
    }
    return cfg.tls_material;
}

fn clientHelloHandshakeMessage(record: []const u8) ![]const u8 {
    if (record.len < 5) return error.Truncated;
    const record_len = (@as(usize, record[3]) << 8) | record[4];
    if (record.len < 5 + record_len) return error.Truncated;
    return record[5 .. 5 + record_len];
}

fn readRecordRaw(stream: std.Io.net.Stream, allocator: std.mem.Allocator, raw_read: RawReadFn) ![]u8 {
    var header: [5]u8 = undefined;
    var used: usize = 0;
    while (used < header.len) {
        const n = try raw_read(stream, header[used..]);
        if (n == 0) return error.ConnectionClosed;
        used += n;
    }

    const payload_len = (@as(usize, header[3]) << 8) | header[4];
    if (payload_len > MAX_RECORD_BYTES - 5) return error.RequestTooLarge;
    const record = try allocator.alloc(u8, 5 + payload_len);
    errdefer allocator.free(record);
    @memcpy(record[0..5], &header);
    used = 5;
    while (used < record.len) {
        const n = try raw_read(stream, record[used..]);
        if (n == 0) return error.ConnectionClosed;
        used += n;
    }
    return record;
}

fn sendPlainRecord(stream: std.Io.net.Stream, content_type: u8, payload: []const u8, raw_write_all: RawWriteAllFn) !void {
    if (payload.len > MAX_INNER_PLAINTEXT_BYTES) return error.TlsPlaintextTooLarge;
    var header: [5]u8 = .{ content_type, 0x03, 0x03, 0, 0 };
    std.mem.writeInt(u16, header[3..5], @intCast(payload.len), .big);
    try raw_write_all(stream, &header);
    if (payload.len > 0) try raw_write_all(stream, payload);
}

fn sendEncryptedRecord(
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    keys: tls13_native.TlsRecordKeys,
    sequence: *u64,
    inner_content_type: u8,
    payload: []const u8,
    raw_write_all: RawWriteAllFn,
) !void {
    const output_allocator = if (resource_budget.emergency_write) resource_budget.control.allocator() else allocator;
    var offset: usize = 0;
    while (true) {
        if (sequence.* == std.math.maxInt(u64)) return error.TlsSequenceOverflow;
        if (sequence.* >= @import("upstream_tls_client.zig").max_key_records) return error.TlsKeyLimit;
        const part = payload[offset..][0..@min(payload.len - offset, MAX_INNER_PLAINTEXT_BYTES - 1)];
        const record = try tls13_native.encryptTlsRecord(output_allocator, keys, sequence.*, inner_content_type, part);
        defer output_allocator.free(record);
        // A failed write may already have exposed ciphertext. Reserve the nonce
        // before I/O so no later alert or retry can encrypt with it again.
        sequence.* += 1;
        try raw_write_all(stream, record);
        offset += part.len;
        if (offset == payload.len) break;
    }
}

pub fn readApplicationData(channel: *Channel, out: []u8) anyerror!usize {
    if (out.len == 0) return 0;
    if (channel.failed.load(.acquire)) return error.TlsSessionFailed;
    return readApplicationRecord(channel, out) catch |err| {
        // H2 wakes a partially read connection when a backend job completes.
        // Like a stream timeout, this is scheduling, not invalid TLS input.
        if (err != error.RequestTimeout and err != error.DispatchReady) channel.failed.store(true, .release);
        return err;
    };
}

fn readApplicationRecord(channel: *Channel, out: []u8) anyerror!usize {
    while (true) {
        if (channel.pending_plaintext) |pending| {
            const available = pending[channel.pending_offset..];
            const copied = @min(out.len, available.len);
            if (copied > 0) {
                @memcpy(out[0..copied], available[0..copied]);
                channel.pending_offset += copied;
                if (channel.pending_offset >= pending.len) {
                    channel.allocator.free(pending);
                    channel.pending_plaintext = null;
                    channel.pending_offset = 0;
                }
                return copied;
            }

            channel.allocator.free(pending);
            channel.pending_plaintext = null;
            channel.pending_offset = 0;
        }

        if (channel.received_close_notify) return 0;
        const record = channel.readRecord() catch |err| switch (err) {
            error.ConnectionClosed => return error.TlsConnectionTruncated,
            else => return err,
        };
        defer channel.allocator.free(record);

        switch (record[0]) {
            CONTENT_TYPE_APPLICATION_DATA => {},
            else => return error.UnexpectedTlsRecordType,
        }

        if (channel.client_sequence == std.math.maxInt(u64)) return error.TlsSequenceOverflow;
        if (channel.client_sequence >= @import("upstream_tls_client.zig").max_key_records) return error.TlsKeyLimit;
        var decrypted = try tls13_native.decryptTlsRecord(
            channel.allocator,
            channel.client_application_keys,
            channel.client_sequence,
            record,
        );
        channel.client_sequence += 1;

        switch (decrypted.content_type) {
            CONTENT_TYPE_APPLICATION_DATA => {
                if (decrypted.payload.len == 0) {
                    decrypted.deinit(channel.allocator);
                    continue;
                }
                channel.pending_plaintext = decrypted.payload;
                channel.pending_offset = 0;
            },
            CONTENT_TYPE_ALERT => {
                defer decrypted.deinit(channel.allocator);
                if (decrypted.payload.len != 2 or decrypted.payload[1] != 0) return error.TlsAlert;
                channel.received_close_notify = true;
                return 0;
            },
            CONTENT_TYPE_HANDSHAKE => {
                decrypted.deinit(channel.allocator);
                return error.UnexpectedTlsHandshake;
            },
            else => {
                decrypted.deinit(channel.allocator);
                return error.UnexpectedTlsInnerContentType;
            },
        }
    }
}

pub fn writeApplicationData(channel: *Channel, bytes: []const u8) !void {
    var accepted: usize = 0;
    try writeApplicationDataCounted(channel, bytes, &accepted);
}

pub fn writeApplicationDataCounted(channel: *Channel, bytes: []const u8, accepted: *usize) !void {
    channel.write_mutex.lockUncancelable(channel.io);
    defer channel.write_mutex.unlock(channel.io);
    if (channel.failed.load(.acquire) or channel.sent_close_notify) return error.TlsSessionFailed;
    errdefer channel.failed.store(true, .release);
    var offset: usize = 0;
    while (offset < bytes.len) {
        const chunk_len = @min(bytes.len - offset, MAX_INNER_PLAINTEXT_BYTES - 1);
        try sendEncryptedRecord(
            channel.stream,
            channel.allocator,
            channel.server_application_keys,
            &channel.server_sequence,
            CONTENT_TYPE_APPLICATION_DATA,
            bytes[offset .. offset + chunk_len],
            channel.raw_write_all,
        );
        offset += chunk_len;
        // Incomplete ciphertext is not a body byte the peer can decrypt.
        accepted.* +|= chunk_len;
    }
}

pub fn end(channel: *Channel) !void {
    channel.write_mutex.lockUncancelable(channel.io);
    defer channel.write_mutex.unlock(channel.io);
    if (channel.failed.load(.acquire)) return error.TlsSessionFailed;
    if (channel.sent_close_notify) return;
    errdefer channel.failed.store(true, .release);
    try sendEncryptedRecord(channel.stream, channel.allocator, channel.server_application_keys, &channel.server_sequence, CONTENT_TYPE_ALERT, &.{ 1, 0 }, channel.raw_write_all);
    channel.sent_close_notify = true;
}

test "counted TLS writes include only complete application records" {
    const Fake = struct {
        var calls: usize = 0;
        var limit: usize = 0;
        fn write(_: std.Io.net.Stream, _: []const u8) !void {
            calls += 1;
            if (calls > limit) return error.ConnectionResetByPeer;
        }
    };
    const keys = tls13_native.deriveTlsRecordKeys([_]u8{0x66} ** 32);
    const payload = [_]u8{'x'} ** 20000;
    for (0..3) |limit| {
        Fake.calls = 0;
        Fake.limit = limit;
        var channel: Channel = .{ .io = std.testing.io, .stream = undefined, .allocator = std.testing.allocator, .client_application_keys = keys, .server_application_keys = keys, .raw_read = partialRecordRead, .raw_write_all = Fake.write };
        defer channel.deinit();
        var bytes: usize = 7;
        if (limit == 2) {
            try writeApplicationDataCounted(&channel, &payload, &bytes);
            try std.testing.expectEqual(20007, bytes);
        } else {
            try std.testing.expectError(error.ConnectionResetByPeer, writeApplicationDataCounted(&channel, &payload, &bytes));
            try std.testing.expectEqual(7 + limit * (MAX_INNER_PLAINTEXT_BYTES - 1), bytes);
            try std.testing.expectEqual(limit + 1, channel.server_sequence);
            try std.testing.expectError(error.TlsSessionFailed, end(&channel));
            try std.testing.expectEqual(limit + 1, Fake.calls);
        }
    }
}

test "large native handshake messages split into independently authenticated records" {
    const Fake = struct {
        var bytes: std.ArrayList(u8) = .empty;
        fn write(_: std.Io.net.Stream, part: []const u8) !void {
            try bytes.appendSlice(std.testing.allocator, part);
        }
    };
    Fake.bytes = .empty;
    defer Fake.bytes.deinit(std.testing.allocator);
    const keys = tls13_native.deriveTlsRecordKeys(@splat(0x48));
    const payload = try std.testing.allocator.alloc(u8, 40000);
    defer std.testing.allocator.free(payload);
    @memset(payload, 0x62);
    var sequence: u64 = 0;
    try sendEncryptedRecord(undefined, std.testing.allocator, keys, &sequence, CONTENT_TYPE_HANDSHAKE, payload, Fake.write);
    try std.testing.expectEqual(3, sequence);
    var offset: usize = 0;
    var received: usize = 0;
    var record_number: u64 = 0;
    while (offset < Fake.bytes.items.len) : (record_number += 1) {
        const length = std.mem.readInt(u16, Fake.bytes.items[offset + 3 ..][0..2], .big);
        try std.testing.expect(length + 5 <= MAX_RECORD_BYTES);
        var clear = try tls13_native.decryptTlsRecord(std.testing.allocator, keys, record_number, Fake.bytes.items[offset..][0 .. 5 + length]);
        defer clear.deinit(std.testing.allocator);
        try std.testing.expectEqual(CONTENT_TYPE_HANDSHAKE, clear.content_type);
        try std.testing.expect(std.mem.allEqual(u8, clear.payload, 0x62));
        received += clear.payload.len;
        offset += 5 + length;
    }
    try std.testing.expectEqual(payload.len, received);
}

test "native TLS half-close sends one authenticated alert and disallows later writes" {
    const Fake = struct {
        var bytes: std.ArrayList(u8) = .empty;
        fn write(_: std.Io.net.Stream, part: []const u8) !void {
            try bytes.appendSlice(std.testing.allocator, part);
        }
    };
    Fake.bytes = .empty;
    defer Fake.bytes.deinit(std.testing.allocator);
    const keys = tls13_native.deriveTlsRecordKeys(@splat(0x73));
    var channel: Channel = .{ .io = std.testing.io, .stream = undefined, .allocator = std.testing.allocator, .client_application_keys = keys, .server_application_keys = keys, .raw_read = partialRecordRead, .raw_write_all = Fake.write };
    defer channel.deinit();
    try end(&channel);
    const length = Fake.bytes.items.len;
    try end(&channel);
    try std.testing.expectEqual(length, Fake.bytes.items.len);
    try std.testing.expectEqual(1, channel.server_sequence);
    var alert = try tls13_native.decryptTlsRecord(std.testing.allocator, keys, 0, Fake.bytes.items);
    defer alert.deinit(std.testing.allocator);
    try std.testing.expectEqual(CONTENT_TYPE_ALERT, alert.content_type);
    try std.testing.expectEqualSlices(u8, &.{ 1, 0 }, alert.payload);
    var accepted: usize = 0;
    try std.testing.expectError(error.TlsSessionFailed, writeApplicationDataCounted(&channel, "late", &accepted));
    try std.testing.expectEqual(0, accepted);
    try std.testing.expectEqual(length, Fake.bytes.items.len);
}

test "fatal TLS input poisons output but soft H2 read interruptions preserve partial records" {
    const Fake = struct {
        var input: []const u8 = "";
        var offset: usize = 0;
        var interrupt: ?anyerror = null;
        var writes: usize = 0;
        fn read(_: std.Io.net.Stream, out: []u8) !usize {
            if (interrupt != null and offset > 0) {
                const err = interrupt.?;
                interrupt = null;
                return err;
            }
            const n = @min(2, out.len, input.len - offset);
            @memcpy(out[0..n], input[offset..][0..n]);
            offset += n;
            return n;
        }
        fn write(_: std.Io.net.Stream, _: []const u8) !void {
            writes += 1;
        }
    };
    const allocator = std.testing.allocator;
    const keys = tls13_native.deriveTlsRecordKeys(@splat(0x45));
    const corrupt = try tls13_native.encryptTlsRecord(allocator, keys, 0, CONTENT_TYPE_APPLICATION_DATA, "invalid authentication");
    defer allocator.free(corrupt);
    corrupt[corrupt.len - 1] ^= 1;
    const invalid_alert = try tls13_native.encryptTlsRecord(allocator, keys, 0, CONTENT_TYPE_ALERT, &.{0});
    defer allocator.free(invalid_alert);
    for ([_][]const u8{ "", "\x15\x03\x03\x00\x02\x01\x00", corrupt, invalid_alert }) |bytes| {
        Fake.input = bytes;
        Fake.offset = 0;
        Fake.writes = 0;
        var channel: Channel = .{ .io = std.testing.io, .stream = undefined, .allocator = allocator, .client_application_keys = keys, .server_application_keys = keys, .raw_read = Fake.read, .raw_write_all = Fake.write };
        defer channel.deinit();
        var out: [32]u8 = undefined;
        if (readApplicationData(&channel, &out)) |_| return error.InvalidTlsWasAccepted else |_| {}
        try std.testing.expect(channel.failed.load(.acquire));
        try std.testing.expectError(error.TlsSessionFailed, writeApplicationData(&channel, "late"));
        try std.testing.expectError(error.TlsSessionFailed, end(&channel));
        try std.testing.expectEqual(0, Fake.writes);
    }
    const valid = try tls13_native.encryptTlsRecord(allocator, keys, 0, CONTENT_TYPE_APPLICATION_DATA, "resumed");
    defer allocator.free(valid);
    for ([_]anyerror{ error.RequestTimeout, error.DispatchReady }) |pause| {
        Fake.input = valid;
        Fake.offset = 0;
        Fake.interrupt = pause;
        var channel: Channel = .{ .io = std.testing.io, .stream = undefined, .allocator = allocator, .client_application_keys = keys, .server_application_keys = keys, .raw_read = Fake.read, .raw_write_all = Fake.write };
        defer channel.deinit();
        var out: [32]u8 = undefined;
        try std.testing.expectError(pause, readApplicationData(&channel, &out));
        try std.testing.expectEqual(2, channel.record_header_used);
        try std.testing.expect(!channel.failed.load(.acquire));
        const n = try readApplicationData(&channel, &out);
        try std.testing.expectEqualStrings("resumed", out[0..n]);
    }
}

threadlocal var partial_record_step: usize = 0;

fn partialRecordRead(_: std.Io.net.Stream, out: []u8) !usize {
    const step = partial_record_step;
    partial_record_step += 1;
    const piece: []const u8 = switch (step) {
        0 => "\x17\x03",
        1, 4 => return error.RequestTimeout,
        2 => "\x03\x00\x04",
        3 => "te",
        5 => "st",
        else => return 0,
    };
    @memcpy(out[0..piece.len], piece);
    return piece.len;
}

fn noRecordWrite(_: std.Io.net.Stream, _: []const u8) !void {
    return error.UnexpectedWrite;
}

test "partial TLS records resume after read timeout and clean up on abandonment" {
    for ([_]bool{ false, true }) |abandon| {
        partial_record_step = 0;
        var channel = Channel{ .io = std.testing.io, .stream = undefined, .allocator = std.testing.allocator, .client_application_keys = undefined, .server_application_keys = undefined, .raw_read = partialRecordRead, .raw_write_all = noRecordWrite };
        defer channel.deinit();
        try std.testing.expectError(error.RequestTimeout, channel.readRecord());
        try std.testing.expectEqual(2, channel.record_header_used);
        try std.testing.expectError(error.RequestTimeout, channel.readRecord());
        try std.testing.expectEqual(7, channel.record_used);
        if (!abandon) {
            const record = try channel.readRecord();
            defer std.testing.allocator.free(record);
            try std.testing.expectEqualStrings("\x17\x03\x03\x00\x04test", record);
        }
    }
}

fn verifyClientFinished(plain: tls13_native.DecryptedRecord, expected_verify_data: [32]u8) !void {
    if (plain.content_type != CONTENT_TYPE_HANDSHAKE) return error.BadTlsFinished;
    if (plain.payload.len != 4 + expected_verify_data.len) return error.BadTlsFinished;
    if (plain.payload[0] != 0x14) return error.BadTlsFinished;
    const finished_len = (@as(usize, plain.payload[1]) << 16) |
        (@as(usize, plain.payload[2]) << 8) |
        @as(usize, plain.payload[3]);
    if (finished_len != expected_verify_data.len) return error.BadTlsFinished;
    const client_verify_data: [32]u8 = plain.payload[4..][0..32].*;
    if (!std.crypto.timing_safe.eql([32]u8, expected_verify_data, client_verify_data)) {
        return error.BadTlsFinishedVerifyData;
    }
}

test "native TLS refuses missing secure entropy before emitting any handshake" {
    const Fake = struct {
        fn entropy(_: ?*anyopaque, _: []u8) std.Io.RandomSecureError!void {
            return error.EntropyUnavailable;
        }
        fn read(_: std.Io.net.Stream, _: []u8) !usize {
            return error.UnexpectedRead;
        }
        fn write(_: std.Io.net.Stream, _: []const u8) !void {
            return error.UnexpectedWrite;
        }
    };
    var vtable = std.testing.io.vtable.*;
    vtable.randomSecure = Fake.entropy;
    const io: std.Io = .{ .userdata = std.testing.io.userdata, .vtable = &vtable };
    var cfg = config_mod.defaultServerConfig();
    try std.testing.expectError(error.EntropyUnavailable, establishTls13(undefined, std.testing.allocator, &cfg, "", .{
        .supports_tls13 = true,
        .offers_aes_128_gcm_sha256 = true,
        .offers_ecdsa_secp256r1_sha256 = true,
        .x25519_key_share = @splat(0x13),
    }, io, Fake.read, Fake.write));
}

pub fn establishTls13(
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    cfg: *const ServerConfig,
    client_hello_record: []const u8,
    info: tls_client_hello.ClientHelloInfo,
    io: std.Io,
    raw_read: RawReadFn,
    raw_write_all: RawWriteAllFn,
) !Result {
    if (!info.supports_tls13) return error.UnsupportedTlsVersion;
    if (!info.offers_aes_128_gcm_sha256) return error.UnsupportedTlsCipherSuite;
    if (!info.offers_ecdsa_secp256r1_sha256 and !info.offers_rsa_pss_rsae_sha256 and !info.offers_ed25519) {
        return error.UnsupportedTlsSignatureScheme;
    }
    const client_x25519 = info.x25519_key_share orelse return error.MissingTlsKeyShare;
    const alpn = selectedAlpn(info);
    if (info.alpn != null and alpn == null) return error.NoApplicationProtocol;

    var entropy: [96]u8 = undefined;
    defer std.crypto.secureZero(u8, &entropy);
    try io.randomSecure(&entropy);
    const server_random = entropy[0..32].*;
    var server_key_pair = try tls13_native.X25519.KeyPair.generateDeterministic(entropy[32..64].*);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&server_key_pair));
    var shared_secret = try tls13_native.X25519.scalarmult(server_key_pair.secret_key, client_x25519);
    defer std.crypto.secureZero(u8, &shared_secret);

    const legacy_session_id = info.legacy_session_id orelse "";
    const server_hello = try tls13_native.buildServerHello(allocator, .{
        .legacy_session_id = legacy_session_id,
        .random = server_random,
        .x25519_public_key = server_key_pair.public_key,
    });
    defer allocator.free(server_hello);

    const client_hello = try clientHelloHandshakeMessage(client_hello_record);
    const hello_hash = tls13_native.transcriptHash(&.{ client_hello, server_hello });
    var traffic = tls13_native.deriveTrafficSecrets(shared_secret, hello_hash);
    defer std.crypto.secureZero(u8, std.mem.asBytes(&traffic));
    const client_handshake_keys = tls13_native.deriveTlsRecordKeys(traffic.client_handshake_traffic_secret);
    const server_handshake_keys = tls13_native.deriveTlsRecordKeys(traffic.server_handshake_traffic_secret);

    const encrypted_extensions = try tls13_native.buildTcpEncryptedExtensions(allocator, alpn);
    defer allocator.free(encrypted_extensions);

    const cert_name = info.sni orelse "localhost";
    const selected_material = selectedMaterialForClientHello(cfg, info);
    const signing_key_kind: SigningKeyKind = if (selected_material) |material| switch (material.private_key) {
        .ecdsa_p256 => if (info.offers_ecdsa_secp256r1_sha256) .configured_ecdsa else return error.UnsupportedTlsSignatureScheme,
        .rsa => if (info.offers_rsa_pss_rsae_sha256) .configured_rsa else return error.UnsupportedTlsSignatureScheme,
    } else if (info.offers_ecdsa_secp256r1_sha256)
        .generated_ecdsa
    else if (info.offers_ed25519)
        .generated_ed25519
    else
        return error.UnsupportedTlsSignatureScheme;

    var generated_ecdsa_key_pair = if (signing_key_kind == .generated_ecdsa)
        try tls13_native.EcdsaP256Sha256.KeyPair.generateDeterministic(entropy[64..96].*)
    else
        null;
    defer if (generated_ecdsa_key_pair) |*pair| std.crypto.secureZero(u8, std.mem.asBytes(pair));
    var generated_ed25519_key_pair = if (signing_key_kind == .generated_ed25519)
        try tls13_native.Ed25519.KeyPair.generateDeterministic(entropy[64..96].*)
    else
        null;
    defer if (generated_ed25519_key_pair) |*pair| std.crypto.secureZero(u8, std.mem.asBytes(pair));
    var generated_cert_der: ?[]u8 = null;
    defer if (generated_cert_der) |cert| allocator.free(cert);

    const certificate = switch (signing_key_kind) {
        .configured_ecdsa, .configured_rsa => try tls13_native.buildCertificate(allocator, selected_material.?.certificate_chain),
        .generated_ecdsa => blk: {
            generated_cert_der = try tls13_native.buildSelfSignedEcdsaP256Sha256Certificate(allocator, generated_ecdsa_key_pair.?, cert_name);
            break :blk try tls13_native.buildCertificate(allocator, &.{generated_cert_der.?});
        },
        .generated_ed25519 => blk: {
            generated_cert_der = try tls13_native.buildSelfSignedEd25519Certificate(allocator, generated_ed25519_key_pair.?, cert_name);
            break :blk try tls13_native.buildCertificate(allocator, &.{generated_cert_der.?});
        },
    };
    defer allocator.free(certificate);

    const cert_verify_hash = tls13_native.transcriptHash(&.{ client_hello, server_hello, encrypted_extensions, certificate });
    const cert_signature = switch (signing_key_kind) {
        .configured_ecdsa => blk: {
            const key_pair = selected_material.?.private_key.ecdsa_p256;
            break :blk try tls13_native.signCertificateVerifyEcdsaP256Sha256(allocator, key_pair, cert_verify_hash);
        },
        .configured_rsa => blk: {
            const key = selected_material.?.private_key.rsa;
            break :blk try tls13_native.signCertificateVerifyRsaPssSha256(io, allocator, key, cert_verify_hash);
        },
        .generated_ecdsa => try tls13_native.signCertificateVerifyEcdsaP256Sha256(allocator, generated_ecdsa_key_pair.?, cert_verify_hash),
        .generated_ed25519 => blk: {
            const signature = try tls13_native.signCertificateVerifyEd25519(generated_ed25519_key_pair.?, cert_verify_hash);
            break :blk try allocator.dupe(u8, &signature);
        },
    };
    defer allocator.free(cert_signature);
    const signature_scheme: tls13_native.SignatureScheme = switch (signing_key_kind) {
        .configured_ecdsa, .generated_ecdsa => .ecdsa_secp256r1_sha256,
        .configured_rsa => .rsa_pss_rsae_sha256,
        .generated_ed25519 => .ed25519,
    };
    const certificate_verify = try tls13_native.buildCertificateVerify(allocator, signature_scheme, cert_signature);
    defer allocator.free(certificate_verify);

    const finished_hash = tls13_native.transcriptHash(&.{
        client_hello,
        server_hello,
        encrypted_extensions,
        certificate,
        certificate_verify,
    });
    const server_verify_data = tls13_native.finishedVerifyData(traffic.server_finished_key, finished_hash);
    const server_finished = try tls13_native.buildFinished(allocator, server_verify_data);
    defer allocator.free(server_finished);

    const application_hash = tls13_native.transcriptHash(&.{
        client_hello,
        server_hello,
        encrypted_extensions,
        certificate,
        certificate_verify,
        server_finished,
    });

    try sendPlainRecord(stream, CONTENT_TYPE_HANDSHAKE, server_hello, raw_write_all);
    var server_handshake_sequence: u64 = 0;
    try sendEncryptedRecord(stream, allocator, server_handshake_keys, &server_handshake_sequence, CONTENT_TYPE_HANDSHAKE, encrypted_extensions, raw_write_all);
    try sendEncryptedRecord(stream, allocator, server_handshake_keys, &server_handshake_sequence, CONTENT_TYPE_HANDSHAKE, certificate, raw_write_all);
    try sendEncryptedRecord(stream, allocator, server_handshake_keys, &server_handshake_sequence, CONTENT_TYPE_HANDSHAKE, certificate_verify, raw_write_all);
    try sendEncryptedRecord(stream, allocator, server_handshake_keys, &server_handshake_sequence, CONTENT_TYPE_HANDSHAKE, server_finished, raw_write_all);

    var client_handshake_sequence: u64 = 0;
    while (true) {
        const client_record = try readRecordRaw(stream, allocator, raw_read);
        defer allocator.free(client_record);
        if (client_record[0] == CONTENT_TYPE_CHANGE_CIPHER_SPEC) continue;
        if (client_record[0] != CONTENT_TYPE_APPLICATION_DATA) return error.UnexpectedTlsRecordType;

        var client_finished = try tls13_native.decryptTlsRecord(allocator, client_handshake_keys, client_handshake_sequence, client_record);
        defer client_finished.deinit(allocator);
        client_handshake_sequence += 1;
        const expected_client_verify_data = tls13_native.finishedVerifyData(traffic.client_finished_key, application_hash);
        try verifyClientFinished(client_finished, expected_client_verify_data);
        break;
    }

    const app_secrets = tls13_native.deriveApplicationTrafficSecrets(traffic.master_secret, application_hash);
    return .{
        .channel = .{
            .io = io,
            .stream = stream,
            .allocator = allocator,
            .client_application_keys = tls13_native.deriveTlsRecordKeys(app_secrets.client_application_traffic_secret),
            .server_application_keys = tls13_native.deriveTlsRecordKeys(app_secrets.server_application_traffic_secret),
            .raw_read = raw_read,
            .raw_write_all = raw_write_all,
        },
        .alpn = alpn,
    };
}
