const std = @import("std");

const config_mod = @import("config.zig");
const h2_native = @import("h2_native.zig");
const h2_support = @import("http2_support.zig");
const flow_mod = @import("http2_flow.zig");
const request_mod = @import("request.zig");

const ServerConfig = config_mod.ServerConfig;

pub const MAX_PENDING_BODY_STREAMS = 128;
pub const ERROR_NO_ERROR: u32 = 0x0;
pub const ERROR_PROTOCOL: u32 = 0x1;
pub const ERROR_STREAM_CLOSED: u32 = 0x5;
pub const ERROR_FRAME_SIZE: u32 = 0x6;
pub const ERROR_REFUSED_STREAM: u32 = 0x7;

pub const SendResponseFn = *const fn (std.Io.net.Stream, std.mem.Allocator, u32, h2_support.BufferedResponse, bool) anyerror!void;
pub const ErrorResponseFn = *const fn (std.mem.Allocator, u16, []const u8, []const u8) anyerror!h2_support.BufferedResponse;
pub const CompleteRequestFn = *const fn (std.Io, std.Io.net.Stream, std.mem.Allocator, *ServerConfig, *const std.process.Environ.Map, u32, request_mod.HttpRequest) anyerror!void;
pub const WriteAllFn = *const fn (std.Io.net.Stream, []const u8) anyerror!void;

pub const Callbacks = struct {
    send_response: SendResponseFn,
    error_response: ErrorResponseFn,
    complete_request: CompleteRequestFn,
    write_all: WriteAllFn,
    shutdown_requested: *std.atomic.Value(bool),
};

fn headerFragment(frame: h2_support.Frame) ![]u8 {
    var offset: usize = 0;
    var padding: usize = 0;
    if (frame.header.flags & h2_native.FLAG_PADDED != 0) {
        if (frame.payload.len == 0) return error.FrameSize;
        padding = frame.payload[0];
        offset = 1;
    }
    if (frame.header.flags & h2_native.FLAG_PRIORITY != 0) {
        if (frame.payload.len < offset + 5) return error.FrameSize;
        offset += 5;
    }
    if (frame.payload.len < offset + padding) return error.BadRequest;
    return frame.payload[offset .. frame.payload.len - padding];
}

fn handleHeadersFrame(
    io: std.Io,
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    state_allocator: std.mem.Allocator,
    decoded: *const h2_native.DecodedHeaders,
    cfg: *ServerConfig,
    process_env: *const std.process.Environ.Map,
    states: *std.ArrayList(h2_support.RequestState),
    frame: h2_support.Frame,
    callbacks: Callbacks,
) !void {
    const req = h2_support.parseRequest(allocator, decoded) catch {
        const response = try callbacks.error_response(allocator, 400, "Bad Request", "Missing required HTTP/2 pseudo-headers.");
        try callbacks.send_response(stream, allocator, frame.header.stream_id, response, false);
        return;
    };

    const expected_content_length = h2_support.parseRequestContentLength(req.headers) catch {
        const response = try callbacks.error_response(allocator, 400, "Bad Request", "Invalid HTTP/2 Content-Length header.");
        try callbacks.send_response(stream, allocator, frame.header.stream_id, response, false);
        return;
    };

    if ((frame.header.flags & h2_native.FLAG_END_STREAM) != 0) {
        if (expected_content_length) |content_length| {
            if (content_length != 0) {
                const response = try callbacks.error_response(allocator, 400, "Bad Request", "HTTP/2 Content-Length did not match the received request body.");
                try callbacks.send_response(stream, allocator, frame.header.stream_id, response, false);
                return;
            }
        }
        try callbacks.complete_request(io, stream, allocator, cfg, process_env, frame.header.stream_id, req);
        return;
    }

    if (expected_content_length) |content_length| {
        if (content_length > cfg.max_body_bytes) {
            const response = try callbacks.error_response(allocator, 413, "Payload Too Large", "Request body exceeds configured limit.");
            try callbacks.send_response(stream, allocator, frame.header.stream_id, response, false);
            return;
        }
    }
    if (states.items.len >= MAX_PENDING_BODY_STREAMS) {
        try h2_support.sendRst(stream, frame.header.stream_id, ERROR_REFUSED_STREAM, callbacks.write_all);
        return;
    }

    var pending = h2_support.RequestState{
        .stream_id = frame.header.stream_id,
        .req = try h2_support.cloneRequest(state_allocator, req),
        .expected_content_length = expected_content_length,
    };
    errdefer pending.deinit(state_allocator);
    try states.append(state_allocator, pending);
}

fn completeBody(
    io: std.Io,
    stream: std.Io.net.Stream,
    scratch_allocator: std.mem.Allocator,
    state_allocator: std.mem.Allocator,
    cfg: *ServerConfig,
    process_env: *const std.process.Environ.Map,
    states: *std.ArrayList(h2_support.RequestState),
    state_index: usize,
    callbacks: Callbacks,
) !void {
    const state = &states.items[state_index];
    defer h2_support.removeRequestState(states, state_allocator, state_index);
    if (state.expected_content_length) |length| {
        if (state.body.items.len != length) {
            const response = try callbacks.error_response(scratch_allocator, 400, "Bad Request", "HTTP/2 Content-Length did not match the received request body.");
            try callbacks.send_response(stream, scratch_allocator, state.stream_id, response, false);
            return;
        }
    }
    state.req.body = state.body.items;
    try callbacks.complete_request(io, stream, scratch_allocator, cfg, process_env, state.stream_id, state.req);
}

fn handleDataFrame(
    io: std.Io,
    stream: std.Io.net.Stream,
    scratch_allocator: std.mem.Allocator,
    state_allocator: std.mem.Allocator,
    cfg: *ServerConfig,
    process_env: *const std.process.Environ.Map,
    states: *std.ArrayList(h2_support.RequestState),
    frame: h2_support.Frame,
    flow: *flow_mod.State,
    callbacks: Callbacks,
) !void {
    if (frame.header.stream_id == 0) return error.BadRequest;

    var offset: usize = 0;
    var pad_len: usize = 0;
    if ((frame.header.flags & h2_native.FLAG_PADDED) != 0) {
        if (frame.payload.len == 0) return error.BadRequest;
        pad_len = frame.payload[0];
        offset = 1;
    }
    if (frame.payload.len < offset + pad_len) return error.BadRequest;
    const data = frame.payload[offset .. frame.payload.len - pad_len];

    // Discarded DATA still consumes connection credit. Restore it even when the
    // stream was reset or the request is rejected below.
    try h2_support.sendWindowUpdate(stream, 0, frame.payload.len, callbacks.write_all);
    const state_index = h2_support.findRequestState(states, frame.header.stream_id) orelse {
        try h2_support.sendRst(stream, frame.header.stream_id, ERROR_STREAM_CLOSED, callbacks.write_all);
        flow.cancel(frame.header.stream_id);
        return;
    };
    const state = &states.items[state_index];

    var pending_bytes: usize = 0;
    for (states.items) |pending| pending_bytes += pending.body.items.len;
    if (data.len > cfg.max_body_bytes or state.body.items.len > cfg.max_body_bytes - data.len or
        data.len > flow_mod.State.max_queued_bytes -| pending_bytes)
    {
        h2_support.removeRequestState(states, state_allocator, state_index);
        const response = try callbacks.error_response(scratch_allocator, 413, "Payload Too Large", "Request body exceeds configured limit.");
        try callbacks.send_response(stream, scratch_allocator, frame.header.stream_id, response, false);
        return;
    }
    if (state.expected_content_length) |content_length| {
        if (state.body.items.len + data.len > content_length) {
            h2_support.removeRequestState(states, state_allocator, state_index);
            const response = try callbacks.error_response(scratch_allocator, 400, "Bad Request", "HTTP/2 Content-Length did not match the received request body.");
            try callbacks.send_response(stream, scratch_allocator, frame.header.stream_id, response, false);
            return;
        }
    }

    if (data.len > 0) try state.body.appendSlice(state_allocator, data);
    try h2_support.sendWindowUpdate(stream, frame.header.stream_id, frame.payload.len, callbacks.write_all);

    if ((frame.header.flags & h2_native.FLAG_END_STREAM) == 0) return;
    try completeBody(io, stream, scratch_allocator, state_allocator, cfg, process_env, states, state_index, callbacks);
}

pub fn runFrameLoop(
    io: std.Io,
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    cfg: *ServerConfig,
    reader: *h2_support.PendingReader,
    process_env: *const std.process.Environ.Map,
    callbacks: Callbacks,
    flow: *flow_mod.State,
    initial_stream_id: u32,
) !void {
    runFrames(io, stream, allocator, cfg, reader, process_env, callbacks, flow, initial_stream_id) catch |err| {
        const code: u32 = switch (err) {
            error.FlowControl => 3,
            error.FrameSize => ERROR_FRAME_SIZE,
            error.ExcessiveLoad => 0xb,
            error.Compression => 9,
            error.OutOfMemory => 2,
            else => 1,
        };
        h2_support.sendGoaway(stream, flow.last_stream_id, code, callbacks.write_all) catch {};
        return err;
    };
}

fn runFrames(
    io: std.Io,
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    cfg: *ServerConfig,
    reader: *h2_support.PendingReader,
    process_env: *const std.process.Environ.Map,
    callbacks: Callbacks,
    flow: *flow_mod.State,
    initial_stream_id: u32,
) !void {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    var hpack_decoder = h2_native.HpackDecoder.init(allocator);
    defer hpack_decoder.deinit();
    var body_states = std.ArrayList(h2_support.RequestState).empty;
    defer {
        for (body_states.items) |*state| state.deinit(allocator);
        body_states.deinit(allocator);
    }
    var requests_seen: usize = 0;
    var last_stream_id: u32 = initial_stream_id;
    var first_frame = true;
    var continuation_id: u32 = 0;
    var continuation_flags: u8 = 0;
    var continuation = std.ArrayList(u8).empty;
    defer continuation.deinit(allocator);

    while (true) {
        if (callbacks.shutdown_requested.load(.acquire)) {
            try h2_support.sendGoaway(stream, last_stream_id, ERROR_NO_ERROR, callbacks.write_all);
            return;
        }

        _ = arena.reset(.retain_capacity);
        const req_alloc = arena.allocator();
        var frame = h2_support.readFrame(reader, req_alloc, 16384) catch |err| switch (err) {
            error.ConnectionClosed => return,
            error.RequestTimeout => return,
            else => return err,
        };

        if (first_frame) {
            first_frame = false;
            if (frame.header.frame_type != h2_native.FRAME_SETTINGS or frame.header.flags & h2_native.FLAG_ACK != 0) return error.BadRequest;
        }
        if (continuation_id != 0) {
            if (frame.header.frame_type != 0x9 or frame.header.stream_id != continuation_id) return error.BadRequest;
            if (frame.payload.len > cfg.max_request_bytes - continuation.items.len) return error.BadRequest;
            try continuation.appendSlice(allocator, frame.payload);
            if (frame.header.flags & h2_native.FLAG_END_HEADERS == 0) continue;
            frame.header = .{ .length = continuation.items.len, .frame_type = h2_native.FRAME_HEADERS, .flags = continuation_flags | h2_native.FLAG_END_HEADERS, .stream_id = continuation_id };
            frame.payload = continuation.items;
            continuation_id = 0;
        } else if (frame.header.frame_type == 0x9) return error.BadRequest;

        switch (frame.header.frame_type) {
            h2_native.FRAME_SETTINGS => {
                if (frame.header.stream_id != 0) return error.BadRequest;
                if (frame.payload.len % 6 != 0 or (frame.header.flags & h2_native.FLAG_ACK != 0 and frame.payload.len != 0)) return error.FrameSize;
                if ((frame.header.flags & h2_native.FLAG_ACK) == 0) {
                    try flow.settings(frame.payload);
                    try h2_support.sendFrame(stream, h2_native.FRAME_SETTINGS, h2_native.FLAG_ACK, 0, "", callbacks.write_all);
                }
            },
            h2_native.FRAME_PING => {
                if (frame.header.stream_id != 0) return error.BadRequest;
                if (frame.payload.len != 8) return error.FrameSize;
                if (frame.payload.len == 8 and (frame.header.flags & h2_native.FLAG_ACK) == 0) {
                    try h2_support.sendFrame(stream, h2_native.FRAME_PING, h2_native.FLAG_ACK, 0, frame.payload, callbacks.write_all);
                }
            },
            h2_native.FRAME_HEADERS => headers: {
                if (frame.header.stream_id == 0 or frame.header.stream_id % 2 == 0) return error.BadRequest;
                const fragment = try headerFragment(frame);
                if (frame.header.flags & h2_native.FLAG_END_HEADERS == 0) {
                    continuation.clearRetainingCapacity();
                    if (fragment.len > cfg.max_request_bytes) return error.BadRequest;
                    try continuation.appendSlice(allocator, fragment);
                    continuation_id = frame.header.stream_id;
                    continuation_flags = frame.header.flags & h2_native.FLAG_END_STREAM;
                    continue;
                }
                if (fragment.len > cfg.max_request_bytes) return error.BadRequest;
                frame.payload = fragment;
                // Even refused and closed streams can update HPACK state. Always
                // decode the field block, never its padding or priority prefix.
                var decoded = hpack_decoder.decodeHeaderBlock(req_alloc, fragment) catch |err| switch (err) {
                    error.OutOfMemory => return err,
                    error.HeaderListTooLarge => return error.ExcessiveLoad,
                    else => return error.Compression,
                };
                defer decoded.deinit(req_alloc);

                if (h2_support.findRequestState(&body_states, frame.header.stream_id)) |i| {
                    const valid = frame.header.flags & h2_native.FLAG_END_STREAM != 0 and
                        h2_support.headerListFits(decoded.headers.items, cfg.max_request_bytes);
                    const fields_valid = if (h2_support.validateTrailerFields(decoded.headers.items)) |_| true else |_| false;
                    if (!valid or !fields_valid) {
                        try h2_support.sendRst(stream, frame.header.stream_id, ERROR_PROTOCOL, callbacks.write_all);
                        flow.cancel(frame.header.stream_id);
                        h2_support.removeRequestState(&body_states, allocator, i);
                    } else {
                        // Optional trailer metadata is validated and discarded,
                        // never merged into routing/authentication headers.
                        try completeBody(io, stream, req_alloc, allocator, cfg, process_env, &body_states, i, callbacks);
                    }
                    break :headers;
                }
                if (frame.header.stream_id <= last_stream_id) {
                    try h2_support.sendRst(stream, frame.header.stream_id, ERROR_STREAM_CLOSED, callbacks.write_all);
                    flow.cancel(frame.header.stream_id);
                    break :headers;
                }
                last_stream_id = frame.header.stream_id;
                if (cfg.max_requests_per_connection > 0 and requests_seen >= cfg.max_requests_per_connection) {
                    try h2_support.sendRst(stream, frame.header.stream_id, ERROR_REFUSED_STREAM, callbacks.write_all);
                    break :headers;
                }
                flow.open(frame.header.stream_id) catch |err| {
                    if (err != error.StreamLimit) return err;
                    try h2_support.sendRst(stream, frame.header.stream_id, ERROR_REFUSED_STREAM, callbacks.write_all);
                    break :headers;
                };
                requests_seen += 1;
                if (!h2_support.headerListFits(decoded.headers.items, cfg.max_request_bytes)) {
                    const response = try callbacks.error_response(req_alloc, 431, "Request Header Fields Too Large", "Decoded HTTP/2 headers exceed the configured limit.");
                    try callbacks.send_response(stream, req_alloc, frame.header.stream_id, response, false);
                } else {
                    try handleHeadersFrame(io, stream, req_alloc, allocator, &decoded, cfg, process_env, &body_states, frame, callbacks);
                }
            },
            h2_native.FRAME_DATA => {
                if (frame.header.stream_id == 0 or frame.header.stream_id % 2 == 0 or frame.header.stream_id > last_stream_id) return error.BadRequest;
                try handleDataFrame(io, stream, req_alloc, allocator, cfg, process_env, &body_states, frame, flow, callbacks);
            },
            h2_native.FRAME_GOAWAY => {
                if (frame.header.stream_id != 0) return error.BadRequest;
                if (frame.payload.len < 8) return error.FrameSize;
                return;
            },
            h2_native.FRAME_WINDOW_UPDATE => {
                if (frame.payload.len != 4) return error.FrameSize;
                if (frame.header.stream_id > last_stream_id) return error.BadRequest;
                const increment = std.mem.readInt(u32, frame.payload[0..4], .big) & 0x7fffffff;
                flow.update(frame.header.stream_id, increment) catch |err| {
                    if (frame.header.stream_id == 0) return err;
                    try h2_support.sendRst(stream, frame.header.stream_id, if (err == error.FlowControl) 3 else 1, callbacks.write_all);
                    flow.cancel(frame.header.stream_id);
                    if (h2_support.findRequestState(&body_states, frame.header.stream_id)) |i| h2_support.removeRequestState(&body_states, allocator, i);
                };
            },
            h2_native.FRAME_RST_STREAM => {
                if (frame.payload.len != 4) return error.FrameSize;
                if (frame.header.stream_id == 0 or frame.header.stream_id > last_stream_id) return error.BadRequest;
                flow.cancel(frame.header.stream_id);
                if (h2_support.findRequestState(&body_states, frame.header.stream_id)) |i| h2_support.removeRequestState(&body_states, allocator, i);
            },
            0x2 => {
                if (frame.header.stream_id == 0) return error.BadRequest;
                if (frame.payload.len != 5) {
                    try h2_support.sendRst(stream, frame.header.stream_id, ERROR_FRAME_SIZE, callbacks.write_all);
                    flow.cancel(frame.header.stream_id);
                    if (h2_support.findRequestState(&body_states, frame.header.stream_id)) |i| h2_support.removeRequestState(&body_states, allocator, i);
                }
            },
            0x5 => return error.BadRequest,
            else => {},
        }
        try flow.flush(stream, callbacks.write_all);

        if (cfg.max_requests_per_connection > 0 and requests_seen >= cfg.max_requests_per_connection and body_states.items.len == 0 and flow.streams.items.len == 0) {
            try h2_support.sendGoaway(stream, last_stream_id, ERROR_NO_ERROR, callbacks.write_all);
            return;
        }
    }
}
