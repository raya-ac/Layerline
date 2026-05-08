const std = @import("std");

const config_mod = @import("config.zig");
const h2_native = @import("h2_native.zig");
const h2_support = @import("http2_support.zig");
const request_mod = @import("request.zig");

const ServerConfig = config_mod.ServerConfig;

pub const MAX_PENDING_BODY_STREAMS = 128;
pub const ERROR_NO_ERROR: u32 = 0x0;
pub const ERROR_PROTOCOL: u32 = 0x1;
pub const ERROR_STREAM_CLOSED: u32 = 0x5;
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

fn handleHeadersFrame(
    io: std.Io,
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    state_allocator: std.mem.Allocator,
    hpack_decoder: *h2_native.HpackDecoder,
    cfg: *ServerConfig,
    process_env: *const std.process.Environ.Map,
    states: *std.ArrayList(h2_support.RequestState),
    frame: h2_support.Frame,
    callbacks: Callbacks,
) !void {
    if (frame.header.stream_id == 0 or (frame.header.flags & h2_native.FLAG_END_HEADERS) == 0) {
        if (frame.header.stream_id != 0) try h2_support.sendRst(stream, frame.header.stream_id, ERROR_PROTOCOL, callbacks.write_all);
        return;
    }
    if (h2_support.findRequestState(states, frame.header.stream_id) != null) {
        try h2_support.sendRst(stream, frame.header.stream_id, ERROR_PROTOCOL, callbacks.write_all);
        return;
    }

    var offset: usize = 0;
    var pad_len: usize = 0;
    if ((frame.header.flags & h2_native.FLAG_PADDED) != 0) {
        if (offset >= frame.payload.len) return error.BadRequest;
        pad_len = frame.payload[offset];
        offset += 1;
    }
    if ((frame.header.flags & h2_native.FLAG_PRIORITY) != 0) {
        if (frame.payload.len < offset + 5) return error.BadRequest;
        offset += 5;
    }
    if (frame.payload.len < offset + pad_len) return error.BadRequest;
    const header_block = frame.payload[offset .. frame.payload.len - pad_len];

    var decoded = hpack_decoder.decodeHeaderBlock(allocator, header_block) catch {
        const response = try callbacks.error_response(allocator, 400, "Bad Request", "Invalid HTTP/2 header block.");
        try callbacks.send_response(stream, allocator, frame.header.stream_id, response, false);
        return;
    };
    defer decoded.deinit(allocator);

    const req = h2_support.parseRequest(allocator, &decoded) catch {
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

fn handleDataFrame(
    io: std.Io,
    stream: std.Io.net.Stream,
    scratch_allocator: std.mem.Allocator,
    state_allocator: std.mem.Allocator,
    cfg: *ServerConfig,
    process_env: *const std.process.Environ.Map,
    states: *std.ArrayList(h2_support.RequestState),
    frame: h2_support.Frame,
    callbacks: Callbacks,
) !void {
    if (frame.header.stream_id == 0) return error.BadRequest;

    const state_index = h2_support.findRequestState(states, frame.header.stream_id) orelse {
        try h2_support.sendRst(stream, frame.header.stream_id, ERROR_STREAM_CLOSED, callbacks.write_all);
        return;
    };
    const state = &states.items[state_index];

    var offset: usize = 0;
    var pad_len: usize = 0;
    if ((frame.header.flags & h2_native.FLAG_PADDED) != 0) {
        if (frame.payload.len == 0) return error.BadRequest;
        pad_len = frame.payload[0];
        offset = 1;
    }
    if (frame.payload.len < offset + pad_len) return error.BadRequest;
    const data = frame.payload[offset .. frame.payload.len - pad_len];

    if (data.len > cfg.max_body_bytes or state.body.items.len > cfg.max_body_bytes - data.len) {
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
    try h2_support.sendWindowUpdate(stream, 0, frame.payload.len, callbacks.write_all);
    try h2_support.sendWindowUpdate(stream, frame.header.stream_id, frame.payload.len, callbacks.write_all);

    if ((frame.header.flags & h2_native.FLAG_END_STREAM) == 0) return;
    if (state.expected_content_length) |content_length| {
        if (state.body.items.len != content_length) {
            h2_support.removeRequestState(states, state_allocator, state_index);
            const response = try callbacks.error_response(scratch_allocator, 400, "Bad Request", "HTTP/2 Content-Length did not match the received request body.");
            try callbacks.send_response(stream, scratch_allocator, frame.header.stream_id, response, false);
            return;
        }
    }

    state.req.body = state.body.items;
    try callbacks.complete_request(io, stream, scratch_allocator, cfg, process_env, frame.header.stream_id, state.req);
    h2_support.removeRequestState(states, state_allocator, state_index);
}

pub fn runFrameLoop(
    io: std.Io,
    stream: std.Io.net.Stream,
    allocator: std.mem.Allocator,
    cfg: *ServerConfig,
    reader: *h2_support.PendingReader,
    process_env: *const std.process.Environ.Map,
    callbacks: Callbacks,
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
    var last_stream_id: u32 = 0;

    while (true) {
        if (callbacks.shutdown_requested.load(.acquire)) {
            try h2_support.sendGoaway(stream, last_stream_id, ERROR_NO_ERROR, callbacks.write_all);
            return;
        }

        _ = arena.reset(.retain_capacity);
        const req_alloc = arena.allocator();
        const frame = h2_support.readFrame(reader, req_alloc, @max(cfg.max_request_bytes, cfg.max_body_bytes)) catch |err| switch (err) {
            error.ConnectionClosed => return,
            error.RequestTimeout => return,
            else => return err,
        };

        switch (frame.header.frame_type) {
            h2_native.FRAME_SETTINGS => {
                if ((frame.header.flags & h2_native.FLAG_ACK) == 0) {
                    try h2_support.sendFrame(stream, h2_native.FRAME_SETTINGS, h2_native.FLAG_ACK, 0, "", callbacks.write_all);
                }
            },
            h2_native.FRAME_PING => {
                if (frame.payload.len == 8 and (frame.header.flags & h2_native.FLAG_ACK) == 0) {
                    try h2_support.sendFrame(stream, h2_native.FRAME_PING, h2_native.FLAG_ACK, 0, frame.payload, callbacks.write_all);
                }
            },
            h2_native.FRAME_HEADERS => {
                if (frame.header.stream_id > last_stream_id) last_stream_id = frame.header.stream_id;
                if (cfg.max_requests_per_connection > 0 and requests_seen >= cfg.max_requests_per_connection) {
                    try h2_support.sendRst(stream, frame.header.stream_id, ERROR_REFUSED_STREAM, callbacks.write_all);
                    continue;
                }
                try handleHeadersFrame(io, stream, req_alloc, allocator, &hpack_decoder, cfg, process_env, &body_states, frame, callbacks);
                requests_seen += 1;
            },
            h2_native.FRAME_DATA => {
                try handleDataFrame(io, stream, req_alloc, allocator, cfg, process_env, &body_states, frame, callbacks);
            },
            h2_native.FRAME_GOAWAY => return,
            h2_native.FRAME_WINDOW_UPDATE => {},
            else => {},
        }

        if (cfg.max_requests_per_connection > 0 and requests_seen >= cfg.max_requests_per_connection and body_states.items.len == 0) {
            try h2_support.sendGoaway(stream, last_stream_id, ERROR_NO_ERROR, callbacks.write_all);
            return;
        }
    }
}
