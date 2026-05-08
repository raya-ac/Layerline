const std = @import("std");

const http_headers = @import("http_headers.zig");

const findHeaderValue = http_headers.findHeaderValue;
const hasConnectionToken = http_headers.hasConnectionToken;
const trimValue = http_headers.trimValue;

// Build a target path for proxying while avoiding `//` and leading path glitches.
pub fn buildProxyPath(allocator: std.mem.Allocator, base_path: []const u8, request_path: []const u8, query: []const u8) ![]const u8 {
    var final_path = std.ArrayList(u8).empty;

    if (std.mem.eql(u8, base_path, "/")) {
        try final_path.appendSlice(allocator, request_path);
    } else {
        try final_path.appendSlice(allocator, base_path);
        if (!std.mem.endsWith(u8, base_path, "/") and request_path.len > 0 and request_path[0] != '/') {
            try final_path.append(allocator, '/');
        }
        if (!std.mem.startsWith(u8, request_path, "/")) {
            try final_path.appendSlice(allocator, request_path);
        } else {
            try final_path.appendSlice(allocator, request_path[1..]);
        }
    }

    if (final_path.items.len == 0) {
        try final_path.append(allocator, '/');
    }

    if (query.len > 0) {
        try final_path.append(allocator, '?');
        try final_path.appendSlice(allocator, query);
    }

    return try final_path.toOwnedSlice(allocator);
}

pub fn isSkippedProxyHeader(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "Connection") or
        std.ascii.eqlIgnoreCase(name, "Content-Length") or
        std.ascii.eqlIgnoreCase(name, "Keep-Alive") or
        std.ascii.eqlIgnoreCase(name, "Proxy-Authenticate") or
        std.ascii.eqlIgnoreCase(name, "Proxy-Authorization") or
        std.ascii.eqlIgnoreCase(name, "TE") or
        std.ascii.eqlIgnoreCase(name, "Trailers") or
        std.ascii.eqlIgnoreCase(name, "Transfer-Encoding") or
        std.ascii.eqlIgnoreCase(name, "Upgrade") or
        std.ascii.eqlIgnoreCase(name, "Host") or
        std.ascii.eqlIgnoreCase(name, "X-Request-Id");
}

pub fn isHttpUpgradeHeaders(headers: []const u8) bool {
    const upgrade = findHeaderValue(headers, "Upgrade") orelse return false;
    const connection = findHeaderValue(headers, "Connection") orelse return false;
    return trimValue(upgrade).len > 0 and hasConnectionToken(connection, "upgrade");
}

pub fn isSkippedProxyResponseHeader(name: []const u8) bool {
    return std.ascii.eqlIgnoreCase(name, "Connection") or
        std.ascii.eqlIgnoreCase(name, "Keep-Alive") or
        std.ascii.eqlIgnoreCase(name, "Proxy-Authenticate") or
        std.ascii.eqlIgnoreCase(name, "Proxy-Authorization") or
        std.ascii.eqlIgnoreCase(name, "TE") or
        std.ascii.eqlIgnoreCase(name, "Trailers") or
        std.ascii.eqlIgnoreCase(name, "Upgrade") or
        std.ascii.eqlIgnoreCase(name, "X-Request-Id");
}

pub const UpstreamResponseForwardResult = struct {
    reusable: bool,
};

pub const UpstreamResponseFraming = struct {
    status_code: ?u16,
    content_length: ?usize,
    transfer_chunked: bool,
    connection_close: bool,
};

const ChunkScanState = enum {
    size,
    size_lf,
    data,
    data_cr,
    data_lf,
    trailer,
    trailer_lf,
    done,
};

pub const ChunkedBodyScanner = struct {
    state: ChunkScanState = .size,
    chunk_size: usize = 0,
    remaining: usize = 0,
    saw_size_digit: bool = false,
    in_extension: bool = false,
    trailer_line_start: bool = true,

    fn resetSize(self: *ChunkedBodyScanner) void {
        self.chunk_size = 0;
        self.saw_size_digit = false;
        self.in_extension = false;
    }

    pub fn consume(self: *ChunkedBodyScanner, byte: u8) !bool {
        switch (self.state) {
            .size => {
                if (byte == ';') {
                    if (!self.saw_size_digit) return error.BadGateway;
                    self.in_extension = true;
                    return false;
                }
                if (byte == '\r') {
                    if (!self.saw_size_digit) return error.BadGateway;
                    self.state = .size_lf;
                    return false;
                }
                if (self.in_extension) return false;

                const digit = std.fmt.charToDigit(byte, 16) catch return error.BadGateway;
                self.saw_size_digit = true;
                self.chunk_size = std.math.mul(usize, self.chunk_size, 16) catch return error.BadGateway;
                self.chunk_size = std.math.add(usize, self.chunk_size, digit) catch return error.BadGateway;
                return false;
            },
            .size_lf => {
                if (byte != '\n') return error.BadGateway;
                if (self.chunk_size == 0) {
                    self.trailer_line_start = true;
                    self.state = .trailer;
                } else {
                    self.remaining = self.chunk_size;
                    self.state = .data;
                }
                self.resetSize();
                return false;
            },
            .data => {
                self.remaining -= 1;
                if (self.remaining == 0) self.state = .data_cr;
                return false;
            },
            .data_cr => {
                if (byte != '\r') return error.BadGateway;
                self.state = .data_lf;
                return false;
            },
            .data_lf => {
                if (byte != '\n') return error.BadGateway;
                self.state = .size;
                return false;
            },
            .trailer => {
                if (byte == '\r') {
                    self.state = .trailer_lf;
                } else {
                    self.trailer_line_start = false;
                }
                return false;
            },
            .trailer_lf => {
                if (byte != '\n') return error.BadGateway;
                if (self.trailer_line_start) {
                    self.state = .done;
                    return true;
                }
                self.trailer_line_start = true;
                self.state = .trailer;
                return false;
            },
            .done => return true,
        }
    }
};

pub fn parseOptionalContentLength(headers: []const u8) !?usize {
    if (findHeaderValue(headers, "Content-Length")) |raw| {
        const value = trimValue(raw);
        if (value.len == 0) return error.BadGateway;
        return std.fmt.parseInt(usize, value, 10) catch return error.BadGateway;
    }
    return null;
}

pub fn parseUpstreamResponseFraming(header_bytes: []const u8, response_headers: []const u8) !UpstreamResponseFraming {
    const connection = findHeaderValue(response_headers, "Connection") orelse "";
    const transfer_encoding = findHeaderValue(response_headers, "Transfer-Encoding") orelse "";
    return .{
        .status_code = parseHttpStatusCode(header_bytes),
        .content_length = try parseOptionalContentLength(response_headers),
        .transfer_chunked = hasConnectionToken(transfer_encoding, "chunked"),
        .connection_close = hasConnectionToken(connection, "close"),
    };
}

pub fn responseHasNoBody(method: []const u8, status_code: ?u16) bool {
    if (std.ascii.eqlIgnoreCase(method, "HEAD")) return true;
    const code = status_code orelse return false;
    return (code >= 100 and code < 200) or code == 204 or code == 304;
}

pub fn parseHttpStatusCode(response_head: []const u8) ?u16 {
    const first_line_end = std.mem.indexOf(u8, response_head, "\r\n") orelse response_head.len;
    const first_line = response_head[0..first_line_end];
    if (!std.mem.startsWith(u8, first_line, "HTTP/")) return null;

    var parts = std.mem.tokenizeAny(u8, first_line, " \t");
    _ = parts.next() orelse return null;
    const code_raw = parts.next() orelse return null;
    if (code_raw.len != 3) return null;
    return std.fmt.parseInt(u16, code_raw, 10) catch null;
}
