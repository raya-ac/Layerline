#!/usr/bin/env python3
"""Wire-level regressions against a temporary verifier server; no dependencies."""
import socket
import sys


HOST, PORT = sys.argv[1], int(sys.argv[2])


def http1(request):
    with socket.create_connection((HOST, PORT), timeout=3) as conn:
        conn.sendall(request)
        data = b""
        while True:
            chunk = conn.recv(65536)
            if not chunk:
                break
            data += chunk
    head, body = data.split(b"\r\n\r\n", 1)
    return int(head.split(b" ")[1]), head.lower(), body


def exact(conn, size):
    data = b""
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise AssertionError("HTTP/2 connection closed before response")
        data += chunk
    return data


def frame(kind, flags, stream, payload):
    return len(payload).to_bytes(3, "big") + bytes([kind, flags]) + stream.to_bytes(4, "big") + payload


def literal(name, value):
    assert len(name) < 127 and len(value) < 127
    return b"\x00" + bytes([len(name)]) + name + bytes([len(value)]) + value


def http2(extra):
    fields = [(b":method", b"GET"), (b":scheme", b"http"), (b":authority", b"test"), (b":path", b"/health")]
    block = b"".join(literal(*field) for field in fields + extra)
    with socket.create_connection((HOST, PORT), timeout=3) as conn:
        conn.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 0, 0, b"") + frame(1, 5, 1, block))
        for _ in range(20):
            head = exact(conn, 9)
            payload = exact(conn, int.from_bytes(head[:3], "big"))
            stream = int.from_bytes(head[5:], "big")
            if head[3] == 1 and stream == 1:
                return payload
        raise AssertionError("HTTP/2 response missing")


bad_requests = [
    b"GET /health HTTP/1.1 extra\r\nHost: test",
    b"GET /health HTTP/1.1\r\nHost: one\r\nHost: two",
    b"GET /health HTTP/1.1\r\nHost: test\r\nX: ok\nInjected: yes",
    b"POST /api/echo HTTP/1.1\r\nHost: test\r\nContent-Length: +0",
    b"POST /api/echo HTTP/1.1\r\nHost: test\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked",
    b"POST /api/echo HTTP/1.1\r\nHost: test\r\nTransfer-Encoding: \r\nContent-Length: 0",
    b"POST /api/echo HTTP/1.1\r\nHost: test\r\nTransfer-Encoding: chunked\r\nContent-Length: 0\r\nExpect: 100-continue",
]
for request in bad_requests:
    status, _, _ = http1(request + b"\r\nConnection: close\r\n\r\n")
    assert status == 400, (request, status)

status, _, body = http1(b"GET http://custom404.test/ HTTP/1.1\r\nHost: wrong.test\r\nConnection: close\r\n\r\n")
assert status == 200 and b"custom domain root" in body, "absolute authority must select the virtual host"

assert http2([]).startswith(b"\x88"), "valid HTTP/2 request must still return 200"
for extra in [
    [(b"x-test", b"ok\r\nContent-Length: 99")],
    [(b"connection", b"keep-alive")],
    [(b"transfer-encoding", b"chunked")],
    [(b":path", b"/other")],
    [(b"host", b"other.test")],
]:
    assert http2(extra).startswith(b"\x8c"), ("HTTP/2 invalid fields were accepted", extra)

print("ok: wire-level HTTP/1 framing, authority routing, and HTTP/2 header validation")
