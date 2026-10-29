#!/usr/bin/env python3
"""Independent HTTP/2 wire tests, including trailers and refused-stream HPACK."""
import socket
import struct
import sys

HOST, PORT = sys.argv[1], int(sys.argv[2])


def frame(kind, flags, stream, payload=b""):
    return len(payload).to_bytes(3, "big") + bytes([kind, flags]) + stream.to_bytes(4, "big") + payload


def literal(name, value):
    return b"\0" + bytes([len(name)]) + name + bytes([len(value)]) + value


def headers(path, method=b"GET"):
    return b"".join(literal(*pair) for pair in [(b":method", method), (b":scheme", b"http"), (b":authority", b"custom404.test"), (b":path", path)])


def exact(conn, count):
    result = b""
    while len(result) < count:
        part = conn.recv(count - len(result))
        if not part:
            raise EOFError("connection closed")
        result += part
    return result


class Client:
    def __init__(self, window=0):
        self.initial_window = window

    def __enter__(self):
        self.conn = socket.create_connection((HOST, PORT), timeout=3)
        self.conn.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 0, 0, struct.pack("!HI", 4, self.initial_window)))
        return self

    def __exit__(self, *_):
        self.conn.close()

    def send(self, kind, flags, stream, payload=b""):
        self.conn.sendall(frame(kind, flags, stream, payload))

    def barrier(self):
        self.send(6, 0, 0, b"barrier!")
        frames = []
        for _ in range(1000):
            item = self.receive()
            if item == (6, 1, 0, b"barrier!"):
                return frames
            frames.append(item)
        raise AssertionError("PING not acknowledged")

    def receive(self):
        head = exact(self.conn, 9)
        body = exact(self.conn, int.from_bytes(head[:3], "big"))
        return head[3], head[4], int.from_bytes(head[5:], "big") & 0x7fffffff, body

    def goaway(self):
        for _ in range(1000):
            kind, _, stream, payload = self.receive()
            if kind == 7 and stream == 0:
                return int.from_bytes(payload[4:8], "big")
        raise AssertionError("GOAWAY not sent")

    def window(self, stream, count):
        self.send(8, 0, stream, count.to_bytes(4, "big"))


with Client() as client:
    client.send(1, 5, 1, headers(b"/large.bin"))
    frames = client.barrier()
    settings = [p for k, f, _, p in frames if k == 4 and not f & 1]
    assert len(settings) == 1
    advertised = dict(struct.unpack("!HI", settings[0][i:i + 6]) for i in range(0, len(settings[0]), 6))
    assert advertised[3] == 128 and advertised[6] == 16384, "server did not advertise its actual limits"
    assert any(k == 1 and s == 1 and p.startswith(b"\x88") for k, _, s, p in frames)
    assert not any(k == 0 for k, _, _, _ in frames), "zero window must stop DATA"
    client.send(1, 5, 3, headers(b"/health"))
    client.window(3, 3)
    frames = client.barrier()
    assert b"".join(p for k, _, s, p in frames if k == 0 and s == 3) == b"ok\n"
    assert any(k == 0 and s == 3 and f & 1 for k, f, s, _ in frames)
    assert not any(k == 0 and s == 1 for k, _, s, _ in frames), "blocked stream affected unrelated response"
    client.window(1, 100000)
    frames = client.barrier()
    assert sum(len(p) for k, _, s, p in frames if k == 0 and s == 1) == 65532, "connection window exceeded"
    client.window(0, 300000)
    frames += client.barrier()
    assert sum(len(p) for k, _, s, p in frames if k == 0 and s == 1) == 100000, "stream window exceeded"
    client.window(1, 300000)
    frames += client.barrier()
    assert b"".join(p for k, _, s, p in frames if k == 0 and s == 1) == bytes(262144)
    assert any(k == 0 and s == 1 and f & 1 for k, f, s, _ in frames)

with Client() as client:
    client.send(1, 5, 1, headers(b"/large.bin"))
    client.barrier()
    client.send(3, 0, 1, bytes(4))
    client.window(1, 100000)
    client.send(1, 5, 3, headers(b"/health"))
    client.window(3, 3)
    frames = client.barrier()
    assert not any(k == 0 and s == 1 for k, _, s, _ in frames), "reset response was still sent"
    assert any(k == 0 and s == 3 and f & 1 for k, f, s, _ in frames)

with Client() as client:
    block = headers(b"/health")
    # Padding and priority belong only to the initial fragment.
    client.send(1, 1 | 8 | 32, 1, b"\x02" + bytes(5) + block[:13] + b"xx")
    client.send(9, 4, 1, block[13:])
    client.window(1, 3)
    frames = client.barrier()
    assert any(k == 1 and p.startswith(b"\x88") for k, _, _, p in frames)
    assert any(k == 0 and f & 1 and p == b"ok\n" for k, f, _, p in frames)

for split in [False, True]:
    with Client() as client:
        # Hold every response at a zero stream window to reach the stream cap.
        for stream in range(1, 257, 2):
            client.send(1, 5, stream, headers(b"/health"))
        client.barrier()
        # An insertion on a refused stream must still update the shared decoder.
        insertion = b"\x40" + literal(b"x-refused-state", b"retained")[1:]
        block = headers(b"/health") + insertion
        if split:
            client.send(1, 1 | 8 | 32, 257, b"\x02" + bytes(5) + block[:13] + bytes(2))
            client.send(9, 4, 257, block[13:])
        else:
            client.send(1, 5 | 8 | 32, 257, b"\x02" + bytes(5) + block + bytes(2))
        frames = client.barrier()
        assert (3, 0, 257, (7).to_bytes(4, "big")) in frames, "excess stream was not refused"
        client.send(3, 0, 1, bytes(4))
        client.send(1, 5, 259, headers(b"/health") + b"\xbe")  # dynamic index 62
        client.window(259, 3)
        frames = client.barrier()
        assert any(k == 0 and s == 259 and f & 1 and p == b"ok\n" for k, f, s, p in frames), "refusal desynchronized HPACK"

for split in [False, True]:
    with Client(window=65535) as client:
        client.send(1, 4, 1, headers(b"/api/echo", b"POST") + literal(b"content-length", b"5"))
        client.send(0, 0, 1, b"hello")
        client.send(1, 5, 3, headers(b"/health"))
        frames = client.barrier()
        assert not any(k in (0, 1) and s == 1 for k, _, s, _ in frames), "request dispatched before trailers"
        trailer = literal(b"content-digest", b"sha-256=:fixture:")
        if split:
            client.send(1, 1 | 8 | 32, 1, b"\x01" + bytes(5) + trailer[:7] + b"\0")
            client.send(9, 4, 1, trailer[7:])
        else:
            client.send(1, 5, 1, trailer)
        frames = client.barrier()
        assert b"".join(p for k, _, s, p in frames if k == 0 and s == 1) == b"hello"
        assert any(k == 0 and s == 1 and f & 1 for k, f, s, _ in frames)

for name, value, flags in [(b":path", b"/health", 5), (b"content-length", b"0", 5), (b"authorization", b"changed", 5), (b"content-digest", b"fixture", 4)]:
    with Client(window=65535) as client:
        client.send(1, 4, 1, headers(b"/api/echo", b"POST"))
        client.send(0, 0, 1, b"hello")
        client.send(1, flags, 1, literal(name, value))
        client.send(1, 5, 3, headers(b"/health"))
        frames = client.barrier()
        assert (3, 0, 1, (1).to_bytes(4, "big")) in frames, "invalid trailers were not stream errors"
        assert not any(k in (0, 1) and s == 1 for k, _, s, _ in frames), "invalid request was routed"
        assert any(k == 0 and s == 3 and f & 1 for k, f, s, _ in frames), "invalid trailers killed an unrelated stream"

with Client(window=65535) as client:
    client.send(1, 4, 1, headers(b"/api/echo", b"POST") + literal(b"content-length", b"6"))
    client.send(0, 0, 1, b"hello")
    client.send(1, 5, 1, b"")
    frames = client.barrier()
    assert not any(k == 1 and s == 1 and p.startswith(b"\x88") for k, _, s, p in frames), "trailers bypassed Content-Length"

with Client(window=65535) as client:
    # Repeating a small dynamic index must not bypass the decoded byte budget.
    insertion = b"\x40" + literal(b"x-large", b"v" * 120)[1:]
    client.send(1, 5, 1, headers(b"/health") + insertion)
    client.barrier()
    block = headers(b"/health") + b"\xbe" * 110
    client.send(1, 5, 3, block)
    client.send(1, 5, 5, headers(b"/health") + b"\xbe")
    frames = client.barrier()
    assert any(k == 1 and s == 3 and not p.startswith(b"\x88") for k, _, s, p in frames), "compressed oversized header list was accepted"
    assert any(k == 0 and s == 5 and f & 1 for k, f, s, _ in frames), "header budget rejection broke HPACK"

with Client(window=65535) as client:
    client.send(1, 5, 1, headers(b"/health"))
    client.barrier()
    client.send(0, 0, 1, b"discarded")
    frames = client.barrier()
    assert (8, 0, 0, (9).to_bytes(4, "big")) in frames, "discarded DATA lost connection credit"
    assert (3, 0, 1, (5).to_bytes(4, "big")) in frames

for kind, flags, stream, payload, code in [
    (4, 0, 0, struct.pack("!HI", 4, 0x80000000), 3),
    (4, 0, 0, struct.pack("!HI", 5, 1), 1),
    (4, 0, 0, b"x", 6),
    (4, 1, 0, bytes(6), 6),
    (6, 0, 0, bytes(7), 6),
    (8, 0, 0, bytes(3), 6),
    (7, 0, 0, bytes(7), 6),
    (1, 5 | 32, 1, bytes(4), 6),
    (1, 5 | 8, 1, b"\x10", 1),
    (0, 1, 1, b"idle", 1),
    (1, 5, 1, bytes(16385), 6),
]:
    with Client() as client:
        if len(payload) > 16384:
            # Reject the oversized declaration before a body is read. Leaving a
            # full invalid body unread can reset TCP and hide the final GOAWAY.
            client.conn.sendall(frame(kind, flags, stream, payload)[:9])
        else:
            client.send(kind, flags, stream, payload)
        assert client.goaway() == code, (kind, stream, "wrong GOAWAY error code")

print("ok: HTTP/2 zero/stream/connection windows, multiplex progress, resets, CONTINUATION and SETTINGS bounds")
print("ok: HTTP/2 trailers, refused-stream HPACK, decoded header budgets, discarded credit and frame errors")
