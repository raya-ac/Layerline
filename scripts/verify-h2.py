#!/usr/bin/env python3
"""Independent wire tests: windows, multiplexing, resets and split headers."""
import socket
import struct
import sys

HOST, PORT = sys.argv[1], int(sys.argv[2])


def frame(kind, flags, stream, payload=b""):
    return len(payload).to_bytes(3, "big") + bytes([kind, flags]) + stream.to_bytes(4, "big") + payload


def literal(name, value):
    return b"\0" + bytes([len(name)]) + name + bytes([len(value)]) + value


def headers(path):
    return b"".join(literal(*pair) for pair in [(b":method", b"GET"), (b":scheme", b"http"), (b":authority", b"custom404.test"), (b":path", path)])


def exact(conn, count):
    result = b""
    while len(result) < count:
        part = conn.recv(count - len(result))
        if not part:
            raise EOFError("connection closed")
        result += part
    return result


class Client:
    def __enter__(self):
        self.conn = socket.create_connection((HOST, PORT), timeout=3)
        self.conn.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 0, 0, struct.pack("!HI", 4, 0)))
        return self

    def __exit__(self, *_):
        self.conn.close()

    def send(self, kind, flags, stream, payload=b""):
        self.conn.sendall(frame(kind, flags, stream, payload))

    def barrier(self):
        self.send(6, 0, 0, b"barrier!")
        frames = []
        for _ in range(1000):
            head = exact(self.conn, 9)
            body = exact(self.conn, int.from_bytes(head[:3], "big"))
            item = (head[3], head[4], int.from_bytes(head[5:], "big") & 0x7fffffff, body)
            if item == (6, 1, 0, b"barrier!"):
                return frames
            frames.append(item)
        raise AssertionError("PING not acknowledged")

    def window(self, stream, count):
        self.send(8, 0, stream, count.to_bytes(4, "big"))


with Client() as client:
    client.send(1, 5, 1, headers(b"/large.bin"))
    frames = client.barrier()
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

for payload in [struct.pack("!HI", 4, 0x80000000), struct.pack("!HI", 5, 1), b"x"]:
    with Client() as client:
        client.send(4, 0, 0, payload)
        try:
            client.barrier()
        except (EOFError, ConnectionResetError):
            pass
        else:
            raise AssertionError("invalid SETTINGS accepted")

print("ok: HTTP/2 zero/stream/connection windows, multiplex progress, resets, CONTINUATION and SETTINGS bounds")
