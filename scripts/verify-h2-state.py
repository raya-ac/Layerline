#!/usr/bin/env python3
"""Stream errors must retain HPACK, cancellation and unrelated-stream progress."""
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time

from wire_h2 import H2, frame

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / "zig-out/bin/layerline"


def literal(name, value):
    assert len(name) < 127 and len(value) < 127
    return b"\0" + bytes([len(name)]) + name + bytes([len(value)]) + value


class Peer(H2):
    def __init__(self, port, tls):
        super().__init__(port, tls=tls)
        self.frames = []

    def receive(self):
        head = self.exact(9)
        item = head[3], head[4], int.from_bytes(head[5:], "big"), self.exact(int.from_bytes(head[:3], "big"))
        self.frames.append(item)
        if item[0] == 4 and not item[1] & 1:
            self.connection.sendall(frame(4, 1, 0))
        return item

    def wait(self, predicate):
        until = time.monotonic() + 3
        while not predicate(self.frames):
            self.connection.settimeout(max(.01, until - time.monotonic()))
            self.receive()
            assert time.monotonic() < until, self.frames

    def goaway(self, code):
        self.wait(lambda frames: any(k == 7 for k, _, _, _ in frames))
        last = next(p for k, _, _, p in self.frames if k == 7)
        assert int.from_bytes(last[4:8], "big") == code, self.frames

    def fields(self, stream, fields, flags=5, prefix=b""):
        block = b"".join(literal(name, value) for name, value in fields)
        self.connection.sendall(frame(1, flags, stream, prefix + block))

    def healthy(self, stream):
        self.request(stream, b"/health")
        self.wait(lambda frames: any(k in [0, 1] and f & 1 and s == stream for k, f, s, _ in frames))
        assert not any(k == 7 for k, _, _, _ in self.frames), self.frames
        assert b"".join(p for k, _, s, p in self.frames if k == 0 and s == stream) == b"ok\n", self.frames


for tls in [False, True]:
    with tempfile.TemporaryDirectory(prefix="layerline-h2-state-", dir="/tmp") as temporary:
        folder = Path(temporary)
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        config, log = folder / "server.conf", folder / "server.log"
        config.write_text(f"""host = 127.0.0.1
port = {port}
dir = {folder}
tls = {str(tls).lower()}
admin = false
admin_ui = false
max_requests_per_connection = 8
graceful_shutdown_timeout_ms = 1000
""")
        process = None
        peers = []

        def peer():
            value = Peer(port, tls)
            peers.append(value)
            return value

        fields = [(b":method", b"POST"), (b":scheme", b"https" if tls else b"http"),
                  (b":authority", b"localhost"), (b":path", b"/api/echo")]
        reset = (3, 0, 1, (1).to_bytes(4, "big"))
        try:
            with log.open("wb") as sink:
                process = subprocess.Popen([str(BINARY), "--config", str(config)], cwd=folder, stdout=sink, stderr=sink)
            until = time.monotonic() + 5
            while '"event":"server.ready"' not in log.read_text():
                assert process.poll() is None and time.monotonic() < until, log.read_text()
                time.sleep(.01)
            for extra, chunks, end in [
                ([(b"X-Invalid", b"x")], [], True),
                ([(b"x-invalid", b" x")], [], True),
                ([(b":method", b"GET")], [], True),
                ([(b"content-length", b"1")], [], True),
                ([(b"content-length", b"no")], [], True),
                ([(b"content-length", b"1")], [b"too", b"long"], False),
                ([(b"content-length", b"5")], [b"x"], False),
            ]:
                client = peer()
                client.fields(1, fields + extra, flags=5 if end else 4)
                for index, chunk in enumerate(chunks):
                    client.connection.sendall(frame(0, int(index == len(chunks) - 1), 1, chunk))
                client.healthy(3)
                assert reset in client.frames, client.frames
                assert sum(k == 3 and s == 1 for k, _, s, _ in client.frames) == 1, "queued DATA caused duplicate resets"
                assert not any(k in [0, 1] and s == 1 for k, _, s, _ in client.frames), client.frames
                client.close()

            for kind in [0, 1, 8, 2]:
                client = peer()
                client.fields(1, fields, flags=4)
                client.connection.sendall(frame(3, 0, 1, (8).to_bytes(4, "big")))
                if kind == 1:
                    client.fields(1, fields)
                else:
                    client.connection.sendall(frame(kind, 0, 1, b"x" if kind == 0 else bytes(4)))
                client.goaway(5 if kind in [0, 1] else 1 if kind == 8 else 6)
                assert not any(k in [0, 1, 3] and s == 1 for k, _, s, _ in client.frames), "frames sent after peer reset"
                client.close()

            client = peer()
            client.request(5, b"/health")
            client.request(3, b"/health")
            client.goaway(1)
            client.close()

            client = peer()
            client.healthy(1)
            client.request(1, b"/health")
            client.goaway(5)
            client.close()

            client = peer()
            client.fields(1, fields, flags=4)
            client.connection.sendall(frame(7, 0, 0, bytes(8)))
            client.request(3, b"/health")
            client.connection.sendall(frame(0, 1, 1, b"finish me"))
            client.wait(lambda frames: any(k == 0 and f & 1 and s == 1 for k, f, s, _ in frames))
            assert b"".join(p for k, _, s, p in client.frames if k == 0 and s == 1) == b"finish me", "peer GOAWAY canceled an existing request"
            assert (3, 0, 3, (7).to_bytes(4, "big")) in client.frames, "draining connection accepted a new stream"
            assert any(k == 7 and p[4:8] == bytes(4) for k, _, _, p in client.frames)
            client.close()

            client = peer()
            # A reduction followed by growth before the next reply must still
            # communicate a table size no larger than the intervening minimum.
            client.connection.sendall(frame(4, 0, 0, struct.pack("!HIHI", 1, 8, 1, 4096)))
            client.healthy(1)
            blocks = [(k, f, p) for k, f, s, p in client.frames if s == 1 and k in [1, 9]]
            assert blocks[0] == (1, 0, b"\x20"), blocks
            assert blocks[-1][0] == 9 and blocks[-1][1] & 4, blocks
            assert b"".join(p for _, _, p in blocks).startswith(b"\x20\x88"), blocks
            client.healthy(3)
            assert [p for k, _, s, p in client.frames if k == 1 and s == 3][0].startswith(b"\x88"), "redundant table resize was emitted"
            client.close()

            # Malformed requests count toward the configured request cap, even
            # though they never get dispatched or retain active stream slots.
            client = peer()
            for stream in range(1, 17, 2):
                client.fields(stream, fields + [(b"connection", b"close")])
            client.goaway(0)
            assert sum(k == 3 for k, _, _, _ in client.frames) == 8, client.frames
            client.close()

            for _ in range(32):
                client = peer()
                client.connection.sendall(frame(8, 0, 0, (0x7fffffff).to_bytes(4, "big")) * 2)
                client.goaway(3)
                client.close()
            assert process.poll() is None, log.read_text()
        finally:
            for client in peers:
                client.close()
            if process and process.poll() is None:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=4)
                    raise AssertionError("state tests prevented joined shutdown")
            if process:
                assert process.returncode == 0, log.read_text()
        print(f"ok: {'TLS' if tls else 'plain'} malformed stream resets, closed/skipped IDs, peer reset silence, request-cap history and repeated GOAWAY delivery")
