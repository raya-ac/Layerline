#!/usr/bin/env python3
"""Exercise process shutdown with real blocked connections and background workers."""
import http.client
import json
import pathlib
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time


ROOT = pathlib.Path(__file__).resolve().parents[1]
BINARY = pathlib.Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / "zig-out/bin/layerline"


def free_port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_until(check, description, timeout=4):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if check():
            return
        time.sleep(0.01)
    raise AssertionError(description)


def exact(conn, count):
    result = b""
    while len(result) < count:
        part = conn.recv(count - len(result))
        if not part:
            raise EOFError("connection closed before expected frame")
        result += part
    return result


class Server:
    def __init__(self, folder, name, grace=1500):
        self.port = free_port()
        self.h3_port = free_port(socket.SOCK_DGRAM)
        self.admin = folder / (name + ".sock")
        self.log = folder / (name + ".log")
        config = folder / (name + ".conf")
        config.write_text(f"""host = 127.0.0.1
port = {self.port}
dir = {folder}
serve_static_root = true
http3 = true
http3_port = {self.h3_port}
admin_socket = {self.admin}
graceful_shutdown_timeout_ms = {grace}
read_body_timeout_ms = 5000
write_timeout_ms = 5000
max_static_file_bytes = 67108864
route = backend /backend/* proxy
route_proxy.backend = http://127.0.0.1:{free_port()}
route_upstream_health_check.backend = true
route_upstream_health_check_interval_ms.backend = 50
route_upstream_health_check_timeout_ms.backend = 100
""")
        self.output = self.log.open("wb")
        self.process = subprocess.Popen([str(BINARY), "--config", str(config)], cwd=ROOT, stdout=self.output, stderr=subprocess.STDOUT)
        try:
            wait_until(self.ready, "server did not start")
        except BaseException:
            self.close()
            raise

    def text(self):
        return self.log.read_text()

    def ready(self):
        assert self.process.poll() is None, self.text()
        if not self.admin.exists() or "HTTP/3 native UDP listener" not in self.text():
            return False
        try:
            conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=0.2)
            conn.request("GET", "/health", headers={"Connection": "close"})
            result = conn.getresponse()
            valid = result.status == 200 and result.read() == b"ok\n"
            conn.close()
            return valid
        except OSError:
            return False

    def connect(self):
        return socket.create_connection(("127.0.0.1", self.port), timeout=2)

    def stop(self):
        self.started_stop = time.monotonic()
        self.process.send_signal(signal.SIGTERM)
        wait_until(lambda: "Shutdown requested; draining workers" in self.text(), "stop signal was not handled")

    def finish(self, expected):
        assert self.process.wait(timeout=3) == expected, self.text()
        elapsed = time.monotonic() - self.started_stop
        text = self.text()
        assert not self.admin.exists(), "admin socket survived shutdown"
        assert "panic" not in text.lower() and "segmentation fault" not in text.lower(), text
        if expected == 0:
            assert "All connection and background workers stopped." in text, text
            assert '"event":"server.shutdown_timeout"' not in text, text
        else:
            events = [json.loads(line) for line in text.splitlines() if line.startswith('{"event":"server.shutdown_timeout"')]
            assert events and events[0]["active_connections"] > 0, text
            assert "All connection and background workers stopped." not in text, text
            assert 0.15 <= elapsed < 2, elapsed

    def close(self):
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait(timeout=3)
        self.output.close()


def h1_upload(server):
    conn = server.connect()
    conn.sendall(b"POST /api/echo HTTP/1.1\r\nHost: local\r\nContent-Length: 5\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n")
    interim = b""
    while not interim.endswith(b"\r\n\r\n"):
        interim += exact(conn, 1)
    assert interim.startswith(b"HTTP/1.1 100"), interim
    return conn


class H2:
    def __init__(self, server, window):
        self.conn = server.connect()
        self.conn.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        self.send(4, 0, 0, struct.pack("!HI", 4, window))

    def send(self, kind, flags, stream, payload=b""):
        self.conn.sendall(len(payload).to_bytes(3, "big") + bytes([kind, flags]) + stream.to_bytes(4, "big") + payload)

    def request(self, stream, path=b"/health", method=b"GET", end=True):
        def literal(name, value):
            return b"\0" + bytes([len(name)]) + name + bytes([len(value)]) + value
        fields = [(b":method", method), (b":scheme", b"http"), (b":authority", b"local"), (b":path", path)]
        self.send(1, 4 | int(end), stream, b"".join(literal(*field) for field in fields))

    def receive(self):
        head = exact(self.conn, 9)
        return head[3], head[4], int.from_bytes(head[5:], "big") & 0x7fffffff, exact(self.conn, int.from_bytes(head[:3], "big"))

    def until(self, predicate):
        frames = []
        for _ in range(100):
            item = self.receive()
            frames.append(item)
            if predicate(item):
                return frames
        raise AssertionError("expected HTTP/2 frame not received")

    def barrier(self):
        self.send(6, 0, 0, b"shutdown")
        return self.until(lambda f: f == (6, 1, 0, b"shutdown"))


with tempfile.TemporaryDirectory(prefix="layerline-shutdown-") as tmp:
    folder = pathlib.Path(tmp)
    servers = []
    try:
        server = Server(folder, "idle")
        servers.append(server)
        server.stop()
        server.finish(0)
        print("ok: idle shutdown joins admin, QUIC, health and reload workers")

        server = Server(folder, "keepalive")
        servers.append(server)
        with server.connect() as idle:
            h2 = H2(server, 65535)
            try:
                h2.request(1)
                h2.until(lambda f: f[0] == 0 and f[1] & 1)
                h2.barrier()
                server.stop()
                frames = h2.until(lambda f: f[0] == 7)
                assert frames[-1][3][4:] == bytes(4)
                assert idle.recv(1) == b""
            finally:
                h2.conn.close()
        server.finish(0)
        print("ok: idle HTTP/1 and HTTP/2 connections wake without consuming the drain deadline")

        server = Server(folder, "upload")
        servers.append(server)
        with h1_upload(server) as conn:
            server.stop()
            conn.sendall(b"hello")
            response = http.client.HTTPResponse(conn)
            response.begin()
            assert response.status == 200 and response.read() == b"hello"
        server.finish(0)
        print("ok: HTTP/1 in-flight upload completes inside the shutdown grace period")

        for upload in [False, True]:
            server = Server(folder, "h2-upload" if upload else "h2-window")
            servers.append(server)
            h2 = H2(server, 65535 if upload else 0)
            try:
                h2.request(1, b"/api/echo" if upload else b"/health", b"POST" if upload else b"GET", end=not upload)
                if upload:
                    h2.send(0, 0, 1, b"he")
                h2.barrier()
                server.stop()
                h2.send(6, 0, 0, b"observe!")
                frames = h2.until(lambda f: f[0] == 7)
                goaway = frames[-1][3]
                assert int.from_bytes(goaway[:4], "big") == 1 and goaway[4:] == bytes(4)
                h2.request(3)
                h2.until(lambda f: f == (3, 0, 3, (7).to_bytes(4, "big")))
                if upload:
                    h2.send(0, 0, 1, b"l")
                    h2.send(0, 1, 1, b"lo")
                else:
                    h2.send(8, 0, 1, (3).to_bytes(4, "big"))
                frames = h2.until(lambda f: f[0] == 0 and f[1] & 1 and f[2] == 1)
                assert b"".join(p for k, _, stream, p in frames if k == 0 and stream == 1) == (b"hello" if upload else b"ok\n")
            finally:
                h2.conn.close()
            server.finish(0)
        print("ok: HTTP/2 GOAWAY refuses new streams while draining uploads and window-stalled responses")

        for mode in ["body", "window", "write"]:
            server = Server(folder, "deadline-" + mode, grace=250)
            servers.append(server)
            if mode == "body":
                conn = h1_upload(server)
                conn.sendall(b"he")
            elif mode == "window":
                h2 = H2(server, 0)
                h2.request(1)
                h2.barrier()
                conn = h2.conn
            else:
                with (folder / "large.bin").open("wb") as large:
                    large.truncate(64 * 1024 * 1024)
                conn = server.connect()
                conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
                conn.sendall(b"GET /large.bin HTTP/1.1\r\nHost: local\r\nConnection: close\r\n\r\n")
                header = b""
                while not header.endswith(b"\r\n\r\n"):
                    header += exact(conn, 1)
                assert header.startswith(b"HTTP/1.1 200"), header
            try:
                server.stop()
                server.finish(1)
            finally:
                conn.close()
        print("ok: blocked reads, HTTP/2 windows and blocked writes hit the absolute shutdown deadline without unsafe cleanup")
    finally:
        for server in servers:
            server.close()
