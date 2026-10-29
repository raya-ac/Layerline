#!/usr/bin/env python3
"""Multiplexed clients must progress while another stream waits on a backend."""
import http.server
import json
import pathlib
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
BINARY = pathlib.Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / "zig-out/bin/layerline"


def frame(kind, flags, stream, payload=b""):
    return len(payload).to_bytes(3, "big") + bytes([kind, flags]) + stream.to_bytes(4, "big") + payload


def literal(name, value):
    assert len(name) < 127 and len(value) < 127
    return b"\0" + bytes([len(name)]) + name + bytes([len(value)]) + value


def exact(conn, count):
    result = b""
    while len(result) < count:
        part = conn.recv(count - len(result))
        if not part:
            raise EOFError("HTTP/2 connection ended early")
        result += part
    return result


class Backend(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64

    def __init__(self):
        self.entered = threading.Event()
        self.release = threading.Event()
        super().__init__(("127.0.0.1", 0), Handler)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.server.entered.set()
        self.server.release.wait(6)
        body = b"released backend\n"
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, *_):
        pass


class Client:
    def __init__(self, port, secure, upgrade=False):
        raw = socket.create_connection(("127.0.0.1", port), timeout=2)
        if secure:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE  # Disposable loopback certificate.
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3
            ctx.set_alpn_protocols(["h2"])
            try:
                self.conn = ctx.wrap_socket(raw, server_hostname="localhost")
            except BaseException:
                raw.close()
                raise
            assert self.conn.selected_alpn_protocol() == "h2"
        else:
            self.conn = raw
        self.secure = secure
        self.port = port
        self.frames = []
        if upgrade:
            assert not secure
            self.conn.sendall(f"GET /slow/upgrade HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAQAAAAA\r\nX-Request-Id: dispatch-1\r\n\r\n".encode())
            reply = b""
            while not reply.endswith(b"\r\n\r\n"):
                reply += exact(self.conn, 1)
            assert reply.startswith(b"HTTP/1.1 101"), reply
        self.conn.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 0, 0, struct.pack("!HI", 4, 0)))

    def send(self, kind, flags, stream, payload=b""):
        self.conn.sendall(frame(kind, flags, stream, payload))

    def request(self, stream, path, method=b"GET", end=True, extra=()):
        pairs = [(b":method", method), (b":scheme", b"https" if self.secure else b"http"), (b":authority", f"127.0.0.1:{self.port}".encode()), (b":path", path), (b"x-request-id", f"dispatch-{stream}".encode()), *extra]
        self.send(1, 4 | int(end), stream, b"".join(literal(*pair) for pair in pairs))

    def window(self, stream, count):
        self.send(8, 0, stream, count.to_bytes(4, "big"))

    def until(self, predicate, seconds=1, allow_goaway=False):
        deadline = time.monotonic() + seconds
        while not predicate(self.frames):
            remaining = deadline - time.monotonic()
            assert remaining > 0, "stream progress exceeded its independent deadline"
            self.conn.settimeout(remaining)
            head = exact(self.conn, 9)
            payload = exact(self.conn, int.from_bytes(head[:3], "big"))
            item = head[3], head[4], int.from_bytes(head[5:], "big") & 0x7fffffff, payload
            self.frames.append(item)
            if item[0] == 4 and not item[1] & 1:
                self.send(4, 1, 0)
            assert allow_goaway or item[0] != 7, ("unexpected GOAWAY", item)

    def ended(self, stream):
        return any(k in [0, 1] and f & 1 and s == stream for k, f, s, _ in self.frames)

    def reset(self, stream, code):
        return any(k == 3 and s == stream and int.from_bytes(p, "big") == code for k, _, s, p in self.frames)

    def body(self, stream):
        return b"".join(p for k, _, s, p in self.frames if k == 0 and s == stream)

    def close(self):
        self.conn.close()


for secure in [False, True]:
    with tempfile.TemporaryDirectory(prefix="layerline-h2-dispatch-") as temporary:
        folder = pathlib.Path(temporary)
        (folder / "queued.txt").write_bytes(b"waiting for a send window")
        backend = Backend()
        threading.Thread(target=backend.serve_forever, daemon=True).start()
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        config = folder / "server.conf"
        log_path = folder / "server.log"
        access = folder / "access.jsonl"
        config.write_text(f"""host = 127.0.0.1
port = {port}
tls = {str(secure).lower()}
dir = {folder}
serve_static_root = true
access_log = {access}
read_header_timeout_ms = 2000
read_body_timeout_ms = 350
write_timeout_ms = 350
idle_timeout_ms = 600
upstream_timeout_ms = 5000
upstream_retries = 0
upstream_max_failures = 1
route = slow /slow/* proxy
route_proxy.slow = http://127.0.0.1:{backend.server_port}
route_header.slow = X-Route: slow-only
graceful_shutdown_timeout_ms = 1200
""")
        process = None
        client = None

        def resources():
            scheme = "https" if secure else "http"
            text = subprocess.check_output(["curl", "-skS", "--http1.1", "--max-time", "2", f"{scheme}://127.0.0.1:{port}/metrics"], text=True)
            return {line.split()[0]: int(line.split()[1]) for line in text.splitlines() if line.startswith("layerline_http2_") or line.startswith("layerline_upstream_failures_total ")}

        def quiescent(memory=False):
            deadline = time.monotonic() + 1.5
            while True:
                snapshot = resources()
                if snapshot["layerline_http2_routing_jobs"] == 0 and (not memory or snapshot["layerline_http2_memory_bytes"] == 0):
                    return
                assert time.monotonic() < deadline, ("HTTP/2 resources not reclaimed", snapshot, log_path.read_text())
                time.sleep(0.02)

        try:
            with log_path.open("wb") as log:
                process = subprocess.Popen([str(BINARY), "--config", str(config)], cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
                deadline = time.monotonic() + 5
                while True:
                    assert process.poll() is None, log_path.read_text()
                    try:
                        client = Client(port, secure)
                        break
                    except OSError:
                        assert time.monotonic() < deadline, log_path.read_text()
                        time.sleep(0.03)
                client.request(1, b"/queued.txt")
                client.until(lambda items: any(k == 1 and s == 1 for k, _, s, _ in items))
                client.request(3, b"/api/echo", method=b"POST", end=False, extra=[(b"content-length", b"4")])
                client.send(0, 0, 3, b"x")
                client.request(5, b"/slow/hold")
                assert backend.entered.wait(1), "backend request did not start"
                started = time.monotonic()
                client.request(7, b"/health")
                client.window(7, 16)
                client.send(6, 0, 0, b"liveping")
                client.until(lambda items: client.ended(7) and (6, 1, 0, b"liveping") in items, seconds=0.6)
                assert time.monotonic() - started < 0.6 and client.body(7) == b"ok\n"
                client.until(lambda _: client.reset(1, 8) and client.reset(3, 8), seconds=0.8)
                assert not backend.release.is_set(), "backend was not held during timeout checks"
                time.sleep(0.4)  # The backend remains active beyond the idle budget.
                client.window(1, 1000)
                client.request(9, b"/health")
                client.window(9, 16)
                backend.release.set()
                client.window(5, 1000)
                client.until(lambda _: client.ended(5) and client.ended(9), seconds=2)
                assert client.body(5) == b"released backend\n" and client.body(9) == b"ok\n"
                assert not client.body(1), "expired response resumed after late credit"
                for stream in [5, 7, 9]:
                    headers = b"".join(p for k, _, s, p in client.frames if k == 1 and s == stream)
                    assert f"dispatch-{stream}".encode() in headers, "request identity crossed jobs"
                    assert (b"slow-only" in headers) == (stream == 5), "route policy crossed jobs"
                client.until(lambda items: any(k == 7 for k, _, _, _ in items), seconds=1.5, allow_goaway=True)
                assert client.frames[-1][3][4:] == bytes(4), "idle connection did not drain with NO_ERROR"
                client.close()
                client = None
                quiescent(memory=True)

                # Saturate this connection without blocking control frames.
                backend.release.clear()
                backend.entered.clear()
                client = Client(port, secure)
                for stream in range(1, 17, 2):
                    client.request(stream, b"/slow/capacity")
                client.send(6, 0, 0, b"capacity")
                client.until(lambda items: (6, 1, 0, b"capacity") in items)
                snapshot = resources()
                assert snapshot["layerline_http2_routing_jobs"] == 8, (snapshot, client.frames)
                client.request(17, b"/health")
                client.until(lambda _: client.reset(17, 7), seconds=0.6)
                for stream in range(1, 17, 2):
                    client.send(3, 0, stream, (8).to_bytes(4, "big"))
                # A PING proves the resets were parsed, not that jobs finished.
                client.send(6, 0, 0, b"canceled")
                client.until(lambda items: (6, 1, 0, b"canceled") in items)
                backend.release.set()
                quiescent()
                client.request(19, b"/health")
                client.window(19, 16)
                client.until(lambda _: client.ended(19))
                assert client.body(19) == b"ok\n"
                assert not any(k in [0, 1] and s < 17 for k, _, s, _ in client.frames), "reset backend job produced a late response"
                client.close()
                client = None
                quiescent(memory=True)

                # Closing a client cancels and joins a real blocked backend read.
                backend.release.clear()
                backend.entered.clear()
                client = Client(port, secure)
                client.request(1, b"/slow/disconnect")
                assert backend.entered.wait(1)
                client.close()
                client = None
                quiescent(memory=True)
                assert resources()["layerline_upstream_failures_total"] == 0, "client cancellation counted as backend failure"
                backend.release.set()

                if not secure:
                    backend.release.clear()
                    backend.entered.clear()
                    client = Client(port, False, upgrade=True)
                    assert backend.entered.wait(1)
                    client.request(3, b"/health")
                    client.window(3, 16)
                    client.send(6, 0, 0, b"upgraded")
                    client.until(lambda items: client.ended(3) and (6, 1, 0, b"upgraded") in items, seconds=0.6)
                    assert client.body(3) == b"ok\n"
                    backend.release.set()
                    client.window(1, 1000)
                    client.until(lambda _: client.ended(1))
                    assert client.body(1) == b"released backend\n"
                    client.close()
                    client = None
                    quiescent(memory=True)
                deadline = time.monotonic() + 2
                while not access.exists() or b'"request_id":"dispatch-9"' not in access.read_bytes():
                    assert time.monotonic() < deadline
                    time.sleep(0.02)
                records = [json.loads(line) for line in access.read_text().splitlines()]
                for stream, path, handler in [(5, "/slow/hold", "route_proxy"), (7, "/health", "health"), (9, "/health", "health")]:
                    record = next(record for record in records if record["request_id"] == f"dispatch-{stream}")
                    assert record["path"] == path and record["status"] == 200, record
                    assert record["handler"] == handler, record
        except BaseException:
            print(log_path.read_text(), file=sys.stderr)
            raise
        finally:
            backend.release.set()
            if client is not None:
                client.close()
            if process is not None and process.poll() is None:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
            backend.shutdown()
            backend.server_close()
        print(f"ok: {'TLS' if secure else 'plain'} HTTP/2 backend isolation, deadlines, routing caps, canceled replies and joined disconnect cleanup")
