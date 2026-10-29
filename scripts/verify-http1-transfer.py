#!/usr/bin/env python3
"""Bound whole HTTP/1 transfers without retrying partial replies or expiring tunnels."""
import http.client
import json
import pathlib
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = pathlib.Path(__file__).resolve().parents[1]
BINARY = pathlib.Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / "zig-out/bin/layerline"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def do_GET(self):
        self.server.requests.append(self.path)
        kind = self.path.strip("/").split("/")[0]
        self.close_connection = True
        try:
            if self.server.fallback:
                self.send_response(200)
                self.send_header("Content-Length", "8")
                self.end_headers()
                self.wfile.write(b"fallback")
                return
            if kind == "upgrade":
                self.send_response_only(101)
                self.send_header("Connection", "Upgrade")
                self.send_header("Upgrade", "websocket")
                self.end_headers()
                self.wfile.flush()
                self.connection.settimeout(3)
                while True:
                    data = self.connection.recv(4096)
                    if not data:
                        return
                    self.connection.sendall(data)
            if kind == "delayed":
                time.sleep(0.6)
            self.send_response(200)
            if kind == "chunked":
                self.send_header("Transfer-Encoding", "chunked")
            elif kind != "unknown":
                self.send_header("Content-Length", "2" if kind == "delayed" else "64")
            self.send_header("Connection", "close")
            self.end_headers()
            if kind == "delayed":
                self.wfile.write(b"ok")
                return
            self.wfile.write(b"1\r\nx\r\n" if kind == "chunked" else b"x")
            self.wfile.flush()
            if kind == "broken":
                return
            if kind == "stall":
                time.sleep(1.2)
            for _ in range(63):
                time.sleep(0.08)
                self.wfile.write(b"1\r\nx\r\n" if kind == "chunked" else b"x")
                self.wfile.flush()
            if kind == "chunked":
                self.wfile.write(b"0\r\n\r\n")
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            pass


def header(conn):
    result = b""
    while not result.endswith(b"\r\n\r\n"):
        part = conn.recv(1)
        assert part, ("response headers cut short", result)
        result += part
    return result


def drain(conn, limit=2):
    data = bytearray()
    until = time.monotonic() + limit
    while True:
        try:
            part = conn.recv(65536)
        except (ConnectionResetError, ssl.SSLEOFError):
            break
        if not part:
            break
        data.extend(part)
        assert time.monotonic() < until, "partial response remained open"
    return bytes(data)


def wire_timeouts(server):
    return sum('"phase":"' + phase + '"' in line for line in server.log.read_text().splitlines() for phase in ["wire", "sendfile"])


class Server:
    def __init__(self, folder, secure):
        self.secure = secure
        self.backends = []
        self.threads = []
        self.process = None
        self.log = folder / ("tls.log" if secure else "plain.log")
        self.output = self.log.open("wb")
        try:
            for fallback in [False, True]:
                backend = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
                backend.fallback, backend.requests = fallback, []
                self.backends.append(backend)
                thread = threading.Thread(target=backend.serve_forever, daemon=True)
                thread.start()
                self.threads.append(thread)
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                self.port = probe.getsockname()[1]
            routes = ""
            for kind in ["broken", "fixed", "chunked", "unknown", "stall", "delayed", "upgrade"]:
                targets = self.backends if kind == "broken" else self.backends[:1]
                routes += f"route = {kind} /{kind}/* proxy\nroute_proxy.{kind} = " + " ".join(f"http://127.0.0.1:{backend.server_port}" for backend in targets) + "\n"
            config = folder / "server.conf"
            config.write_text(f"""host = 127.0.0.1
port = {self.port}
tls = {str(secure).lower()}
dir = {folder}
serve_static_root = true
write_timeout_ms = 350
read_header_timeout_ms = 500
read_body_timeout_ms = 1000
idle_timeout_ms = 1500
upstream_timeout_ms = 2000
upstream_retries = 1
graceful_shutdown_timeout_ms = 1000
{routes}""")
            self.process = subprocess.Popen([str(BINARY), "--config", str(config)], cwd=ROOT, stdout=self.output, stderr=subprocess.STDOUT)
            until = time.monotonic() + 4
            while True:
                assert self.process.poll() is None, self.log.read_text()
                try:
                    self.health()
                    break
                except OSError:
                    assert time.monotonic() < until, self.log.read_text()
                    time.sleep(0.02)
        except BaseException:
            self.close()
            raise

    def connect(self, small_buffer=False):
        conn = socket.socket()
        conn.settimeout(2)
        try:
            if small_buffer:
                conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
            conn.connect(("127.0.0.1", self.port))
            if not self.secure:
                return conn
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            ctx.minimum_version = ctx.maximum_version = ssl.TLSVersion.TLSv1_3
            ctx.set_alpn_protocols(["http/1.1"])
            return ctx.wrap_socket(conn, server_hostname="localhost")
        except BaseException:
            conn.close()
            raise

    def health(self):
        with self.connect() as conn:
            conn.sendall(b"GET /health HTTP/1.1\r\nHost: local\r\nConnection: close\r\n\r\n")
            response = http.client.HTTPResponse(conn)
            response.begin()
            assert response.status == 200 and response.read() == b"ok\n"

    def close(self):
        if self.process is not None and self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)
        self.output.close()
        for backend, thread in zip(self.backends, self.threads):
            backend.shutdown()
            backend.server_close()
            thread.join(timeout=2)


with tempfile.TemporaryDirectory(prefix="layerline-http1-transfer-") as temporary:
    folder = pathlib.Path(temporary)
    (folder / "large.bin").write_bytes(b"b" * (8 * 1024 * 1024))
    for secure in [False, True]:
        server = Server(folder, secure)
        try:
            for kind in ["broken", "fixed", "chunked", "unknown", "stall"]:
                with server.connect() as conn:
                    started = time.monotonic()
                    conn.sendall(f"GET /{kind}/run HTTP/1.1\r\nHost: local\r\nConnection: close\r\n\r\n".encode())
                    response = header(conn) + drain(conn)
                    assert response.startswith(b"HTTP/1.1 200 ") and response.count(b"HTTP/1.1 ") == 1 and b"fallback" not in response, (kind, response)
                    assert time.monotonic() - started < 0.9, (kind, "backend body waits renewed the transfer budget")
                assert not server.backends[1].requests, ("retried after visible response bytes", server.backends[1].requests)
            with server.connect() as conn:
                started = time.monotonic()
                conn.sendall(b"GET /delayed/run HTTP/1.1\r\nHost: local\r\nConnection: close\r\n\r\n")
                response = http.client.HTTPResponse(conn)
                response.begin()
                assert response.status == 200 and response.read() == b"ok" and time.monotonic() - started > 0.5
            print(f"ok: {'TLS' if secure else 'plain'} proxy body deadlines, no retry/second status after partial responses, delayed first byte remains allowed")

            for ranged in [False, True]:
                with server.connect(small_buffer=True) as conn:
                    previous = wire_timeouts(server)
                    started = time.monotonic()
                    extra = b"Range: bytes=0-8388607\r\n" if ranged else b""
                    conn.sendall(b"GET /large.bin HTTP/1.1\r\nHost: local\r\n" + extra + b"Connection: close\r\n\r\n")
                    assert header(conn).startswith(b"HTTP/1.1 206 " if ranged else b"HTTP/1.1 200 ")
                    while wire_timeouts(server) == previous and time.monotonic() - started < 0.9:
                        assert conn.recv(1024)
                        time.sleep(0.08)
                    assert wire_timeouts(server) == previous + 1, "static writes renewed the transfer deadline"
                    assert time.monotonic() - started < 0.9
                    conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
                    drain(conn, limit=3)
            if sys.platform == "darwin" and not secure:
                assert server.log.read_text().count('"phase":"sendfile"') == 2, "Darwin sendfile path was not exercised"
            print(f"ok: {'TLS' if secure else 'plain'} large static/range writes are bounded")

            with server.connect() as conn:
                conn.sendall(b"POST /api/echo HTTP/1.1\r\nHost: local\r\nContent-Length: 1\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n")
                assert header(conn).startswith(b"HTTP/1.1 100 ")
                time.sleep(0.6)
                conn.sendall(b"x")
                response = http.client.HTTPResponse(conn)
                response.begin()
                assert response.status == 200 and b"x" in response.read()
            with server.connect() as conn:
                conn.sendall(b"POST /api/echo HTTP/1.1\r\nHost: local\r\nContent-Length: 1\r\nExpect: 100-continue\r\n\r\n")
                assert header(conn).startswith(b"HTTP/1.1 100 ")
                assert header(conn).startswith(b"HTTP/1.1 408 "), "completed interim reply exhausted the final error response budget"
            with server.connect() as conn:
                for _ in range(2):
                    conn.sendall(b"GET /health HTTP/1.1\r\nHost: local\r\n\r\n")
                    response = http.client.HTTPResponse(conn)
                    response.begin()
                    assert response.status == 200 and response.read() == b"ok\n"
                    response.close()
                    time.sleep(0.6)
            with server.connect() as conn:
                conn.sendall(b"GET /upgrade/run HTTP/1.1\r\nHost: local\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
                assert header(conn).startswith(b"HTTP/1.1 101 ")
                time.sleep(0.6)
                conn.sendall(b"tunnel remains open")
                assert conn.recv(100) == b"tunnel remains open", "response budget leaked into an upgraded connection"
            events = [json.loads(line) for line in server.log.read_text().splitlines() if line.startswith('{"event":"server.write_timeout"')]
            assert len(events) >= 6 and all(row["protocol"] == "h1" and row["stream_id"] == 0 for row in events)
            server.health()
            print(f"ok: {'TLS' if secure else 'plain'} interim responses, keep-alive and upgraded tunnels have separate lifetimes")
        finally:
            server.close()
