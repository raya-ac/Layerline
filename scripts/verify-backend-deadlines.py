#!/usr/bin/env python3
"""Backend progress must not renew an attempt's absolute deadline."""
import http.server
import json
import pathlib
import signal
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
BINARY = pathlib.Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / "zig-out/bin/layerline"


def exact(conn, count):
    data = b""
    while len(data) < count:
        piece = conn.recv(count - len(data))
        if not piece:
            raise EOFError
        data += piece
    return data


class HTTP(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def do_GET(self):
        kind = self.path.strip("/").split("/")[0]
        self.close_connection = True
        probe = self.headers.get("User-Agent") == "Layerline-healthcheck"
        started = time.monotonic()
        try:
            if self.server.fallback:
                body = b"fallback"
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            if kind == "upgrade":
                self.send_response_only(101)
                self.send_header("Connection", "Upgrade")
                self.send_header("Upgrade", "websocket")
                self.end_headers()
                self.wfile.flush()
                self.connection.settimeout(2)
                while True:
                    data = self.connection.recv(1024)
                    if not data:
                        return
                    self.connection.sendall(data)
            if kind in ["headers", "retry"]:
                reply = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                for byte in reply:
                    self.connection.sendall(bytes([byte]))
                    time.sleep(0.04)
                return
            if kind in ["okay", "pooled"]:
                time.sleep(0.12)
            if kind == "combined":
                time.sleep(0.21)
            self.send_response(200)
            if kind == "chunked":
                self.send_header("Transfer-Encoding", "chunked")
            elif kind != "unknown":
                self.send_header("Content-Length", "2" if kind in ["okay", "pooled", "combined"] else "64")
            if kind == "pooled" and self.headers.get("Connection", "").lower() == "keep-alive":
                self.close_connection = False
                self.server.pooled.add(self.connection.fileno())
            self.send_header("Connection", "close" if self.close_connection else "keep-alive")
            self.end_headers()
            self.wfile.flush()
            if kind == "combined":
                time.sleep(0.21)
            if kind in ["okay", "pooled", "combined"]:
                self.wfile.write(b"ok")
                return
            for _ in range(64):
                self.wfile.write(b"1\r\nx\r\n" if kind == "chunked" else b"x")
                self.wfile.flush()
                time.sleep(0.07)
            if kind == "chunked":
                self.wfile.write(b"0\r\n\r\n")
        except (ConnectionError, TimeoutError):
            pass
        finally:
            if probe:
                self.server.probe_times.append(time.monotonic() - started)

    def do_POST(self):
        self.close_connection = True
        if self.path.startswith("/retry-write-"):
            try:
                self.rfile.read(int(self.headers.get("Content-Length", "0")))
                self.server.posts.append(self.path)
                reply = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
                if self.server.fallback:
                    self.connection.sendall(reply)
                else:
                    for byte in reply:
                        self.connection.sendall(bytes([byte]))
                        time.sleep(0.04)
            except (ConnectionError, TimeoutError):
                pass
            return
        self.connection.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
        try:
            for _ in range(100):
                time.sleep(0.07)
                if not self.rfile.read(1024):
                    return
        except (ConnectionError, TimeoutError):
            pass


class FastCGI(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        pending = b""
        try:
            while True:
                version, kind, request_id, count, padding, _ = struct.unpack("!BBHHBB", exact(self.request, 8))
                assert version == 1 and request_id == 1
                payload = exact(self.request, count)
                exact(self.request, padding)
                if kind == 1:
                    pending = b""
                elif kind == 4:
                    pending += payload
                elif kind == 5 and not payload:
                    slow_header = b"slow-header" in pending
                    fast = b"fast" in pending or b"close-after" in pending
                    body = b"Content-Type: text/plain\r\n\r\nok"
                    header = struct.pack("!BBHHBB", 1, 6, 1, len(body), 0, 0)
                    if slow_header:
                        for byte in header:
                            self.request.sendall(bytes([byte]))
                            time.sleep(0.08)
                    else:
                        self.request.sendall(header)
                    if fast:
                        self.request.sendall(body)
                    else:
                        for byte in body:
                            self.request.sendall(bytes([byte]))
                            time.sleep(0.08)
                    self.request.sendall(struct.pack("!BBHHBB", 1, 6, 1, 0, 0, 0))
                    self.request.sendall(struct.pack("!BBHHBB", 1, 3, 1, 8, 0, 0) + bytes(8))
                    if b"close-after" in pending:
                        return
        except (EOFError, ConnectionError, TimeoutError):
            pass


class FPM(socketserver.ThreadingTCPServer):
    daemon_threads = True


class UnixFPM(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True


with tempfile.TemporaryDirectory(prefix="ll-backend-", dir="/tmp") as temporary:
    folder = pathlib.Path(temporary)
    (folder / "index.php").write_text("<?php // Path fixture; only the mock FPM handles it.\n")
    upload = folder / "upload.bin"
    upload.write_bytes(bytes(4 * 1024 * 1024))
    backends = []
    for fallback in [False, True]:
        backend = HTTP(("127.0.0.1", 0), Handler)
        backend.fallback, backend.pooled, backend.posts, backend.probe_times = fallback, set(), [], []
        backends.append(backend)
    fpm = FPM(("127.0.0.1", 0), FastCGI)
    unix = UnixFPM(str(folder / "fpm.sock"), FastCGI)
    backends += [fpm, unix]
    for backend in backends:
        threading.Thread(target=backend.serve_forever, daemon=True).start()

    try:
        for secure in [False, True]:
            backends[0].probe_times.clear()
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]
            routes = ""
            for kind in ["headers", "fixed", "chunked", "unknown", "combined", "okay", "pooled", "retry", "retry-write-h1", "retry-write-h2", "upload", "upgrade"]:
                targets = backends[:2] if kind.startswith("retry") else backends[:1]
                routes += f"route = {kind} /{kind}/* proxy\nroute_proxy.{kind} = " + " ".join(f"http://localhost:{backend.server_port}" for backend in targets) + "\n"
                if kind.startswith("retry"):
                    routes += f"route_upstream_policy.{kind} = sticky_cookie\n"
            config = folder / "server.conf"
            access = folder / ("tls-access.jsonl" if secure else "plain-access.jsonl")
            config.write_text(f"""host = 127.0.0.1
port = {port}
tls = {str(secure).lower()}
access_log = {access}
php_root = {folder}
php_front_controller = true
upstream_timeout_ms = 350
upstream_retries = 1
upstream_keepalive = true
fastcgi_keepalive = true
read_body_timeout_ms = 3000
write_timeout_ms = 3000
max_body_bytes = 8388608
graceful_shutdown_timeout_ms = 1000
route = fpm /fpm/* php
route_php_index.fpm = index.php
route_php_fastcgi.fpm = localhost:{fpm.server_address[1]}
route_php_timeout_ms.fpm = 350
route = unix /unix/* php
route_php_index.unix = index.php
route_php_fastcgi.unix = unix:{folder}/fpm.sock
route_php_timeout_ms.unix = 350
route = probe /probe-unused/* proxy
route_proxy.probe = http://localhost:{backends[0].server_port}
route_upstream_health_check.probe = true
route_upstream_health_check_path.probe = /headers/check
route_upstream_health_check_timeout_ms.probe = 350
route_upstream_health_check_interval_ms.probe = 30000
{routes}""")
            log_path = folder / ("tls.log" if secure else "plain.log")
            process = None
            scheme = "https" if secure else "http"

            def request(path, protocol, data=None):
                (folder / "body").unlink(missing_ok=True)
                command = ["curl", "-skS", "--max-time", "1.4", protocol, "-o", str(folder / "body"), "-w", "%{http_code} %{http_version}"]
                if data:
                    command += ["--data-binary", "@" + str(data)]
                if path.startswith("retry"):
                    command += ["-H", "Cookie: ll_upstream=0"]
                command += [f"{scheme}://127.0.0.1:{port}/{path}"]
                started = time.monotonic()
                reply = subprocess.run(command, capture_output=True, text=True)
                elapsed = time.monotonic() - started
                assert elapsed < 1.2, ("backend progress renewed deadline", path, elapsed, reply.stderr)
                status, version = reply.stdout.split()
                assert version == ("1.1" if protocol == "--http1.1" else "2"), reply.stdout
                body = (folder / "body").read_bytes() if (folder / "body").exists() else b""
                return int(status), body, reply.returncode

            def failures():
                status, body, code = request("metrics", "--http1.1")
                assert status == 200 and code == 0
                return int(next(line.split()[1] for line in body.decode().splitlines() if line.startswith("layerline_upstream_failures_total ")))

            try:
                with log_path.open("wb") as log:
                    process = subprocess.Popen([str(BINARY), "--config", str(config)], cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
                    until = time.monotonic() + 4
                    while True:
                        assert process.poll() is None, log_path.read_text()
                        try:
                            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                                break
                        except OSError:
                            assert time.monotonic() < until
                            time.sleep(0.02)
                    for protocol in ["--http1.1", "--http2" if secure else "--http2-prior-knowledge"]:
                        for kind in ["headers", "fixed", "chunked", "unknown", "combined"]:
                            before = failures() if protocol == "--http1.1" and kind != "headers" else None
                            status, body, code = request(kind + "/check", protocol)
                            expected = 200 if protocol == "--http1.1" and kind != "headers" else 504
                            assert status == expected, (kind, protocol, status, body)
                            if expected == 200:
                                assert (code == 0 if kind == "unknown" else code != 0) and len(body) < 64, (kind, body, code)
                            else:
                                assert code == 0, (kind, code)
                            if before is not None:
                                assert failures() == before, "streamed attempt timeout falsely penalized backend health"
                        assert request("okay/check", protocol) == (200, b"ok", 0)
                        for route in ["fpm", "unix"]:
                            for query in ["slow-header", "slow-body"]:
                                reply = request(f"{route}/check?{query}", protocol)
                                assert reply[0] == 504, (route, query, protocol, reply[0], reply[1][:160], reply[2])
                            assert request(f"{route}/check?fast", protocol) == (200, b"ok", 0)
                        assert request("retry/check", protocol) == (200, b"fallback", 0)
                        assert request("fpm/check?close-after", protocol) == (200, b"ok", 0)
                        assert request("fpm/check?fast", protocol)[0] == 502
                        assert request("fpm/check?fast", protocol) == (200, b"ok", 0)
                        tiny = folder / "post.txt"
                        tiny.write_bytes(b"one application write")
                        route = "retry-write-h1" if protocol == "--http1.1" else "retry-write-h2"
                        primary, fallback = len(backends[0].posts), len(backends[1].posts)
                        reply = request(f"{route}/check", protocol, tiny)
                        assert reply[0] == 504, (route, protocol, reply[0], reply[1][:200], reply[2], backends[0].posts, backends[1].posts)
                        assert len(backends[0].posts) == primary + 1 and len(backends[1].posts) == fallback, "non-idempotent request was replayed"
                    assert request("upload/check", "--http1.1", upload)[0] == 504
                    for _ in range(2):
                        assert request("pooled/check", "--http1.1") == (200, b"ok", 0)
                        assert request("fpm/check?fast", "--http1.1") == (200, b"ok", 0)
                        time.sleep(0.4)
                    assert backends[0].pooled, "keep-alive path was not exercised"
                    assert backends[0].probe_times and max(backends[0].probe_times) < 1, ("health probe progress renewed its deadline", backends[0].probe_times)
                    raw = socket.create_connection(("127.0.0.1", port), timeout=2)
                    if secure:
                        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
                        ctx.set_alpn_protocols(["http/1.1"])
                        raw = ctx.wrap_socket(raw, server_hostname="localhost")
                    with raw:
                        raw.sendall(f"GET /upgrade/check HTTP/1.1\r\nHost: localhost:{port}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n".encode())
                        head = b""
                        while not head.endswith(b"\r\n\r\n"):
                            head += exact(raw, 1)
                        assert head.startswith(b"HTTP/1.1 101"), head
                        for _ in range(6):
                            time.sleep(0.1)
                            raw.sendall(b"x")
                            assert exact(raw, 1) == b"x"
                    events = [json.loads(line) for line in log_path.read_text().splitlines() if line.startswith('{"event":"server.backend_timeout"')]
                    assert len(events) >= 10, ("backend deadlines were not logged", events)
                    assert all(set(event) == {"event", "phase"} for event in events), events
                    assert all(event["phase"] in ["connect", "read", "write"] for event in events), events
            except BaseException:
                print(log_path.read_text(), file=sys.stderr)
                if access.exists():
                    print("\n".join(access.read_text().splitlines()[-5:]), file=sys.stderr)
                raise
            finally:
                if process is not None and process.poll() is None:
                    process.send_signal(signal.SIGTERM)
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=2)
            print(f"ok: {'TLS' if secure else 'plain'} HTTP/1+HTTP/2 backend attempt deadlines, retries, FastCGI, reuse and tunnel lifetimes")
    finally:
        for backend in backends:
            backend.shutdown()
            backend.server_close()
