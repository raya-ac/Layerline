#!/usr/bin/env python3
"""Keep real readers alive while replacing and reclaiming config generations."""
import collections
import http.client
import http.server
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
ADMIN = "/_layerline/admin"


def exact(conn, count):
    result = b""
    while len(result) < count:
        part = conn.recv(count - len(result))
        if not part:
            raise EOFError("connection closed during reload")
        result += part
    return result


def frame(kind, flags, stream, payload=b""):
    return len(payload).to_bytes(3, "big") + bytes([kind, flags]) + stream.to_bytes(4, "big") + payload


def literal(name, value):
    assert len(name) < 127 and len(value) < 127
    return b"\0" + bytes([len(name)]) + name + bytes([len(value)]) + value


class H2:
    def __init__(self, port, secure):
        self.conn = socket.create_connection(("127.0.0.1", port), timeout=4)
        if secure:
            context = ssl._create_unverified_context()
            context.set_alpn_protocols(["h2"])
            self.conn = context.wrap_socket(self.conn, server_hostname="reload.test")
            assert self.conn.selected_alpn_protocol() == "h2"
        self.responses = {}
        self.conn.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 0, 0, struct.pack("!HI", 4, 0)))

    def request(self, stream, path):
        block = b"\x82" + (b"\x87" if isinstance(self.conn, ssl.SSLSocket) else b"\x86")
        block += literal(b":authority", b"reload.test") + literal(b":path", path.encode())
        self.responses[stream] = {"status": None, "body": b"", "done": False}
        self.conn.sendall(frame(1, 5, stream, block))

    def receive(self):
        header = exact(self.conn, 9)
        length, kind, flags, stream = int.from_bytes(header[:3], "big"), header[3], header[4], int.from_bytes(header[5:], "big")
        payload = exact(self.conn, length)
        assert kind not in [3, 7], ("unexpected reset/goaway", kind, stream, payload)
        if kind == 4 and not flags & 1:
            self.conn.sendall(frame(4, 1, 0))
        if kind in [0, 1] and stream in self.responses:
            response = self.responses[stream]
            if kind == 1:
                # Layerline puts the indexed :status first, without a table update.
                response["status"] = {0x88: 200, 0x8d: 404}.get(payload[0], payload[:30])
            else:
                response["body"] += payload
            response["done"] |= bool(flags & 1)

    def headers(self, stream):
        while self.responses[stream]["status"] is None:
            self.receive()
        return self.responses[stream]

    def finish(self, stream):
        self.conn.sendall(frame(8, 0, stream, (65535).to_bytes(4, "big")))
        while not self.responses[stream]["done"]:
            self.receive()
        return self.responses[stream]

    def close(self):
        self.conn.close()


class HTTP(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def setup(self):
        super().setup()
        self.connection.settimeout(10)
        with self.server.lock:
            self.server.open_connections += 1

    def finish(self):
        try:
            super().finish()
        finally:
            with self.server.lock:
                self.server.open_connections -= 1

    def log_message(self, *_):
        pass

    def do_GET(self):
        with self.server.lock:
            self.server.paths[self.path] += 1
        if self.path.endswith("/hold"):
            self.server.entered.set()
            if not self.server.release.wait(timeout=120):
                self.server.hold_expired.set()
                self.close_connection = True
                return
        self.send_response(200)
        self.send_header("Content-Length", "7")
        self.end_headers()
        self.wfile.write(b"backend")


class FastCGI(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
        self.request.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        with self.server.lock:
            self.server.connections += 1
            self.server.open_connections += 1
        try:
            while True:
                version, kind, request_id, count, padding, _ = struct.unpack("!BBHHBB", exact(self.request, 8))
                assert version == 1 and request_id == 1
                exact(self.request, count + padding)
                if kind == 5 and count == 0:
                    body = b"Content-Type: text/plain\r\n\r\nfpm"
                    packet = struct.pack("!BBHHBB", 1, 6, 1, len(body), 0, 0) + body
                    packet += struct.pack("!BBHHBB", 1, 6, 1, 0, 0, 0)
                    packet += struct.pack("!BBHHBB", 1, 3, 1, 8, 0, 0) + bytes(8)
                    self.request.sendall(packet)
                    with self.server.lock:
                        self.server.requests += 1
        except (EOFError, ConnectionError, TimeoutError):
            pass
        finally:
            with self.server.lock:
                self.server.open_connections -= 1


class FPM(socketserver.ThreadingTCPServer):
    daemon_threads = True
    request_queue_size = 64


def wait_until(check, description, timeout=4):
    until = time.monotonic() + timeout
    while True:
        if check():
            return
        assert time.monotonic() < until, description
        time.sleep(0.02)


with tempfile.TemporaryDirectory(prefix="ll-reload-", dir="/tmp") as temporary:
    folder = pathlib.Path(temporary)
    roots = {}
    for name in ["a", "b"]:
        root = folder / name
        root.mkdir()
        (root / "index.html").write_text(name)
        (root / "404.html").write_text("missing-" + name)
        (root / "script.php").write_text("<?php // Mock FPM owns this request.\n")
        roots[name] = root
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "1", "-subj", "/CN=reload.test", "-keyout", str(folder / "key.pem"), "-out", str(folder / "cert.pem")], check=True, capture_output=True)
    backend = HTTP(("127.0.0.1", 0), Handler)
    backend.lock, backend.open_connections, backend.paths = threading.Lock(), 0, collections.Counter()
    backend.entered, backend.release, backend.hold_expired = threading.Event(), threading.Event(), threading.Event()
    fpm = FPM(("127.0.0.1", 0), FastCGI)
    fpm.lock, fpm.connections, fpm.requests, fpm.open_connections = threading.Lock(), 0, 0, 0
    threads = []
    for server in [backend, fpm]:
        thread = threading.Thread(target=server.serve_forever)
        thread.start()
        threads.append(thread)
    try:
        for secure in [False, True]:
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]
            config, admin = folder / "server.conf", folder / "admin.sock"
            log_path = folder / ("tls.log" if secure else "plain.log")
            held, h2, process = None, None, None
            started = time.monotonic()

            def write_config(name, health=False, ui=True):
                config.write_text(f"""host = 127.0.0.1
port = {port}
tls = {str(secure).lower()}
tls_cert = {folder}/cert.pem
tls_key = {folder}/key.pem
dir = {roots[name]}
serve_static_root = true
server = site
server_name.site = reload.test
server_root.site = {roots[name]}
php_root = {roots[name]}
php_fastcgi = 127.0.0.1:{fpm.server_address[1]}
admin_socket = {admin}
admin_ui = {str(ui).lower()}
admin_credentials_path = {folder}/owner.creds
idle_timeout_ms = 120000
write_timeout_ms = 120000
upstream_timeout_ms = 120000
upstream_keepalive_idle_timeout_ms = 60000
fastcgi_keepalive_idle_timeout_ms = 60000
fastcgi_keepalive_max_requests = 1000
graceful_shutdown_timeout_ms = 1000
route = app /app/* proxy
route_proxy.app = http://127.0.0.1:{backend.server_port}
route = fast /fast/* proxy
route_proxy.fast = http://127.0.0.1:{backend.server_port}
route_upstream_health_check.fast = {str(health).lower()}
route_upstream_health_check_path.fast = /health-fast
route_upstream_health_check_interval_ms.fast = 100
route = slow /slow/* proxy
route_proxy.slow = http://127.0.0.1:{backend.server_port}
route_upstream_health_check.slow = {str(health).lower()}
route_upstream_health_check_path.slow = /health-slow
route_upstream_health_check_interval_ms.slow = 800
upstream_health_check_interval_ms = 30000
""")

            def connect():
                conn = http.client.HTTPSConnection("127.0.0.1", port, timeout=4, context=ssl._create_unverified_context()) if secure else http.client.HTTPConnection("127.0.0.1", port, timeout=4)
                return conn

            def request(path, conn=None):
                own = conn is None
                conn = conn or connect()
                try:
                    conn.request("GET", path, headers={"Host": "reload.test"})
                    response = conn.getresponse()
                    return response.status, response.read()
                finally:
                    if own:
                        conn.close()

            def reload(okay=True):
                with socket.socket(socket.AF_UNIX) as conn:
                    conn.settimeout(4)
                    conn.connect(str(admin))
                    conn.sendall(b"reload\n")
                    response = b""
                    while True:
                        part = conn.recv(4096)
                        if not part:
                            break
                        response += part
                assert response.startswith(b"OK " if okay else b"ERROR "), response

            def metrics():
                status, body = request("/metrics")
                assert status == 200
                return {line.split()[0]: int(line.split()[1]) for line in body.decode().splitlines() if line.startswith("layerline_config_")}

            try:
                write_config("a")
                with log_path.open("wb") as log:
                    process = subprocess.Popen([str(BINARY), "--config", str(config)], cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)

                    def ready():
                        assert process.poll() is None, log_path.read_text()
                        try:
                            return admin.exists() and request("/") == (200, b"a")
                        except (OSError, http.client.HTTPException):
                            return False

                    wait_until(ready, "reload fixture failed to start")
                    write_config("b")
                    reload()
                    held = connect()
                    assert request("/", held) == (200, b"b")
                    held_socket = held.sock
                    assert request(ADMIN, held)[0] == 200
                    assert request("/app/pool") == (200, b"backend")
                    h2 = H2(port, secure)
                    h2.request(1, "/missing")
                    assert h2.headers(1)["status"] == 404
                    assert not h2.responses[1]["body"], "zero-window stream sent body"
                    backend.entered.clear()
                    backend.release.clear()
                    backend.hold_expired.clear()
                    h2.request(3, "/app/hold")
                    assert backend.entered.wait(timeout=4), "H2 child never reached backend"
                    with fpm.lock:
                        first_requests, first_connections = fpm.requests, fpm.connections
                    for number in range(96):
                        name = "a" if number % 2 else "b"
                        write_config(name)
                        reload()
                        assert request("/") == (200, name.encode())
                        assert request("/app/pool") == (200, b"backend")
                        assert request("/script.php") == (200, b"fpm")
                    # Check the lifetime limit first so old binaries fail for the actual regression.
                    assert metrics()["layerline_config_generation"] == 98
                    wait_until(lambda: metrics()["layerline_config_snapshots"] == 2, "unleased snapshots were retained")
                    stats = metrics()
                    assert 0 < stats["layerline_config_owned_bytes"] < 4 * 1024 * 1024, stats
                    old_error = request("/missing", held)
                    assert old_error == (404, b"missing-b"), old_error
                    assert held.sock is held_socket, "HTTP/1 reader silently reconnected"
                    assert request("/missing") == (404, b"missing-a")
                    assert h2.finish(1)["body"] == b"missing-b"
                    assert not backend.hold_expired.is_set(), ("mock backend hold expired during reload loop", time.monotonic() - started)
                    backend.release.set()
                    reply = h2.finish(3)
                    assert reply["status"] == 200 and reply["body"] == b"backend", (reply["status"], reply["body"][:180], time.monotonic() - started)
                    h2.request(5, "/")
                    assert h2.finish(5)["body"] == b"b"
                    wait_until(lambda: fpm.requests - first_requests == 96, "FPM request accounting incomplete")
                    with fpm.lock:
                        assert fpm.requests - first_requests == 96, fpm.requests
                        assert fpm.connections - first_connections == 1, ("FPM was not reused across freed arenas", fpm.connections)
                    wait_until(lambda: backend.open_connections <= 4, "retired HTTP pools left idle connections open")
                    generation = metrics()["layerline_config_generation"]
                    with config.open("a") as output:
                        output.write("port = not-a-port\n")
                    reload(okay=False)
                    assert metrics()["layerline_config_generation"] == generation
                    assert request("/") == (200, b"a")

                    with backend.lock:
                        backend.paths.clear()
                    write_config("a", health=True, ui=False)
                    reload()
                    assert request(ADMIN, held)[0] == 404, "old HTTP/1 connection bypassed admin disable"
                    assert held.sock is held_socket, "admin revocation was not checked on the held reader"
                    h2.request(7, ADMIN)
                    assert h2.headers(7)["status"] == 404, "old HTTP/2 connection bypassed admin disable"
                    h2.finish(7)
                    time.sleep(1.3)
                    with backend.lock:
                        fast, slow = backend.paths["/health-fast"], backend.paths["/health-slow"]
                    assert fast >= 4 and 1 <= slow <= 3 and fast >= slow * 2, ("health reload/interval", fast, slow)
                    held.close()
                    held = None
                    h2.close()
                    h2 = None
                    wait_until(lambda: metrics()["layerline_config_snapshots"] == 1, "last reader did not reclaim its config")
                    assert metrics()["layerline_config_readers"] <= 2
                    process.send_signal(signal.SIGTERM)
                    assert process.wait(timeout=4) == 0, log_path.read_text()
                    assert "panic" not in log_path.read_text().lower(), log_path.read_text()
                    wait_until(lambda: backend.open_connections == 0 and fpm.open_connections == 0, "shutdown retained backend pool sockets")
                print(f"ok: {'TLS/ALPN' if secure else 'plain/h2c'} reload leases, 96 replacements, pool cleanup, health refresh and admin revocation ({time.monotonic() - started:.1f}s)", flush=True)
            except BaseException:
                print(log_path.read_text()[-6000:], file=sys.stderr)
                raise
            finally:
                backend.release.set()
                if held:
                    held.close()
                if h2:
                    h2.close()
                if process is not None and process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=4)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=4)
    finally:
        for server in [backend, fpm]:
            server.shutdown()
            server.server_close()
        for thread in threads:
            thread.join(timeout=4)
