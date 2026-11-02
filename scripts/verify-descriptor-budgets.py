#!/usr/bin/env python3
"""Fill managed descriptor capacity in isolated low-RLIMIT children, then recover."""
import http.server
import os
from pathlib import Path
import shlex
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

if sys.platform not in ["darwin", "linux"]:
    print("skip: native descriptor admission requires Linux or macOS")
    raise SystemExit(0)

import resource
from wire_h2 import H2

if len(sys.argv) > 1 and sys.argv[1] == "--limited":
    soft, extra = int(sys.argv[2]), int(sys.argv[3])
    resource.setrlimit(resource.RLIMIT_NOFILE, (soft, soft))
    for _ in range(extra):
        fd = os.open("/dev/null", os.O_RDONLY)
        os.set_inheritable(fd, True)
    os.execv(sys.argv[4], sys.argv[4:])

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / "zig-out/bin/layerline"
WORKER = Path(os.environ.get("LAYERLINE_CHILD_WORKER", BINARY.with_name("child-process-worker"))).resolve()
if not WORKER.is_file() or not os.access(WORKER, os.X_OK):
    raise RuntimeError(f"native child fixture missing: {WORKER}; build with 'zig build test-tools' or set LAYERLINE_CHILD_WORKER")
NORMAL = 'layerline_descriptor_owned_by_pool{pool="normal"}'
RESERVATIONS = 'layerline_descriptor_reservations{pool="normal"}'
NORMAL_LIMIT = 'layerline_descriptor_limit{pool="normal"}'
DATA = b"descriptor capacity recovered"


def wait_for(check, label, seconds=5):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        if value := check():
            return value
        time.sleep(.02)
    raise AssertionError(label)


def command(path, text):
    with socket.socket(socket.AF_UNIX) as peer:
        peer.settimeout(3)
        peer.connect(str(path))
        peer.sendall(text.encode() + b"\n")
        data = bytearray()
        while part := peer.recv(16384):
            data.extend(part)
            assert len(data) < 1048576
        return data.decode()


def metrics(path):
    return {line.rsplit(" ", 1)[0]: int(line.rsplit(" ", 1)[1]) for line in command(path, "metrics").splitlines() if line and not line.startswith("#")}


def port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=4)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=4)
            raise AssertionError("descriptor pressure prevented joined shutdown")


class HTTP1:
    def __init__(self, number, tls):
        self.socket = socket.create_connection(("127.0.0.1", number), timeout=3)
        if tls:
            self.socket = ssl._create_unverified_context().wrap_socket(self.socket, server_hostname="localhost")

    def request(self, method, path, close=False):
        connection = b"close" if close else b"keep-alive"
        self.socket.sendall(method.encode() + b" " + path.encode() + b" HTTP/1.1\r\nHost: localhost\r\nConnection: " + connection + b"\r\n\r\n")
        headers = bytearray()
        while not headers.endswith(b"\r\n\r\n"):
            part = self.socket.recv(1)
            assert part, headers
            headers.extend(part)
            assert len(headers) < 65536
        fields = dict(line.lower().split(b":", 1) for line in bytes(headers).split(b"\r\n")[1:] if b":" in line)
        assert b"transfer-encoding" not in fields, fields
        body = bytearray()
        if close:
            while True:
                try:
                    part = self.socket.recv(16384)
                except ConnectionResetError:
                    break
                if not part:
                    break
                body.extend(part)
        else:
            expected = 0 if method == "HEAD" else int(fields[b"content-length"])
            while len(body) < expected:
                part = self.socket.recv(expected - len(body))
                assert part, (headers, body)
                body.extend(part)
        if method == "HEAD":
            assert not body, ("HEAD included payload", body[:80])
        else:
            assert len(body) == int(fields[b"content-length"]), (headers, len(body))
        return int(headers.split(b" ", 2)[1]), bytes(body)

    def close(self):
        self.socket.close()


class Backend(http.server.ThreadingHTTPServer):
    daemon_threads = True


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.hits.append(self.path)
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *_):
        pass


with tempfile.TemporaryDirectory(prefix="layerline-fds-", dir="/tmp") as temporary:
    root = Path(temporary)
    invalid_config = root / "invalid.conf"
    invalid_config.write_text(f"host = 127.0.0.1\nport = {port()}\nadmin = false\nadmin_ui = false\n")
    for setting in ["31", "1048577", "-1", "invalid"]:
        result = subprocess.run([str(BINARY), "--config", str(invalid_config), "--descriptor-limit", setting], cwd=ROOT, capture_output=True, timeout=5)
        assert result.returncode != 0 and b"InvalidConfigValue" in result.stderr, (setting, result.stderr)
    result = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--limited", "64", "12", str(BINARY), "--config", str(invalid_config)], cwd=ROOT, capture_output=True, timeout=5)
    assert result.returncode != 0 and b"DescriptorLimitTooLow" in result.stderr, result.stderr
    print("ok: invalid descriptor CLI values and insufficient kernel headroom fail startup", flush=True)
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "1", "-subj", "/CN=localhost", "-keyout", str(root / "key.pem"), "-out", str(root / "cert.pem")], check=True, capture_output=True)
    backend = Backend(("127.0.0.1", 0), Handler)
    backend.hits = []
    thread = threading.Thread(target=backend.serve_forever, daemon=True)
    thread.start()
    try:
        for tls, requested in [(False, 32), (True, 32), (False, 4096), (True, 4096)]:
            folder = root / f"{tls}-{requested}"
            folder.mkdir()
            (folder / "pids").mkdir()
            (folder / "fast.txt").write_bytes(DATA)
            (folder / "index.php").write_text("<?php // Only the harmless fixture process executes this path.\n")
            php = folder / "php-cgi"
            php.write_text(f"#!/bin/sh\nexec {shlex.quote(str(WORKER))} --cgi {shlex.quote(str(folder))}\n")
            php.chmod(0o700)
            number = port()
            admin, config, log = folder / "admin.sock", folder / "server.conf", folder / "server.log"
            original = f"""host = 127.0.0.1
port = {number}
dir = {folder}
serve_static_root = true
php_root = {folder}
php_binary = {php}
admin = true
admin_ui = false
admin_socket = {admin}
descriptor_limit = {requested}
max_concurrent_connections = 512
read_header_timeout_ms = 20000
idle_timeout_ms = 20000
upstream_timeout_ms = 2500
upstream_max_failures = 1
upstream_retries = 2
upstream_keepalive = false
graceful_shutdown_timeout_ms = 1200
tls = {str(tls).lower()}
tls_cert = {root / 'cert.pem'}
tls_key = {root / 'key.pem'}
route = backend /backend/* proxy
route_proxy.backend = http://127.0.0.1:{backend.server_port}
route = dns /dns/* proxy
route_proxy.dns = http://localhost:{backend.server_port}
"""
            config.write_text(original)
            process, h2 = None, None
            clients, idle = [], []
            try:
                with log.open("wb") as output:
                    process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--limited", "128", "12", str(BINARY), "--config", str(config), "--descriptor-limit", str(requested)], cwd=ROOT, stdout=output, stderr=output)
                wait_for(lambda: process.poll() is not None or '"event":"server.ready"' in log.read_text(), "server did not become ready")
                assert process.poll() is None, log.read_text()
                initial = metrics(admin)
                assert initial["layerline_descriptor_enabled"] == 1
                assert initial["layerline_descriptor_kernel_limit"] == 128
                assert initial["layerline_descriptor_inherited"] >= 15
                effective = min(requested, 128 - initial["layerline_descriptor_inherited"] - 32)
                assert initial["layerline_descriptor_effective_limit"] == effective
                assert initial["layerline_descriptor_configured_limit"] == requested
                h2 = H2(number, tls=tls)
                h2.request(1, b"/health")
                assert h2.response(1)[0] == 200
                base = metrics(admin)[NORMAL]
                stream = 1
                for cycle in range(3):
                    head = HTTP1(number, tls)
                    php_client = HTTP1(number, tls)
                    clients.extend([head, php_client])
                    assert head.request("GET", "/fast.txt") == (200, DATA)
                    assert php_client.request("GET", "/fast.txt") == (200, DATA)
                    stream += 2
                    h2.request(stream, b"/backend/warm")
                    assert h2.response(stream) == (200, b"ok")
                    wait_for(lambda: metrics(admin)[NORMAL] == base + 2, "warm backend descriptor did not close")

                    def fill():
                        # Close unregisters the handle before releasing its slot.
                        # Refill only after both parts of that ownership change finish.
                        current = wait_for(lambda: (m if (m := metrics(admin))[NORMAL] == m[RESERVATIONS] else None), "descriptor reservations did not settle before refill")
                        needed = current[NORMAL_LIMIT] - current[NORMAL]
                        for _ in range(needed):
                            idle.append(socket.create_connection(("127.0.0.1", number), timeout=3))
                        return wait_for(lambda: (m if (m := metrics(admin))[NORMAL] == m[NORMAL_LIMIT] else None), "normal descriptor partition did not fill")

                    observed = fill()
                    assert "Layerline" in command(admin, "status")
                    assert command(admin, "validate-runtime").startswith("OK runtime config"), "protected validation failed"
                    if sys.platform == "linux":
                        assert len(list(Path(f"/proc/{process.pid}/fd").iterdir())) < 112, "kernel descriptor headroom was exhausted"
                    hits = len(backend.hits)
                    for path, expected in [(b"/health", 200), (b"/fast.txt", 503), (b"/backend/denied", 503), (b"/dns/denied", 503)]:
                        stream += 2
                        h2.request(stream, path)
                        assert h2.response(stream)[0] == expected, (path, expected)
                        h2.ping()
                    assert len(backend.hits) == hits, "descriptor pressure reached an upstream"
                    assert metrics(admin)["layerline_upstream_failures_total"] == 0, "local descriptor pressure poisoned upstream health"
                    assert head.request("HEAD", "/fast.txt", close=True)[0] == 503
                    head.close()
                    clients.remove(head)
                    wait_for(lambda: metrics(admin)[NORMAL] < observed[NORMAL_LIMIT], "closed HEAD peer did not release its descriptor")
                    fill()
                    pids = set((folder / "pids").iterdir())
                    assert php_client.request("GET", "/index.php", close=True)[0] == 503
                    php_client.close()
                    clients.remove(php_client)
                    assert set((folder / "pids").iterdir()) == pids, "CGI launched despite full descriptor admission"
                    wait_for(lambda: metrics(admin)[NORMAL] < observed[NORMAL_LIMIT], "closed CGI peer did not release its descriptor")
                    fill()
                    rejected = socket.create_connection(("127.0.0.1", number), timeout=3)
                    try:
                        if tls:
                            try:
                                session = ssl._create_unverified_context().wrap_socket(rejected, server_hostname="localhost")
                            except (ssl.SSLError, ConnectionError):
                                pass
                            else:
                                session.close()
                                raise AssertionError("overloaded TLS admission unexpectedly completed a handshake")
                        else:
                            rejected.sendall(b"GET /health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                            reply = bytearray()
                            while True:
                                try:
                                    part = rejected.recv(16384)
                                except ConnectionResetError:
                                    break
                                if not part:
                                    break
                                reply.extend(part)
                            assert reply.startswith(b"HTTP/1.1 503 ") and reply.endswith(b"server busy\n"), reply
                    finally:
                        rejected.close()
                    config.write_text(original + f"descriptor_limit = {requested + 1}\n")
                    assert "global.descriptor_limit" in command(admin, "diff")
                    assert "ReloadRequiresRestart" in command(admin, "reload")
                    config.write_text(original)
                    generation = metrics(admin)["layerline_config_generation"]
                    process.send_signal(signal.SIGHUP)
                    wait_for(lambda: metrics(admin)["layerline_config_generation"] > generation, "SIGHUP reload lost reserved descriptors")
                    h2.ping()

                    # Leave enough capacity to validate the script, but not to
                    # create all four CGI pipes. Partial setup must roll back.
                    for _ in range(5):
                        idle.pop().close()
                    before = wait_for(lambda: (m if (m := metrics(admin))[NORMAL] == observed[NORMAL_LIMIT] - 5 else None), "idle descriptor capacity did not return")
                    partial = HTTP1(number, tls)
                    clients.append(partial)
                    assert partial.request("GET", "/index.php", close=True)[0] == 503
                    partial.close()
                    clients.remove(partial)
                    wait_for(lambda: metrics(admin)[NORMAL] == before[NORMAL], "partial CGI pipe setup leaked descriptors")
                    assert set((folder / "pids").iterdir()) == pids, "partial pipe admission forked a child"
                    for peer in idle:
                        peer.close()
                    idle.clear()
                    wait_for(lambda: metrics(admin)[NORMAL] == base, "descriptor capacity did not recover")
                    stream += 2
                    h2.request(stream, b"/fast.txt")
                    assert h2.response(stream) == (200, DATA)
                    stream += 2
                    h2.request(stream, b"/dns/recovered")
                    assert h2.response(stream) == (200, b"ok")
                    successful = HTTP1(number, tls)
                    clients.append(successful)
                    assert successful.request("GET", "/index.php", close=True) == (200, b"ok")
                    successful.close()
                    clients.remove(successful)
                    wait_for(lambda: metrics(admin)[NORMAL] == base, "completed CGI retained descriptors")
                    after = metrics(admin)
                    assert after['layerline_descriptor_rejections_total{pool="control"}'] == 0, after
                    for pool in ["normal", "control", "emergency"]:
                        assert after[f'layerline_descriptor_peak{{pool="{pool}"}}'] <= after[f'layerline_descriptor_limit{{pool="{pool}"}}']
                    assert after["layerline_upstream_failures_total"] == 0
                h2.close()
                h2 = None
                stop(process)
                assert process.returncode == 0, log.read_text()
                print(f"ok: {'TLS' if tls else 'plain'} descriptor limit {requested}->{effective}, inherited handles, H1/H2 saturation, protected control/reload, CGI rollback and repeated recovery", flush=True)
            except BaseException:
                print(log.read_text() if log.exists() else "server did not start", file=sys.stderr)
                raise
            finally:
                for client in clients:
                    client.close()
                for peer in idle:
                    peer.close()
                if h2 is not None:
                    h2.close()
                if process is not None:
                    stop(process)
    finally:
        backend.shutdown()
        backend.server_close()
        thread.join(timeout=2)
