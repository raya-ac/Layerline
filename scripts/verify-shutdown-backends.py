#!/usr/bin/env python3
"""Join long-budget backend work at shutdown without confusing FIN with cancellation."""
import argparse
import hashlib
import http.client
import json
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("binary", type=Path)
parser.add_argument("--output", type=Path)
args = parser.parse_args()
binary = args.binary.resolve(strict=True)
binary_hash = hashlib.sha256(binary.read_bytes()).hexdigest()
fixture_hash = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
results = []
if args.output:
    args.output.unlink(missing_ok=True)


def wait(check, message, timeout=5):
    until = time.monotonic() + timeout
    while not check():
        assert time.monotonic() < until, message
        time.sleep(.01)


class Backend:
    def __init__(self, mode):
        self.mode = mode
        self.started, self.closed, self.reply, self.release = (threading.Event() for _ in range(4))
        self.error = None
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(0 if mode == "dial" else 1)
        self.port = self.listener.getsockname()[1]
        self.filler = None
        self.worker = None
        if mode == "dial":
            # Linux drops new SYNs once this unaccepted queue is full.
            self.filler = socket.create_connection(("127.0.0.1", self.port), timeout=2)
        else:
            self.listener.settimeout(5)
            self.worker = threading.Thread(target=self.run)
            self.worker.start()

    def run(self):
        try:
            with self.listener.accept()[0] as peer:
                peer.settimeout(5)
                data = b""
                if self.mode == "tls-handshake":
                    data = peer.recv(4096)
                    assert data[:1] == b"\x16", "upstream did not begin TLS"
                else:
                    while not data.endswith(b"\r\n\r\n"):
                        block = peer.recv(1)
                        assert block, "upstream closed before its request"
                        data += block
                        assert len(data) < 8192
                    if self.mode == "body":
                        peer.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 100000\r\n\r\nx")
                    elif self.mode == "upgrade":
                        peer.sendall(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nready")
                self.started.set()
                if self.mode == "finish":
                    assert self.reply.wait(3)
                    peer.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello")
                while peer.recv(4096):
                    pass
                self.closed.set()
                # A tunnel's opposite writer stays alive until after server exit.
                assert self.release.wait(5)
        except BaseException as error:
            self.error = error
            self.started.set()

    def pending(self):
        if self.mode != "dial":
            return self.started.is_set()
        return any(len(fields) > 3 and fields[2].endswith(f":{self.port:04X}") and fields[3] == "02"
                   for line in Path("/proc/net/tcp").read_text().splitlines()[1:] if (fields := line.split()))

    def close(self):
        self.reply.set()
        self.release.set()
        self.listener.close()
        if self.filler:
            self.filler.close()
        if self.worker:
            self.worker.join(timeout=6)
            assert not self.worker.is_alive(), "backend fixture did not join"
        assert self.error is None, repr(self.error)


class Server:
    def __init__(self, folder, backend, secure, host="127.0.0.1", health=False):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            self.port = probe.getsockname()[1]
        self.log = folder / "server.log"
        config = folder / "server.conf"
        scheme = "https" if backend.mode == "tls-handshake" else "http"
        target = f"{scheme}://{host}:{backend.port}"
        if scheme == "https":
            target += " tls_ca_file=" + str(folder / "unused-ca.pem")
            # This trust source is valid; the fixture never sends a certificate.
            subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                            "-nodes", "-days", "1", "-subj", "/CN=fixture", "-addext", "basicConstraints=critical,CA:TRUE",
                            "-keyout", str(folder / "fixture.key"), "-out", str(folder / "unused-ca.pem")],
                           check=True, capture_output=True, timeout=10)
        config.write_text(f"""host = 127.0.0.1
port = {self.port}
admin = false
admin_ui = false
http3 = false
tls = {str(secure).lower()}
proxy = {target}
upstream_timeout_ms = 120000
upstream_retries = 0
upstream_health_check = {str(health).lower()}
upstream_health_check_interval_ms = 50
upstream_health_check_timeout_ms = 120000
graceful_shutdown_timeout_ms = 1000
""")
        self.output = self.log.open("wb")
        self.process = subprocess.Popen([str(binary), "--config", str(config)], cwd=folder, stdout=self.output, stderr=self.output)
        self.secure = secure
        try:
            wait(lambda: self.process.poll() is not None or '"event":"server.ready"' in self.log.read_text(), "server readiness")
            assert self.process.poll() is None, self.log.read_text()
        except BaseException:
            self.close()
            raise

    def connect(self):
        raw = socket.create_connection(("127.0.0.1", self.port), timeout=3)
        if not self.secure:
            return raw
        context = ssl._create_unverified_context()
        context.set_alpn_protocols(["http/1.1"])
        try:
            return context.wrap_socket(raw, server_hostname="localhost")
        except BaseException:
            raw.close()
            raise

    def stop(self):
        self.stopped_at = time.monotonic()
        self.process.send_signal(signal.SIGTERM)

    def finish(self):
        code = self.process.wait(timeout=3)
        elapsed = time.monotonic() - self.stopped_at
        text = self.log.read_text()
        assert code == 0, (code, elapsed, text)
        assert elapsed < 1.5, ("shutdown exceeded its original budget", elapsed)
        assert '"event":"server.shutdown_timeout"' not in text and "All connection and background workers stopped." in text, text
        assert "panic" not in text.lower(), text
        return elapsed

    def close(self):
        if self.process.poll() is None:
            self.process.kill()
            self.process.wait(timeout=3)
        self.output.close()


with tempfile.TemporaryDirectory(prefix="layerline-backend-shutdown-", dir="/tmp") as temporary:
    for secure in [False, True]:
        modes = [(mode, "127.0.0.1") for mode in ["head", "body", "upgrade", "tls-handshake"]]
        if sys.platform.startswith("linux"):
            modes += [("dial", host) for host in ["127.0.0.1", "localhost"]]
        for mode, host in modes:
            for disconnected in [False, True]:
                folder = Path(temporary) / f"{secure}-{mode}-{host}-{disconnected}"
                folder.mkdir()
                backend, server, client = Backend(mode), None, None
                try:
                    server = Server(folder, backend, secure, host)
                    client = server.connect()
                    extra = b"Connection: Upgrade\r\nUpgrade: websocket\r\n" if mode == "upgrade" else b"Connection: close\r\n"
                    client.sendall(b"GET /pending HTTP/1.1\r\nHost: localhost\r\n" + extra + b"\r\n")
                    wait(backend.pending, (mode, "backend work did not begin"))
                    if mode == "dial":
                        time.sleep(.10)
                        assert backend.pending(), "dial was not persistently stalled"
                    assert backend.error is None, repr(backend.error)
                    if disconnected:
                        client.close()
                        client = None
                    server.stop()
                    elapsed = server.finish()
                    if mode != "dial":
                        wait(backend.closed.is_set, "server left its backend socket open")
                    results.append({"mode": mode, "host": host, "tls": secure, "client_closed": disconnected, "exit": 0, "seconds": elapsed})
                    print(f"ok: tls={secure} {mode}/{host} client_closed={disconnected}: joined backend cleanup", flush=True)
                finally:
                    if client:
                        client.close()
                    if server:
                        server.close()
                    backend.close()

    for mode in ["head", "tls-handshake"]:
        folder = Path(temporary) / ("health-" + mode)
        folder.mkdir()
        backend, server = Backend(mode), None
        try:
            server = Server(folder, backend, False, health=True)
            wait(backend.started.is_set, "health probe did not begin")
            assert backend.error is None, repr(backend.error)
            server.stop()
            elapsed = server.finish()
            wait(backend.closed.is_set, "health worker left its backend socket open")
            results.append({"mode": "health-" + mode, "exit": 0, "seconds": elapsed})
            print(f"ok: {mode} long-budget active health probe cancels and joins on shutdown", flush=True)
        finally:
            if server:
                server.close()
            backend.close()

    folder = Path(temporary) / "half-close"
    folder.mkdir()
    backend, server, client = Backend("finish"), None, None
    try:
        server = Server(folder, backend, False)
        client = server.connect()
        client.sendall(b"GET /finish HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        wait(backend.started.is_set, "half-close backend did not begin")
        client.shutdown(socket.SHUT_WR)
        server.stop()
        time.sleep(.05)
        backend.reply.set()
        with http.client.HTTPResponse(client) as response:
            response.begin()
            assert (response.status, response.read()) == (200, b"hello")
        elapsed = server.finish()
        results.append({"mode": "half-close", "exit": 0, "response_verified": True, "seconds": elapsed})
        print("ok: half-closed HTTP/1 request finishes normally inside the shutdown grace period", flush=True)
    finally:
        if client:
            client.close()
        if server:
            server.close()
        backend.close()

assert len(results) == (27 if sys.platform.startswith("linux") else 19)
assert hashlib.sha256(binary.read_bytes()).hexdigest() == binary_hash, "server changed during verification"
assert hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == fixture_hash, "fixture changed during verification"
if not sys.platform.startswith("linux"):
    print("skip: backlog-stalled TCP dial checks require Linux /proc/net/tcp", flush=True)
if args.output:
    args.output.write_text(json.dumps({"binary_sha256": binary_hash, "fixture_sha256": fixture_hash, "platform": sys.platform, "results": results}, indent=2) + "\n")
