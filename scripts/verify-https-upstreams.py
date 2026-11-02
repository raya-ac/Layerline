#!/usr/bin/env python3
"""Real HTTPS origins through Layerline's HTTP/1 and HTTP/2 proxy paths."""
import argparse
import contextlib
import hashlib
import http.client
import http.server
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

from wire_h2 import H2, frame

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("binary", type=Path)
parser.add_argument("--output", type=Path)
args = parser.parse_args()
if args.output:
    args.output.unlink(missing_ok=True)
binary = args.binary.resolve(strict=True)
fingerprint = hashlib.sha256(binary.read_bytes()).hexdigest()
fixture_fingerprint = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
helper_path = Path(__file__).with_name("wire_h2.py")
helper_fingerprint = hashlib.sha256(helper_path.read_bytes()).hexdigest()
results = []
body = b"layerline authenticated origin\n" * 512


def openssl(*arguments):
    subprocess.run(["openssl", *map(str, arguments)], check=True, capture_output=True, timeout=20)


def certificates(folder, name, key_kind="p256", large=False):
    root, root_key = folder / (name + ".pem"), folder / (name + ".key")
    openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
            "-days", "1", "-subj", "/CN=" + name, "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-addext", "subjectKeyIdentifier=hash",
            "-out", root, "-keyout", root_key)
    key, csr, leaf = (folder / (name + suffix) for suffix in ["-leaf.key", "-leaf.csr", "-leaf.pem"])
    key_args = {"p256": ["ec", "-pkeyopt", "ec_paramgen_curve:P-256"], "p384": ["ec", "-pkeyopt", "ec_paramgen_curve:P-384"], "rsa": ["rsa:2048"], "ed25519": ["ed25519"]}[key_kind]
    openssl("req", "-new", "-newkey", *key_args, "-nodes",
            "-subj", "/CN=origin.example.test", "-keyout", key, "-out", csr)
    extensions = folder / (name + ".ext")
    san = "DNS:origin.example.test"
    if large:
        san += "".join(f",DNS:{number}.{'a' * 60}.tenant.example.test" for number in range(240))
    extensions.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=" + san + "\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid:always\n")
    openssl("x509", "-req", "-in", csr, "-CA", root, "-CAkey", root_key, "-set_serial", "2",
            "-days", "1", "-sha256", "-extfile", extensions, "-out", leaf)
    return root, leaf, key


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def do_GET(self):
        self.server.requests.append((self.path, self.headers.get("Host"), self.client_address))
        if self.path == "/cancel-body":
            self.close_connection = True
            self.connection.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\nConnection: close\r\n\r\nx")
            self.server.stalled.set()
            try:
                assert not self.connection.recv(1), "unexpected HTTP bytes during canceled response"
            finally:
                self.server.canceled.set()
            return
        if self.path == "/upgrade":
            self.close_connection = True
            self.connection.sendall(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nearly")
            while data := self.rfile.read(4096):
                self.connection.sendall(data)
            # A TLS 1.3 close-notify closes one direction, not the other.
            self.server.clean_tunnels.append(self.client_address)
            self.connection.sendall(b"origin saw close_notify")
            self.connection.unwrap().close()
            return
        if self.path in ["/eof-clean", "/eof-truncated"]:
            self.close_connection = True
            self.connection.sendall(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n" + body)
            if self.path == "/eof-clean":
                self.connection.unwrap().close()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        if self.path == "/php-version":
            self.send_header("X-Powered-By", "PHP/7.4.33")
        if self.path == "/chunked":
            self.send_header("Transfer-Encoding", "chunked")
            self.send_header("Trailer", "X-Origin-End")
            self.end_headers()
            self.wfile.write(f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\nX-Origin-End: ok\r\n\r\n")
        else:
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if self.path.startswith("/slow-"):
                for offset in range(0, len(body), 1024):
                    if offset:
                        time.sleep(.2)
                    self.wfile.write(body[offset:offset + 1024])
            else:
                self.wfile.write(body)
            if self.path == "/poison":
                self.wfile.flush()
                self.connection.sendall(b"unsolicited application bytes")


class Origin(http.server.ThreadingHTTPServer):
    daemon_threads = False
    block_on_close = True

    def __init__(self, leaf, key, version):
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.minimum_version = self.context.maximum_version = version
        self.context.set_alpn_protocols(["http/1.1"])
        self.context.num_tickets = 0
        self.context.load_cert_chain(leaf, key)
        self.requests, self.sni, self.failures, self.peer_closures, self.clean_tunnels = [], [], [], [], []
        self.active = set()
        self.lock = threading.Lock()
        self.stalled, self.canceled = threading.Event(), threading.Event()
        self.context.set_servername_callback(lambda _, name, __: self.sni.append(name))
        super().__init__(("127.0.0.1", 0), Handler)
        self.worker = threading.Thread(target=self.serve_forever, kwargs={"poll_interval": .05})
        self.worker.start()

    def get_request(self):
        stream, address = super().get_request()
        stream.settimeout(2)
        try:
            encrypted = self.context.wrap_socket(stream, server_side=True)
            with self.lock:
                self.active.add(encrypted)
            return encrypted, address
        except BaseException:
            stream.close()
            raise

    def shutdown_request(self, request):
        with self.lock:
            self.active.discard(request)
        super().shutdown_request(request)

    def handle_error(self, request, address):
        error = sys.exception()
        if isinstance(error, (ConnectionResetError, BrokenPipeError, ssl.SSLEOFError)):
            self.peer_closures.append(type(error).__name__)
        else:
            self.failures.append(repr(error))
            super().handle_error(request, address)

    def close(self):
        self.shutdown()
        self.worker.join(4)
        assert not self.worker.is_alive(), "origin listener did not join"
        self.server_close()
        assert not self.failures, self.failures


@contextlib.contextmanager
def server(folder, origin, ca, secure, name="origin.example.test", health=False, admin=False, extra="", details=None):
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))
        port = reserved.getsockname()[1]
    config = folder / "server.conf"
    config.write_text(f"""host = 127.0.0.1
port = {port}
tls = {str(secure).lower()}
admin = {str(admin).lower()}
admin_socket = {folder / 'control.sock'}
admin_ui = false
http3 = false
compression = false
response_cache = false
access_log = false
serve_static_root = false
upstream_retries = 0
upstream_max_failures = 0
upstream_timeout_ms = 1500
graceful_shutdown_timeout_ms = 2000
upstream_health_check = {str(health).lower()}
upstream_health_check_interval_ms = 100
upstream_health_check_timeout_ms = 500
proxy = https://127.0.0.1:{origin.server_port} tls_ca_file={ca} tls_server_name={name}
{extra}
""")
    log_path = folder / "server.log"
    with log_path.open("wb") as log:
        process = subprocess.Popen([str(binary), "--config", str(config)], cwd=folder, stdout=log, stderr=subprocess.STDOUT)
        try:
            until = time.monotonic() + 5
            while True:
                assert process.poll() is None, log_path.read_text()
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=.1):
                        pass
                    if admin:
                        assert b"Layerline" in control(folder, b"status"), "admin listener returned an invalid readiness reply"
                    break
                except OSError:
                    assert time.monotonic() < until, log_path.read_text()
                    time.sleep(.02)
            if details is not None:
                details.update(port=port, config=config, process=process, log=log_path)
            yield port
        except BaseException:
            with contextlib.suppress(OSError):
                with log_path.open("rb") as failure_log:
                    failure_log.seek(max(0, log_path.stat().st_size - 32768))
                    print("HTTPS fixture server log:", repr(failure_log.read(32768)), file=sys.stderr, flush=True)
            raise
        finally:
            if process.poll() is None:
                process.send_signal(signal.SIGTERM)
            try:
                process.wait(5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                raise AssertionError("server did not join HTTPS work", log_path.read_text())
            assert process.returncode == 0, log_path.read_text()


def request(port, secure, path="/fixed"):
    if secure:
        context = ssl._create_unverified_context()
        context.set_alpn_protocols(["http/1.1"])
        connection = http.client.HTTPSConnection("127.0.0.1", port, context=context, timeout=4)
    else:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=4)
    try:
        connection.request("GET", path, headers={"Host": "browser-supplied.example"})
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


class DuplexClient:
    """Single-threaded independent peer, including TLS write-half-close."""

    def __init__(self, port, secure):
        self.wire = socket.create_connection(("127.0.0.1", port), timeout=4)
        self.incoming, self.outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        self.tls = None
        if secure:
            context = ssl._create_unverified_context()
            context.set_alpn_protocols(["http/1.1"])
            self.tls = context.wrap_bio(self.incoming, self.outgoing, server_hostname="localhost")
            while True:
                try:
                    self.tls.do_handshake()
                    self.flush()
                    break
                except ssl.SSLWantReadError:
                    self.flush()
                    self.receive()

    def flush(self):
        while self.outgoing.pending:
            self.wire.sendall(self.outgoing.read())

    def receive(self):
        data = self.wire.recv(65536)
        if data:
            self.incoming.write(data)
        else:
            self.incoming.write_eof()

    def sendall(self, data):
        if not self.tls:
            self.wire.sendall(data)
            return
        while data:
            used = self.tls.write(data[:16384])
            data = data[used:]
            self.flush()

    def recv(self, count):
        if not self.tls:
            return self.wire.recv(count)
        while True:
            try:
                data = self.tls.read(count)
                self.flush()
                return data
            except ssl.SSLWantReadError:
                self.flush()
                self.receive()
            except ssl.SSLZeroReturnError:
                return b""

    def end(self):
        if not self.tls:
            self.wire.shutdown(socket.SHUT_WR)
            return
        try:
            self.tls.unwrap()
        except ssl.SSLWantReadError:
            pass
        self.flush()

    def close(self):
        self.wire.close()


def exact(connection, count):
    data = bytearray()
    while len(data) < count:
        piece = connection.recv(count - len(data))
        assert piece, ("tunnel closed before its final bytes", len(data), count)
        data.extend(piece)
    return bytes(data)


def wait_bytes(path, marker, count=1):
    until = time.monotonic() + 4
    while True:
        data = path.read_bytes() if path.exists() else b""
        assert len(data) < 4 * 1024 * 1024, "unbounded OpenSSL fixture output"
        if data.count(marker) >= count:
            return
        assert time.monotonic() < until, f"OpenSSL fixture did not produce {marker!r} x {count}"
        time.sleep(.01)


def key_updates(folder, ca, leaf, key, secure):
    # s_server's documented K command sends KeyUpdate(requested). Its message
    # trace must also show the actual authenticated reply; data alone is not proof.
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))
        port = reserved.getsockname()[1]
    output, trace = folder / "openssl.stdout", folder / "openssl.trace"
    with output.open("wb") as log, (folder / "openssl.stderr").open("wb") as errors:
        process = subprocess.Popen(["openssl", "s_server", "-accept", f"127.0.0.1:{port}", "-cert", str(leaf), "-key", str(key), "-tls1_3", "-alpn", "http/1.1", "-num_tickets", "0", "-msg", "-msgfile", str(trace), "-naccept", "1"], stdin=subprocess.PIPE, stdout=log, stderr=errors)
        try:
            wait_bytes(output, b"ACCEPT")
            origin = type("CommandOrigin", (), {"server_port": port})()
            with server(folder, origin, ca, secure) as downstream:
                client = DuplexClient(downstream, secure)
                try:
                    client.sendall(b"GET /upgrade HTTP/1.1\r\nHost: browser.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
                    wait_bytes(output, b"GET /upgrade HTTP/1.1")
                    process.stdin.write(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
                    process.stdin.flush()
                    head = bytearray()
                    while not head.endswith(b"\r\n\r\n"):
                        head.extend(exact(client, 1))
                        assert len(head) < 8192
                    assert head.startswith(b"HTTP/1.1 101 "), head
                    for number in range(4):
                        process.stdin.write(b"K\n")
                        process.stdin.flush()
                        wait_bytes(trace, b"KeyUpdate", number * 2 + 1)
                        upload = b"client after update " + str(number).encode() + b":" + b"x" * 32768 + b"\n"
                        client.sendall(upload)
                        download = b"origin after update " + str(number).encode() + b":" + b"y" * 32768 + b"\n"
                        process.stdin.write(download)
                        process.stdin.flush()
                        assert exact(client, len(download)) == download
                        wait_bytes(output, upload)
                        wait_bytes(trace, b"KeyUpdate", (number + 1) * 2)
                    messages = trace.read_text()
                    lines = [line for line in messages.splitlines() if "KeyUpdate" in line]
                    assert len(lines) == 8 and sum(line.startswith("<<<") for line in lines) == 4 and sum(line.startswith(">>>") for line in lines) == 4, lines
                finally:
                    client.close()
        finally:
            process.stdin.close()
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(4)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                raise AssertionError("OpenSSL origin did not join")
    results.append({"case": "four requested TLS key rotations during bidirectional upgraded traffic", "downstream_tls": secure})
    print(f"ok: downstream_tls={secure} actual origin KeyUpdate replies and tunnel traffic", flush=True)


def tunnel(port, secure, origin):
    client = DuplexClient(port, secure)
    try:
        client.sendall(b"GET /upgrade HTTP/1.1\r\nHost: browser.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
        head = bytearray()
        while not head.endswith(b"\r\n\r\n"):
            head.extend(exact(client, 1))
            assert len(head) < 8192, "unbounded upgrade headers"
        assert head.startswith(b"HTTP/1.1 101 "), head
        assert exact(client, 5) == b"early", "lost prefetched tunnel bytes"
        payload = bytes(range(256)) * 16
        for _ in range(64):
            client.sendall(payload)
            assert exact(client, len(payload)) == payload
        before = len(origin.clean_tunnels)
        client.sendall(b"final partial record")
        client.end()
        assert exact(client, len(b"final partial recordorigin saw close_notify")) == b"final partial recordorigin saw close_notify"
        assert client.recv(1) == b"", "tunnel did not finish with authenticated EOF"
        assert len(origin.clean_tunnels) == before + 1, "origin did not observe a clean TLS half-close"
    finally:
        client.close()


def control(folder, command):
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(4)
        connection.connect(str(folder / "control.sock"))
        connection.sendall(command + b"\n")
        reply = b""
        while True:
            piece = connection.recv(4096)
            if not piece:
                return reply
            reply += piece
            assert len(reply) < 1024 * 1024, "unbounded control response"


class StalledHandshake:
    def __init__(self):
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.listener.settimeout(.1)
        self.server_port = self.listener.getsockname()[1]
        self.stalled, self.canceled, self.stopping = (threading.Event() for _ in range(3))
        self.failures = []
        self.worker = threading.Thread(target=self.serve)
        self.worker.start()

    def serve(self):
        try:
            while not self.stopping.is_set():
                try:
                    connection, _ = self.listener.accept()
                except socket.timeout:
                    continue
                with connection:
                    connection.settimeout(.1)
                    count = 0
                    while not self.stopping.is_set():
                        try:
                            data = connection.recv(4096)
                        except socket.timeout:
                            continue
                        except ConnectionResetError:
                            break
                        if not data:
                            break
                        count += len(data)
                        assert count < 128 * 1024, "unbounded bytes before TLS authentication"
                        self.stalled.set()
                    self.canceled.set()
        except BaseException as error:
            self.failures.append(repr(error))

    def close(self):
        self.stopping.set()
        self.worker.join(3)
        self.listener.close()
        assert not self.worker.is_alive() and not self.failures, self.failures


def cancellation(folder, origin, ca, secure, stage):
    with server(folder, origin, ca, secure, admin=True, extra="upstream_timeout_ms = 10000") as port:
        for disconnect in [False, False, True]:
            origin.stalled.clear()
            origin.canceled.clear()
            client = H2(port, secure)
            try:
                client.request(1, b"/cancel-body")
                assert origin.stalled.wait(2), f"origin did not stall in {stage}"
                if disconnect:
                    client.close()
                else:
                    client.connection.sendall(frame(3, 0, 1, (8).to_bytes(4, "big")))
                    client.ping()
                until = time.monotonic() + 1.5
                while True:
                    metrics = dict(line.split() for line in control(folder, b"metrics").decode().splitlines() if line.startswith("layerline_") and len(line.split()) == 2)
                    if metrics["layerline_http2_routing_jobs"] == "0" and metrics["layerline_upstream_connections_opened_total"] == metrics["layerline_upstream_connections_discarded_total"]:
                        break
                    assert time.monotonic() < until, (f"canceled {stage} retained its job/socket", metrics)
                    time.sleep(.02)
                assert origin.canceled.wait(.3), f"canceled {stage} left origin socket alive"
                assert metrics["layerline_upstream_failures_total"] == "0", "client cancellation ejected a TLS origin"
            finally:
                client.close()
    results.append({"case": f"H2 resets/disconnect join stalled TLS {stage} without peer ejection", "downstream_tls": secure})
    print(f"ok: downstream_tls={secure} TLS {stage} cancellation and descriptor cleanup", flush=True)


def scoped_origins(folder, origin, ca, secure):
    target = f"https://127.0.0.1:{origin.server_port} tls_ca_file={ca} tls_server_name=origin.example.test"
    for scope, extra in [
        ("route", f"route = app /scope/* proxy\nroute_proxy.app = {target}"),
        ("domain", f"server = site\nserver_name.site = browser-supplied.example localhost\nserver_proxy.site = {target}"),
        ("domain route", f"server = site\nserver_name.site = browser-supplied.example localhost\nserver_route.site = app /scope/* proxy\nserver_route_proxy.site.app = {target}"),
    ]:
        with server(folder, origin, ca, secure, extra="proxy = off\n" + extra) as port:
            assert request(port, secure, "/scope/fixed") == (200, body), scope
            client = H2(port, secure)
            try:
                client.request(1, b"/scope/fixed")
                assert client.response(1) == (200, body), scope
            finally:
                client.close()
        results.append({"case": f"H1/H2 {scope} HTTPS origin", "downstream_tls": secure})
    details = {}
    with server(folder, origin, ca, secure, admin=True, details=details, extra="proxy = off"):
        original = details["config"].read_text()
        details["config"].write_text(original.replace("\nproxy = off\n", "\n"))
        reply = control(folder, b"reload")
        assert reply.startswith(b"ERROR ") and b"ReloadRequiresRestart" in reply, reply
        details["config"].write_text(original)
        assert control(folder, b"reload").startswith(b"OK "), "rejected stack growth damaged reload state"
    results.append({"case": "first HTTPS reload refuses unsafe worker stack growth", "downstream_tls": secure})
    print(f"ok: downstream_tls={secure} scoped origins and stack restart boundary", flush=True)


def worker_certificates(folder):
    for kind, large in [("p384", False), ("rsa", False), ("ed25519", False), ("p256", True)]:
        ca, leaf, key = certificates(folder, "worker-" + kind, key_kind=kind, large=large)
        if large:
            assert len(ssl.PEM_cert_to_DER_cert(leaf.read_text())) > 16384, "large certificate did not span TLS records"
        origin = Origin(leaf, key, ssl.TLSVersion.TLSv1_3)
        try:
            for secure in [False, True]:
                with server(folder, origin, ca, secure) as port:
                    assert request(port, secure) == (200, body)
                    client = H2(port, secure)
                    try:
                        client.request(1, b"/fixed")
                        assert client.response(1) == (200, body)
                    finally:
                        client.close()
                results.append({"case": "nested H1/H2 worker handshake", "leaf_key": kind, "large_leaf": large, "downstream_tls": secure})
        finally:
            origin.close()
    print("ok: real worker RSA/P384/Ed25519 and fragmented large certificate handshakes", flush=True)


def reload_trust(folder, first, second, first_ca, second_ca, secure):
    details = {}
    with server(folder, first, first_ca, secure, admin=True, details=details) as port:
        assert request(port, secure) == (200, body)
        old = H2(port, secure)
        try:
            old.request(1, b"/fixed")
            assert old.response(1) == (200, body)
            old.connection.sendall(frame(8, 0, 0, len(body).to_bytes(4, "big")))
            original = details["config"].read_text()
            for number in range(8):
                origin, ca = (first, first_ca) if number % 2 else (second, second_ca)
                config = original.replace(f":{first.server_port} tls_ca_file={first_ca}", f":{origin.server_port} tls_ca_file={ca}")
                details["config"].write_text(config)
                assert control(folder, b"reload").startswith(b"OK ")
                before = len(origin.requests)
                assert request(port, secure) == (200, body)
                assert len(origin.requests) > before, "new connection did not use published origin"
                stream = 3 + number * 2
                old.request(stream, b"/fixed")
                reply = old.response(stream)
                assert reply == (200, body), ("retired trust did not survive its old H2 reader", {
                    "downstream_tls": secure, "replacement": number, "stream": stream,
                    "status": reply[0], "body_bytes": len(reply[1]),
                    "body_sha256": hashlib.sha256(reply[1]).hexdigest(),
                })
                old.connection.sendall(frame(8, 0, 0, len(body).to_bytes(4, "big")))
            # Publish the second trust source so only the old H2 lease owns the
            # first. Remove that file: old requests must use immutable bytes.
            details["config"].write_text(original.replace(f":{first.server_port} tls_ca_file={first_ca}", f":{second.server_port} tls_ca_file={second_ca}"))
            assert control(folder, b"reload").startswith(b"OK ")
            saved = first_ca.read_bytes()
            first_ca.unlink()
            try:
                old.request(21, b"/fixed")
                reply = old.response(21)
                assert reply == (200, body), ("trust was loaded lazily or freed before its last reader", {
                    "downstream_tls": secure, "stream": 21, "status": reply[0],
                    "body_bytes": len(reply[1]), "body_sha256": hashlib.sha256(reply[1]).hexdigest(),
                })
                good_config = details["config"].read_text()
                details["config"].write_text(good_config.replace(str(second_ca), str(folder / "missing-ca.pem")))
                assert control(folder, b"reload").startswith(b"ERROR ")
                assert request(port, secure) == (200, body), "failed trust preflight damaged the active config"
                details["config"].write_text(good_config)
            finally:
                first_ca.write_bytes(saved)
        finally:
            old.close()
        until = time.monotonic() + 3
        while b"layerline_config_snapshots 1\n" not in control(folder, b"metrics"):
            assert time.monotonic() < until, "retired HTTPS snapshots were not reclaimed"
            time.sleep(.02)
    results.append({"case": "TLS trust rotation, old H2 leases, immutable roots, failed preflight, reclamation", "downstream_tls": secure})
    print(f"ok: downstream_tls={secure} HTTPS trust reload ownership", flush=True)


with tempfile.TemporaryDirectory(prefix="layerline-https-proxy-", dir="/tmp") as temporary:
    folder = Path(temporary)
    ca, leaf, key = certificates(folder, "trusted-root")
    other_ca, other_leaf, other_key = certificates(folder, "untrusted-root")
    worker_certificates(folder)
    large_ca, large_leaf, large_key = certificates(folder, "downstream-large-root", large=True)
    large_der = ssl.PEM_cert_to_DER_cert(large_leaf.read_text())
    assert 16384 < len(large_der) <= 128 * 1024, "large certificate must cross records within the listener limit"
    large_chain = folder / "downstream-large-chain.pem"
    # Fragment one real certificate, not a chain inflated past its admission cap.
    large_chain.write_bytes(large_leaf.read_bytes() + large_ca.read_bytes())
    assert large_chain.read_bytes().count(b"-----BEGIN CERTIFICATE-----") == 2
    origin = Origin(leaf, key, ssl.TLSVersion.TLSv1_3)
    try:
        with server(folder, origin, ca, True, extra=f"tls_cert = {large_chain}\ntls_key = {large_key}") as port:
            verified = ssl.create_default_context(cafile=str(large_ca))
            verified.set_alpn_protocols(["http/1.1"])
            with socket.create_connection(("127.0.0.1", port), timeout=4) as raw:
                with verified.wrap_socket(raw, server_hostname="origin.example.test") as connection:
                    assert connection.getpeercert(binary_form=True) == large_der
                    assert connection.selected_alpn_protocol() == "http/1.1"
                    connection.sendall(b"GET /fixed HTTP/1.1\r\nHost: browser-supplied.example\r\nConnection: close\r\n\r\n")
                    with http.client.HTTPResponse(connection) as response:
                        response.begin()
                        assert (response.status, response.read()) == (200, body)
            assert request(port, True) == (200, body)
            client = H2(port, True)
            try:
                client.request(1, b"/fixed")
                assert client.response(1) == (200, body)
            finally:
                client.close()
    finally:
        origin.close()
    results.append({"case": "large native server Certificate message fragments across authenticated TLS records",
                    "certificate_bytes": len(large_der), "chain_certificates": 2, "certificate_verified": True})
    print("ok: real native listener large certificate fragmentation", flush=True)
    for secure in [False, True]:
        key_updates(folder, ca, leaf, key, secure)
        stalled = StalledHandshake()
        try:
            cancellation(folder, stalled, ca, secure, "handshake")
        finally:
            stalled.close()
    for version in [ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3]:
        origin = Origin(leaf, key, version)
        try:
            for secure in [False, True]:
                with server(folder, origin, ca, secure) as port:
                    first = len(origin.requests)
                    assert request(port, secure) == (200, body)
                    assert request(port, secure) == (200, body)
                    recent = origin.requests[first:]
                    assert len(recent) == 2 and recent[0][2] == recent[1][2], ("TLS connection was not reused", recent)
                    assert all(host == "browser-supplied.example" for _, host, _ in recent)
                    assert origin.sni[-1] == "origin.example.test", origin.sni
                    assert request(port, secure, "/chunked") == (200, body)
                    assert request(port, secure, "/php-version")[0] == 503
                    client = H2(port, secure)
                    try:
                        client.request(1, b"/fixed")
                        assert client.response(1) == (200, body)
                        client.request(3, b"/chunked")
                        assert client.response(3) == (200, body)
                        client.request(5, b"/php-version")
                        assert client.response(5)[0] == 503
                    finally:
                        client.close()
                    assert request(port, secure, "/poison") == (200, body)
                    poisoned = origin.requests[-1][2]
                    time.sleep(.1)
                    assert request(port, secure) == (200, body)
                    assert origin.requests[-1][2] != poisoned, "reused TLS with unsolicited idle bytes"
                    if version == ssl.TLSVersion.TLSv1_3:
                        tunnel(port, secure, origin)
                        assert request(port, secure) == (200, body), "tunnel cleanup damaged subsequent traffic"
                        results.append({"version": version.name, "downstream_tls": secure, "case": "bidirectional upgrade, prefetched bytes, TLS half-close and recovery"})
                results.append({"version": version.name, "downstream_tls": secure, "case": "authenticated H1/H2 framing, pool reuse, idle poison"})
                print(f"ok: {version.name} downstream_tls={secure}", flush=True)
            with server(folder, origin, ca, False) as port:
                assert request(port, False, "/eof-clean") == (200, body)
                client = H2(port)
                try:
                    client.request(1, b"/eof-clean")
                    assert client.response(1) == (200, body)
                    client.request(3, b"/eof-truncated")
                    assert client.response(3)[0] == 502, "accepted unauthenticated transport EOF as an HTTP response boundary"
                finally:
                    client.close()
            results.append({"version": version.name, "case": "authenticated EOF vs truncated TLS response"})
            for anchor, name in [(other_ca, "origin.example.test"), (ca, "wrong.example.test")]:
                with server(folder, origin, anchor, False, name=name) as port:
                    before = len(origin.requests)
                    assert request(port, False)[0] == 502
                    client = H2(port)
                    try:
                        client.request(1, b"/fixed")
                        assert client.response(1)[0] == 502
                    finally:
                        client.close()
                    assert len(origin.requests) == before, "HTTP bytes reached an unauthenticated origin"
                results.append({"version": version.name, "case": "H1/H2 refuse untrusted or mismatched TLS", "identity": name})
            before = len(origin.requests)
            with server(folder, origin, ca, False, health=True):
                until = time.monotonic() + 3
                while not any(path == "/health" for path, _, _ in origin.requests[before:]):
                    assert time.monotonic() < until, "HTTPS active health did not run"
                    time.sleep(.02)
            print(f"ok: {version.name} authentication failures and TLS active health", flush=True)
            with server(folder, origin, ca, False, extra="route = h1 /slow-h1 proxy\nroute_proxy_timeout_ms.h1 = 350\nroute = h2 /slow-h2 proxy\nroute_proxy_timeout_ms.h2 = 2000") as port:
                # Reuse an authenticated H1 socket: a slow Debug handshake must
                # not accidentally turn a body-budget test into a dial timeout.
                assert request(port, False) == (200, body)
                started = time.monotonic()
                try:
                    reply = request(port, False, "/slow-h1")
                    raise AssertionError("prewarmed HTTP1 did not abort the slow TLS body", reply[0])
                except http.client.IncompleteRead as error:
                    assert 0 < len(error.partial) < len(body), "H1 did not exercise progress followed by body timeout"
                assert time.monotonic() - started < 1.5, "HTTPS reset the backend body budget"
                client = H2(port)
                try:
                    before = len(origin.requests)
                    started = time.monotonic()
                    # H2 opens a fresh origin channel. Its total budget must
                    # fit the real Debug handshake, but not the 2.8s trickle.
                    client.request(1, b"/slow-h2")
                    assert client.response(1)[0] == 504
                    assert any(path == "/slow-h2" for path, _, _ in origin.requests[before:]), "H2 timed out before exercising the TLS body"
                    assert time.monotonic() - started < 3, "H2 HTTPS reset the backend body budget"
                finally:
                    client.close()
            results.append({"version": version.name, "case": "prewarmed H1 and authenticated H2 slow-body absolute deadline", "h1_attempt_budget_ms": 350, "h2_attempt_budget_ms": 2000})
            print(f"ok: {version.name} original HTTPS body deadlines", flush=True)
            if version == ssl.TLSVersion.TLSv1_3:
                for secure in [False, True]:
                    cancellation(folder, origin, ca, secure, "body")
                    scoped_origins(folder, origin, ca, secure)
                alternate = Origin(other_leaf, other_key, version)
                try:
                    for secure in [False, True]:
                        reload_trust(folder, origin, alternate, ca, other_ca, secure)
                finally:
                    alternate.close()
        finally:
            origin.close()

assert hashlib.sha256(binary.read_bytes()).hexdigest() == fingerprint, "server binary changed during gate"
assert hashlib.sha256(Path(__file__).read_bytes()).hexdigest() == fixture_fingerprint, "fixture changed during gate"
assert hashlib.sha256(helper_path.read_bytes()).hexdigest() == helper_fingerprint, "H2 helper changed during gate"
if args.output:
    args.output.write_text(json.dumps({"binary_sha256": fingerprint, "fixture_sha256": fixture_fingerprint, "helper_sha256": helper_fingerprint, "ssl_version": ssl.OPENSSL_VERSION, "openssl_version": subprocess.check_output(["openssl", "version"], text=True).strip(), "results": results}, indent=2) + "\n")
print("ok: HTTPS reverse-proxy integration", flush=True)
