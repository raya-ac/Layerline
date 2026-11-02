#!/usr/bin/env python3
"""Verify separate, bounded request trailers all the way to a real upstream."""
import hashlib
import http.client
import http.server
import io
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

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / "zig-out/bin/layerline"


def integer(value, bits):
    mask = (1 << bits) - 1
    if value < mask:
        return bytes([value])
    result = bytearray([mask])
    value -= mask
    while value >= 128:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def literal(name, value, indexing=False):
    return (b"\x40" if indexing else b"\0") + integer(len(name), 7) + name + integer(len(value), 7) + value


class Peer(H2):
    def begin(self, stream, path=b"/app/trailers", method=b"POST", extra=()):
        fields = [(b":method", method), (b":scheme", b"https" if self.tls else b"http"),
                  (b":authority", b"localhost"), (b":path", path), *extra]
        self.connection.sendall(frame(1, 4, stream, b"".join(literal(*pair) for pair in fields)))

    def finish(self, stream, body, fields, split=False, indexing=False):
        for offset in range(0, len(body), 16384):
            self.connection.sendall(frame(0, 0, stream, body[offset:offset + 16384]))
        block = b"".join(literal(*pair, indexing=indexing) for pair in fields)
        if split and block:
            self.connection.sendall(frame(1, 1, stream, block[:3]) + frame(9, 4, stream, block[3:]))
        else:
            self.connection.sendall(frame(1, 5, stream, block))

    def reset(self, stream):
        self.until(lambda kind, _, number, payload: kind == 3 and number == stream and payload == (1).to_bytes(4, "big"))
        self.request(stream + 2, b"/health")
        assert self.response(stream + 2) == (200, b"ok\n"), "trailer rejection killed an unrelated stream"


class Origin(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    requests = 0
    errors = []

    def log_message(self, *_):
        pass

    def do_GET(self):
        try:
            self.connection.settimeout(3)
            body, trailer_lines = bytearray(), bytearray()
            if self.headers.get("Transfer-Encoding") == "chunked":
                assert "Content-Length" not in self.headers, "ambiguous upstream request framing"
                while True:
                    line = self.rfile.readline(128)
                    assert line.endswith(b"\r\n")
                    count = int(line[:-2], 16)
                    assert count <= 65536 - len(body)
                    if count == 0:
                        break
                    part = self.rfile.read(count)
                    assert len(part) == count and self.rfile.read(2) == b"\r\n"
                    body.extend(part)
                while True:
                    line = self.rfile.readline(8192)
                    assert line.endswith(b"\r\n") and len(trailer_lines) + len(line) <= 8192
                    trailer_lines.extend(line)
                    if line == b"\r\n":
                        break
            else:
                count = int(self.headers.get("Content-Length", "0"))
                assert count <= 65536
                body.extend(self.rfile.read(count))
                assert len(body) == count
            trailers = http.client.parse_headers(io.BytesIO(trailer_lines))
            Origin.requests += 1
            result = {"sequence": Origin.requests, "headers": [[k.lower(), v] for k, v in self.headers.raw_items()],
                      "trailers": [[k.lower(), v] for k, v in trailers.raw_items()], "length": len(body),
                      "sha256": hashlib.sha256(body).hexdigest(), "client_port": self.client_address[1]}
            encoded = json.dumps(result).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(encoded)
        except Exception as error:
            Origin.errors.append(repr(error))
            self.close_connection = True

    do_POST = do_GET


def h1(port, secure, wire):
    connection = socket.create_connection(("127.0.0.1", port), timeout=3)
    if secure:
        context = ssl._create_unverified_context()
        context.set_alpn_protocols(["http/1.1"])
        connection = context.wrap_socket(connection, server_hostname="localhost")
    with connection:
        connection.sendall(wire)
        reply = http.client.HTTPResponse(connection)
        reply.begin()
        body = reply.read(65537)
        assert len(body) <= 65536
        return reply.status, body


def chunked(body, fields):
    data = (f"{len(body):x}; ext=\"kept;\\\"quoted\"\r\n".encode() + body + b"\r\n") if body else b""
    return data + b"0\r\n" + b"".join(name + b": " + value + b"\r\n" for name, value in fields) + b"\r\n"


class OriginServer(http.server.ThreadingHTTPServer):
    daemon_threads = False


origin = OriginServer(("127.0.0.1", 0), Origin)
thread = threading.Thread(target=origin.serve_forever)
thread.start()
try:
    for secure in [False, True]:
        with tempfile.TemporaryDirectory(prefix="layerline-request-trailers-", dir="/tmp") as temporary:
            folder = Path(temporary)
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]
            config, log = folder / "server.conf", folder / "server.log"
            config.write_text(f"""host = 127.0.0.1
port = {port}
dir = {folder}
tls = {str(secure).lower()}
admin = false
admin_ui = false
access_log = false
http3 = false
max_request_bytes = 4096
max_body_bytes = 65536
read_body_timeout_ms = 1000
graceful_shutdown_timeout_ms = 1200
upstream_keepalive = true
response_cache = true
response_cache_max_bytes = 1048576
response_cache_max_entry_bytes = 65536
route = app /app/* proxy
route_proxy.app = http://127.0.0.1:{origin.server_port}
""")
            process, peers = None, []

            def peer():
                value = Peer(port, tls=secure)
                peers.append(value)
                return value

            def wire(body, fields, path=b"/app/trailers"):
                return b"POST " + path + b" HTTP/1.1\r\nHost: localhost\r\nX-Result: initial\r\nTransfer-Encoding: chunked\r\nTrailer: X-Fake, Authorization\r\n\r\n" + chunked(body, fields)

            fields = [(b"content-digest", b"sha-256=:test:"), (b"x-result", b"one"), (b"x-result", b"two")]
            try:
                with log.open("wb") as sink:
                    process = subprocess.Popen([str(BINARY), "--config", str(config)], cwd=folder, stdout=sink, stderr=sink)
                until = time.monotonic() + 5
                while '"event":"server.ready"' not in log.read_text():
                    assert process.poll() is None and time.monotonic() < until, log.read_text()
                    time.sleep(.01)
                for protocol in ["h1", "h2"]:
                    for body in [b"", b"hello\0\r\n", bytes(range(256)) * 256]:
                        if protocol == "h1":
                            status, data = h1(port, secure, wire(body, fields))
                        else:
                            client = peer()
                            client.begin(1, extra=[(b"content-length", str(len(body)).encode()), (b"x-result", b"initial")])
                            client.finish(1, body, fields, split=True)
                            status, data = client.response(1)
                            client.request(3, b"/health")
                            assert client.response(3) == (200, b"ok\n")
                            client.close()
                        assert status == 200, (protocol, status, data[:300])
                        observed = json.loads(data)
                        assert observed["length"] == len(body) and observed["sha256"] == hashlib.sha256(body).hexdigest(), observed
                        assert observed["trailers"] == [[k.decode(), v.decode()] for k, v in fields], ("trailers lost or reordered", observed)
                        assert [v for k, v in observed["headers"] if k == "x-result"] == ["initial"], "trailers merged into initial headers"
                        assert [v for k, v in observed["headers"] if k == "trailer"] == ["content-digest, x-result"], observed
                        assert not any(k == "content-length" for k, _ in observed["headers"]), observed
                        if protocol == "h1":
                            result = json.loads(h1(port, secure, b"GET /app/reuse HTTP/1.1\r\nHost: localhost\r\n\r\n")[1])
                            assert result["client_port"] == observed["client_port"], "fully forwarded trailers prevented safe upstream reuse"
                    print(f"ok: {'TLS' if secure else 'plain'} {protocol} empty/binary/64KiB bodies, separate ordered trailers and framing", flush=True)

                client = peer()
                client.request(1, b"/app/cache")
                ordinary = json.loads(client.response(1)[1])
                client.request(3, b"/app/cache")
                assert json.loads(client.response(3)[1])["sequence"] == ordinary["sequence"], "cache fixture never stored a response"
                for stream, value in [(5, b"one"), (7, b"two")]:
                    client.begin(stream, b"/app/cache", b"GET")
                    client.finish(stream, b"", [(b"x-result", value)])
                    observed = json.loads(client.response(stream)[1])
                    assert observed["sequence"] > ordinary["sequence"] and observed["trailers"] == [["x-result", value.decode()]], "request trailers reused a cached representation"
                client.close()

                # The trailer block shares the original body-phase budget. It
                # does not get a fresh deadline after the zero chunk or DATA.
                before = Origin.requests
                started = time.monotonic()
                partial = b"POST /app/never HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nDigest: unfinished"
                assert h1(port, secure, partial)[0] == 408
                assert .5 < time.monotonic() - started < 2.5
                client = peer()
                client.begin(1)
                client.connection.sendall(frame(0, 0, 1, b"finished body"))
                started = time.monotonic()
                client.until(lambda kind, _, stream, payload: kind == 3 and stream == 1 and payload == (8).to_bytes(4, "big"))
                assert .5 < time.monotonic() - started < 2.5
                client.request(3, b"/health")
                assert client.response(3) == (200, b"ok\n")
                client.close()
                assert Origin.requests == before, "unfinished trailer request reached the upstream"

                client = peer()
                client.begin(1)
                client.finish(1, b"", [(b"x-metadata", b"kept")], indexing=True, split=True)
                assert json.loads(client.response(1)[1])["trailers"] == [["x-metadata", "kept"]]
                # Dynamic index 62 was introduced in the trailer field block.
                block = b"\x82" + (b"\x87" if secure else b"\x86") + literal(b":authority", b"localhost") + literal(b":path", b"/health") + b"\xbe"
                client.connection.sendall(frame(1, 5, 3, block))
                assert client.response(3) == (200, b"ok\n"), "trailer block lost HPACK state"
                client.close()

                for forbidden in [b"host", b"content-length", b"authorization", b"cookie", b"connection", b"trailer", b"content-type", b"cache-control", b"x-forwarded-for", b":path"]:
                    before = Origin.requests
                    assert h1(port, secure, wire(b"", [(forbidden, b"changed")]))[0] == 400
                    client = peer()
                    client.begin(1)
                    client.finish(1, b"", [(forbidden, b"changed")])
                    client.reset(1)
                    client.close()
                    assert Origin.requests == before, "forbidden trailer reached upstream"

                before = Origin.requests
                nominated = wire(b"", [(b"x-hop", b"not end-to-end")]).replace(b"Host: localhost\r\n", b"Host: localhost\r\nConnection: keep-alive\r\nConnection: X-Hop\r\n")
                assert h1(port, secure, nominated)[0] == 400
                assert Origin.requests == before, "Connection-nominated trailer was forwarded"

                for bad, expected in [([(b"x-a", b"")] * 101, 413), ([(b"x-a", b"a" * 220)] * 17, 413), ([(b"x-a", b"bad\0value")], 400)]:
                    before = Origin.requests
                    assert h1(port, secure, wire(b"", bad))[0] == expected
                    client = peer()
                    client.begin(1)
                    client.finish(1, b"", bad)
                    client.reset(1)
                    client.close()
                    assert Origin.requests == before

                for fields in [[(b"x-meta", b"php2shell")], [(b"php_value", b"auto_prepend_file=evil")]]:
                    before = Origin.requests
                    status, body = h1(port, secure, wire(b"", fields))
                    assert status == 403 and b"shell vending machine" in body
                    client = peer()
                    client.begin(1)
                    client.finish(1, b"", fields)
                    status, body = client.response(1)
                    assert status == 403 and b"shell vending machine" in body
                    client.close()
                    assert Origin.requests == before and '"security.block"' in log.read_text()
                assert not Origin.errors, Origin.errors
                print(f"ok: {'TLS' if secure else 'plain'} trailer cache bypass, metadata limits, security guard and unrelated-stream recovery", flush=True)
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
                        raise AssertionError("trailer tests prevented joined shutdown")
                if process:
                    assert process.returncode == 0, log.read_text()
finally:
    origin.shutdown()
    origin.server_close()
    thread.join(timeout=4)
    assert not thread.is_alive(), "origin thread did not stop"
