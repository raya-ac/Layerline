#!/usr/bin/env python3
"""Real upstream boundaries, hop fields and HTTP/2 terminal response trailers."""
import collections
import http.server
import pathlib
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import urlsplit

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
            raise EOFError("HTTP/2 connection closed early")
        result += part
    return result


def h1_header(conn):
    result = b""
    while not result.endswith(b"\r\n\r\n"):
        result += exact(conn, 1)
        assert len(result) <= 65536, "unbounded HTTP/1 response head"
    return result


def decode(block):
    # Layerline emits non-Huffman literals/static indexes. This independent
    # decoder deliberately rejects dynamic references rather than guessing.
    static = {8: (b":status", b"200"), 9: (b":status", b"204"), 10: (b":status", b"206"), 11: (b":status", b"304"), 12: (b":status", b"400"), 13: (b":status", b"404"), 14: (b":status", b"500")}
    names = {24: b"cache-control", 28: b"content-length", 31: b"content-type", 33: b"date", 34: b"etag", 44: b"last-modified", 46: b"location", 54: b"server", 55: b"set-cookie", 56: b"strict-transport-security", 59: b"vary"}
    cursor = 0

    def integer(bits):
        nonlocal cursor
        mask = (1 << bits) - 1
        value = block[cursor] & mask
        cursor += 1
        if value == mask:
            shift = 0
            while True:
                byte = block[cursor]
                cursor += 1
                value += (byte & 127) << shift
                if not byte & 128:
                    break
                shift += 7
                assert shift < 64
        return value

    def string():
        nonlocal cursor
        assert not block[cursor] & 128, "unexpected Huffman response"
        count = integer(7)
        value = block[cursor:cursor + count]
        cursor += count
        return value

    result = []
    while cursor < len(block):
        if block[cursor] & 128:
            result.append(static[integer(7)])
        else:
            index = integer(6 if block[cursor] & 64 else 4)
            name = names[index] if index else string()
            result.append((name, string()))
    assert cursor == len(block)
    return dict(result)


class H2:
    def __init__(self, port, secure, window=65535):
        self.conn = socket.create_connection(("127.0.0.1", port), timeout=3)
        if secure:
            context = ssl._create_unverified_context()
            context.set_alpn_protocols(["h2"])
            self.conn = context.wrap_socket(self.conn, server_hostname="localhost")
            assert self.conn.selected_alpn_protocol() == "h2"
        self.secure, self.frames, self.blocks, self.partial = secure, [], collections.defaultdict(list), {}
        self.conn.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 0, 0, struct.pack("!HI", 4, window)))

    def request(self, stream, path, method=b"GET", extra=(), end=True):
        pairs = [(b":method", method), (b":scheme", b"https" if self.secure else b"http"), (b":authority", b"localhost"), (b":path", path.encode()), *extra]
        self.conn.sendall(frame(1, 4 | int(end), stream, b"".join(literal(*pair) for pair in pairs)))

    def receive(self):
        head = exact(self.conn, 9)
        kind, flags, stream = head[3], head[4], int.from_bytes(head[5:], "big")
        payload = exact(self.conn, int.from_bytes(head[:3], "big"))
        self.frames.append((kind, flags, stream, payload))
        assert kind != 7, ("unexpected GOAWAY", payload)
        if kind == 4 and not flags & 1:
            self.conn.sendall(frame(4, 1, 0))
        if kind == 0 and payload:
            credit = len(payload).to_bytes(4, "big")
            self.conn.sendall(frame(8, 0, 0, credit) + frame(8, 0, stream, credit))
        if kind in [1, 9]:
            if kind == 1:
                self.partial[stream] = b""
            self.partial[stream] += payload
            if flags & 4:
                self.blocks[stream].append(decode(self.partial.pop(stream)))

    def until(self, predicate):
        until = time.monotonic() + 3
        while not predicate():
            self.conn.settimeout(max(0.01, until - time.monotonic()))
            self.receive()
            assert time.monotonic() < until, "response waited past its framed message boundary"

    def done(self, stream):
        return any(k in [0, 1] and f & 1 and s == stream for k, f, s, _ in self.frames)

    def reply(self, stream):
        self.until(lambda: self.done(stream))
        statuses = [int(block[b":status"]) for block in self.blocks[stream] if b":status" in block]
        body = b"".join(p for k, _, s, p in self.frames if k == 0 and s == stream)
        return statuses, body

    def close(self):
        self.conn.close()


class Origin(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        case = urlsplit(self.path).path.rsplit("/", 1)[-1]
        with self.server.lock:
            self.server.counts[case] += 1
            self.server.requests[case] = dict((name.lower(), value) for name, value in self.headers.items())
        common = b"Content-Type: text/plain\r\nCache-Control: public, max-age=3600\r\nConnection: keep-alive, X-Hop, Content-Length\r\nConnection: X-Other, X-Trailer\r\nX-Hop: private-hop\r\nX-Other: other-hop\r\nX-End: public\r\nX-Empty:\r\nProxy-Connection: keep-alive\r\n"
        prefix, payload = b"", b"ok"
        if case == "info":
            prefix = b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </a.css>; rel=preload\r\nConnection: X-Hop\r\nX-Hop: private-info\r\n\r\nHTTP/1.1 102 Processing\r\n\r\n"
        elif case == "limit-info":
            prefix = b"HTTP/1.1 100 Continue\r\n\r\n" * 16
        if case in ["trailer", "empty-trailer", "bad-trailer", "incomplete-chunk", "version-trailer", "server-trailer"]:
            payload = b"2; name=\"quoted\\\"value\"\r\nok\r\n" if case != "empty-trailer" else b""
            payload += b"0\r\nDigest: sha-test\r\nX-Empty:\r\nX-Trailer: private-trailer\r\n"
            if case == "bad-trailer":
                payload += b"Content-Length: 2\r\n"
            if case == "version-trailer":
                payload += b"X-Powered-By: PHP/8.4.26\r\n"
            if case == "server-trailer":
                payload += b"Server: Apache PHP/8.4.26\r\n"
            if case != "incomplete-chunk":
                payload += b"\r\n"
            reply = b"HTTP/1.1 200 OK\r\n" + common + b"Transfer-Encoding: chunked\r\nTrailer: Digest, X-Trailer\r\n\r\n" + payload
        elif case == "oversize":
            reply = b"HTTP/1.1 200 OK\r\nContent-Length: 65536\r\n\r\n"
        elif case == "bad-status":
            reply = b"HTTP/1.1 +20 Odd\r\nContent-Length: 0\r\n\r\n"
        elif case == "ambiguous":
            reply = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nTransfer-Encoding: chunked\r\n\r\nok"
        elif case == "flood":
            reply = b"HTTP/1.1 100 Continue\r\n\r\n" * 17 + b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
        elif case == "unexpected-upgrade":
            reply = b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
        elif case in ["204", "304", "head", "head-unknown"]:
            status = case.encode() if not case.startswith("head") else b"200"
            reply = b"HTTP/1.1 " + status + b" Empty\r\n" + (b"Content-Length: 77\r\n" if case in ["head", "304"] else b"") + b"\r\n"
        elif case == "eof":
            reply = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nok"
        else:
            reply = prefix + b"HTTP/1.1 200 OK\r\n" + common + b"Content-Length: 2\r\n\r\nok"
        try:
            self.connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            if case == "early":
                self.connection.sendall(b"HTTP/1.1 103 Early Hints\r\nLink: </early.css>; rel=preload\r\n\r\n")
                assert self.server.final_release.wait(3), "early hint was not forwarded before the final reply"
            self.connection.sendall(reply)
            if case in ["fixed", "trailer", "empty-trailer", "info", "204", "304", "head"]:
                # Read the next request normally, keeping the origin open beyond
                # the attempt budget without blocking legitimate pool reuse.
                self.connection.settimeout(4)
                self.close_connection = False
                return
        except (ConnectionError, TimeoutError):
            pass
        self.close_connection = True


with tempfile.TemporaryDirectory(prefix="ll-framing-", dir="/tmp") as temporary:
    folder = pathlib.Path(temporary)
    origin = Origin(("127.0.0.1", 0), Handler)
    origin.lock, origin.counts, origin.requests, origin.release = threading.Lock(), collections.Counter(), {}, threading.Event()
    origin.final_release = threading.Event()
    thread = threading.Thread(target=origin.serve_forever)
    thread.start()
    try:
        for secure in [False, True]:
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]
            config, log_path = folder / "server.conf", folder / "server.log"
            config.write_text(f"""host = 127.0.0.1
port = {port}
tls = {str(secure).lower()}
admin_socket = off
worker_stack_size = 65536
upstream_timeout_ms = 700
upstream_retries = 0
upstream_max_failures = 0
write_timeout_ms = 1500
max_static_file_bytes = 16384
response_cache = true
response_cache_max_bytes = 1048576
response_cache_max_entry_bytes = 16384
response_cache_ttl_ms = 60000
graceful_shutdown_timeout_ms = 1000
route = app /app/* proxy
route_proxy.app = http://127.0.0.1:{origin.server_port}
""")
            process, clients = None, []

            def client(window=65535):
                value = H2(port, secure, window)
                clients.append(value)
                return value

            def h1(case, method="GET", extra=()):
                args = ["curl", "-skS", "--http1.1", "--max-time", "3", "-D", str(folder / "headers"), "-o", str(folder / "body"), "-w", "%{http_code}"]
                if method == "HEAD":
                    args += ["--head"]
                for field in extra:
                    args += ["-H", field]
                result = subprocess.run(args + [f"{'https' if secure else 'http'}://127.0.0.1:{port}/app/{case}"], capture_output=True, text=True)
                return int(result.stdout or 0), (folder / "body").read_bytes(), (folder / "headers").read_bytes().lower(), result.returncode

            try:
                with log_path.open("wb") as log:
                    process = subprocess.Popen([str(BINARY), "--config", str(config)], cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
                    until = time.monotonic() + 5
                    while True:
                        assert process.poll() is None, log_path.read_text()
                        try:
                            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                                break
                        except OSError:
                            assert time.monotonic() < until, log_path.read_text()
                            time.sleep(0.03)
                    connection = client()
                    connection.request(1, "/app/fixed", extra=[(b"x-empty", b"")])
                    assert connection.reply(1) == ([200], b"ok"), connection.blocks[1]
                    assert connection.blocks[1][0][b"x-empty"] == b""
                    with origin.lock:
                        assert origin.requests["fixed"]["x-empty"] == ""
                    origin.final_release.clear()
                    connection.request(3, "/app/early")
                    connection.until(lambda: bool(connection.blocks[3]))
                    assert connection.blocks[3] == [{b":status": b"103", b"link": b"</early.css>; rel=preload"}], connection.blocks[3]
                    assert not connection.done(3), "interim reply ended the stream"
                    connection.request(5, "/health")
                    assert connection.reply(5) == ([200], b"ok\n")
                    origin.final_release.set()
                    assert connection.reply(3) == ([103, 200], b"ok")
                    for index, case in enumerate(["head", "204", "304", "eof", "info", "head-unknown", "limit-info"], 3):
                        stream = index * 2 + 1
                        connection.request(stream, "/app/" + case, b"HEAD" if case.startswith("head") else b"GET")
                        statuses, body = connection.reply(stream)
                        assert statuses == ([103, 102, 200] if case == "info" else [200 if case in ["head", "head-unknown", "eof", "limit-info"] else int(case)]), (case, statuses)
                        assert body == (b"ok" if case in ["info", "eof", "limit-info"] else b""), (case, body)
                        if case in ["head", "304"]:
                            assert connection.blocks[stream][-1][b"content-length"] == b"77"
                        if case == "head-unknown":
                            assert b"content-length" not in connection.blocks[stream][-1]
                        assert all(b"x-hop" not in fields for fields in connection.blocks[stream]), connection.blocks[stream]
                    status, body, fields, code = h1("fixed", extra=["Connection: keep-alive, X-Hop", "Connection: X-Other, X-Forwarded-Proto", "X-Hop: no", "X-Other: no", "X-End: yes", "X-Forwarded-Proto: wrong", "Trailer: Digest", "Proxy-Connection: keep-alive"])
                    assert (status, body, code) == (200, b"ok", 0), (status, body, code)
                    assert b"private-hop" not in fields and b"other-hop" not in fields and b"proxy-connection:" not in fields
                    with origin.lock:
                        forwarded = origin.requests["fixed"]
                    assert not any(name in forwarded for name in ["x-hop", "x-other", "trailer", "proxy-connection"]), forwarded
                    assert forwarded["x-end"] == "yes" and forwarded["x-forwarded-proto"] == ("https" if secure else "http"), forwarded
                    status, body, fields, code = h1("info")
                    assert (status, body, code) == (200, b"ok", 0) and b"103 early hints" in fields and b"102 processing" in fields, (status, body[:180], fields, code)
                    assert b"100 continue" not in fields and b"private-info" not in fields
                    origin.final_release.clear()
                    with socket.create_connection(("127.0.0.1", port), timeout=3) as raw:
                        if secure:
                            context = ssl._create_unverified_context()
                            context.set_alpn_protocols(["http/1.1"])
                            raw = context.wrap_socket(raw, server_hostname="localhost")
                        try:
                            raw.sendall(b"GET /app/early HTTP/1.1\r\nHost: localhost\r\nX-Empty:\r\nConnection: close\r\n\r\n")
                            assert h1_header(raw).startswith(b"HTTP/1.1 103 "), "HTTP/1 early hints waited for final response"
                            with origin.lock:
                                assert origin.requests["early"]["x-empty"] == ""
                            origin.final_release.set()
                            assert h1_header(raw).startswith(b"HTTP/1.1 200 ")
                            assert exact(raw, 2) == b"ok"
                            assert raw.recv(1) == b""
                        finally:
                            origin.final_release.set()
                            raw.close()
                    status, body, _, code = h1("limit-info")
                    assert (status, body, code) == (200, b"ok", 0)
                    for case in ["bad-status", "ambiguous", "flood", "unexpected-upgrade"]:
                        status, _, _, code = h1(case)
                        assert status == 502 and code == 0, (case, status, code)
                    for case in ["bad-trailer", "incomplete-chunk", "version-trailer", "server-trailer"]:
                        status, _, fields, code = h1(case)
                        assert status == 200 and code != 0 and b"content-length: 2" not in fields, (case, status, code, fields)
                        assert b"php/8.4.26" not in fields
                    for case in ["trailer", "empty-trailer"]:
                        queued = client(0)
                        queued.request(1, "/app/" + case)
                        queued.until(lambda: bool(queued.blocks[1]))
                        if case == "trailer":
                            queued.conn.sendall(frame(6, 0, 0, b"boundary"))
                            queued.until(lambda: (6, 1, 0, b"boundary") in queued.frames)
                            assert not queued.done(1), "trailers escaped ahead of flow-blocked DATA"
                            queued.conn.sendall(frame(8, 0, 1, (2).to_bytes(4, "big")))
                        assert queued.reply(1) == ([200], b"ok" if case == "trailer" else b"")
                        assert queued.blocks[1][-1] == {b"digest": b"sha-test", b"x-empty": b""}, queued.blocks[1]
                        terminal = [item for item in queued.frames if item[2] == 1 and item[0] in [0, 1]][-1]
                        assert terminal[0] == 1 and terminal[1] & 1, terminal
                        status, body, fields, code = h1(case)
                        assert status == 200 and code == 0 and b"digest: sha-test" in fields and b"private-trailer" not in fields, (status, fields, code)
                    for index, case in enumerate(["bad-status", "ambiguous", "flood", "oversize", "bad-trailer", "incomplete-chunk", "version-trailer", "server-trailer", "unexpected-upgrade"], 20):
                        stream = index * 2 + 1
                        connection.request(stream, "/app/" + case)
                        assert connection.reply(stream)[0] == [502], (case, connection.blocks[stream])
                    for index, value in enumerate([b" value", b"value ", b"\tvalue", b"value\t"], 40):
                        stream = index * 2 + 1
                        connection.request(stream, "/app/never", extra=[(b"x-test", value)])
                        assert connection.reply(stream)[0] == [400], (value, connection.blocks[stream])
                    connection.request(99, "/health", end=False)
                    connection.conn.sendall(frame(1, 5, 99, literal(b"digest", b" bad")))
                    connection.until(lambda: any(k == 3 and s == 99 for k, _, s, _ in connection.frames))
                    assert any(k == 3 and s == 99 and p == bytes([0, 0, 0, 1]) for k, _, s, p in connection.frames)
                    connection.request(101, "/health", extra=[(b"x-empty", b""), (b"x-internal", b"a\tb c")])
                    assert connection.reply(101) == ([200], b"ok\n")
                    assert origin.counts["never"] == 0
                    for value in clients:
                        value.close()
                    clients.clear()
                    process.terminate()
                    assert process.wait(timeout=4) == 0, log_path.read_text()
                print(f"ok: {'TLS/ALPN' if secure else 'plain/h2c'} upstream boundaries, bodyless metadata, 1xx, hop fields, terminal trailers and strict H2 values", flush=True)
            except BaseException:
                print(log_path.read_text()[-5000:], file=sys.stderr)
                raise
            finally:
                origin.final_release.set()
                for value in clients:
                    value.close()
                if process is not None and process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=4)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=4)
    finally:
        origin.final_release.set()
        origin.release.set()
        origin.shutdown()
        origin.server_close()
        thread.join(timeout=4)
