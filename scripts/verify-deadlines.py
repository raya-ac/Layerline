#!/usr/bin/env python3
"""Real slow clients: absolute HTTP/1, TLS and multiplexed HTTP/2 budgets."""
import http.client
import pathlib
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
BINARY = pathlib.Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / "zig-out/bin/layerline"


def context(protocol="http/1.1"):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # Only the disposable loopback certificate.
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
    ctx.set_alpn_protocols([protocol])
    return ctx


class Server:
    def __init__(self, folder, secure):
        self.secure = secure
        (folder / "queued.bin").write_bytes(b"q" * (128 * 1024))
        (folder / "blocked.bin").write_bytes(b"b" * (8 * 1024 * 1024))
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            self.port = probe.getsockname()[1]
        self.log = folder / ("tls.log" if secure else "plain.log")
        config = self.log.with_suffix(".conf")
        config.write_text(f"""host = 127.0.0.1
port = {self.port}
tls = {str(secure).lower()}
dir = {folder}
serve_static_root = true
read_header_timeout_ms = 500
read_body_timeout_ms = 300
write_timeout_ms = 350
idle_timeout_ms = 1500
graceful_shutdown_timeout_ms = 1000
admin_ui = {str(secure).lower()}
admin_credentials_path = {folder / 'owner.creds'}
""")
        self.output = self.log.open("wb")
        self.process = subprocess.Popen([str(BINARY), "--config", str(config)], cwd=ROOT, stdout=self.output, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 4
        try:
            while True:
                assert self.process.poll() is None, self.log.read_text()
                try:
                    self.health()
                    break
                except OSError:
                    assert time.monotonic() < deadline, self.log.read_text()
                    time.sleep(0.02)
        except BaseException:
            self.close()
            raise

    def raw(self, receive_buffer=None):
        if receive_buffer is None:
            return socket.create_connection(("127.0.0.1", self.port), timeout=2)
        conn = socket.socket()
        try:
            conn.settimeout(2)
            conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, receive_buffer)
            conn.connect(("127.0.0.1", self.port))
            return conn
        except BaseException:
            conn.close()
            raise

    def connect(self, protocol="http/1.1", receive_buffer=None):
        conn = self.raw(receive_buffer)
        return context(protocol).wrap_socket(conn, server_hostname="localhost") if self.secure else conn

    def health(self):
        with self.connect() as conn:
            conn.sendall(b"GET /health HTTP/1.1\r\nHost: local\r\nConnection: close\r\n\r\n")
            response = http.client.HTTPResponse(conn)
            response.begin()
            assert response.status == 200 and response.read() == b"ok\n"

    def close(self):
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=2)
        self.output.close()


def exact(conn, count):
    result = b""
    while len(result) < count:
        part = conn.recv(count - len(result))
        if not part:
            raise EOFError("connection closed early")
        result += part
    return result


def header(conn):
    data = b""
    while not data.endswith(b"\r\n\r\n"):
        data += exact(conn, 1)
    return data


def plaintext_rejected(conn):
    received = b""
    try:
        while b"\r\n" not in received:
            part = conn.recv(4096)
            if not part:
                break
            received += part
    except ConnectionResetError:
        pass  # Rejecting before reading the request can reset TCP on close.
    assert not received or received.startswith(b"HTTP/1.1 400 "), ("TLS-only listener routed plaintext", received[:150])


def trickle(conn, pieces):
    started = time.monotonic()
    for piece in pieces:
        try:
            conn.sendall(piece)
        except OSError:
            break
        time.sleep(0.08)
    received = b""
    try:
        while True:
            part = conn.recv(65536)
            if not part:
                break
            received += part
    except (ConnectionResetError, BrokenPipeError, ConnectionAbortedError, ssl.SSLError):
        pass
    assert not received or received.startswith(b"HTTP/1.1 408"), received[:150]
    assert time.monotonic() - started < 1.6, "trickle traffic renewed the budget"


class TLSWire:
    """Expose encrypted bytes so a test can pause inside a TLS record."""
    def __init__(self, server):
        self.conn = server.raw()
        self.incoming = ssl.MemoryBIO()
        self.outgoing = ssl.MemoryBIO()
        self.tls = context("h2").wrap_bio(self.incoming, self.outgoing, server_side=False, server_hostname="localhost")
        while True:
            try:
                self.tls.do_handshake()
                self.flush()
                break
            except ssl.SSLWantReadError:
                self.flush()
                self.incoming.write(self.conn.recv(65536))

    def flush(self):
        if self.outgoing.pending:
            self.conn.sendall(self.outgoing.read())

    def encrypt(self, data):
        assert self.tls.write(data) == len(data)
        return self.outgoing.read()

    def sendall(self, data):
        self.conn.sendall(self.encrypt(data))

    def recv(self, count):
        while True:
            try:
                return self.tls.read(count)
            except ssl.SSLWantReadError:
                self.flush()
                data = self.conn.recv(65536)
                if not data:
                    return b""
                self.incoming.write(data)

    def close(self):
        self.conn.close()


def frame(kind, flags, stream, payload=b""):
    return len(payload).to_bytes(3, "big") + bytes([kind, flags]) + stream.to_bytes(4, "big") + payload


def fields(path=b"/health", method=b"GET"):
    def literal(name, value):
        return b"\0" + bytes([len(name)]) + name + bytes([len(value)]) + value
    return b"".join(literal(*pair) for pair in [(b":method", method), (b":scheme", b"http"), (b":authority", b"local"), (b":path", path)])


class H2:
    def __init__(self, server, wire=False, initial_window=None, receive_buffer=None):
        self.conn = TLSWire(server) if wire else server.connect("h2", receive_buffer)
        settings = b"" if initial_window is None else struct.pack("!HI", 4, initial_window)
        self.conn.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 0, 0, settings))
        self.barrier()

    @classmethod
    def upgrade(cls, server):
        client = cls.__new__(cls)
        client.conn = server.connect()
        client.conn.sendall(b"GET /queued.bin HTTP/1.1\r\nHost: local\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAQAAAAA\r\n\r\n")
        assert header(client.conn).startswith(b"HTTP/1.1 101"), "h2c upgrade failed"
        client.conn.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 0, 0, struct.pack("!HI", 4, 0)))
        client.until(lambda f: f[0] == 1 and f[2] == 1)
        return client

    def send(self, kind, flags, stream, payload=b""):
        self.conn.sendall(frame(kind, flags, stream, payload))

    def receive(self):
        head = exact(self.conn, 9)
        return head[3], head[4], int.from_bytes(head[5:], "big") & 0x7fffffff, exact(self.conn, int.from_bytes(head[:3], "big"))

    def until(self, match):
        frames = []
        for _ in range(100):
            item = self.receive()
            frames.append(item)
            if match(item):
                return frames
        raise AssertionError("expected frame not received")

    def barrier(self, complete=None):
        self.send(6, 0, 0, b"deadline")
        frames = self.until(lambda f: f == (6, 1, 0, b"deadline"))
        if complete is not None and not any(complete(item) for item in frames):
            frames += self.until(complete)
        return frames

    def upload(self):
        self.send(1, 4, 1, fields(b"/api/echo", b"POST"))
        self.send(0, 0, 1, b"a")
        self.barrier()


with tempfile.TemporaryDirectory(prefix="layerline-deadline-") as tmp:
    for secure in [False, True]:
        server = Server(pathlib.Path(tmp), secure)
        try:
            if secure:
                for path, extra in [(b"/health", b""), (b"/_layerline/admin", b""), (b"/_layerline/admin", b"X-Forwarded-Proto: https\r\n")]:
                    with server.raw() as conn:
                        conn.sendall(b"GET " + path + b" HTTP/1.1\r\nHost: local\r\n" + extra + b"\r\n")
                        plaintext_rejected(conn)
                assert not (pathlib.Path(tmp) / ".owner.creds.setup-token").exists(), "plaintext request reached admin setup"
                with server.raw() as conn:
                    conn.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 0, 0))
                    plaintext_rejected(conn)
                with server.connect() as conn:
                    conn.sendall(b"GET /_layerline/admin HTTP/1.1\r\nHost: local\r\nConnection: close\r\n\r\n")
                    response = http.client.HTTPResponse(conn)
                    response.begin()
                    assert response.status == 200 and b"setup_token" in response.read()
                print("ok: TLS-only listener rejects plaintext and spoofed forwarding before admin bootstrap")
            with server.connect() as conn:
                trickle(conn, [b"GET /health HTTP/1.1\r\nHost: local\r\nX-Slow: "] + [b"x"] * 9 + [b"\r\nConnection: close\r\n\r\n"])
            for chunked in [False, True]:
                with server.connect() as conn:
                    framing = b"Transfer-Encoding: chunked" if chunked else b"Content-Length: 8"
                    conn.sendall(b"POST /api/echo HTTP/1.1\r\nHost: local\r\n" + framing + b"\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n")
                    assert header(conn).startswith(b"HTTP/1.1 100")
                    pieces = [b"1\r\na\r\n"] * 8 + [b"0\r\n\r\n"] if chunked else [b"a"] * 8
                    trickle(conn, pieces)
            with server.connect() as conn:
                conn.sendall(b"GET /health HTTP/1.1\r\nHost: local\r\n\r\n")
                response = http.client.HTTPResponse(conn)
                response.begin()
                assert response.status == 200 and response.read() == b"ok\n"
                response.close()
                time.sleep(0.7)  # Beyond header timeout, inside keep-alive idle budget.
                conn.sendall(b"GET /health HTTP/1.1\r\nHost: local\r\nConnection: close\r\n\r\n")
                response = http.client.HTTPResponse(conn)
                response.begin()
                assert response.status == 200 and response.read() == b"ok\n"
            print(f"ok: {'TLS' if secure else 'plain'} HTTP/1 absolute header/Content-Length/chunked budgets and separate keep-alive idle time")

            for progress in [False, True]:
                h2 = H2(server, initial_window=0)
                try:
                    started = time.monotonic()
                    h2.send(1, 5, 1, fields(b"/queued.bin"))
                    h2.until(lambda f: f[0] == 1 and f[2] == 1)
                    received = []
                    if progress:
                        for stream in [3, 5, 7, 9, 11]:
                            time.sleep(0.08)
                            h2.send(8, 0, 1, (1).to_bytes(4, "big"))
                            h2.send(1, 5, stream, fields())
                            h2.send(8, 0, stream, (3).to_bytes(4, "big"))
                            received += h2.barrier(lambda f: f[0] == 0 and f[1] & 1 and f[2] == stream)
                        assert any(k == 0 and s == 11 and f & 1 and p == b"ok\n" for k, f, s, p in received)
                    else:
                        received = h2.until(lambda f: f == (3, 0, 1, (8).to_bytes(4, "big")))
                    assert (3, 0, 1, (8).to_bytes(4, "big")) in received, "PING/window traffic renewed a queued response deadline"
                    assert not any(k == 7 for k, _, _, _ in received)
                    assert time.monotonic() - started < 0.9, "zero-window output survived its response budget"
                    h2.send(8, 0, 1, (65535).to_bytes(4, "big"))
                    assert not any(k == 0 and s == 1 for k, _, s, _ in h2.barrier()), "expired response resumed sending"
                finally:
                    h2.conn.close()

            h2 = H2(server)
            try:
                started = time.monotonic()
                h2.send(1, 5, 1, fields(b"/queued.bin"))
                received = []
                total = 0
                while total < 65535:
                    item = h2.receive()
                    received.append(item)
                    if item[0] == 0:
                        total += len(item[3])
                assert total == 65535
                h2.send(8, 0, 1, (131072).to_bytes(4, "big"))  # Only connection credit is now stalled.
                received += h2.until(lambda f: f == (3, 0, 1, (8).to_bytes(4, "big")))
                assert time.monotonic() - started < 0.9
                h2.send(8, 0, 0, (65535).to_bytes(4, "big"))
                h2.send(1, 5, 3, fields())
                received = h2.until(lambda f: f[0] == 0 and f[1] & 1 and f[2] == 3)
                assert any(k == 0 and s == 3 and p == b"ok\n" for k, _, s, p in received)
            finally:
                h2.conn.close()
            for cut in [4, 16]:
                h2 = H2(server, initial_window=0)
                try:
                    h2.send(1, 5, 1, fields(b"/queued.bin"))
                    h2.until(lambda f: f[0] == 1 and f[2] == 1)
                    wire = frame(1, 5, 3, fields()) + frame(8, 0, 3, (3).to_bytes(4, "big"))
                    h2.conn.sendall(wire[:cut])
                    h2.until(lambda f: f == (3, 0, 1, (8).to_bytes(4, "big")))
                    h2.conn.sendall(wire[cut:])
                    received = h2.until(lambda f: f[0] == 0 and f[1] & 1 and f[2] == 3)
                    assert any(k == 0 and p == b"ok\n" for k, _, _, p in received), "partial input lost when queued output expired"
                finally:
                    h2.conn.close()
            print(f"ok: {'TLS' if secure else 'plain'} HTTP/2 zero windows and window trickle expire output without disrupting healthy streams")

            if not secure:
                h2 = H2.upgrade(server)
                try:
                    started = time.monotonic()
                    h2.until(lambda f: f == (3, 0, 1, (8).to_bytes(4, "big")))
                    assert time.monotonic() - started < 0.9
                    h2.send(1, 5, 3, fields())
                    h2.send(8, 0, 3, (3).to_bytes(4, "big"))
                    received = h2.until(lambda f: f[0] == 0 and f[1] & 1 and f[2] == 3)
                    assert any(k == 0 and p == b"ok\n" for k, _, _, p in received)
                finally:
                    h2.conn.close()
                print("ok: h2c upgrade stream uses the same absolute response budget")

            h2 = H2(server, initial_window=1 << 30, receive_buffer=4096)
            try:
                previous = server.log.read_text().count('"phase":"wire"')
                started = time.monotonic()
                h2.send(8, 0, 0, (1 << 30).to_bytes(4, "big"))
                h2.send(1, 5, 1, fields(b"/blocked.bin"))
                h2.until(lambda f: f[0] == 1 and f[2] == 1)
                while server.log.read_text().count('"phase":"wire"') == previous and time.monotonic() - started < 0.9:
                    assert h2.conn.recv(1024), "writer closed before recording its timeout"
                    time.sleep(0.08)
                assert server.log.read_text().count('"phase":"wire"') == previous + 1, "small successful writes renewed the response wire budget"
                assert time.monotonic() - started < 0.9
                h2.conn.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)
                draining_until = time.monotonic() + 3
                while True:
                    try:
                        if not h2.conn.recv(65536):
                            break
                    except (ConnectionResetError, ssl.SSLEOFError):
                        break
                    assert time.monotonic() < draining_until, "timed-out frame writer kept the connection alive"
            finally:
                h2.conn.close()
            server.health()
            print(f"ok: {'TLS' if secure else 'plain'} HTTP/2 blocked socket writes close at the original response deadline")

            h2 = H2(server)
            try:
                h2.upload()
                received = []
                for stream in [3, 5, 7, 9, 11]:
                    time.sleep(0.08)
                    h2.send(0, 0, 1, b"x")
                    h2.send(1, 5, stream, fields())
                    received += h2.barrier(lambda f: f[0] == 0 and f[1] & 1 and f[2] == stream)
                assert (3, 0, 1, (8).to_bytes(4, "big")) in received, "upload progress renewed the stream deadline"
                assert any(k == 0 and s == 11 and f & 1 and p == b"ok\n" for k, f, s, p in received)
                assert not any(k == 7 for k, _, _, _ in received)
            finally:
                h2.conn.close()

            for cut in [4, 16]:
                h2 = H2(server)
                try:
                    h2.upload()
                    wire = frame(1, 5, 3, fields())
                    h2.conn.sendall(wire[:cut])
                    h2.until(lambda f: f == (3, 0, 1, (8).to_bytes(4, "big")))
                    h2.conn.sendall(wire[cut:])
                    received = h2.until(lambda f: f[0] == 0 and f[1] & 1 and f[2] == 3)
                    assert any(k == 0 and p == b"ok\n" for k, _, _, p in received), "partial frame lost at another stream's timeout"
                finally:
                    h2.conn.close()

            h2 = H2(server)
            try:
                block = fields()
                started = time.monotonic()
                h2.send(1, 1, 1, block[:1])
                for part in block[1:4]:
                    time.sleep(0.15)
                    h2.send(9, 0, 1, bytes([part]))
                received = h2.until(lambda f: f[0] == 7)
                assert int.from_bytes(received[-1][3][4:], "big") == 11, "CONTINUATION traffic renewed the header deadline"
                assert time.monotonic() - started < 0.9, "header fragments renewed the aggregate budget"
            finally:
                h2.conn.close()
            h2 = H2(server)
            try:
                wire = frame(1, 5, 1, fields())
                started = time.monotonic()
                h2.conn.sendall(wire[:10])
                for part in wire[10:13]:
                    time.sleep(0.15)
                    h2.conn.sendall(bytes([part]))
                received = h2.until(lambda f: f[0] == 7)
                assert int.from_bytes(received[-1][3][4:], "big") == 11
                assert time.monotonic() - started < 0.9, "frame bytes renewed their assembly budget"
            finally:
                h2.conn.close()
            print(f"ok: {'TLS' if secure else 'plain'} HTTP/2 stream expiry preserves healthy streams and partial frames; aggregate header deadline enforced")

            if secure:
                for cut in [2, 7]:
                    h2 = H2(server, wire=True, initial_window=0)
                    try:
                        h2.send(1, 5, 1, fields(b"/queued.bin"))
                        h2.until(lambda f: f[0] == 1 and f[2] == 1)
                        packet = frame(1, 5, 3, fields()) + frame(8, 0, 3, (3).to_bytes(4, "big"))
                        wire = h2.conn.encrypt(packet)
                        h2.conn.conn.sendall(wire[:cut])
                        h2.until(lambda f: f == (3, 0, 1, (8).to_bytes(4, "big")))
                        h2.conn.conn.sendall(wire[cut:])
                        received = h2.until(lambda f: f[0] == 0 and f[1] & 1 and f[2] == 3)
                        assert any(k == 0 and p == b"ok\n" for k, _, _, p in received), "partial ciphertext lost when queued output expired"
                    finally:
                        h2.conn.close()
                for cut in [2, 7]:
                    h2 = H2(server, wire=True)
                    try:
                        h2.upload()
                        wire = h2.conn.encrypt(frame(1, 5, 3, fields()))
                        h2.conn.conn.sendall(wire[:cut])
                        h2.until(lambda f: f == (3, 0, 1, (8).to_bytes(4, "big")))
                        h2.conn.conn.sendall(wire[cut:])
                        received = h2.until(lambda f: f[0] == 0 and f[1] & 1 and f[2] == 3)
                        assert any(k == 0 and p == b"ok\n" for k, _, _, p in received), "partial ciphertext lost at stream expiry"
                    finally:
                        h2.conn.close()
                h2 = H2(server, wire=True)
                try:
                    wire = h2.conn.encrypt(frame(1, 5, 1, fields()))
                    started = time.monotonic()
                    h2.conn.conn.sendall(wire[:2])
                    for part in wire[2:5]:
                        time.sleep(0.15)
                        h2.conn.conn.sendall(bytes([part]))
                    received = h2.until(lambda f: f[0] == 7)
                    assert int.from_bytes(received[-1][3][4:], "big") == 11
                    assert time.monotonic() - started < 0.9, "encrypted record bytes renewed the header budget"
                finally:
                    h2.conn.close()
                print("ok: HTTP/2 stream expiry resumes partial TLS record headers and ciphertext without desynchronization")
            server.health()
        finally:
            server.close()
