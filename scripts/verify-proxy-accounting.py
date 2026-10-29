#!/usr/bin/env python3
"""HTTP/1 proxy logs and metrics must agree with final replies, not upstream attempts."""
import collections
import http.server
import json
import pathlib
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
BINARY = pathlib.Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / "zig-out/bin/layerline"


class Origin(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, *_):
        pass


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_):
        pass

    def do_GET(self):
        case = self.path.rsplit("/", 1)[-1]
        self.close_connection = True
        with self.server.lock:
            self.server.seen[case] += 1
        try:
            if case == "info-abort":
                self.connection.sendall(b"HTTP/1.1 103 Early Hints\r\nLink: </a.css>; rel=preload\r\n\r\n")
            if case in ["malformed", "info-abort", "retry"] and not self.server.fallback:
                self.connection.sendall(b"not an HTTP response\r\n\r\n")
                return
            if case == "upgrade":
                self.connection.sendall(b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\nhello")
                self.connection.settimeout(3)
                while data := self.connection.recv(4096):
                    self.connection.sendall(data)
                return
            if case == "info":
                self.connection.sendall(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </a.css>; rel=preload\r\n\r\n")
            if case in ["chunked", "bad-trailer"]:
                trailer = b"Digest: test" if case == "chunked" else b"Content-Length: 4"
                self.connection.sendall(b"HTTP/1.1 202 Accepted\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nabcd\r\n0\r\n" + trailer + b"\r\n\r\n")
                return
            if case in ["204", "304"]:
                self.connection.sendall(b"HTTP/1.1 " + case.encode() + b" Empty\r\n\r\n")
                return
            if case == "eof":
                self.connection.sendall(b"HTTP/1.1 203 Non-Authoritative Information\r\nConnection: close\r\n\r\nbye")
                return
            if case == "php":
                self.connection.sendall(b"HTTP/1.1 200 OK\r\nX-Powered-By: PHP/8.4.26\r\nContent-Length: 6\r\n\r\nsecret")
                return
            body = b"abc" if case in ["broken", "timeout"] else b"hello"
            length = 64 if case in ["broken", "timeout"] else len(body)
            self.connection.sendall(f"HTTP/1.1 201 Created\r\nContent-Length: {length}\r\n\r\n".encode())
            if self.command != "HEAD":
                self.connection.sendall(body)
            if case == "timeout":
                time.sleep(1.5)
        except (OSError, TimeoutError):
            pass

    do_HEAD = do_GET


def head(conn):
    result = bytearray()
    while not result.endswith(b"\r\n\r\n"):
        part = conn.recv(1)
        assert part, ("response head truncated", bytes(result))
        result.extend(part)
        assert len(result) < 65536
    return bytes(result)


def drain(conn):
    result = bytearray()
    while True:
        try:
            data = conn.recv(65536)
        except (ConnectionResetError, ssl.SSLEOFError):
            break
        if not data:
            return bytes(result)
        result.extend(data)
    return bytes(result)


def metrics(path):
    with socket.socket(socket.AF_UNIX) as conn:
        conn.settimeout(3)
        conn.connect(str(path))
        conn.sendall(b"metrics\n")
        body = drain(conn).decode()
    return {line.split()[0]: int(line.split()[1]) for line in body.splitlines() if line.startswith("layerline_")}


def entries(path):
    if not path.exists():
        return []
    # A concurrent file write can leave its last line temporarily incomplete.
    return [json.loads(line) for line in path.read_text().splitlines(keepends=True) if line.endswith("\n") and line.strip()]


def exact(conn, count):
    result = bytearray()
    while len(result) < count:
        part = conn.recv(count - len(result))
        assert part, "tunnel closed before its payload arrived"
        result.extend(part)
    return bytes(result)


def wait_entry(path, request_id):
    until = time.monotonic() + 3
    while True:
        found = [entry for entry in entries(path) if entry.get("request_id") == request_id]
        if found:
            assert len(found) == 1, ("duplicate final access log", found)
            return found[0]
        assert time.monotonic() < until, ("missing final access log", request_id, entries(path))
        time.sleep(.01)


def connect(port, secure):
    conn = socket.create_connection(("127.0.0.1", port), timeout=3)
    if secure:
        context = ssl._create_unverified_context()
        context.set_alpn_protocols(["http/1.1"])
        conn = context.wrap_socket(conn, server_hostname="localhost")
    return conn


def run(folder, origins, secure, logging):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    folder.mkdir()
    config, log, access, admin = [folder / name for name in ["server.conf", "server.log", "access.log", "admin.sock"]]
    config.write_text(f"""host = 127.0.0.1
port = {port}
tls = {str(secure).lower()}
worker_stack_size = 65536
admin_socket = {admin}
admin_ui = false
access_log = {access if logging else 'off'}
upstream_keepalive = false
upstream_retries = 1
upstream_max_failures = 0
upstream_timeout_ms = 1000
write_timeout_ms = 350
graceful_shutdown_timeout_ms = 1000
route = app /app/* proxy
route_proxy.app = http://127.0.0.1:{origins[0].server_port}
route = retry /retry/* proxy
route_proxy.retry = http://127.0.0.1:{origins[0].server_port} http://127.0.0.1:{origins[1].server_port}
route_upstream_policy.retry = sticky_cookie
""")
    process = None
    try:
        with log.open("wb") as output:
            process = subprocess.Popen([str(BINARY), "--config", str(config)], cwd=ROOT, stdout=output, stderr=subprocess.STDOUT)
            until = time.monotonic() + 5
            while True:
                assert process.poll() is None, log.read_text()
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=.1):
                        if admin.exists():
                            break
                except OSError:
                    pass
                assert time.monotonic() < until, log.read_text()
                time.sleep(.02)
            before = metrics(admin)
            expected = []

            def check(case, status, byte_count, complete=True, method="GET"):
                request_id = f"account-{len(expected)}"
                prefix = "retry" if case == "retry" else "app"
                path = f"/{prefix}/{case}"
                conn = connect(port, secure)
                try:
                    upgrade = b"Upgrade: websocket\r\nConnection: Upgrade\r\n" if case == "upgrade" else b"Connection: close\r\n"
                    if case == "retry":
                        upgrade += b"Cookie: ll_upstream=0\r\n"
                    conn.sendall(f"{method} {path} HTTP/1.1\r\nHost: localhost\r\nX-Request-Id: {request_id}\r\n".encode() + upgrade + b"\r\n")
                    info, reply_head = [], head(conn)
                    while 100 <= int(reply_head.split()[1]) < 200 and not reply_head.startswith(b"HTTP/1.1 101 "):
                        info.append(int(reply_head.split()[1]))
                        reply_head = head(conn)
                    assert int(reply_head.split()[1]) == status, (case, reply_head)
                    assert info == ([103] if case in ["info", "info-abort"] else []), (case, info)
                    if case == "upgrade":
                        assert exact(conn, 5) == b"hello"
                        # The log and metrics must be visible before tunnel EOF.
                        if logging:
                            wait_entry(access, request_id)
                        assert metrics(admin)['layerline_responses_total{class="all"}'] == before['layerline_responses_total{class="all"}'] + len(expected) + 1
                        conn.sendall(b"ping")
                        assert exact(conn, 4) == b"ping"
                        wire_body = b""
                    else:
                        wire_body = drain(conn)
                    if method == "HEAD" or status in [204, 304]:
                        assert not wire_body, (case, wire_body)
                    elif case == "chunked":
                        assert wire_body == b"4\r\nabcd\r\n0\r\nDigest: test\r\n\r\n", wire_body
                    elif case == "bad-trailer":
                        assert wire_body == b"4\r\nabcd\r\n", wire_body
                    elif case not in ["malformed", "info-abort", "php", "upgrade"]:
                        assert wire_body == (b"abc" if case in ["broken", "timeout"] else b"bye" if case == "eof" else b"hello"), (case, wire_body)
                    if case == "php" and method != "HEAD":
                        assert b"Site owner: update PHP" in wire_body and b"secret" not in wire_body
                    count = len(wire_body) if byte_count is None else byte_count
                    expected.append((status, count))
                    if logging:
                        entry = wait_entry(access, request_id)
                        assert (entry["status"], entry["bytes"], entry["path"], entry["method"], entry["protocol"]) == (status, count, path, method, "HTTP/1.1"), entry
                        assert entry["handler"] == "route_proxy" and entry.get("upstream"), entry
                        if complete is not None:
                            assert entry.get("response_complete") is complete, entry
                        if complete is False:
                            assert entry.get("error"), entry
                        else:
                            assert "error" not in entry, entry
                finally:
                    conn.close()

            check("fixed", 201, 5)
            check("head", 201, 0, method="HEAD")
            check("204", 204, 0)
            check("304", 304, 0)
            check("chunked", 202, 4)
            check("eof", 203, 3)
            check("info", 201, 5)
            check("broken", 201, 3, False)
            check("bad-trailer", 202, 4, False)
            check("timeout", 201, 3, False)
            check("malformed", 502, None, None)
            check("info-abort", 502, None, None)
            with origins[0].lock, origins[1].lock:
                retry_before = [origin.seen["retry"] for origin in origins]
            check("retry", 201, 5)
            with origins[0].lock, origins[1].lock:
                assert [origin.seen["retry"] for origin in origins] == [value + 1 for value in retry_before], "retry fixture did not exercise both attempts"
            check("php", 503, None, None)
            check("php", 503, 0, None, method="HEAD")
            check("upgrade", 101, 0)
            after = metrics(admin)
            for group in ["all", "2xx", "3xx", "4xx", "5xx"]:
                key = f'layerline_responses_total{{class="{group}"}}'
                want = len(expected) if group == "all" else sum(status // 100 == int(group[0]) for status, _ in expected)
                assert after[key] - before[key] == want, (key, before[key], after[key], want)
            key = "layerline_response_body_bytes_total"
            assert after[key] - before[key] == sum(count for _, count in expected), (key, after[key] - before[key], expected)
            key = "layerline_requests_total"
            assert after[key] - before[key] == len(expected), (key, before[key], after[key], expected)
            for key, count in [("layerline_upstream_requests_total", len(expected) + 1), ("layerline_upstream_retries_total", 1), ("layerline_upstream_failures_total", 5)]:
                assert after[key] - before[key] == count, (key, before[key], after[key], count)
            if logging:
                all_entries = entries(access)
                assert len(all_entries) == len(expected), ("missing or duplicate entries", all_entries)
                assert all(entry["status"] != 0 for entry in all_entries), all_entries
            else:
                assert not entries(access), "disabled logging still emitted access entries"
            assert process.poll() is None, log.read_text()
            print(f"ok: {'TLS' if secure else 'plain'} proxy accounting, partial bodies, hints, retries, PHP notices, live upgrade; logging={'on' if logging else 'off'}")
    except BaseException:
        print(log.read_text() if log.exists() else "no server log", file=sys.stderr)
        raise
    finally:
        if process is not None:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


with tempfile.TemporaryDirectory(prefix="ll-account-", dir="/tmp") as temporary:
    origins, threads = [], []
    try:
        for fallback in [False, True]:
            origin = Origin(("127.0.0.1", 0), Handler)
            origin.lock, origin.seen, origin.fallback = threading.Lock(), collections.Counter(), fallback
            origins.append(origin)
            thread = threading.Thread(target=origin.serve_forever)
            thread.start()
            threads.append(thread)
        for secure in [False, True]:
            for logging in [True, False]:
                run(pathlib.Path(temporary) / f"{int(secure)}-{int(logging)}", origins, secure, logging)
    finally:
        for origin in origins:
            origin.shutdown()
            origin.server_close()
        for thread in threads:
            thread.join()
