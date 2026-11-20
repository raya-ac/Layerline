#!/usr/bin/env python3
"""A pooled origin socket must still be quiet and open before its next request."""
import http.client
import http.server
import os
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

    def finish(self):
        try:
            super().finish()
        finally:
            with self.server.lock:
                self.server.closed.add(self.connection)

    def answer(self):
        length = int(self.headers.get("Content-Length", "0"))
        payload = self.rfile.read(length)
        with self.server.lock:
            self.server.seen.append((self.path, self.command, self.connection, payload))
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(b"ok")
            self.wfile.flush()

    do_GET = answer
    do_HEAD = answer
    do_POST = answer


def request(port, secure, path, method="GET", body=None, h2=False):
    if h2:
        command = [
            "curl", "-skS", "--max-time", "3", "--http2" if secure else "--http2-prior-knowledge",
            "-w", "%{response_code}/%{http_version}\n",
        ]
        if method == "HEAD":
            command += ["--head", "-o", os.devnull]
        if body is not None:
            command += ["--data-binary", "@-"]
        scheme = "https" if secure else "http"
        result = subprocess.run(command + [f"{scheme}://127.0.0.1:{port}/pool/{path}"], input=body, capture_output=True, check=True)
        assert result.stdout == (b"" if method == "HEAD" else b"ok") + b"200/2\n", result.stdout
        return
    connection = (http.client.HTTPSConnection("127.0.0.1", port, timeout=3, context=ssl._create_unverified_context())
                  if secure else http.client.HTTPConnection("127.0.0.1", port, timeout=3))
    try:
        connection.request(method, "/pool/" + path, body=body)
        response = connection.getresponse()
        result = response.status, response.read()
        assert result == (200, b"" if method == "HEAD" else b"ok"), (response.status, len(result[1]))
    finally:
        connection.close()


def check_expiry(origin, folder, secure):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    config = folder / "expiry.conf"
    config.write_text(f"""host = 127.0.0.1
port = {port}
tls = {str(secure).lower()}
admin_socket = off
upstream_keepalive = true
upstream_keepalive_idle_timeout_ms = 1500
route = pool /pool/* proxy
route_proxy.pool = http://127.0.0.1:{origin.server_port}
""")
    log_path = folder / "expiry.log"
    with log_path.open("wb") as log:
        process = subprocess.Popen([str(BINARY), "--config", str(config)], cwd=ROOT, stdout=log, stderr=log)
        try:
            until = time.monotonic() + 5
            while True:
                assert process.poll() is None and time.monotonic() < until, log_path.read_text()
                try:
                    request(port, secure, "expiry-first", "HEAD")
                    break
                except OSError:
                    time.sleep(.02)
            with origin.lock:
                old = origin.seen[-1][2]
            request(port, secure, "expiry-reuse", "HEAD", h2=True)
            with origin.lock:
                assert origin.seen[-1][2] is old and old not in origin.closed

            # no client request checks out this socket to make it close.
            until = time.monotonic() + 5
            while True:
                with origin.lock:
                    if old in origin.closed:
                        break
                assert process.poll() is None and time.monotonic() < until, "idle socket never closed"
                time.sleep(.02)
            request(port, secure, "after-expiry", h2=True)
            with origin.lock:
                assert origin.seen[-1][2] is not old
            print(f"ok: {'TLS' if secure else 'plain'} origin socket expires without another checkout", flush=True)
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)


with tempfile.TemporaryDirectory(prefix="ll-idle-", dir="/tmp") as temporary:
    origin = Origin(("127.0.0.1", 0), Handler)
    origin.lock, origin.seen = threading.Lock(), []
    origin.closed = set()
    thread = threading.Thread(target=origin.serve_forever)
    thread.start()
    try:
        for secure in [False, True]:
            with origin.lock:
                origin.seen.clear()
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]
            folder = pathlib.Path(temporary)
            config = folder / "server.conf"
            config.write_text(f"""host = 127.0.0.1
port = {port}
tls = {str(secure).lower()}
admin_socket = off
upstream_keepalive = true
upstream_keepalive_idle_timeout_ms = 30000
upstream_keepalive_max_requests = 4
upstream_retries = 0
upstream_max_failures = 0
route = pool /pool/* proxy
route_proxy.pool = http://127.0.0.1:{origin.server_port}
""")
            with (folder / "server.log").open("wb") as log:
                process = subprocess.Popen([str(BINARY), "--config", str(config)], cwd=ROOT, stdout=log, stderr=log)
                try:
                    for _ in range(60):
                        assert process.poll() is None, (folder / "server.log").read_text()
                        try:
                            request(port, secure, "ready", "HEAD")
                            break
                        except (OSError, http.client.HTTPException):
                            time.sleep(.05)
                    else:
                        raise AssertionError("server never became ready")
                    request(port, secure, "quiet", "HEAD")
                    with origin.lock:
                        original = origin.seen[-1][2]
                    request(port, secure, "quiet", h2=True)
                    with origin.lock:
                        assert origin.seen[-1][2] is original, "HTTP/2 didn't reuse the HTTP/1 origin socket"
                    request(port, secure, "quiet-again")
                    with origin.lock:
                        assert origin.seen[-1][2] is original, "HTTP/2 didn't return the socket to the shared pool"

                    for h2 in [False, True]:
                        for case, method, payload in [("closed-get", "GET", None), ("closed-post", "POST", b"once"), ("unsolicited", "GET", None)]:
                            path = f"{'h2' if h2 else 'h1'}-{case}"
                            request(port, secure, path + "-seed", "HEAD", h2=h2)
                            with origin.lock:
                                old_socket = origin.seen[-1][2]
                                if path == "h1-closed-get":
                                    assert old_socket is not original, "shared socket exceeded the four-request cap"
                            if case == "unsolicited":
                                old_socket.sendall(b"unexpected bytes")
                            else:
                                old_socket.shutdown(socket.SHUT_RDWR)
                                old_socket.close()
                            # Wait for the loopback FIN or bytes to reach the idle socket.
                            time.sleep(.05)
                            request(port, secure, path, method, payload, h2=h2)
                            with origin.lock:
                                matches = [entry for entry in origin.seen if entry[0] == "/pool/" + path]
                                assert len(matches) == 1, ("request was retried", path, len(matches))
                                assert matches[0][2] is not old_socket, ("unsafe socket reused", path)
                                if method == "POST":
                                    assert matches[0][3] == b"once"
                    print(f"ok: {'TLS' if secure else 'plain'} HTTP/1 and HTTP/2 share origin sockets, discard idle EOF/bytes and send POST once", flush=True)
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)
            check_expiry(origin, folder, secure)
    finally:
        origin.shutdown()
        origin.server_close()
        thread.join(timeout=3)
