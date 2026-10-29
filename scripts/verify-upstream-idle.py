#!/usr/bin/env python3
"""A pooled origin socket must still be quiet and open before its next request."""
import http.client
import http.server
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


def request(port, secure, path, method="GET", body=None):
    connection = (http.client.HTTPSConnection("127.0.0.1", port, timeout=3, context=ssl._create_unverified_context())
                  if secure else http.client.HTTPConnection("127.0.0.1", port, timeout=3))
    try:
        connection.request(method, "/pool/" + path, body=body)
        response = connection.getresponse()
        result = response.status, response.read()
        assert result == (200, b"" if method == "HEAD" else b"ok"), (response.status, len(result[1]))
    finally:
        connection.close()


with tempfile.TemporaryDirectory(prefix="ll-idle-", dir="/tmp") as temporary:
    origin = Origin(("127.0.0.1", 0), Handler)
    origin.lock, origin.seen = threading.Lock(), []
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
                    request(port, secure, "quiet")
                    with origin.lock:
                        assert origin.seen[-1][2] is original, "healthy idle connection was discarded"

                    for case, method, payload in [("closed-get", "GET", None), ("closed-post", "POST", b"once"), ("unsolicited", "GET", None)]:
                        request(port, secure, case + "-seed", "HEAD")
                        with origin.lock:
                            old_socket = origin.seen[-1][2]
                        if case == "unsolicited":
                            old_socket.sendall(b"HTTP/1.1 200 Poisoned\r\nContent-Length: 6\r\n\r\npoison")
                        else:
                            old_socket.shutdown(socket.SHUT_RDWR)
                            old_socket.close()
                        # Let the loopback FIN/data reach the pool's endpoint.
                        time.sleep(.05)
                        request(port, secure, case, method, payload)
                        with origin.lock:
                            matches = [entry for entry in origin.seen if entry[0] == "/pool/" + case]
                            assert len(matches) == 1, ("request was retried", case, len(matches))
                            assert matches[0][2] is not old_socket, ("unsafe socket reused", case)
                            if method == "POST":
                                assert matches[0][3] == b"once"
                    print(f"ok: {'TLS' if secure else 'plain'} idle upstream EOF/unsolicited bytes discarded, quiet sockets reused, POST sent once", flush=True)
                finally:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)
    finally:
        origin.shutdown()
        origin.server_close()
        thread.join(timeout=3)
