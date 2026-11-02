#!/usr/bin/env python3
"""Real Darwin libc stalls must not outlive backend ownership or deadlines."""
import concurrent.futures
import http.client
import http.server
import os
from pathlib import Path
import signal
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time

from wire_h2 import H2, frame

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / "zig-out/bin/layerline"
NEGATIVE = "--negative-control" in sys.argv[2:]
if sys.platform != "darwin":
    print("skip: libc resolver process cancellation is a macOS-specific gate")
    raise SystemExit(0)


def wait_for(check, label, seconds=1.5):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        if check():
            return
        time.sleep(.01)
    raise AssertionError(label)


def gone(pid):
    try:
        os.kill(pid, 0)
        return False
    except ProcessLookupError:
        return True


class Backend(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 32


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        if self.path.startswith("/combined/"):
            time.sleep(.2)
        try:
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b"ok")
        except (ConnectionError, OSError):
            pass


with tempfile.TemporaryDirectory(prefix="layerline-resolver-", dir="/tmp") as temporary:
    folder = Path(temporary)
    dylib, lookups = folder / "resolver.dylib", folder / "lookups.log"
    subprocess.run(["/usr/bin/clang", "-dynamiclib", "-Wall", "-Wextra", "-Werror",
                    f'-DRESOLVER_TEST_DYLIB="{dylib}"', f'-DRESOLVER_TEST_LOG="{lookups}"',
                    str(ROOT / "scripts/resolver-interpose.c"), "-o", str(dylib)], check=True)
    environment = dict(os.environ, DYLD_INSERT_LIBRARIES=str(dylib))
    backend = Backend(("127.0.0.1", 0), Handler)
    threading.Thread(target=backend.serve_forever, daemon=True).start()
    try:
        if not NEGATIVE:
            # The private mode must run before config parsing and reject extra
            # arguments rather than accidentally entering normal server startup.
            (folder / "server.conf").write_text("not a valid server config\n")
            result = subprocess.run([str(BINARY), "--layerline-resolver-v1", "localhost", "443"], cwd=folder,
                                    capture_output=True, timeout=3)
            assert result.returncode == 0 and not result.stderr, result
            assert result.stdout[:5] == b"LND1\0", result.stdout
            count = struct.unpack("!H", result.stdout[5:7])[0]
            assert 0 < count <= 128 and len(result.stdout) == 7 + count * 25
            assert {result.stdout[7 + i * 25] for i in range(count)} <= {4, 6}
            for extra in [[], ["localhost"], ["localhost", "443", "--config", "server.conf"],
                          ["bad/name", "443"], ["localhost", "65536"]]:
                bad = subprocess.run([str(BINARY), "--layerline-resolver-v1", *extra], cwd=folder,
                                     capture_output=True, timeout=3)
                assert bad.returncode != 0 and not bad.stdout, bad
        for tls in [False, True]:
            lookups.write_text("")
            with socket.socket() as probe:
                probe.bind(("127.0.0.1", 0))
                port = probe.getsockname()[1]
            routes = ""
            for name in ["okay", "slow", "combined", "unknown", "exit", "cancel"]:
                routes += f"route = {name} /{name}/* proxy\nroute_proxy.{name} = http://{name}.resolver.test:{backend.server_port}\n"
            routes += "route_upstream_timeout_ms.cancel = 5000\n"
            config = folder / "server.conf"
            config.write_text(f"""host = 127.0.0.1
port = {port}
dir = {folder}
tls = {str(tls).lower()}
upstream_timeout_ms = 250
upstream_retries = 0
upstream_keepalive = false
upstream_max_failures = 1000
graceful_shutdown_timeout_ms = 300
{routes}""")
            process, client = None, None
            log = folder / f"server-{tls}.log"

            def request(path):
                connection = http.client.HTTPSConnection("127.0.0.1", port, timeout=8, context=ssl._create_unverified_context()) if tls else http.client.HTTPConnection("127.0.0.1", port, timeout=8)
                try:
                    start = time.monotonic()
                    connection.request("GET", path)
                    response = connection.getresponse()
                    body = response.read()
                    return response.status, body, time.monotonic() - start
                finally:
                    connection.close()

            def recorded(name=None):
                return [(int(pid), int(parent), host) for pid, parent, host in
                        (line.split() for line in lookups.read_text().splitlines())
                        if name is None or host == f"{name}.resolver.test"] if lookups.exists() else []

            def reaped():
                owned = [pid for pid, parent, _ in recorded() if parent == process.pid]
                return all(gone(pid) for pid in owned)

            try:
                with log.open("wb") as output:
                    process = subprocess.Popen([str(BINARY), "--config", str(config)], cwd=folder,
                                               env=environment, stdout=output, stderr=output)
                wait_for(lambda: process.poll() is not None or '"event":"server.ready"' in log.read_text(), "resolver fixture did not become ready", 6)
                assert process.poll() is None, log.read_text()
                assert request("/health")[:2] == (200, b"ok\n")
                assert request("/okay/value")[:2] == (200, b"ok")
                status, _, elapsed = request("/slow/value")
                assert status == 504 and elapsed < 1, ("resolver exceeded the original deadline", status, elapsed)
                assert not NEGATIVE, "old binary unexpectedly passed the stalled resolver gate"
                assert recorded("slow") and all(parent == process.pid for _, parent, _ in recorded("slow")), "getaddrinfo did not run in an owned helper"
                wait_for(reaped, "deadline left a live or zombie resolver child")
                # Lookup and response time share one budget, rather than getting
                # a fresh timeout once DNS has completed.
                status, _, elapsed = request("/combined/value")
                assert status == 504 and elapsed < 1, (status, elapsed)
                for name in ["unknown", "exit"]:
                    status, _, elapsed = request(f"/{name}/value")
                    assert status == 502 and elapsed < 1, (name, status, elapsed)
                with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                    results = list(pool.map(request, ["/slow/concurrent"] * 16))
                assert all(status in [503, 504] and elapsed < 1.5 for status, _, elapsed in results), results
                wait_for(reaped, "repeated deadlines leaked resolver children")
                assert request("/okay/recovered")[:2] == (200, b"ok")

                before = len(recorded("cancel"))
                client = H2(port, tls=tls)
                client.request(1, b"/cancel/disconnect")
                wait_for(lambda: len(recorded("cancel")) > before, "slow helper never entered libc")
                client.ping()
                client.close()
                client = None
                wait_for(reaped, "HTTP/2 disconnect did not cancel and reap resolver work")
                assert request("/okay/after-cancel")[:2] == (200, b"ok")
                before = len(recorded("cancel"))
                client = H2(port, tls=tls)
                client.request(1, b"/cancel/reset")
                wait_for(lambda: len(recorded("cancel")) > before, "reset helper never entered libc")
                client.connection.sendall(frame(3, 0, 1, (8).to_bytes(4, "big")))
                client.request(3, b"/health")
                assert client.response(3) == (200, b"ok\n")
                wait_for(reaped, "HTTP/2 reset did not cancel and reap resolver work")
                client.request(5, b"/okay/after-reset")
                assert client.response(5) == (200, b"ok")
                client.close()
                client = None
                before = len(recorded("cancel"))
                client = H2(port, tls=tls)
                client.request(1, b"/cancel/shutdown")
                wait_for(lambda: len(recorded("cancel")) > before, "shutdown helper never entered libc")
                start = time.monotonic()
                process.send_signal(signal.SIGTERM)
                process.wait(timeout=3)
                assert process.returncode == 0 and time.monotonic() - start < 2, (process.returncode, log.read_text())
                wait_for(reaped, "shutdown left a resolver child behind")
                assert "panic" not in log.read_text().lower(), log.read_text()
            finally:
                if client:
                    client.close()
                if process and process.poll() is None:
                    process.send_signal(signal.SIGTERM)
                    try:
                        process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=3)
                if process:
                    # Negative-control libc sleeps occur in the server itself.
                    # No injected test child is allowed to survive the fixture.
                    for pid, parent, _ in recorded():
                        if parent == process.pid and not gone(pid):
                            os.kill(pid, signal.SIGKILL)
            print(f"ok: {'TLS' if tls else 'plain'} resolver deadlines, shared budget, failures, joined disconnect/shutdown and recovery")
    finally:
        backend.shutdown()
        backend.server_close()
