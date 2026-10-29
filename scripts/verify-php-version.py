#!/usr/bin/env python3
"""Harmless CGI/FastCGI backends exercise the exposed-version response guard."""
import json
import os
import pathlib
import shlex
import signal
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import parse_qs, urlencode


def backend_output(query):
    fields = parse_qs(query)
    version = fields.get("version", [""])[0]
    name = fields.get("header", ["X-Powered-By"])[0]
    assert name in ["X-Powered-By", "Server"]
    assert all(char.isalnum() or char in ".-_" for char in version)
    exposed = f"{name}: PHP/{version}\r\n" if version else ""
    return (exposed + "Content-Type: text/plain\r\n\r\noriginal PHP fixture page").encode()


if len(sys.argv) > 1 and sys.argv[1] == "--cgi":
    sys.stdout.buffer.write(backend_output(os.environ.get("QUERY_STRING", "")))
    sys.exit(0)


ROOT = pathlib.Path(__file__).resolve().parents[1]
BINARY = pathlib.Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / "zig-out/bin/layerline"


def exact(conn, count):
    data = b""
    while len(data) < count:
        part = conn.recv(count - len(data))
        if not part:
            raise EOFError
        data += part
    return data


def params(data):
    data = bytes(data)
    offset = 0

    def length():
        nonlocal offset
        value = data[offset]
        size = 4 if value & 0x80 else 1
        value = int.from_bytes(data[offset:offset + size], "big") & 0x7fffffff
        offset += size
        return value

    values = {}
    while offset < len(data):
        name_len, value_len = length(), length()
        name = data[offset:offset + name_len]
        offset += name_len
        values[name] = data[offset:offset + value_len]
        offset += value_len
    return values


class FastCGI(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        pending = bytearray()
        try:
            while True:
                version, kind, request_id, count, padding, _ = struct.unpack("!BBHHBB", exact(self.request, 8))
                assert version == 1 and request_id == 1
                payload = exact(self.request, count)
                exact(self.request, padding)
                if kind == 1:
                    pending.clear()
                elif kind == 4:
                    pending.extend(payload)
                elif kind == 5 and not payload:
                    output = backend_output(params(pending).get(b"QUERY_STRING", b"").decode())
                    for response_kind, response in [(6, output), (6, b""), (3, bytes(8))]:
                        self.request.sendall(struct.pack("!BBHHBB", 1, response_kind, request_id, len(response), 0, 0) + response)
        except (EOFError, ConnectionError, TimeoutError):
            pass


class Backend(socketserver.ThreadingTCPServer):
    daemon_threads = True


with tempfile.TemporaryDirectory(prefix="layerline-php-version-") as temporary:
    folder = pathlib.Path(temporary)
    backend = Backend(("127.0.0.1", 0), FastCGI)
    thread = threading.Thread(target=backend.serve_forever, daemon=True)
    thread.start()
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    cgi = folder / "php-cgi"
    cgi.write_text(f"#!/bin/sh\nexec {shlex.quote(sys.executable)} {shlex.quote(str(pathlib.Path(__file__).resolve()))} --cgi\n")
    cgi.chmod(0o700)
    (folder / "index.php").write_text("<?php // Only a path fixture; the fake backends never execute PHP.\n")
    config = folder / "server.conf"
    config.write_text(f"""host = 127.0.0.1
port = {port}
php_root = {folder}
php_binary = {cgi}
php_front_controller = true
route = cgi /cgi/* php
route_php_index.cgi = index.php
route = fpm /fpm/* php
route_php_index.fpm = index.php
route_php_fastcgi.fpm = 127.0.0.1:{backend.server_address[1]}
graceful_shutdown_timeout_ms = 1000
""")
    process = None
    log_path = folder / "server.log"
    try:
        with log_path.open("wb") as log:
            process = subprocess.Popen([str(BINARY), "--config", str(config)], cwd=ROOT, stdout=log, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + 4
            while True:
                assert process.poll() is None, log_path.read_text()
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        break
                except OSError:
                    assert time.monotonic() < deadline, log_path.read_text()
                    time.sleep(0.02)
            body, headers = folder / "body", folder / "headers"
            for route, protocol in [("cgi", "--http1.1"), ("fpm", "--http1.1"), ("fpm", "--http2-prior-knowledge")]:
                for name in ["X-Powered-By", "Server"]:
                    for version, expected in [("8.4.26", 503), ("8.5.12-dev", 503), ("8.5.12", 200), ("8.4.27-1ubuntu1", 200), ("", 200)]:
                        url = f"http://127.0.0.1:{port}/{route}/check?" + urlencode({"header": name, "version": version})
                        command = ["curl", "-sS", "--max-time", "5", protocol, "-D", str(headers), "-o", str(body), "-w", "%{http_code}", url]
                        status = int(subprocess.check_output(command))
                        response = body.read_text()
                        assert status == expected, (route, protocol, name, version, status, response[:300])
                        if expected == 503:
                            assert "Site owner: update PHP" in response and "original PHP fixture page" not in response
                            assert "cache-control: no-store" in headers.read_text().lower()
                            assert "x-powered-by:" not in headers.read_text().lower()
                            if version.endswith("-dev"):
                                assert "(pre-release)" in response
                            head_command = command[:-1] + ["--head", url]
                            assert int(subprocess.check_output(head_command)) == 503
                        else:
                            assert response == "original PHP fixture page"
                print(f"ok: {route} {protocol} version notices, HEAD, patched/vendor and unexposed responses")
            events = [json.loads(line) for line in log_path.read_text().splitlines() if line.startswith('{"event":"security.php_version"')]
            assert len(events) == 24 and sum(row["prerelease"] for row in events) == 12, events
            assert all(row["action"] == "deny" and row["status"] == 503 for row in events)
    except BaseException:
        print(log_path.read_text(), file=sys.stderr)
        raise
    finally:
        if process is not None and process.poll() is None:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
        backend.shutdown()
        backend.server_close()
        thread.join(timeout=2)
