#!/usr/bin/env python3
"""Use harmless request fixtures to verify native denials and private logging."""
import json
import pathlib
import subprocess
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

base = f"http://{sys.argv[1]}:{sys.argv[2]}"
secret = "private-guard-fixture-do-not-log"
multipart_type = "Content-Type: multipart/form-data; boundary=guard-boundary"


def part(name="file", extra=""):
    return f'--guard-boundary\r\nContent-Disposition: form-data; name="{name}"; filename=""\r\n{extra}\r\nx\r\n'.encode()


ending = b"--guard-boundary--\r\n"
cases = [
    ("/php2shell", [], None),
    (f"/health?password={secret}&probe=%2570hp2%2573hell", [], None),
    ("/api/echo", [], b"CVE-2026-109618"),
    ("/health", ["PHP_ADMIN_VALUE: auto_prepend_file=php://input"], None),
    ("/api/echo", [multipart_type], part("PHP_SESSION_UPLOAD_PROGRESS") + ending),
    ("/api/echo", [multipart_type], part(extra="X-Padding: x\r\n" * 33) + ending),
    ("/api/echo", [multipart_type], part() * 129 + ending),
    ("/api/echo", [multipart_type], part("x[a][b][c][d][e][f][g][h][i]") + ending),
    ("/api/echo", [multipart_type, "Content-Encoding: gzip"], part() + ending),
    ("/api/echo", [multipart_type], part()),
]
with tempfile.TemporaryDirectory(prefix="layerline-guard-") as folder:
    output = pathlib.Path(folder) / "response"
    for protocol in ["--http1.1", "--http2-prior-knowledge"]:
        for path, fields, body in cases:
            command = ["curl", "-sS", "--max-time", "5", protocol, "-H", f"Authorization: Bearer {secret}", "-o", str(output), "-w", "%{http_code}"]
            for field in fields:
                command += ["-H", field]
            if body is not None:
                command += ["--data-binary", "@-"]
            command.append(base + path)
            status = subprocess.check_output(command, input=body)
            assert status == b"403", (protocol, path, status)
            assert b"shell vending machine" in output.read_bytes()
        command = ["curl", "-sS", "--max-time", "5", protocol, "-H", multipart_type, "--data-binary", "@-", "-o", str(output), "-w", "%{http_code}", base + "/api/echo"]
        assert subprocess.check_output(command, input=part() + ending) == b"200", "ordinary uploads must still work"
        print(f"ok: {protocol} native PHP2Shell/multipart denial and ordinary upload")

log = pathlib.Path(sys.argv[3]).read_text()
events = [json.loads(line) for line in log.splitlines() if line.startswith("{")]
denials = [row for row in events if row.get("event") == "security.block"]
assert len(denials) >= len(cases) * 2
assert all(row["action"] == "deny" and row["status"] == 403 and len(row["path_sha256"]) == 64 for row in denials)
assert secret not in log, "security probe credentials leaked into logs"
print("ok: structured security denials without raw query, credentials or request bodies")


class Backend(BaseHTTPRequestHandler):
    def do_GET(self):
        self.respond(True)

    def do_HEAD(self):
        self.respond(False)

    def respond(self, include_body):
        version = self.path.rsplit("/", 1)[-1]
        self.send_response(200)
        self.send_header("X-Powered-By", "PHP/" + version)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", "21")
        self.end_headers()
        if include_body:
            self.wfile.write(b"original backend page")

    def log_message(self, *_):
        pass


backend = ThreadingHTTPServer(("127.0.0.1", 19000), Backend)
thread = threading.Thread(target=backend.serve_forever, daemon=True)
thread.start()
try:
    with tempfile.TemporaryDirectory(prefix="layerline-version-") as folder:
        output = pathlib.Path(folder) / "response"
        headers = pathlib.Path(folder) / "headers"
        for protocol in ["--http1.1", "--http2-prior-knowledge"]:
            for version in ["8.2.34", "8.3.35", "8.4.26", "8.5.11", "7.4.33"]:
                status = subprocess.check_output(["curl", "-sS", "--max-time", "5", protocol, "-D", str(headers), "-o", str(output), "-w", "%{http_code}", base + "/verify-proxy/version/" + version])
                response = output.read_text()
                assert status == b"503" and "Site owner: update PHP" in response and version in response
                assert "original backend page" not in response
                assert "cache-control: no-store" in headers.read_text().lower()
                assert "x-powered-by:" not in headers.read_text().lower()
            for version in ["8.2.35", "8.3.36", "8.4.27", "8.5.12"]:
                status = subprocess.check_output(["curl", "-sS", "--max-time", "5", protocol, "-o", str(output), "-w", "%{http_code}", base + "/verify-proxy/version/" + version])
                assert status == b"200" and output.read_bytes() == b"original backend page", (protocol, version, status, output.read_bytes())
            for version in ["8.2.35-dev", "8.3.36-RC1", "8.4.27-beta1", "8.5.12-alpha2"]:
                status = subprocess.check_output(["curl", "-sS", "--max-time", "5", protocol, "-o", str(output), "-w", "%{http_code}", base + "/verify-proxy/version/" + version])
                response = output.read_text()
                assert status == b"503" and "(pre-release)" in response and "original backend page" not in response
            status = subprocess.check_output(["curl", "-sS", "--max-time", "5", protocol, "--head", "-o", str(headers), "-w", "%{http_code}", base + "/verify-proxy/version/8.4.26"])
            assert status == b"503" and "cache-control: no-store" in headers.read_text().lower()
            print(f"ok: {protocol} affected exposed PHP versions show owner update notice; patched releases serve normally")
        status = subprocess.check_output(["curl", "-sS", "--max-time", "5", "--http1.1", "-H", "Connection: Upgrade", "-H", "Upgrade: websocket", "-o", str(output), "-w", "%{http_code}", base + "/verify-proxy/version/8.4.26"])
        assert status == b"503" and "Site owner: update PHP" in output.read_text()
finally:
    backend.shutdown()
    backend.server_close()
    thread.join(timeout=3)

version_events = [json.loads(line) for line in pathlib.Path(sys.argv[4]).read_text().splitlines() if line.startswith('{"event":"security.php_version"')]
assert len(version_events) >= 13
assert all(row["action"] == "deny" and row["status"] == 503 and row["reported_version"] for row in version_events)
print("ok: exposed-version notices are non-cacheable, HEAD-safe and security-logged")
