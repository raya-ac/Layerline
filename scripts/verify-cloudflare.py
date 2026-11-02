#!/usr/bin/env python3
"""Exercise auto-DNS setup against a local API; never contact real DNS providers."""
import http.server
import json
import os
import pathlib
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse

ROOT = pathlib.Path(__file__).resolve().parents[1]
BINARY = pathlib.Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / "zig-out/bin/layerline"
TOKEN = "private-cloudflare-wire-fixture"
ZONE = "fixture-zone"
RECORD = "fixture-record"
NAME = "fixture.invalid&name=other.invalid?query+%"
ZONE_NAME = "fixture.invalid&status=active?query+%"
CONTENT = 'text "quoted" \\ snowman \u2603'
COMMENT = 'note ","proxied":true,"injected":"value'


def encode(value):
    return json.dumps(value, indent=2).encode()


def success(result):
    return encode({"messages": [{"id": "wrong-message"}], "result": result, "success": True})


class API(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self):
        case = self.server.case
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        case["requests"].append({"method": self.command, "path": self.path, "body": body, "auth": self.headers.get("Authorization")})
        if self.command == "GET":
            phase = "zone" if urllib.parse.urlsplit(self.path).path == "/zones" else "list"
        else:
            phase = "mutation"
        if case.get("delay") == phase:
            time.sleep(1.5)
        payload = case.get(phase, success([] if phase == "list" else [{"id": ZONE}] if phase == "zone" else {"id": RECORD}))
        status = case.get("http_status", 200)
        try:
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError):
            pass

    do_GET = reply
    do_POST = reply
    do_PUT = reply


def port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def stop(process):
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
            raise AssertionError("fixture did not shut down cleanly")


cases = [
    {"label": "pretty create", "okay": True, "methods": ["GET", "POST"]},
    {"label": "zone lookup", "lookup_zone": True, "okay": True, "methods": ["GET", "GET", "POST"]},
    {"label": "direct escaped ID", "list": b'{"result":[{"account":{"id":"wrong-nested"},"i\\u0064":"fixture-\\u0072ecord"}],"succ\\u0065ss":true}', "okay": True, "methods": ["GET", "PUT"]},
    {"label": "empty result ignores later ID", "list": b'{"success":true,"result":[],"metadata":{"id":"wrong-later"}}', "okay": True, "methods": ["GET", "POST"]},
    {"label": "nested true is not success", "list": b'{"success":false,"result":[],"nested":{"success":true}}'},
    {"label": "success string", "list": b'{"success":"true","result":[]}'},
    {"label": "missing root success", "list": b'{"nested":{"success":true},"result":[]}'},
    {"label": "duplicate success", "list": b'{"success":true,"success":false,"result":[]}'},
    {"label": "duplicate result", "list": b'{"success":true,"result":[],"result":[]}'},
    {"label": "missing result", "list": b'{"success":true}'},
    {"label": "null result", "list": b'{"success":true,"result":null}'},
    {"label": "wrong result shape", "list": b'{"success":true,"result":{"id":"fixture-record"}}'},
    {"label": "nested ID only", "list": b'{"success":true,"result":[{"nested":{"id":"wrong"}}]}'},
    {"label": "wrong ID type", "list": b'{"success":true,"result":[{"id":42}]}'},
    {"label": "duplicate ID", "list": b'{"success":true,"result":[{"id":"fixture-record","id":"other"}]}'},
    {"label": "ambiguous records", "list": success([{"id": RECORD}, {"id": "other"}])},
    {"label": "empty ID", "list": success([{"id": ""}])},
    {"label": "ID path injection", "list": success([{"id": "../other-zone/dns_records"}])},
    {"label": "ID query injection", "list": success([{"id": "record?force=true"}])},
    {"label": "long ID", "list": success([{"id": "x" * 33}])},
    {"label": "truncated JSON", "list": b'{"success":true,"result":['},
    {"label": "trailing garbage", "list": b'{"success":true,"result":[]} trailing'},
    {"label": "invalid UTF8", "list": b'{"success":true,"result":[{"id":"\xff"}]}'},
    {"label": "oversized response", "list": b" " * (1024 * 1024) + b'{"success":true,"result":[]}'},
    {"label": "failed HTTP", "http_status": 500, "list": encode({"error": TOKEN})},
    {"label": "API timeout", "delay": "list", "timeout": 350},
    {"label": "empty zones", "lookup_zone": True, "zone": success([]), "error": "CloudflareZoneMissing"},
    {"label": "ambiguous zones", "lookup_zone": True, "zone": success([{"id": ZONE}, {"id": "other"}]), "error": "CloudflareZoneLookupFailed"},
    {"label": "failed zone with nested success", "lookup_zone": True, "zone": b'{"success":false,"result":[],"nested":{"success":true}}', "error": "CloudflareZoneLookupFailed"},
    {"label": "unsafe zone ID", "zone_id": "../other", "methods": [], "error": "InvalidConfigValue"},
    {"label": "unsafe bearer header", "token": "private\rInjected: header", "methods": [], "error": "InvalidConfigValue"},
    {"label": "failed mutation", "mutation": encode({"success": False, "result": {"id": RECORD}, "errors": [{"message": TOKEN}], "nested": {"success": True}}), "methods": ["GET", "POST"], "error": "CloudflareRecordUpdateFailed"},
    {"label": "missing mutation result", "mutation": b'{"success":true}', "methods": ["GET", "POST"], "error": "CloudflareRecordUpdateFailed"},
    {"label": "wrong mutation shape", "mutation": success([]), "methods": ["GET", "POST"], "error": "CloudflareRecordUpdateFailed"},
    {"label": "mismatched update ID", "list": success([{"id": RECORD}]), "mutation": success({"id": "wrong-record"}), "methods": ["GET", "PUT"], "error": "CloudflareRecordUpdateFailed"},
]

with tempfile.TemporaryDirectory(prefix="layerline-cloudflare-") as temporary:
    folder = pathlib.Path(temporary)
    api = http.server.ThreadingHTTPServer(("127.0.0.1", 0), API)
    api.daemon_threads = True
    worker = threading.Thread(target=api.serve_forever, daemon=True)
    worker.start()
    process = None
    try:
        for case in cases:
            number = port()
            case["requests"] = []
            api.case = case
            zone = f"cf_zone_name = {ZONE_NAME}" if case.get("lookup_zone") else f"cf_zone_id = {case.get('zone_id', ZONE)}"
            config = folder / "server.conf"
            config.write_text(f"host = 127.0.0.1\nport = {number}\ncf_auto_deploy = true\ncf_api_base = http://127.0.0.1:{api.server_port}\ncf_token = {case.get('token', TOKEN)}\n{zone}\ncf_record_name = {NAME}\ncf_record_type = TXT\ncf_record_content = {CONTENT}\ncf_record_comment = {COMMENT}\ncf_record_ttl = 120\ncf_record_proxied = false\nexternal_command_timeout_ms = {case.get('timeout', 3000)}\n")
            log_path = folder / "server.log"
            with log_path.open("wb") as output:
                environment = {**os.environ, "NO_PROXY": "127.0.0.1,localhost", "no_proxy": "127.0.0.1,localhost"}
                process = subprocess.Popen([str(BINARY), "--config", str(config)], cwd=ROOT, stdout=output, stderr=output, env=environment)
                until = time.monotonic() + 6
                while process.poll() is None and '"event":"server.ready"' not in log_path.read_text():
                    assert time.monotonic() < until, (case["label"], "setup did not finish", log_path.read_text())
                    time.sleep(.01)
                log = log_path.read_text()
                if case.get("okay"):
                    assert process.poll() is None and '"event":"server.ready"' in log, (case["label"], log)
                    with socket.create_connection(("127.0.0.1", number), timeout=1) as connection:
                        connection.sendall(b"GET /health HTTP/1.1\r\nHost: fixture.invalid\r\nConnection: close\r\n\r\n")
                        assert b" 200 " in connection.recv(1024), case["label"]
                    stop(process)
                    assert process.returncode == 0, log_path.read_text()
                else:
                    assert process.poll() is not None and process.returncode != 0 and '"event":"server.ready"' not in log, (case["label"], log)
                    if "error" in case:
                        assert case["error"] in log, (case["label"], log)
                    with socket.socket() as probe:
                        assert probe.connect_ex(("127.0.0.1", number)) != 0, (case["label"], "failed setup left a listener")
                process = None
            assert TOKEN not in log_path.read_text(), (case["label"], "API output exposed credentials")
            assert CONTENT not in log_path.read_text() and COMMENT not in log_path.read_text(), (case["label"], "DNS values reached logs")
            expected = case.get("methods", ["GET"])
            assert [request["method"] for request in case["requests"]] == expected, (case["label"], case["requests"])
            for request in case["requests"]:
                assert request["auth"] == f"Bearer {TOKEN}", case["label"]
                url = urllib.parse.urlsplit(request["path"])
                query = urllib.parse.parse_qs(url.query)
                if request["method"] == "GET":
                    if url.path == "/zones":
                        assert query == {"name": [ZONE_NAME]}, query
                    else:
                        assert url.path == f"/zones/{ZONE}/dns_records", url.path
                        assert query == {"type": ["TXT"], "name": [NAME]}, query
                else:
                    suffix = f"/{RECORD}" if request["method"] == "PUT" else ""
                    assert url.path == f"/zones/{ZONE}/dns_records{suffix}" and not query, url
                    assert json.loads(request["body"]) == {"type": "TXT", "name": NAME, "content": CONTENT, "comment": COMMENT, "ttl": 120, "proxied": False}, request["body"]
            print(f"ok: Cloudflare {case['label']}", flush=True)
    finally:
        if process is not None:
            stop(process)
        api.shutdown()
        api.server_close()
        worker.join(timeout=2)
print(f"ok: {len(cases)} local Cloudflare API cases; no real DNS requests", flush=True)
