#!/usr/bin/env python3
"""Reject origin trust before ACME/DNS writes; ACME may still create listener keys."""
import http.client
import http.server
import json
import os
from pathlib import Path
import shlex
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / "zig-out/bin/layerline"
WORKER = Path(sys.argv[2] if len(sys.argv) > 2 else os.environ.get("LAYERLINE_CHILD_WORKER", BINARY.with_name("child-process-worker"))).resolve()
if not WORKER.is_file() or not os.access(WORKER, os.X_OK):
    raise RuntimeError("build test-tools or set LAYERLINE_CHILD_WORKER to the native child fixture")
TOKEN = "startup-fixture-not-a-real-token"


class API(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self):
        self.server.calls.append(self.command)
        self.rfile.read(int(self.headers.get("Content-Length", "0")))
        body = json.dumps({"success": True, "result": [] if self.command == "GET" else {"id": "fixture-record"}}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = reply
    do_POST = reply


def port():
    with socket.socket() as reserved:
        reserved.bind(("127.0.0.1", 0))
        return reserved.getsockname()[1]


def scope_config(scope, ca):
    target = f"https://127.0.0.1:9 tls_ca_file={ca}"
    if scope in ["proxy", "h2_upstream"]:
        return f"{scope} = {target}\n"
    if scope == "route":
        return f"route = app /app/* proxy\nroute_proxy.app = {target}\n"
    site = "server = site\nserver_name.site = fixture.invalid\n"
    if scope == "domain":
        return site + f"server_proxy.site = {target}\n"
    assert scope == "domain route"
    return site + f"server_route.site = app /app/* proxy\nserver_route_proxy.site.app = {target}\n"


def stop(process):
    if process.poll() is None:
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
            raise AssertionError("startup material fixture did not shut down cleanly")


with tempfile.TemporaryDirectory(prefix="layerline-startup-materials-") as temporary:
    root = Path(temporary)
    ca, ca_key = root / "origin-ca.pem", root / "origin-ca-key.pem"
    cert, key = root / "listener.pem", root / "listener-key.pem"
    common = ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "1"]
    subprocess.run(common + ["-subj", "/CN=fixture origin root", "-addext", "basicConstraints=critical,CA:TRUE", "-keyout", str(ca_key), "-out", str(ca)], check=True, capture_output=True)
    subprocess.run(common + ["-subj", "/CN=localhost", "-addext", "basicConstraints=critical,CA:FALSE", "-addext", "keyUsage=critical,digitalSignature", "-addext", "extendedKeyUsage=serverAuth", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1", "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True)
    malformed = root / "malformed-ca.pem"
    malformed.write_text("not a PEM trust anchor\n")
    api = http.server.ThreadingHTTPServer(("127.0.0.1", 0), API)
    api.daemon_threads = True
    api.calls = []
    thread = threading.Thread(target=api.serve_forever)
    thread.start()
    try:
        cases = [(scope, kind) for scope in ["proxy", "h2_upstream", "route", "domain", "domain route"] for kind in ["missing", "malformed"]]
        cases.append(("proxy", "valid"))
        for index, (scope, kind) in enumerate(cases):
            folder = root / str(index)
            folder.mkdir()
            (folder / "pids").mkdir()
            (folder / "command-mode").write_text("okay")
            generated_cert, generated_key = folder / "generated.pem", folder / "generated-key.pem"
            certbot = folder / "certbot"
            certbot.write_text("#!/bin/sh\nset -eu\n" +
                              f"cp {shlex.quote(str(cert))} {shlex.quote(str(generated_cert))}\n" +
                              f"cp {shlex.quote(str(key))} {shlex.quote(str(generated_key))}\n" +
                              f"exec {shlex.quote(str(WORKER))} --command {shlex.quote(str(folder))} \"$@\"\n")
            certbot.chmod(0o700)
            selected_ca = ca if kind == "valid" else malformed if kind == "malformed" else folder / "missing-ca.pem"
            number = port()
            config, log = folder / "server.conf", folder / "server.log"
            config.write_text(f"""host = 127.0.0.1
port = {number}
dir = {folder}
admin = false
admin_ui = false
http3 = false
tls = true
tls_cert = {generated_cert}
tls_key = {generated_key}
tls_auto = true
letsencrypt_domains = fixture.invalid
letsencrypt_certbot = {certbot}
letsencrypt_webroot = {folder / 'webroot'}
letsencrypt_renew = false
external_command_timeout_ms = 3000
cf_auto_deploy = true
cf_api_base = http://127.0.0.1:{api.server_port}
cf_token = {TOKEN}
cf_zone_id = fixture-zone
cf_record_name = fixture.invalid
cf_record_type = TXT
cf_record_content = startup-material-fixture
cf_record_proxied = false
graceful_shutdown_timeout_ms = 1200
""" + scope_config(scope, selected_ca))
            api.calls = []
            if kind != "valid":
                result = subprocess.run([str(BINARY), "--config", str(config)], cwd=ROOT, capture_output=True, timeout=10)
                assert result.returncode != 0, (scope, kind, result.stdout)
                assert not api.calls, ("DNS API reached before trust validation", scope, kind, api.calls)
                assert not list((folder / "pids").iterdir()), ("certificate helper ran", scope, kind)
                assert not (folder / "webroot").exists(), ("challenge directory created", scope, kind)
                assert not generated_cert.exists() and not generated_key.exists()
                assert b"Failed to load configured origin trust" in result.stderr, result.stderr
                assert TOKEN.encode() not in result.stderr and b"private-child-marker" not in result.stderr
                print(f"ok: {scope} {kind} trust rejected before certificate/DNS work", flush=True)
                continue

            with log.open("wb") as output:
                process = subprocess.Popen([str(BINARY), "--config", str(config)], cwd=ROOT, stdout=output, stderr=output, start_new_session=True)
                try:
                    until = time.monotonic() + 6
                    while b'"event":"server.ready"' not in log.read_bytes():
                        assert process.poll() is None and time.monotonic() < until, log.read_bytes()
                        time.sleep(.02)
                    context = ssl.create_default_context(cafile=str(cert))
                    client = http.client.HTTPSConnection("127.0.0.1", number, context=context, timeout=5)
                    try:
                        client.request("GET", "/health", headers={"Connection": "close"})
                        reply = client.getresponse()
                        assert reply.status == 200, reply.status
                        reply.read()
                    finally:
                        client.close()
                    assert api.calls == ["GET", "POST"], api.calls
                    assert any(path.name.isdecimal() for path in (folder / "pids").iterdir())
                    assert generated_cert.exists() and generated_key.exists()
                finally:
                    stop(process)
                assert process.returncode == 0, log.read_bytes()
                assert TOKEN.encode() not in log.read_bytes() and b"private-child-marker" not in log.read_bytes()
            print("ok: valid origin trust loads once, ACME creates listener keys, DNS runs, verified HTTPS starts and shuts down", flush=True)
    finally:
        api.shutdown()
        api.server_close()
        thread.join(timeout=3)
        assert not thread.is_alive()
