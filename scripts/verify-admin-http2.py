#!/usr/bin/env python3
"""Disposable native-TLS admin acceptance, with no live config or credentials."""
import json
import pathlib
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from urllib.parse import urlencode

ROOT = pathlib.Path(__file__).resolve().parents[1]
BINARY = pathlib.Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / "zig-out/bin/layerline"
ADMIN = "/_layerline/admin"


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
            raise EOFError("admin response ended early")
        result += part
    return result


with tempfile.TemporaryDirectory(prefix="layerline-admin-h2-") as temporary:
    folder = pathlib.Path(temporary)
    webroot = folder / "public"
    webroot.mkdir()
    (folder / "sites").mkdir()
    (webroot / "index.html").write_text("ordinary site")
    for status in [401, 403]:
        (webroot / f"{status}.html").write_text("tenant custom error must not replace admin output")
    (folder / "sites/tenant.conf").write_text(f"server_name = 127.0.0.1\nroot = {webroot}\n")
    config = folder / "server.conf"
    credentials = folder / "owner.creds"
    token_path = folder / ".owner.creds.setup-token"
    cookie_jar = folder / "cookies"
    process = None
    output = None

    def stop():
        if process is not None and process.poll() is None:
            process.send_signal(signal.SIGTERM)
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
        if output is not None:
            output.close()

    def request(path=ADMIN, method="GET", data=None, headers=(), authenticated=False, protocol="--http2", expected=200, admin=True):
        command = ["curl", "-skS", "--max-time", "6", protocol, "-D", str(folder / "headers"), "-o", str(folder / "body"), "-w", "%{http_version} %{http_code}"]
        if authenticated or path in [ADMIN + "/setup", ADMIN + "/login"]:
            command += ["-c", str(cookie_jar)]
        if authenticated:
            command += ["-b", str(cookie_jar)]
        for header in headers:
            command += ["-H", header]
        if method == "HEAD":
            command += ["--head"]
        elif data is not None:
            command += ["--data", urlencode(data)]
        elif method != "GET":
            command += ["-X", method]
        version, status = subprocess.check_output(command + [f"https://127.0.0.1:{port}{path}"], text=True).split()
        body = (folder / "body").read_bytes()
        raw_headers = (folder / "headers").read_text()
        assert version == ("2" if protocol == "--http2" else "1.1"), (version, raw_headers)
        assert int(status) == expected, (path, method, version, status, body[max(0, body.find(b"Reload blocked")):][:300])
        fields = {}
        for line in raw_headers.splitlines()[1:]:
            if ":" in line:
                name, value = line.split(":", 1)
                fields.setdefault(name.lower(), []).append(value.strip())
        if admin:
            assert fields.get("cache-control") == ["no-store"], fields
            assert fields.get("x-frame-options") == ["DENY"], fields
            assert fields.get("x-content-type-options") == ["nosniff"], fields
            assert "content-encoding" not in fields and "cache-status" not in fields, fields
            assert b"tenant custom error" not in body
        return fields, body

    def start(enabled):
        global port, process, output
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        config.write_text(f"""host = 127.0.0.1
port = {port}
tls = true
http_redirect_port = 8081
http_redirect_https_port = {port}
dir = {webroot}
serve_static_root = true
domain_config_dir = {folder / 'sites'}
{('admin_ui = true' if enabled else '')}
admin_socket = off
admin_credentials_path = {credentials}
compression = true
gzip = true
response_header = Cache-Control: public, max-age=3600
graceful_shutdown_timeout_ms = 1000
""")
        output = (folder / "server.log").open("wb")
        process = subprocess.Popen([str(BINARY), "--config", str(config)], cwd=ROOT, stdout=output, stderr=subprocess.STDOUT)
        deadline = time.monotonic() + 5
        while True:
            assert process.poll() is None, (folder / "server.log").read_text()
            try:
                request("/health", admin=False)
                return
            except (subprocess.CalledProcessError, OSError):
                assert time.monotonic() < deadline, (folder / "server.log").read_text()
                time.sleep(0.03)

    try:
        start(False)
        request(expected=404, admin=False)
        assert not token_path.exists() and not credentials.exists(), "disabled admin created bootstrap state"
        stop()
        start(True)
        _, body = request(headers=["Accept-Encoding: gzip"])
        assert b"Create admin access" in body, "HTTP/2 did not serve first-launch setup"
        token = token_path.read_text().strip()
        assert len(token) == 64 and token.encode() not in body
        assert token_path.stat().st_mode & 0o777 == 0o600
        fields, _ = request(method="HEAD")
        assert int(fields["content-length"][0]) == len(body), "HEAD lost representation size"
        request(method="OPTIONS", expected=204)
        request(method="DELETE", expected=405)
        setup = {"username": "admin", "password": "layerline-test-pass", "password_confirm": "layerline-test-pass"}
        request(ADMIN + "/setup", data=setup, expected=403)
        assert not credentials.exists()
        request(ADMIN + "/setup", data={**setup, "setup_token": token}, headers=["Origin: https://elsewhere.invalid"], expected=403)
        assert not credentials.exists()
        fields, _ = request(ADMIN + "/setup", data={**setup, "setup_token": token}, expected=303)
        assert fields["location"] == [ADMIN] and "Secure" in fields["set-cookie"][0]
        assert not token_path.exists() and credentials.stat().st_mode & 0o777 == 0o600
        _, body = request(authenticated=True)
        for label in [b"Control surface", b"Add site", b"Save settings", b"Activation diff", b"Live proxy targets"]:
            assert label in body, label
        request(ADMIN + "/api/cache/purge", data={"target": ""}, expected=401)
        _, body = request(ADMIN + "/api/cache/purge", data={"target": ""}, authenticated=True)
        assert json.loads(body)["ok"] is True
        request(ADMIN + "/api/cache/purge", data={"target": ""}, authenticated=True, headers=["Sec-Fetch-Site: cross-site"], expected=403)
        _, body = request(ADMIN + "/sites/add", data={"name": "h2-site", "server_names": "h2.test", "root": str(webroot), "index": "index.html", "serve_static_root": "on"}, authenticated=True, expected=201)
        assert b"Created " in body and "server_name = h2.test" in (folder / "sites/h2-site.conf").read_text()
        settings = {
            "host": "127.0.0.1", "port": port, "static_dir": str(webroot),
            "index_file": "index.html", "domain_config_dir": str(folder / "sites"),
            "serve_static_root": "true", "compression": "true", "gzip": "true",
            "security_headers": "basic", "response_cache": "false",
            "response_cache_max_bytes": "1048576", "response_cache_max_entry_bytes": "65536",
            "response_cache_ttl_ms": "60000", "php_root": str(webroot), "php_binary": "php-cgi",
            "php_fastcgi": "off", "php_front_controller": "false", "proxy": "off",
            "upstream_policy": "round_robin", "upstream_timeout_ms": "5000",
            "upstream_retries": "1", "upstream_keepalive": "true", "fastcgi_keepalive": "true",
            "tls": "true", "http_redirect": "false", "http_redirect_port": "8081",
            "http_redirect_https_port": port, "http3": "false", "http3_port": "8443",
            "admin_socket": "off", "admin_ui": "true", "admin_ui_path": ADMIN,
            "admin_credentials_path": str(credentials), "access_log": "off",
            "max_concurrent_connections": "1024", "max_request_bytes": "1048576",
            "read_header_timeout_ms": "5000", "idle_timeout_ms": "30000", "worker_stack_size": "524288",
        }
        _, body = request(ADMIN + "/settings/save", data=settings, authenticated=True)
        assert b"Saved settings to " in body and config.with_suffix(".conf.bak").exists()
        assert "tls = true" in config.read_text() and "admin_ui = true" in config.read_text()
        _, body = request(ADMIN + "/validate", data={}, authenticated=True)
        assert b"Activation config is valid" in body
        _, body = request(ADMIN + "/reload", data={}, authenticated=True)
        assert b"Config reloaded in memory" in body
        for _ in range(8):
            request(authenticated=True)
            request("/health", admin=False)

        # Two actual Cookie fields, not a single semicolon-delimited curl cookie.
        cookie = fields["set-cookie"][0].split(";", 1)[0].encode()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # Only this fixture's loopback certificate.
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.set_alpn_protocols(["h2"])
        with socket.create_connection(("127.0.0.1", port), timeout=4) as raw:
            with ctx.wrap_socket(raw, server_hostname="localhost") as conn:
                assert conn.selected_alpn_protocol() == "h2"
                pairs = [(b":method", b"GET"), (b":scheme", b"https"), (b":authority", f"127.0.0.1:{port}".encode()), (b":path", ADMIN.encode()), (b"cookie", b"unrelated=first"), (b"cookie", cookie)]
                conn.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 0, 0) + frame(1, 5, 1, b"".join(literal(*pair) for pair in pairs)))
                response = b""
                for _ in range(200):
                    head = exact(conn, 9)
                    payload = exact(conn, int.from_bytes(head[:3], "big"))
                    kind, flags, stream = head[3], head[4], int.from_bytes(head[5:], "big")
                    if kind == 4 and not flags & 1:
                        conn.sendall(frame(4, 1, 0))
                    if kind == 0:
                        response += payload
                        conn.sendall(frame(8, 0, 0, len(payload).to_bytes(4, "big")) + frame(8, 0, stream, len(payload).to_bytes(4, "big")))
                    assert kind not in [3, 7], (kind, payload)
                    if stream == 1 and kind in [0, 1] and flags & 1:
                        break
                else:
                    raise AssertionError("split-cookie response never ended")
                assert b"Control surface" in response, "split HTTP/2 Cookie fields lost admin session"
        request(ADMIN + "/logout", data={}, authenticated=True, expected=303)
        request(ADMIN + "/api/cache/purge", data={"target": ""}, authenticated=True, expected=401)
        request(ADMIN + "/api/cache/purge", data={"target": ""}, headers=["Cookie: " + cookie.decode()], expected=401)
        request(ADMIN + "/login", data={"username": "admin", "password": "wrong-password"}, expected=401)
        _, body = request(protocol="--http1.1")
        assert b"Sign in" in body
        request(ADMIN + "/login", data={"username": "admin", "password": "layerline-test-pass"}, expected=303)
        request(authenticated=True)
        request(authenticated=True, protocol="--http1.1", headers=["Accept-Encoding: gzip"])
        request(ADMIN + "/api/cache/purge", data={"target": ""}, protocol="--http1.1", expected=401)
    finally:
        stop()

print("ok: native TLS HTTP/2 admin setup, authentication, controls, isolation and split cookies")
