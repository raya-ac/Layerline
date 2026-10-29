#!/usr/bin/env python3
"""CGI and certificate children must finish, time out, or be killed and reaped."""
import hashlib
import http.client
import http.server
import json
import os
import pathlib
import shlex
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time


ROOT = pathlib.Path(__file__).resolve().parents[1]
BINARY = pathlib.Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / "zig-out/bin/layerline"


def port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def records(folder):
    return {int(path.name): json.loads(path.read_text()) for path in (folder / "pids").iterdir() if path.name.isdecimal()}


def running(pid, folder):
    result = subprocess.run(["ps", "-p", str(pid), "-o", "stat=", "-o", "args="], capture_output=True, text=True)
    line = result.stdout.strip()
    return bool(line and not line.startswith("Z") and str(folder) in line)


def stopped(folder, previous, label):
    current = {pid: value for pid, value in records(folder).items() if previous.get(pid) != value}
    assert current, ("fixture did not execute", label, previous, records(folder))
    until = time.monotonic() + 1
    while time.monotonic() < until and any(running(pid, folder) for pid in current):
        time.sleep(.02)
    assert not any(running(pid, folder) for pid in current), ("live child after request", current)
    for pid, value in current.items():
        if value["kind"] != "sleeper":
            assert subprocess.run(["ps", "-p", str(pid), "-o", "stat="], capture_output=True, text=True).stdout.strip() == "", ("unreaped leader", pid)


def request(number, tls, kind, body=None, path="/index.php"):
    context = ssl._create_unverified_context()
    connection = http.client.HTTPSConnection("127.0.0.1", number, context=context, timeout=3) if tls else http.client.HTTPConnection("127.0.0.1", number, timeout=3)
    try:
        connection.connect()
        start = time.monotonic()
        connection.request("POST" if body else "GET", path + "?" + kind, body=body)
        reply = connection.getresponse()
        data = reply.read()
        return reply.status, data, time.monotonic() - start
    finally:
        connection.close()


def stop_server(process):
    if process is not None and process.poll() is None:
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=3)


class Cloudflare(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self):
        self.server.ready.wait(2)
        pids = subprocess.run(["pgrep", "-P", str(self.server.layerline)], capture_output=True, text=True).stdout.split()
        arguments = [subprocess.run(["ps", "-p", pid, "-o", "args="], capture_output=True, text=True).stdout for pid in pids]
        length = int(self.headers.get("Content-Length", "0"))
        self.server.requests.append({"method": self.command, "auth": self.headers.get("Authorization"), "body": self.rfile.read(length), "argv": arguments, "pids": pids})
        body = b'{"success":true,"result":[]}' if not self.server.fail else ('{"success":false,"errors":[{"message":"' + self.server.token + '"}]}').encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = reply
    do_POST = reply


def config(folder, number, tls, cert, key):
    return f"""host = 127.0.0.1
port = {number}
php_root = {folder}
php_binary = {folder / 'php-cgi'}
max_body_bytes = 1048576
max_php_output_bytes = 131072
upstream_timeout_ms = 350
route = missing /missing/* php
route_php_front_controller.missing = true
route_php_bin.missing = {folder / 'missing-php'}
route = extended /extended/* php
route_php_front_controller.extended = true
route_upstream_timeout_ms.extended = 1200
worker_stack_size = 65536
graceful_shutdown_timeout_ms = 1200
tls = {'true' if tls else 'false'}
tls_cert = {cert}
tls_key = {key}
letsencrypt_certbot = {folder / 'certbot'}
letsencrypt_domains = fixture.invalid
letsencrypt_webroot = {folder}
"""


with tempfile.TemporaryDirectory(prefix="layerline-child-processes-") as temporary:
    folder = pathlib.Path(temporary)
    (folder / "pids").mkdir()
    (folder / "index.php").write_text("<?php // Harmless path fixture.\n")
    (folder / "command-mode").write_text("okay")
    for name, mode in [("php-cgi", "--cgi"), ("certbot", "--command")]:
        wrapper = folder / name
        worker = pathlib.Path(__file__).with_name("child-process-worker.py").resolve()
        wrapper.write_text(f"#!/bin/sh\nexec {shlex.quote(sys.executable)} {shlex.quote(str(worker))} {mode} {shlex.quote(str(folder))} \"$@\"\n")
        wrapper.chmod(0o700)
    cert, key = folder / "cert.pem", folder / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=localhost"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    process = None
    log_path = folder / "server.log"
    try:
        for bits, tls in [(2048, False), (2048, True), (4096, True)]:
            if bits == 4096:
                subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:4096", "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=localhost"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            number = port()
            filename = folder / "server.conf"
            filename.write_text(config(folder, number, tls, cert, key))
            with log_path.open("wb") as log:
                process = subprocess.Popen([str(BINARY), "--config", str(filename)], cwd=ROOT, stdout=log, stderr=log, start_new_session=True)
                for _ in range(100):
                    assert process.poll() is None, log_path.read_text()
                    try:
                        with socket.create_connection(("127.0.0.1", number), timeout=.1):
                            break
                    except OSError:
                        time.sleep(.02)
                else:
                    raise AssertionError("server never listened")
                previous = records(folder)
                status, data, elapsed = request(number, tls, "okay", path="/extended/warm")
                assert status == 200 and data == b"ok", ("initial CGI launch", status, elapsed)
                stopped(folder, previous, "initial CGI launch")
                print(f"initial CGI launch: {elapsed:.3f}s", flush=True)
                cases = [("hang", 504), ("trickle", 504), ("closed", 504), ("noinput", 504), ("overflow", 502), ("stderr", 502), ("exit", 502), ("duplex", 200), ("earlyinput", 200), ("descendant", 200), ("okay", 200)]
                for kind, expected in cases:
                    previous = records(folder)
                    body = b"upload" * 87381 if kind in ["noinput", "duplex", "earlyinput"] else None
                    status, data, elapsed = request(number, tls, kind, body)
                    assert status == expected and elapsed < 2, (kind, status, expected, elapsed)
                    if kind == "duplex":
                        assert data == b"x" * 65536 + hashlib.sha256(body).hexdigest().encode()
                    elif expected == 200:
                        assert data == b"ok", (kind, data)
                    stopped(folder, previous, kind)
                    if kind in ["hang", "descendant"]:
                        assert any(value["kind"] == "sleeper" for pid, value in records(folder).items() if previous.get(pid) != value), "descendant cleanup was not exercised"
                connection = http.client.HTTPSConnection("127.0.0.1", number, context=ssl._create_unverified_context(), timeout=3) if tls else http.client.HTTPConnection("127.0.0.1", number, timeout=3)
                try:
                    connection.request("GET", "/missing/page")
                    response = connection.getresponse()
                    response.read()
                    assert response.status == 502
                finally:
                    connection.close()
                listing = subprocess.run(["ps", "-axo", "pid=,ppid=,stat="], capture_output=True, text=True).stdout.splitlines()
                children = [line.split() for line in listing if len(line.split()) == 3 and int(line.split()[1]) == process.pid]
                assert not children, ("child left after failed exec", children)
                previous = records(folder)
                status, data, elapsed = request(number, tls, "slow", path="/extended/page")
                assert status == 200 and data == b"ok" and elapsed >= .6, (status, elapsed)
                stopped(folder, previous, "route timeout override")
                stop_server(process)
                assert process.returncode == 0, log_path.read_text()
                process = None
            lines = log_path.read_text()
            assert "private-child-marker" not in lines
            assert '"phase":"cgi"' in lines and "RequestTimeout" in lines
            print(f"ok: {f'RSA-{bits} TLS' if tls else 'plain'} CGI deadlines, duplex pipes, output caps, child/group cleanup and early stdin close", flush=True)

        for kind in ["slow", "hang"]:
            previous = records(folder)
            number = port()
            filename.write_text(config(folder, number, False, cert, key) + "upstream_timeout_ms = 5000\n")
            outcome = []

            def pending_request():
                try:
                    outcome.append(request(number, False, kind)[:2])
                except (ConnectionError, http.client.HTTPException):
                    outcome.append("closed")

            with log_path.open("wb") as log:
                process = subprocess.Popen([str(BINARY), "--config", str(filename)], cwd=ROOT, stdout=log, stderr=log, start_new_session=True)
                until = time.monotonic() + 3
                while True:
                    assert process.poll() is None, log_path.read_text()
                    try:
                        with socket.create_connection(("127.0.0.1", number), timeout=.1):
                            break
                    except OSError:
                        assert time.monotonic() < until
                        time.sleep(.02)
                client_thread = threading.Thread(target=pending_request)
                client_thread.start()
                needed = {kind} | ({"sleeper"} if kind == "hang" else set())
                while not needed.issubset({value["kind"] for pid, value in records(folder).items() if previous.get(pid) != value}):
                    assert process.poll() is None and time.monotonic() < until, log_path.read_text()
                    time.sleep(.01)
                start = time.monotonic()
                stop_server(process)
                client_thread.join(timeout=3)
                assert not client_thread.is_alive()
                assert process.returncode == 0 and time.monotonic() - start < 2, log_path.read_text()
                assert outcome == [(200, b"ok")] if kind == "slow" else outcome == ["closed"], outcome
                stopped(folder, previous, f"CGI shutdown {kind}")
                process = None
        print("ok: shutdown drains short CGI work, then kills long-budget CGI/group work and joins before forced exit", flush=True)

        # Exercise the real startup command path, not a process-runner mock.
        previous = records(folder)
        (folder / "command-mode").write_text("hang")
        # Include enough cold interpreter startup time to reach the worker's
        # SIGTERM handler; the CGI trickle cases retain their 350 ms budget.
        filename.write_text(config(folder, port(), True, cert, key) + "tls_auto = true\nexternal_command_timeout_ms = 1200\n")
        start = time.monotonic()
        with log_path.open("wb") as log:
            process = subprocess.Popen([str(BINARY), "--config", str(filename)], cwd=ROOT, stdout=log, stderr=log, start_new_session=True)
            process.wait(timeout=3)
        assert process.returncode != 0 and time.monotonic() - start < 2
        assert "RequestTimeout" in log_path.read_text(), log_path.read_text()
        stopped(folder, previous, "certificate setup")
        process = None
        print("ok: certificate setup command timeout kills and reaps a SIGTERM-ignoring child", flush=True)

        previous = records(folder)
        filename.write_text(config(folder, port(), True, cert, key) + "tls_auto = true\nexternal_command_timeout_ms = 5000\n")
        with log_path.open("wb") as log:
            process = subprocess.Popen([str(BINARY), "--config", str(filename)], cwd=ROOT, stdout=log, stderr=log, start_new_session=True)
            until = time.monotonic() + 3
            while not any(value["kind"] == "hang" for pid, value in records(folder).items() if previous.get(pid) != value):
                assert process.poll() is None and time.monotonic() < until, log_path.read_text()
                time.sleep(.02)
            start = time.monotonic()
            stop_server(process)
            assert process.returncode != 0 and time.monotonic() - start < 2, log_path.read_text()
            assert "Canceled" in log_path.read_text()
            stopped(folder, previous, "setup shutdown")
            process = None
        print("ok: shutdown cancels setup before the listeners start", flush=True)

        # Renewal has a long command limit here; shutdown must cancel it sooner.
        previous = records(folder)
        (folder / "command-mode").write_text("okay")
        control = folder / "admin.sock"
        filename.write_text(config(folder, port(), True, cert, key) + f"tls_auto = true\nexternal_command_timeout_ms = 5000\nadmin = true\nadmin_socket = {control}\n")
        with log_path.open("wb") as log:
            process = subprocess.Popen([str(BINARY), "--config", str(filename)], cwd=ROOT, stdout=log, stderr=log, start_new_session=True)
            until = time.monotonic() + 3
            while not control.exists():
                assert process.poll() is None, log_path.read_text()
                assert time.monotonic() < until, "admin socket never listened"
                time.sleep(.02)
            client = socket.socket(socket.AF_UNIX)
            client.connect(str(control))
            client.sendall(b"cert-renew\n")
            while not any(value["kind"] == "renew" for pid, value in records(folder).items() if previous.get(pid) != value):
                assert process.poll() is None, log_path.read_text()
                assert time.monotonic() < until, "renewal never started"
                time.sleep(.02)
            start = time.monotonic()
            stop_server(process)
            client.close()
            assert process.returncode == 0 and time.monotonic() - start < 2, log_path.read_text()
            stopped(folder, previous, "renewal")
            process = None
        print("ok: shutdown cancels and joins a running certificate renewal before its command deadline", flush=True)
        assert "private-child-marker" not in log_path.read_text()

        api = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Cloudflare)
        api.requests = []
        api.fail = False
        api.ready = threading.Event()
        thread = threading.Thread(target=api.serve_forever, daemon=True)
        thread.start()
        token = "private-fixture-token-only"
        api.token = token
        number = port()
        filename.write_text(config(folder, number, False, cert, key) + f"cf_auto_deploy = true\ncf_api_base = http://127.0.0.1:{api.server_port}\ncf_token = {token}\ncf_zone_id = fixture\ncf_record_name = fixture.invalid\ncf_record_content = 203.0.113.1\n")
        try:
            with log_path.open("wb") as log:
                process = subprocess.Popen([str(BINARY), "--config", str(filename)], cwd=ROOT, stdout=log, stderr=log, start_new_session=True)
                api.layerline = process.pid
                api.ready.set()
                until = time.monotonic() + 3
                while True:
                    assert process.poll() is None, log_path.read_text()
                    try:
                        with socket.create_connection(("127.0.0.1", number), timeout=.1):
                            break
                    except OSError:
                        assert time.monotonic() < until, "server did not finish local Cloudflare setup"
                        time.sleep(.02)
                assert [value["method"] for value in api.requests] == ["GET", "POST"], api.requests
                for value in api.requests:
                    assert value["auth"] == f"Bearer {token}"
                    assert value["argv"] and all(token not in command and "@-" in command for command in value["argv"])
                    for pid in value["pids"]:
                        assert not subprocess.run(["ps", "-p", pid, "-o", "stat="], capture_output=True, text=True).stdout.strip(), "curl child was not reaped"
                assert json.loads(api.requests[-1]["body"])["content"] == "203.0.113.1"
                stop_server(process)
                assert process.returncode == 0, log_path.read_text()
                process = None
            assert token not in log_path.read_text()
            print("ok: Cloudflare API headers arrive through stdin, token stays out of child argv/logs, children are reaped", flush=True)
            api.fail = True
            with log_path.open("wb") as log:
                process = subprocess.Popen([str(BINARY), "--config", str(filename)], cwd=ROOT, stdout=log, stderr=log, start_new_session=True)
                api.layerline = process.pid
                process.wait(timeout=3)
                assert process.returncode != 0
                process = None
            assert token not in log_path.read_text() and "CloudflareDnsLookupFailed" in log_path.read_text()
            print("ok: Cloudflare setup failure exits nonzero without echoing untrusted API error text", flush=True)
        finally:
            api.shutdown()
            api.server_close()
            thread.join(timeout=2)
    except BaseException:
        print(log_path.read_text() if log_path.exists() else "no server log", file=sys.stderr)
        raise
    finally:
        stop_server(process)
        for pid in records(folder):
            if running(pid, folder):
                os.kill(pid, signal.SIGKILL)
