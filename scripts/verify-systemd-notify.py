#!/usr/bin/env python3
"""Native notify datagrams, child isolation, and optional real systemd acceptance."""
import http.client
import json
import os
from pathlib import Path
import shlex
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import time
import uuid


ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / "zig-out/bin/layerline"


def port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def wait_for(test, timeout=5):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        if value := test():
            return value
        time.sleep(.01)
    raise AssertionError("timed out waiting for lifecycle transition")


def request(number, path="/health"):
    client = http.client.HTTPConnection("127.0.0.1", number, timeout=2)
    try:
        client.request("GET", path)
        response = client.getresponse()
        return response.status, response.read()
    finally:
        client.close()


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=4)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=4)
            raise AssertionError("notification backpressure stalled shutdown")


class Receiver:
    def __init__(self, path):
        self.path = path
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        self.socket.bind("\0" + path[1:] if path.startswith("@") else path)
        self.socket.settimeout(4)

    def receive(self, pid=None):
        data, control, flags, _ = self.socket.recvmsg(2048, socket.CMSG_SPACE(12))
        assert not flags
        assert not any(level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS for level, kind, _ in control)
        credentials = [struct.unpack("3i", value) for level, kind, value in control if level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS]
        if pid is not None:
            assert len(credentials) == 1 and credentials[0][0] == pid, credentials
        return data.decode()

    def empty(self):
        self.socket.settimeout(.05)
        try:
            raise AssertionError("unexpected notification: " + self.receive())
        except socket.timeout:
            pass
        finally:
            self.socket.settimeout(4)

    def close(self):
        self.socket.close()
        if self.path.startswith("/"):
            Path(self.path).unlink(missing_ok=True)


def configuration(folder, number, extra=""):
    return f"""host = 127.0.0.1
port = {number}
dir = {folder / 'www'}
serve_static_root = true
admin_socket = {folder / 'admin.sock'}
admin_ui = false
graceful_shutdown_timeout_ms = 1200
""" + extra


def saturate(path):
    # One sender can exhaust its own send buffer before the receiver queue.
    # Keep senders alive and require a fresh sender's first datagram to fail.
    fillers = []
    count = 0
    try:
        for _ in range(16):
            filler = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
            fillers.append(filler)
            filler.setblocking(False)
            sent = 0
            while True:
                try:
                    filler.sendto(b"fixture", "\0" + path[1:] if path.startswith("@") else path)
                    sent += 1
                    count += 1
                except BlockingIOError:
                    break
            if sent == 0:
                return fillers, count
        raise AssertionError("could not saturate isolated notify queue")
    except BaseException:
        for filler in fillers:
            filler.close()
        raise


def failures(folder):
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(2)
        client.connect(str(folder / "admin.sock"))
        client.sendall(b"metrics\n")
        data = b""
        while part := client.recv(65536):
            data += part
            assert len(data) < 1048576
        return int(next(line.split()[1] for line in data.decode().splitlines() if line.startswith("layerline_supervisor_notification_failures_total ")))


def wire_tests(folder):
    for abstract in [False, True]:
        name = "@ll-notify-" + uuid.uuid4().hex if abstract else str(folder / "notify.sock")
        receiver = Receiver(name)
        number = port()
        config = folder / "server.conf"
        original = configuration(folder, number)
        config.write_text(original)
        environment = dict(os.environ, NOTIFY_SOCKET=name, WATCHDOG_PID="1", WATCHDOG_USEC="1000000")
        # Validation and control clients inherit the unit's environment too.
        subprocess.run([str(BINARY), "--config", str(config), "--validate-config"], env=environment, check=True, capture_output=True)
        receiver.empty()
        with (folder / "wire.log").open("wb") as log:
            process = subprocess.Popen([str(BINARY), "--config", str(config)], env=environment, cwd=ROOT, stdout=log, stderr=log)
            try:
                assert receiver.receive(process.pid).startswith("STATUS=Loading")
                assert receiver.receive(process.pid).startswith("READY=1\nSTATUS=Listening")
                assert request(number)[0] == 200
                subprocess.run([str(BINARY), "--config", str(config), "--runtime-status"], env=environment, check=True, capture_output=True)
                receiver.empty()
                for bad in [False, True, False]:
                    config.write_text(original + ("port = invalid\n" if bad else "max_concurrent_connections = 17\n"))
                    process.send_signal(signal.SIGHUP)
                    assert receiver.receive(process.pid).startswith("RELOADING=1\n")
                    reply = receiver.receive(process.pid)
                    assert reply.startswith("READY=1\n"), reply
                    assert ("Reload rejected" in reply) == bad, reply
                    assert request(number)[0] == 200
                fillers, queued = saturate(name)
                try:
                    config.write_text(original)
                    process.send_signal(signal.SIGHUP)
                    wait_for(lambda: failures(folder) >= 2)
                    assert request(number)[0] == 200
                    for _ in range(queued):
                        assert receiver.receive() == "fixture"
                finally:
                    for filler in fillers:
                        filler.close()
                receiver.empty()
                # A pending upload keeps the drain observable after STOPPING.
                with socket.create_connection(("127.0.0.1", number), timeout=2) as pending:
                    pending.sendall(b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\na")
                    time.sleep(.05)
                    process.terminate()
                    assert receiver.receive(process.pid).startswith("STOPPING=1\n")
                process.wait(timeout=4)
                assert process.returncode == 0, (folder / "wire.log").read_text()
                receiver.empty()
            finally:
                stop(process)
                receiver.close()
        print(f"ok: {'abstract' if abstract else 'filesystem'} notify credentials, ready, reload rejection/recovery, CLI silence and stopping", flush=True)

    # A configured but unavailable/full manager must never give a false READY.
    for mode in ["missing", "full", "disappearing", "listener-failure"]:
        receiver = Receiver(str(folder / "notify.sock")) if mode != "missing" else None
        occupied = socket.socket()
        fillers = []
        try:
            extra = ""
            if mode == "listener-failure":
                occupied.bind(("127.0.0.1", 0))
                occupied.listen()
                extra = f"tls = true\nhttp_redirect = true\nhttp_redirect_port = {occupied.getsockname()[1]}\n"
            config.write_text(configuration(folder, port(), extra))
            environment = dict(os.environ, NOTIFY_SOCKET=str(folder / "notify.sock"))
            if mode == "full":
                fillers, _ = saturate(environment["NOTIFY_SOCKET"])
            with (folder / "failure.log").open("wb") as log:
                process = subprocess.Popen([str(BINARY), "--config", str(config)], env=environment, cwd=ROOT, stdout=log, stderr=log)
                try:
                    if mode == "disappearing":
                        assert receiver.receive(process.pid).startswith("STATUS=")
                        # The server may already have sent READY. Once stopped,
                        # its failed status send still must not hold shutdown.
                        receiver.close()
                        receiver = None
                        process.terminate()
                    try:
                        process.wait(timeout=4)
                    except subprocess.TimeoutExpired:
                        raise AssertionError((mode, (folder / "failure.log").read_text())) from None
                    if mode != "disappearing":
                        assert process.returncode != 0
                        assert '"event":"server.ready"' not in (folder / "failure.log").read_text()
                finally:
                    stop(process)
        finally:
            occupied.close()
            for filler in fillers:
                filler.close()
            if receiver:
                receiver.close()
        print(f"ok: {mode} notification/startup failure is bounded", flush=True)


def slow_start_config(folder):
    cert, key = folder / "cert.pem", folder / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(cert), "-days", "1", "-subj", "/CN=localhost"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    helper = folder / "certbot"
    snapshot = folder / "child-env.json"
    code = f"import json,os,time; from pathlib import Path; Path({str(snapshot)!r}).write_text(json.dumps({{k:os.environ[k] for k in ['NOTIFY_SOCKET','WATCHDOG_PID','WATCHDOG_USEC'] if k in os.environ}})); time.sleep(.8)"
    helper.write_text("#!/bin/sh\nexec " + shlex.quote(sys.executable) + " -c " + shlex.quote(code) + "\n")
    helper.chmod(0o700)
    number = port()
    original = configuration(folder, number, f"tls = true\ntls_auto = true\nletsencrypt_renew = false\nletsencrypt_domains = fixture.invalid\nletsencrypt_webroot = {folder}\nletsencrypt_certbot = {helper}\ntls_cert = {cert}\ntls_key = {key}\n")
    config = folder / "slow.conf"
    config.write_text(original)
    return config, snapshot, original


def delayed_wire_test(folder):
    config, snapshot, _ = slow_start_config(folder)
    receiver = Receiver(str(folder / "notify.sock"))
    environment = dict(os.environ, NOTIFY_SOCKET=receiver.path, WATCHDOG_PID="1", WATCHDOG_USEC="1000000")
    with (folder / "delayed.log").open("wb") as log:
        process = subprocess.Popen([str(BINARY), "--config", str(config)], env=environment, cwd=ROOT, stdout=log, stderr=log)
        try:
            assert receiver.receive(process.pid).startswith("STATUS=")
            wait_for(snapshot.exists)
            assert json.loads(snapshot.read_text()) == {}, "supervisor capability leaked to certificate helper"
            receiver.empty()
            assert receiver.receive(process.pid).startswith("READY=1\n")
            stop(process)
            assert receiver.receive(process.pid).startswith("STOPPING=1\n")
            assert process.returncode == 0, (folder / "delayed.log").read_text()
        finally:
            stop(process)
            receiver.close()
    print("ok: no READY while certificate helper runs; child receives no notify/watchdog authority", flush=True)


def manager_test(folder):
    assert os.geteuid() == 0 and Path("/run/systemd/system").exists(), "--systemd requires root and a running systemd manager"
    config, snapshot, original = slow_start_config(folder)
    snapshot.unlink(missing_ok=True)
    unit = "layerline-notify-test-" + uuid.uuid4().hex + ".service"

    def manager(*args, check=True):
        return subprocess.run(["systemctl", *args, unit], check=check, capture_output=True, text=True)

    def state():
        reply = manager("show", "-p", "ActiveState", "-p", "SubState", "-p", "StatusText", "-p", "MainPID", "-p", "Result")
        return dict(line.split("=", 1) for line in reply.stdout.splitlines() if "=" in line)

    command = ["systemd-run", "--unit=" + unit, "--property=Type=notify", "--property=NotifyAccess=main", "--property=TimeoutStartSec=8s", "--property=TimeoutStopSec=5s", "--property=Restart=no", str(BINARY), "--config", str(config)]
    starter = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        wait_for(snapshot.exists)
        observed = state()
        assert observed["ActiveState"] == "activating" and observed["SubState"] == "start", observed
        assert json.loads(snapshot.read_text()) == {}
        stdout, stderr = starter.communicate(timeout=6)
        assert starter.returncode == 0, (stdout, stderr, state())
        active = state()
        assert active["ActiveState"] == "active" and active["StatusText"] == "Listening; configuration active", active
        pid = active["MainPID"]
        for bad in [False, True]:
            config.write_text(original + ("port = invalid\n" if bad else "max_concurrent_connections = 17\n"))
            manager("kill", "--kill-whom=main", "--signal=HUP")
            expected = "Reload rejected; previous configuration remains active" if bad else "Listening; replacement configuration active"
            wait_for(lambda: state()["StatusText"] == expected)
            assert state()["MainPID"] == pid and state()["ActiveState"] == "active", state()
        manager("stop")
        assert state()["Result"] == "success", state()
        print("ok: real systemd waits for native READY, accepts main-thread/worker credentials, tracks both reload outcomes and clean shutdown", flush=True)
        # A late listener collision must fail activation, not leave a running
        # unit just because the primary socket was successfully prepared.
        with socket.socket() as occupied:
            occupied.bind(("127.0.0.1", 0))
            occupied.listen()
            config.write_text(original + f"http_redirect = true\nhttp_redirect_port = {occupied.getsockname()[1]}\n")
            result = subprocess.run(command, capture_output=True, text=True, timeout=6)
            assert result.returncode != 0, (result.stdout, result.stderr)
            failed = state()
            assert failed["ActiveState"] == "failed" and failed["Result"] == "exit-code", failed
        print("ok: real systemd rejects startup when an optional listener cannot bind", flush=True)
    finally:
        if starter.poll() is None:
            starter.terminate()
            starter.communicate(timeout=3)
        manager("stop", check=False)
        manager("reset-failed", check=False)


if sys.platform != "linux":
    print("skip: systemd notify uses Linux Unix datagrams; native unit tests cover lifecycle and environment filtering")
    sys.exit(0)

with tempfile.TemporaryDirectory(prefix="ll-notify-") as temporary:
    folder = Path(temporary)
    (folder / "www").mkdir()
    wire_tests(folder)
    delayed_wire_test(folder)
    if "--systemd" in sys.argv[2:]:
        manager_test(folder)
