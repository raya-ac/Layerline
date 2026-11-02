#!/usr/bin/env python3
"""Bounded I/O admission, restart-only settings and optional Linux cgroup checks."""
import configparser
import http.client
import http.server
import os
from pathlib import Path
import shlex
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / "zig-out/bin/layerline"


def wait_for(test, seconds=5):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        if value := test():
            return value
        time.sleep(.01)
    raise AssertionError("runtime budget condition did not settle")


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def command(path, text):
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(2)
        client.connect(str(path))
        client.sendall(text.encode() + b"\n")
        data = b""
        while part := client.recv(65536):
            data += part
            assert len(data) < 1048576
        return data.decode()


def metrics(path):
    return {line.rsplit(" ", 1)[0]: int(line.rsplit(" ", 1)[1]) for line in command(path, "metrics").splitlines() if line and not line.startswith("#")}


def request(port, path):
    client = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
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
            raise AssertionError("bounded runtime failed to stop")


class Backend(http.server.ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 32

    def __init__(self):
        super().__init__(("127.0.0.1", 0), Handler)
        self.release = threading.Event()


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.server.release.wait(8)
        try:
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"ok")
        except ConnectionError:
            pass

    def log_message(self, *_):
        pass


def frame(kind, flags, stream, payload=b""):
    return len(payload).to_bytes(3, "big") + bytes([kind, flags]) + stream.to_bytes(4, "big") + payload


class H2:
    def __init__(self, port):
        self.connection = socket.create_connection(("127.0.0.1", port), timeout=3)
        self.connection.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 0, 0))

    def request(self, stream, path):
        def literal(name, value):
            assert len(name) < 127 and len(value) < 127
            return b"\0" + bytes([len(name)]) + name + bytes([len(value)]) + value
        self.connection.sendall(frame(1, 5, stream, b"\x82\x86" + literal(b":authority", b"localhost") + literal(b":path", path)))

    def exact(self, count):
        result = b""
        while len(result) < count:
            part = self.connection.recv(count - len(result))
            if not part:
                raise EOFError("HTTP/2 transport ended under I/O pressure")
            result += part
        return result

    def until(self, predicate):
        until = time.monotonic() + 3
        while True:
            self.connection.settimeout(max(.01, until - time.monotonic()))
            header = self.exact(9)
            kind, flags, stream = header[3], header[4], int.from_bytes(header[5:], "big")
            payload = self.exact(int.from_bytes(header[:3], "big"))
            if kind == 4 and not flags & 1:
                self.connection.sendall(frame(4, 1, 0))
            assert kind != 7, ("unexpected GOAWAY", payload)
            if predicate(kind, flags, stream, payload):
                return
            assert time.monotonic() < until

    def close(self):
        self.connection.close()


def wire(folder):
    port = free_port()
    backend = Backend()
    thread = threading.Thread(target=backend.serve_forever, daemon=True)
    thread.start()
    config, admin, log = folder / "server.conf", folder / "admin.sock", folder / "server.log"
    (folder / "fast.txt").write_bytes(b"pool still alive")
    original = f"""host = 127.0.0.1
port = {port}
dir = {folder}
serve_static_root = true
admin_socket = {admin}
admin_ui = false
io_thread_limit = 8
io_stack_size = 1048576
upstream_timeout_ms = 6000
upstream_retries = 0
upstream_max_failures = 1
idle_timeout_ms = 10000
graceful_shutdown_timeout_ms = 1200
route = slow /slow/* proxy
route_proxy.slow = http://127.0.0.1:{backend.server_port}
"""
    config.write_text(original)
    for key, value in [("io_thread_limit", "0"), ("io_thread_limit", "4097"), ("io_stack_size", "65536"), ("io_stack_size", "67108865")]:
        config.write_text(original + f"{key} = {value}\n")
        invalid = subprocess.run([str(BINARY), "--config", str(config), "--validate-config"], capture_output=True, timeout=5)
        assert invalid.returncode != 0, (key, value, invalid.stderr)
    config.write_text(original)
    clients = []
    process = None
    try:
        with log.open("wb") as output:
            process = subprocess.Popen([str(BINARY), "--config", str(config), "--io-thread-limit", "8", "--io-stack-size", "1048576"], cwd=ROOT, stdout=output, stderr=output)
        wait_for(lambda: process.poll() is not None or '"event":"server.ready"' in log.read_text())
        assert process.poll() is None, log.read_text()
        baseline = metrics(admin)
        assert baseline["layerline_io_thread_limit"] == 8 and baseline["layerline_io_stack_size_bytes"] == 1048576
        clients = [H2(port) for _ in range(3)]
        # Fill retained backend jobs gradually; dial timers need pool capacity
        # too. Later requests must reject or complete, never grow a ninth worker.
        for index in range(12):
            clients[index % 3].request(1 + (index // 3) * 2, b"/slow/held")
            time.sleep(.04)
            observed = metrics(admin)
            assert observed["layerline_io_threads"] <= 8 and observed["layerline_io_busy_threads"] <= 8
        observed = wait_for(lambda: (m if (m := metrics(admin))["layerline_io_busy_threads"] >= 5 else None))
        assert observed['layerline_heap_bytes{pool="io"}'] > 0
        assert observed['layerline_heap_bytes{pool="total"}'] <= observed['layerline_heap_limit_bytes{pool="total"}']
        assert observed["layerline_upstream_failures_total"] == 0, "local I/O saturation poisoned upstream health"
        for client in clients:
            client.connection.sendall(frame(6, 0, 0, b"bounded!"))
            client.until(lambda k, f, s, p: k == 6 and f == 1 and s == 0 and p == b"bounded!")
        assert request(port, "/fast.txt") == (200, b"pool still alive")
        assert "Layerline" in command(admin, "status")
        backend.release.set()
        for client in clients:
            client.close()
        clients.clear()
        wait_for(lambda: metrics(admin)["layerline_io_busy_threads"] == 0)
        # Capacity must be reusable, not merely bounded until the first overload.
        for _ in range(3):
            client = H2(port)
            clients.append(client)
            client.request(1, b"/slow/recovered")
            body = bytearray()
            def complete(k, f, s, p):
                if k == 0 and s == 1:
                    body.extend(p)
                assert not (k == 3 and s == 1), "routing capacity did not recover"
                return k in [0, 1] and s == 1 and f & 1
            client.until(complete)
            assert body == b"ok"
            client.close()
            clients.remove(client)
        wait_for(lambda: metrics(admin)["layerline_io_busy_threads"] == 0)
        for key, value in [("io_thread_limit", "16"), ("io_stack_size", "2097152")]:
            config.write_text(original + f"{key} = {value}\n")
            assert "global." + key in command(admin, "diff")
            assert "ReloadRequiresRestart" in command(admin, "reload")
            assert metrics(admin)["layerline_io_thread_limit"] == 8
            assert metrics(admin)["layerline_io_stack_size_bytes"] == 1048576
        config.write_text(original)
        assert "ReloadRequiresRestart" not in command(admin, "reload")
        stop(process)
        assert process.returncode == 0, log.read_text()
        print("ok: bounded I/O workers/stacks, shared heap accounting, H2 PING/control under saturation, repeated recovery and restart-only settings", flush=True)
    except BaseException:
        print(log.read_text() if log.exists() else "server not started", file=sys.stderr)
        raise
    finally:
        backend.release.set()
        for client in clients:
            client.close()
        if process:
            stop(process)
        backend.shutdown()
        backend.server_close()
        thread.join(timeout=2)


def manager(folder):
    assert sys.platform == "linux" and os.geteuid() == 0 and Path("/run/systemd/system").exists()
    parser = configparser.ConfigParser(interpolation=None)
    parser.read(ROOT / "deploy/systemd/layerline.service")
    settings = {key: parser["Service"][key] for key in ["MemoryAccounting", "MemoryHigh", "MemoryMax", "MemorySwapMax", "OOMPolicy", "TasksAccounting", "TasksMax", "LimitNOFILE"]}
    unit = "layerline-resource-test-" + uuid.uuid4().hex + ".service"
    config = folder / "manager.conf"
    port = free_port()
    config.write_text(f"host = 127.0.0.1\nport = {port}\nadmin = false\nadmin_ui = false\n")
    command_line = ["systemd-run", "--unit=" + unit, "--property=Type=notify", "--property=NotifyAccess=main", "--property=Restart=no", "--property=TimeoutStartSec=8s", "--property=TimeoutStopSec=5s"]
    command_line += ["--property=" + key + "=" + value for key, value in settings.items()]
    try:
        subprocess.run(command_line + [str(BINARY), "--config", str(config)], check=True, capture_output=True, text=True, timeout=10)
        values = subprocess.check_output(["systemctl", "show", unit, "-p", "ControlGroup", "-p", "MainPID", "-p", "MemoryHigh", "-p", "MemoryMax", "-p", "MemorySwapMax", "-p", "TasksMax", "-p", "LimitNOFILE"], text=True)
        observed = dict(line.split("=", 1) for line in values.splitlines())
        assert observed["MemoryHigh"] == "1073741824" and observed["MemoryMax"] == "1610612736", observed
        assert observed["TasksMax"] == "2048" and observed["LimitNOFILE"] == "65536", observed
        cgroup = Path("/sys/fs/cgroup") / observed["ControlGroup"].lstrip("/")
        assert (cgroup / "memory.high").read_text().strip() == observed["MemoryHigh"]
        assert (cgroup / "memory.max").read_text().strip() == observed["MemoryMax"]
        assert observed["MemorySwapMax"] == "0" and (cgroup / "memory.swap.max").read_text().strip() == "0"
        assert (cgroup / "pids.max").read_text().strip() == observed["TasksMax"]
        limits = (Path("/proc") / observed["MainPID"] / "limits").read_text()
        assert "65536" in next(line for line in limits.splitlines() if line.startswith("Max open files")), limits
        assert request(port, "/health")[0] == 200
        print("ok: packaged memory/task/fd limits are installed in the real service cgroup and process", flush=True)
    finally:
        subprocess.run(["systemctl", "stop", unit], capture_output=True)
        subprocess.run(["systemctl", "reset-failed", unit], capture_output=True)


def child_memory_boundary(folder):
    # Deliberately exhaust ONLY a disposable 64 MiB cgroup. The helper is a
    # Layerline certificate child, not an unrelated synthetic unit payload.
    unit = "layerline-child-memory-test-" + uuid.uuid4().hex + ".service"
    marker, helper = folder / "child-cgroup", folder / "certbot-memory"
    code = ("import os,time; from pathlib import Path; "
            f"Path({str(marker)!r}).write_text(Path('/proc/self/cgroup').read_text()); "
            "data=bytearray(96*1024*1024); "
            "data[::4096]=b'x'*(len(data)//4096); time.sleep(10)")
    helper.write_text("#!/bin/sh\nexec " + shlex.quote(sys.executable) + " -c " + shlex.quote(code) + "\n")
    helper.chmod(0o700)
    config = folder / "child-memory.conf"
    config.write_text(f"""host = 127.0.0.1
port = {free_port()}
admin = false
admin_ui = false
tls = true
tls_auto = true
letsencrypt_renew = false
letsencrypt_domains = resource.invalid
letsencrypt_webroot = {folder}
letsencrypt_certbot = {helper}
external_command_timeout_ms = 5000
""")
    launch = ["systemd-run", "--unit=" + unit, "--property=Type=notify", "--property=NotifyAccess=main", "--property=Restart=no", "--property=TimeoutStartSec=10s", "--property=TimeoutStopSec=5s", "--property=MemoryAccounting=true", "--property=MemoryMax=64M", "--property=MemorySwapMax=0", "--property=OOMPolicy=stop", "--property=TasksMax=64", str(BINARY), "--config", str(config)]
    try:
        result = subprocess.run(launch, capture_output=True, text=True, timeout=12)
        assert result.returncode != 0, "the memory-hungry child unexpectedly finished startup"
        assert marker.exists() and unit in marker.read_text(), "child did not inherit the service cgroup"
        def failed_as_expected():
            text = subprocess.check_output(["systemctl", "show", unit, "-p", "Result", "-p", "ActiveState"], text=True)
            state = dict(line.split("=", 1) for line in text.splitlines())
            return state["Result"] == "oom-kill" and state["ActiveState"] == "failed"
        wait_for(failed_as_expected)
        print("ok: certificate child inherits the cgroup; isolated 64 MiB hard-limit exhaustion stops the unit with oom-kill", flush=True)
    finally:
        subprocess.run(["systemctl", "stop", unit], capture_output=True)
        subprocess.run(["systemctl", "reset-failed", unit], capture_output=True)


with tempfile.TemporaryDirectory(prefix="ll-runtime-budget-") as temporary:
    folder = Path(temporary)
    wire(folder)
    if "--systemd" in sys.argv[2:]:
        manager(folder)
        child_memory_boundary(folder)
