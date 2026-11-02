#!/usr/bin/env python3
"""Exercise real CGI/helper execs with inheritable low/high handles and a low soft limit."""
import concurrent.futures
import hashlib
import http.client
import json
import os
from pathlib import Path
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from wire_h2 import H2

if sys.platform not in ["darwin", "linux"]:
    print("skip: native child descriptor isolation requires Linux or macOS")
    raise SystemExit(0)

import fcntl
import resource

ROOT = Path(__file__).resolve().parents[1]


def force_proc():
    import ctypes
    # Apply only to this isolated launcher/server. Pretend close_range is
    # unavailable, so a modern Linux host also tests the /proc fallback.
    assert sys.platform == "linux" and os.uname().machine in ["x86_64", "aarch64"]
    class Filter(ctypes.Structure):
        _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte), ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint)]
    class Program(ctypes.Structure):
        _fields_ = [("length", ctypes.c_ushort), ("filters", ctypes.POINTER(Filter))]
    filters = (Filter * 4)(Filter(0x20, 0, 0, 0), Filter(0x15, 0, 1, 436),
                           Filter(0x06, 0, 0, 0x00050000 | 38), Filter(0x06, 0, 0, 0x7fff0000))
    program = Program(len(filters), filters)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    for args in [(38, 1, 0, 0, 0), (22, 2, ctypes.addressof(program), 0, 0)]:
        assert libc.prctl(*args) == 0, os.strerror(ctypes.get_errno())
    libc.syscall.restype = ctypes.c_long
    ctypes.set_errno(0)
    # Invalid bounds would return EINVAL if the filter did not intercept it.
    assert libc.syscall(ctypes.c_long(436), ctypes.c_uint(1), ctypes.c_uint(0), ctypes.c_uint(0)) == -1 and ctypes.get_errno() == 38


def launch(folder, binary, fallback):
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    desired = max(soft, 4097)
    assert hard == resource.RLIM_INFINITY or hard >= desired, "fixture requires a raisable soft nofile limit of at least 4097"
    resource.setrlimit(resource.RLIMIT_NOFILE, (desired, hard))
    file = os.open(folder / "sentinel.txt", os.O_RDONLY)
    directory = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    read, write = os.pipe()
    high = fcntl.fcntl(file, fcntl.F_DUPFD, 4096)
    handles = {"file": file, "directory": directory, "listener": listener.fileno(), "pipe_read": read, "pipe_write": write, "high_file": high}
    expected = {}
    for name, fd in handles.items():
        os.set_inheritable(fd, True)
        value = os.fstat(fd)
        expected[name] = {"fd": fd, "identity": [value.st_dev, value.st_ino, value.st_mode]}
    environment = dict(os.environ, LAYERLINE_FD_FIXTURE=json.dumps(expected))
    control = subprocess.run([str(folder / "php-cgi")], input=b"baseline", env=environment,
                             pass_fds=tuple(handles.values()), capture_output=True, check=True, timeout=5)
    baseline = json.loads(control.stdout.split(b"\r\n\r\n", 1)[1])
    assert set(baseline["leaks"]) == set(handles), ("probe concealed inherited handles", baseline)
    assert set(baseline["extra_fds"]) == set(handles.values()), baseline
    # A close loop bounded by the current soft limit would miss high_file.
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, hard))
    if fallback:
        force_proc()
    (folder / "launcher.json").write_text(json.dumps({"handles": expected, "soft_limit": 128, "forced_proc": fallback, "baseline": baseline}))
    os.execve(binary, [str(binary), "--config", str(folder / "server.conf")], environment)


if len(sys.argv) > 1 and sys.argv[1] == "--launch":
    launch(Path(sys.argv[2]), Path(sys.argv[3]), sys.argv[4] == "proc")
    raise AssertionError("exec returned")

BINARY = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT / "zig-out/bin/layerline"
INPUT = b"descriptor isolation input"


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def wait_for(check, label, seconds=6):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        if check():
            return
        time.sleep(.02)
    raise AssertionError(label)


def stop(process):
    if process is not None and process.poll() is None:
        process.send_signal(signal.SIGTERM)
        try:
            process.wait(timeout=4)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=4)
            raise AssertionError("descriptor isolation prevented joined shutdown")


def check_result(result, body):
    assert result["leaks"] == [] and result["extra_fds"] == [], result
    assert result["own_group"] and result["stdio_pipes"], result
    assert result["input_sha256"] == hashlib.sha256(body).hexdigest(), result


with tempfile.TemporaryDirectory(prefix="layerline-child-fds-", dir="/tmp") as temporary:
    root = Path(temporary)
    seed_cert, seed_key = root / "cert.pem", root / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "1", "-subj", "/CN=localhost", "-keyout", str(seed_key), "-out", str(seed_cert)], check=True, capture_output=True)
    cases = [(False, False), (True, False)]
    if sys.platform == "linux" and os.uname().machine in ["x86_64", "aarch64"]:
        cases += [(False, True), (True, True)]
    elif sys.platform == "linux":
        print("skip: forced close_range filter has only been verified on Linux x86_64/aarch64", flush=True)
    worker = (ROOT / "scripts/child-fd-worker.py").read_text().split("\n", 1)[1]
    assert " " not in sys.executable, "fixture shebang requires a no-space interpreter path"
    for tls, fallback in cases:
        folder = root / f"{tls}-{fallback}"
        folder.mkdir()
        (folder / "results").mkdir()
        (folder / "index.php").write_text("<?php // Inert script-name fixture.\n")
        (folder / "sentinel.txt").write_text("not a credential\n")
        for name in ["php-cgi", "certbot"]:
            probe = folder / name
            probe.write_text(f"#!{sys.executable}\n" + worker)
            probe.chmod(0o700)
        number = free_port()
        (folder / "server.conf").write_text(f"""host = 127.0.0.1
port = {number}
dir = {folder}
serve_static_root = true
php_root = {folder}
php_binary = {folder / 'php-cgi'}
upstream_timeout_ms = 2500
external_command_timeout_ms = 5000
admin = true
admin_ui = false
admin_socket = {folder / 'admin.sock'}
tls = {str(tls).lower()}
tls_auto = {str(tls).lower()}
tls_cert = {seed_cert}
tls_key = {seed_key}
letsencrypt_certbot = {folder / 'certbot'}
letsencrypt_email = fixture@example.test
letsencrypt_domains = example.test
letsencrypt_webroot = {folder}
letsencrypt_staging = true
letsencrypt_renew = false
graceful_shutdown_timeout_ms = 1500
""")
        log = folder / "server.log"
        process, h2 = None, None
        idle = []
        try:
            with log.open("wb") as output:
                process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--launch", str(folder), str(BINARY), "proc" if fallback else "native"], cwd=ROOT, stdout=output, stderr=output)
            wait_for(lambda: process.poll() is not None or '"event":"server.ready"' in log.read_text(), "server did not become ready")
            assert process.poll() is None, log.read_text()
            state = json.loads((folder / "launcher.json").read_text())
            assert state["handles"]["high_file"]["fd"] >= 4096 > state["soft_limit"]
            if tls:
                commands = list((folder / "results").glob("certbot-*.json"))
                assert len(commands) == 1
                check_result(json.loads(commands[0].read_text()), b"")
            h2 = H2(number, tls=tls)
            h2.request(1, b"/health")
            assert h2.response(1)[0] == 200
            idle = [socket.create_connection(("127.0.0.1", number), timeout=3) for _ in range(2)]

            def request_many():
                for _ in range(8):
                    connection = http.client.HTTPSConnection("127.0.0.1", number, context=ssl._create_unverified_context(), timeout=5) if tls else http.client.HTTPConnection("127.0.0.1", number, timeout=5)
                    try:
                        connection.request("POST", "/index.php", body=INPUT)
                        reply = connection.getresponse()
                        data = reply.read()
                        assert reply.status == 200, (reply.status, data[:100])
                        check_result(json.loads(data), INPUT)
                    finally:
                        connection.close()

            def churn():
                for _ in range(24):
                    peer = H2(number, tls=tls)
                    try:
                        peer.request(1, b"/static/sentinel.txt")
                        assert peer.response(1) == (200, b"not a credential\n")
                        peer.ping()
                    finally:
                        peer.close()

            with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
                futures = [pool.submit(request_many), pool.submit(request_many), pool.submit(churn)]
                for future in futures:
                    future.result()
            h2.ping()
            if sys.platform == "linux":
                for item in state["handles"].values():
                    value = os.stat(f"/proc/{process.pid}/fd/{item['fd']}")
                    assert [value.st_dev, value.st_ino, value.st_mode] == item["identity"], "child cleanup altered an inherited parent handle"
            h2.close()
            h2 = None
            for peer in idle:
                peer.close()
            idle.clear()
            stop(process)
            assert process.returncode == 0, log.read_text()
            print(f"ok: {'TLS + certificate helper' if tls else 'plain'} child fd isolation, high handles above soft nofile, stdio/groups and concurrent H2 churn; {'forced /proc fallback' if fallback else 'native path'}", flush=True)
        except BaseException:
            print(log.read_text() if log.exists() else "server did not start", file=sys.stderr)
            raise
        finally:
            if h2 is not None:
                h2.close()
            for peer in idle:
                peer.close()
            stop(process)
