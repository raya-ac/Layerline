#!/usr/bin/env python3
"""Small, deterministic child for the process-lifetime wire tests."""
import json
import os
import pathlib
import signal
import sys
import time


def worker(folder, kind):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    pid = os.getpid()
    record = folder / "pids" / str(pid)
    temporary = record.with_suffix(".tmp")
    temporary.write_text(json.dumps({"kind": kind, "pgid": os.getpgrp(), "started_ns": time.monotonic_ns()}))
    temporary.replace(record)
    if kind in ["hang", "descendant"]:
        child = os.fork()
        if child == 0:
            worker(folder, "sleeper")
            os._exit(0)
        until = time.monotonic() + 1
        while not (folder / "pids" / str(child)).exists():
            assert time.monotonic() < until
            time.sleep(.002)
    if kind in ["hang", "noinput", "sleeper", "renew"]:
        time.sleep(8)
    elif kind == "closed":
        os.close(1)
        os.close(2)
        time.sleep(8)
    elif kind == "trickle":
        os.write(1, b"Content-Type: text/plain\r\n\r\n")
        for _ in range(100):
            os.write(1, b"x")
            time.sleep(.05)
    elif kind == "duplex":
        import hashlib
        sys.stdout.buffer.write(b"Content-Type: text/plain\r\n\r\n" + b"x" * 65536)
        sys.stdout.buffer.flush()
        sys.stderr.buffer.write(b"diagnostic fixture\n" * 1800)
        sys.stderr.buffer.flush()
        body = sys.stdin.buffer.read()
        sys.stdout.buffer.write(hashlib.sha256(body).hexdigest().encode())
    elif kind == "overflow":
        sys.stdout.buffer.write(b"x" * 262144)
        sys.stdout.buffer.flush()
        time.sleep(8)
    elif kind == "stderr":
        sys.stderr.buffer.write(b"private-child-marker\n" * 8192)
        sys.stderr.buffer.flush()
        time.sleep(8)
    elif kind == "descendant":
        sys.stdout.buffer.write(b"Content-Type: text/plain\r\n\r\nok")
    elif kind == "earlyinput":
        os.close(0)
        sys.stdout.buffer.write(b"Content-Type: text/plain\r\n\r\nok")
    elif kind == "exit":
        sys.stdout.buffer.write(b"Content-Type: text/plain\r\n\r\nnot a successful reply")
        sys.stdout.buffer.flush()
        sys.exit(7)
    elif kind == "slow":
        time.sleep(.6)
        sys.stdout.buffer.write(b"Content-Type: text/plain\r\n\r\nok")
    else:
        sys.stdout.buffer.write(b"Content-Type: text/plain\r\n\r\nok")


if __name__ == "__main__":
    root = pathlib.Path(sys.argv[2])
    if sys.argv[1] == "--cgi":
        worker(root, os.environ.get("QUERY_STRING", "okay"))
    else:
        sys.stderr.write("private-child-marker\n")
        mode = (root / "command-mode").read_text()
        worker(root, "renew" if "renew" in sys.argv[3:] else mode)
