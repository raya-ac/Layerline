#!/usr/bin/env python3
"""Report inherited handles without reading their contents; all fixtures are inert."""
import hashlib
import json
import os
from pathlib import Path
import stat
import sys


def identity(fd):
    value = os.fstat(fd)
    return [value.st_dev, value.st_ino, value.st_mode]


expected = json.loads(os.environ["LAYERLINE_FD_FIXTURE"])
leaks = []
for name, item in expected.items():
    try:
        if identity(item["fd"]) == item["identity"]:
            leaks.append(name)
    except OSError:
        pass

own = os.stat(__file__)
own_identity = [own.st_dev, own.st_ino, own.st_mode]
extra = []
for name in os.listdir("/proc/self/fd" if sys.platform == "linux" else "/dev/fd"):
    if not name.isdecimal() or int(name) <= 2:
        continue
    try:
        # CPython can keep its own executing script open. That handle was
        # opened by this image, not inherited from the HTTP server.
        if identity(int(name)) != own_identity:
            extra.append(int(name))
    except OSError:
        pass

body = sys.stdin.buffer.read()
result = {"leaks": sorted(leaks), "extra_fds": sorted(extra), "pid": os.getpid(),
          "own_group": os.getpgrp() == os.getpid(),
          "stdio_pipes": all(stat.S_ISFIFO(os.fstat(fd).st_mode) for fd in range(3)),
          "input_sha256": hashlib.sha256(body).hexdigest()}
folder = Path(__file__).parent
kind = "certbot" if Path(__file__).name == "certbot" else "cgi"
(folder / "results" / f"{kind}-{os.getpid()}.json").write_text(json.dumps(result))
if kind == "cgi":
    sys.stdout.buffer.write(b"Content-Type: application/json\r\n\r\n")
sys.stdout.write(json.dumps(result))
