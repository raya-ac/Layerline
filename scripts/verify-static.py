#!/usr/bin/env python3
"""Exercise conditional and range semantics using independent HTTP/1 and h2 clients."""
import pathlib
import subprocess
import sys
import tempfile


with tempfile.TemporaryDirectory(prefix="layerline-static-") as directory:
    root = pathlib.Path(directory)

    def fetch(protocol, fields=(), head=False):
        (root / "body").write_bytes(b"")
        command = ["curl", "-sS", "--max-time", "5", protocol, "-D", str(root / "headers"), "-o", str(root / "body"), "-w", "%{http_code}", "-H", "Host: custom404.test"]
        if head:
            command.append("--head")
        for field in fields:
            command.extend(["-H", field])
        command.append(f"http://{sys.argv[1]}:{sys.argv[2]}/index.html")
        status = int(subprocess.check_output(command))
        headers = {}
        for line in (root / "headers").read_text().splitlines():
            if ":" in line:
                name, value = line.split(":", 1)
                headers[name.lower()] = value.strip()
        return status, headers, (root / "body").read_bytes()

    for protocol in ["--http1.1", "--http2-prior-knowledge"]:
        status, headers, body = fetch(protocol)
        assert status == 200
        etag, modified = headers["etag"], headers["last-modified"]
        status, _, unchanged = fetch(protocol, ['If-None-Match: "old"', f"If-Modified-Since: {modified}"])
        assert status == 200 and unchanged == body, "ETag mismatch must override modification date"
        status, headers, empty = fetch(protocol, [f"If-None-Match: W/{etag}"])
        assert status == 304 and not empty and "content-length" not in headers, (protocol, status, headers, empty)
        status, headers, part = fetch(protocol, ["Range: bytes=0-4", f"If-Range: {etag}", "Accept-Encoding: gzip"])
        assert status == 206 and part == body[:5]
        assert headers["content-range"] == f"bytes 0-4/{len(body)}" and "content-encoding" not in headers
        status, _, suffix = fetch(protocol, ["Range: bytes=-5"])
        assert status == 206 and suffix == body[-5:]
        status, _, full = fetch(protocol, ["Range: bytes=0-4", 'If-Range: "stale"'])
        assert status == 200 and full == body
        status, _, full = fetch(protocol, ["Range: bytes=0-4", "If-Range: Sun, 06 Nov 2094 08:49:37 GMT"])
        assert status == 200 and full == body, "If-Range dates require exact match"
        status, headers, _ = fetch(protocol, ["Range: bytes=999999-"])
        assert status == 416 and headers["content-range"] == f"bytes */{len(body)}"
        status, headers, _ = fetch(protocol, ["Range: bytes=0-4"], head=True)
        assert status == 200 and headers["content-length"] == str(len(body))
        assert "content-range" not in headers
        print(f"ok: {protocol} validators, ranges, stale fallback, HEAD metadata, and bodyless 304")
