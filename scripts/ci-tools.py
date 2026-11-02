#!/usr/bin/env python3
"""Prepare checksum-pinned CI compilers and the existing independent H2 peer."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import subprocess
import tarfile
import time
import urllib.parse
import urllib.request

ZIG_VERSION = "0.16.0"
H2_REVISION = "af83a65f0b6273ef38bf778d400d98892e7653d8"
H2_ARCHIVE_SHA = "eaf456f4021325349615020cb8ceaaf0c51c7c5f0e1c74db089dced212b2060c"
ZIG_TARGETS = {
    ("Linux", "x86_64"): ("x86_64-linux", "70e49664a74374b48b51e6f3fdfbf437f6395d42509050588bd49abe52ba3d00"),
    ("Darwin", "arm64"): ("aarch64-macos", "b23d70deaa879b5c2d486ed3316f7eaa53e84acf6fc9cc747de152450d401489"),
    ("Darwin", "x86_64"): ("x86_64-macos", "0387557ed1877bc6a2e1802c8391953baddba76081876301c522f52977b52ba7"),
}


def sha(path):
    with Path(path).open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


class HttpsRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, url):
        if urllib.parse.urlsplit(url).scheme != "https":
            raise ValueError("tool download redirected outside HTTPS")
        return super().redirect_request(request, fp, code, message, headers, url)


def download(url, target, digest, limit):
    if urllib.parse.urlsplit(url).scheme != "https":
        raise ValueError("tool downloads require HTTPS")
    opener = urllib.request.build_opener(HttpsRedirects())
    until = time.monotonic() + 120
    size = 0
    with opener.open(url, timeout=15) as response, target.open("xb") as output:
        while chunk := response.read(1024 * 1024):
            size += len(chunk)
            if size > limit or time.monotonic() > until:
                raise ValueError("tool download exceeded its size or time bound")
            output.write(chunk)
    if sha(target) != digest:
        raise ValueError("tool archive checksum mismatch")


def extract(archive, destination, root):
    with tarfile.open(archive) as source:
        members = source.getmembers()
        if len(members) > 100000 or sum(member.size for member in members) > 1024 * 1024 * 1024:
            raise ValueError("tool archive exceeds extraction limits")
        for member in members:
            name = PurePosixPath(member.name)
            if not (member.isfile() or member.isdir()) or member.size < 0 or name.is_absolute() or ".." in name.parts or "\\" in member.name or not name.parts or name.parts[0] != root:
                raise ValueError("unsafe tool archive member")
        source.extractall(destination, members=members, filter="data")
    return destination / root


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--export-github-path", action="store_true")
    args = parser.parse_args()
    target, zig_digest = ZIG_TARGETS[(platform.system(), platform.machine())]
    destination = args.destination.resolve()
    destination.mkdir(mode=0o700)
    zig_name = f"zig-{target}-{ZIG_VERSION}"
    zig_archive = destination / "zig.tar.xz"
    download(f"https://ziglang.org/download/{ZIG_VERSION}/{zig_name}.tar.xz", zig_archive, zig_digest, 70 * 1024 * 1024)
    zig_root = extract(zig_archive, destination, zig_name)
    zig = zig_root / "zig"
    assert zig.is_file() and not zig.is_symlink()
    assert subprocess.check_output([str(zig), "version"], text=True).strip() == ZIG_VERSION

    h2_archive = destination / "h2spec.tar.gz"
    download(f"https://codeload.github.com/summerwind/h2spec/tar.gz/{H2_REVISION}", h2_archive, H2_ARCHIVE_SHA, 1024 * 1024)
    h2_root = extract(h2_archive, destination, "h2spec-" + H2_REVISION)
    executable_dir = destination / "bin"
    executable_dir.mkdir(mode=0o700)
    h2spec = executable_dir / "h2spec"
    env = {
        **os.environ, "CGO_ENABLED": "0", "GOTOOLCHAIN": "local", "GOWORK": "off",
        "GOENV": "off", "GOFLAGS": "", "GOSUMDB": "sum.golang.org", "GOPROXY": "https://proxy.golang.org",
        "GOPRIVATE": "", "GONOSUMDB": "", "GONOPROXY": "",
        "GOPATH": str(destination / "go"), "GOMODCACHE": str(destination / "go/pkg/mod"), "GOCACHE": str(destination / "go-cache"),
    }
    go_version = subprocess.check_output(["go", "version"], text=True, env=env).strip()
    # Compile only the audited client. Makefile targets, generators, and h2specd
    # are not part of CI setup, and the pinned module files stay read-only.
    inputs = {name: sha(h2_root / name) for name in ["go.mod", "go.sum"]}
    subprocess.run(["go", "build", "-mod=readonly", "-trimpath", "-ldflags", f"-X main.VERSION=2.6.0 -X main.COMMIT={H2_REVISION}", "-o", str(h2spec), "./cmd/h2spec"], cwd=h2_root, env=env, check=True, timeout=300)
    assert all(sha(h2_root / name) == digest for name, digest in inputs.items())
    assert subprocess.check_output([str(h2spec), "--version"], text=True).strip() == f"Version: 2.6.0 ({H2_REVISION})"
    receipt = {
        "zig_version": ZIG_VERSION, "zig_target": target, "zig_archive_sha256": zig_digest,
        "zig_binary": str(zig.relative_to(destination)), "zig_sha256": sha(zig),
        "h2spec_revision": H2_REVISION, "h2spec_source_sha256": H2_ARCHIVE_SHA,
        "h2spec_binary": str(h2spec.relative_to(destination)), "h2spec_sha256": sha(h2spec),
        "h2spec_module_inputs": inputs, "go_version": go_version,
    }
    (destination / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    if args.export_github_path:
        assert os.environ.get("GITHUB_ACTIONS") == "true"
        path_file = Path(os.environ["GITHUB_PATH"])
        assert path_file.resolve().is_relative_to(Path(os.environ["RUNNER_TEMP"]).resolve())
        assert path_file.name.startswith("add_path_") and path_file.is_file() and not path_file.is_symlink()
        with path_file.open("a") as output:
            for path in [zig_root, executable_dir]:
                assert "\n" not in str(path) and "\r" not in str(path)
                output.write(str(path) + "\n")
    print(json.dumps(receipt), flush=True)


if __name__ == "__main__":
    main()
