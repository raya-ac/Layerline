#!/usr/bin/env python3
"""Run native checks and retain exact-input evidence, including failed runs."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import ssl
import stat
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]


def sha(path):
    with Path(path).open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def require_curl_features(version, platform):
    features = next((line.split()[1:] for line in version.splitlines() if line.startswith("Features:")), [])
    assert "HTTP2" in features, "independent curl client lacks HTTP/2"
    if platform == "darwin":
        assert "HTTP3" in features, "macOS CI must exercise the independent HTTP/3 client"


def sources():
    result = {}
    names = subprocess.check_output(["git", "ls-files", "-z"], cwd=ROOT).decode().split("\0")
    for name in filter(None, names):
        path = ROOT / name
        if Path(name).is_absolute() or ".." in Path(name).parts or path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(ROOT):
            raise ValueError("tracked source is not a contained regular file")
        result[name] = sha(path)
    return result


def record_run(name, command, output, checks, env=None):
    print("running:", name, flush=True)
    start = time.monotonic()
    log = output / (name + ".log")
    with log.open("xb") as handle:
        result = subprocess.run(command, cwd=ROOT, stdout=handle, stderr=handle, env=env)
    checks[name] = {"command": command, "exit": result.returncode, "seconds": time.monotonic() - start, "log_sha256": sha(log)}
    if result.returncode:
        raise subprocess.CalledProcessError(result.returncode, command)


def copy_evidence(source, target):
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise ValueError("evidence is not a regular file")
        data = handle.read(8 * 1024 * 1024 + 1)
    if len(data) > 8 * 1024 * 1024:
        raise ValueError("evidence exceeds its file bound")
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("xb") as handle:
        handle.write(data)


def collect_h2(runtime_log, output, server_hash, tester_hash):
    matches = re.findall(r"^evidence: (/tmp/layerline-h2spec-[A-Za-z0-9_\-]+)$", runtime_log.read_text(), re.M)
    if len(matches) != 1:
        raise ValueError("runtime did not produce exactly one independent H2 receipt")
    folder = Path(matches[0])
    if folder.is_symlink() or folder.resolve().parent != Path("/tmp").resolve():
        raise ValueError("H2 evidence is outside the fixture temporary root")
    # Keep raw reports, but never publish the fixture's disposable private keys.
    for relative in ["receipt.json", *[f"{transport}/{name}" for transport in ["plain", "tls"] for name in ["h2spec.log", "junit.xml", "server.log"]]]:
        parent = (folder / relative).parent
        if parent.is_symlink() or not parent.resolve().is_relative_to(folder.resolve()):
            raise ValueError("H2 evidence parent escaped its fixture")
        copy_evidence(folder / relative, output / "h2" / relative)
    receipt = json.loads((output / "h2/receipt.json").read_text())
    assert receipt["server_sha256"] == server_hash and receipt["tester_sha256"] == tester_hash
    tls, plain = receipt["transports"]["tls"], receipt["transports"]["plain"]
    assert tls["tests"] == 147 and tls["exit"] == tls["failures"] == tls["errors"] == tls["skipped"] == 0
    assert plain["tests"] == 147 and plain["skipped"] == 0
    if plain["exit"] or plain["failures"] or plain["errors"]:
        failures = plain["failures_detail"]
        assert plain["failures"] + plain["errors"] == 1 and plain["qualified_cleartext_exception"]
        assert len(failures) == 1 and failures[0]["section"] == "http2/3.5" and failures[0]["case"] == "Sends invalid connection preface"
        assert plain["invalid_text_http1_status"] == 400 and tls["invalid_preface_case_passed"]
    for transport in ["plain", "tls"]:
        assert receipt["transports"][transport]["report_sha256"] == sha(output / "h2" / transport / "junit.xml")
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["Debug", "ReleaseFast"], required=True)
    parser.add_argument("--tools", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(mode=0o700)
    tools = args.tools.resolve()
    prepared = json.loads((tools / "receipt.json").read_text())
    paths = {}
    for tool in ["zig", "h2spec"]:
        name = prepared[tool + "_binary"]
        path = tools / name
        assert not Path(name).is_absolute() and ".." not in Path(name).parts
        assert path.is_file() and not path.is_symlink() and path.resolve().is_relative_to(tools)
        assert sha(path) == prepared[tool + "_sha256"]
        paths[tool] = str(path)
    assert prepared["zig_version"] == "0.16.0" and prepared["h2spec_revision"] == "af83a65f0b6273ef38bf778d400d98892e7653d8"
    assert not subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], cwd=ROOT).strip()
    before = sources()
    revision = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    copy_evidence(tools / "receipt.json", output / "tools.json")
    checks, errors, artifacts = {}, [], {}
    receipt = {"revision": revision, "mode": args.mode, "sources": before, "checks": checks, "errors": errors, "artifacts": artifacts,
               "python": sys.version, "python_ssl": ssl.OPENSSL_VERSION, "status": "failed",
               "scope": "hosted native unit/wire checks; not production activation, full PKIX, RFC9113 or HTTP3 acceptance"}
    try:
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        receipt["nofile_before"] = [soft, hard]
        assert hard == resource.RLIM_INFINITY or hard >= 8192, "CI requires a raisable nofile limit of 8192"
        if soft != resource.RLIM_INFINITY and soft < 8192:
            resource.setrlimit(resource.RLIMIT_NOFILE, (8192, hard))
        receipt["nofile_after"] = list(resource.getrlimit(resource.RLIMIT_NOFILE))
        curl = subprocess.check_output(["curl", "--version"], text=True)
        require_curl_features(curl, sys.platform)
        receipt["curl"] = curl
        receipt["openssl"] = subprocess.check_output(["openssl", "version"], text=True).strip()
        for script in (ROOT / "scripts").glob("*.py"):
            compile(script.read_text(), str(script), "exec")
        record_run("ci-tests", [sys.executable, "scripts/test-ci-tools.py", "-v"], output, checks)
        record_run("deadline-fixture-tests", [sys.executable, "scripts/test-deadline-fixture.py", "-v"], output, checks)
        record_run("format", [paths["zig"], "fmt", "--check", "build.zig", "src"], output, checks)
        record_run("shell-syntax", ["bash", "-n", "scripts/verify-layerline.sh"], output, checks)
        record_run("units", [paths["zig"], "build", "test", "-Doptimize=" + args.mode, "--summary", "all", "-j2"], output, checks)
        if args.mode == "Debug":
            record_run("safe-units", [paths["zig"], "build", "test", "-Doptimize=ReleaseSafe", "--summary", "all", "-j2"], output, checks)
        server = output / "server"
        helper = output / "test-tools"
        record_run("build", [paths["zig"], "build", "-Doptimize=" + args.mode, "--prefix", str(server), "-j2"], output, checks)
        record_run("build-helper", [paths["zig"], "build", "test-tools", "-Doptimize=ReleaseFast", "--prefix", str(helper), "-j2"], output, checks)
        binary, child = server / "bin/layerline", helper / "bin/child-process-worker"
        artifacts.update(server=sha(binary), child_worker=sha(child))
        env = {**os.environ, "LAYERLINE_VERIFY_BINARY": str(binary), "LAYERLINE_CHILD_WORKER": str(child), "LAYERLINE_H2SPEC": paths["h2spec"]}
        record_run("runtime", ["bash", "scripts/verify-layerline.sh"], output, checks, env)
        collect_h2(output / "runtime.log", output, artifacts["server"], prepared["h2spec_sha256"])
        receipt["status"] = "passed"
    except Exception as error:
        errors.append({"type": type(error).__name__, "message": str(error)})
    finally:
        try:
            assert sources() == before, "tracked source changed during verification"
            assert all(sha(Path(paths[name])) == prepared[name + "_sha256"] for name in paths)
            if artifacts:
                assert sha(output / "server/bin/layerline") == artifacts["server"]
                assert sha(output / "test-tools/bin/child-process-worker") == artifacts["child_worker"]
            if (output / "runtime.log").exists() and not (output / "h2").exists():
                collect_h2(output / "runtime.log", output, artifacts["server"], prepared["h2spec_sha256"])
        except Exception as error:
            errors.append({"type": type(error).__name__, "message": str(error)})
        if errors:
            receipt["status"] = "failed"
        receipt["evidence"] = {str(path.relative_to(output)): sha(path) for path in output.rglob("*") if path.is_file() and not path.is_symlink()}
        (output / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
        print(json.dumps({"revision": revision, "status": receipt["status"], "checks": checks, "errors": errors}), flush=True)
    return 0 if receipt["status"] == "passed" else 1


if __name__ == "__main__":
    sys.exit(main())
