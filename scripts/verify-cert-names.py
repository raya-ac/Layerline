#!/usr/bin/env python3
"""Check listener certificate names using real PEM files and the CLI."""
from pathlib import Path
import socket
import subprocess
import sys
import tempfile


BINARY = Path(sys.argv[1]).resolve(strict=True)


def certificate(folder, label, san=None, expired=False):
    path = folder / (label + ".pem")
    command = ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
               "-nodes", "-keyout", str(folder / "discard.key"), "-out", str(path),
               "-days", "1", "-subj", f"/CN={label}.example.test"]
    if san:
        command += ["-addext", "subjectAltName=" + san]
    subprocess.run(command, check=True, capture_output=True, timeout=10)
    if expired:
        key, request, config = (folder / name for name in ("discard.key", "expired.req", "ca.conf"))
        (folder / "serial").write_text("01\n")
        (folder / "index").touch()
        config.write_text(f"""[ca]
default_ca = test
[test]
database = {folder / 'index'}
serial = {folder / 'serial'}
new_certs_dir = {folder}
default_md = sha256
policy = subject
x509_extensions = leaf
[subject]
commonName = supplied
[leaf]
subjectAltName = {san}
""")
        subprocess.run(["openssl", "req", "-new", "-key", str(key), "-out", str(request),
                        "-subj", f"/CN={label}.example.test"], check=True, capture_output=True, timeout=10)
        stale = folder / "stale.pem"
        subprocess.run(["openssl", "ca", "-selfsign", "-batch", "-notext", "-config", str(config),
                        "-keyfile", str(key), "-cert", str(path), "-in", str(request), "-out", str(stale),
                        "-startdate", "20000101000000Z", "-enddate", "20000102000000Z"],
                       check=True, capture_output=True, timeout=10)
        path = stale
    (folder / "discard.key").unlink()
    return path


def check(file, settings, port, *expected, success=False):
    file.write_text(f"host = 127.0.0.1\nport = {port}\ntls = true\n" + settings)
    run = subprocess.run([str(BINARY), "--config", str(file), "--check-cert-names"],
                         capture_output=True, text=True, timeout=10)
    assert (run.returncode == 0) == success, run.stderr
    for line in expected:
        assert line in run.stderr.splitlines(), run.stderr
    assert "server.ready" not in run.stderr


def main():
    with tempfile.TemporaryDirectory(prefix="ll-cert-names-") as temporary, socket.socket() as occupied:
        folder = Path(temporary)
        occupied.bind(("127.0.0.1", 0))
        occupied.listen()
        port = occupied.getsockname()[1]
        fallback = certificate(folder, "fallback", "DNS:site.example.test,IP:127.0.0.1,IP:::1")
        wildcard = certificate(folder, "wildcard", "DNS:*.example.test")
        common_name_only = certificate(folder, "common")
        config = folder / "server.conf"
        setup = f"""tls_cert = {fallback}
tls_key = {folder / 'unused.key'}
server = fallback
server_name.fallback = site.example.test
server = wild
server_name.wild = *.example.test
server_tls_cert.wild = {wildcard}
server_tls_key.wild = {folder / 'unused.key'}
server = fallback_default
server_name.fallback_default = _
"""
        check(config, setup, port,
              'ok: certificate name="site.example.test"',
              'ok: certificate name="*.example.test" (one label only)',
              "certificate names: checked=2 failed=0", success=True)
        check(config, setup + f"""server = addresses
server_name.addresses = 127.0.0.1 [::1]
server_tls_cert.addresses = {wildcard}
server_tls_key.addresses = {folder / 'unused.key'}
""", port, 'ok: certificate name="127.0.0.1"', 'ok: certificate name="[::1]"',
              "certificate names: checked=4 failed=0", success=True)
        check(config, setup + f"""server = exact
server_name.exact = api.example.test
server_tls_cert.exact = {fallback}
server_tls_key.exact = {folder / 'unused.key'}
server = deeper
server_name.deeper = a.b.example.test
server_tls_cert.deeper = {wildcard}
server_tls_key.deeper = {folder / 'unused.key'}
server = common
server_name.common = common.example.test
server_tls_cert.common = {common_name_only}
server_tls_key.common = {folder / 'unused.key'}
""", port, 'fail: certificate name="api.example.test" error=CertificateHostMismatch',
              'fail: certificate name="a.b.example.test" error=CertificateHostMismatch',
              'fail: certificate name="common.example.test" error=CertificateHostMismatch',
              "certificate names: checked=5 failed=3")
        check(config, f"""server = wild
server_name.wild = *.example.test
server_tls_cert.wild = {fallback}
server_tls_key.wild = {folder / 'unused.key'}
""", port, 'fail: certificate name="*.example.test" error=CertificateHostMismatch')
        check(config, "server = single\nserver_name.single = site.example.test\n", port,
              'fail: certificate name="site.example.test" error=NoConfiguredCertificate')
        check(config, "server = catch_all\nserver_name.catch_all = _\n", port,
              "fail: no named TLS sites to check (catch-all names are skipped)")
        expired = certificate(folder, "expired", "DNS:expired.example.test", expired=True)
        check(config, f"""server = expired
server_name.expired = expired.example.test
server_tls_cert.expired = {expired}
server_tls_key.expired = {folder / 'unused.key'}
""", port, 'fail: certificate name="expired.example.test" error=CertificateExpired')
    print("ok: listener certificate names, fallback, wildcard, exact overrides and read-only CLI", flush=True)


if __name__ == "__main__":
    main()
