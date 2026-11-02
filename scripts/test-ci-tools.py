#!/usr/bin/env python3
"""Offline tests for CI archive admission, failure propagation and evidence."""
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


def module(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), Path(__file__).with_name(name + ".py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


tools, verify = module("ci-tools"), module("ci-verify")


class ToolChecks(unittest.TestCase):
    def test_download_checks_hash_and_size_before_use(self):
        payload = b"download fixture"
        opener = SimpleNamespace(open=lambda *a, **k: io.BytesIO(payload))
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(tools.urllib.request, "build_opener", return_value=opener):
            folder = Path(temporary)
            tools.download("https://example.invalid/tool", folder / "good", hashlib.sha256(payload).hexdigest(), 100)
            self.assertEqual((folder / "good").read_bytes(), payload)
            with self.assertRaisesRegex(ValueError, "checksum"):
                tools.download("https://example.invalid/tool", folder / "bad-hash", "0" * 64, 100)
            with self.assertRaisesRegex(ValueError, "size or time"):
                tools.download("https://example.invalid/tool", folder / "too-large", "0" * 64, 3)

    def test_download_refuses_http_and_downgrades(self):
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            tools.download("http://example.invalid/tool", Path("unused"), "0" * 64, 10)
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            tools.HttpsRedirects().redirect_request(None, None, 302, "redirect", {}, "http://example.invalid/tool")

    def archive(self, folder, name, kind=tarfile.REGTYPE, link=""):
        path = folder / "input.tar"
        with tarfile.open(path, "w") as output:
            member = tarfile.TarInfo(name)
            member.type, member.linkname, member.mode = kind, link, 0o755
            payload = b"tool fixture" if kind == tarfile.REGTYPE else b""
            member.size = len(payload)
            output.addfile(member, io.BytesIO(payload))
        return path

    def test_archive_retains_only_contained_regular_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            archive = self.archive(folder, "fixture/zig")
            target = folder / "output"
            target.mkdir()
            result = tools.extract(archive, target, "fixture")
            self.assertEqual((result / "zig").read_bytes(), b"tool fixture")
            self.assertTrue((result / "zig").stat().st_mode & 0o100)

    def test_archive_refuses_traversal_links_and_special_files(self):
        for name, kind, link in [
            ("/tmp/escape", tarfile.REGTYPE, ""), ("fixture/../escape", tarfile.REGTYPE, ""),
            ("other/zig", tarfile.REGTYPE, ""), ("fixture/zig", tarfile.SYMTYPE, "/tmp/escape"),
            ("fixture/zig", tarfile.LNKTYPE, "fixture/other"), ("fixture/device", tarfile.CHRTYPE, ""),
        ]:
            with self.subTest(name=name, kind=kind), tempfile.TemporaryDirectory() as temporary:
                folder = Path(temporary)
                archive = self.archive(folder, name, kind, link)
                target = folder / "output"
                target.mkdir()
                with self.assertRaisesRegex(ValueError, "unsafe"):
                    tools.extract(archive, target, "fixture")
                self.assertFalse(list(target.iterdir()))

    def test_failed_command_records_nonzero_and_cannot_continue(self):
        with tempfile.TemporaryDirectory() as temporary, mock.patch.object(verify.subprocess, "run", return_value=subprocess.CompletedProcess(["fake"], 7)):
            checks = {}
            with self.assertRaises(subprocess.CalledProcessError) as observed:
                verify.record_run("negative", ["fake"], Path(temporary), checks)
            self.assertEqual(observed.exception.returncode, 7)
            self.assertEqual(checks["negative"]["exit"], 7)
            self.assertEqual(checks["negative"]["log_sha256"], hashlib.sha256(b"").hexdigest())

    def test_evidence_refuses_symlinks_and_oversized_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            original, target = folder / "source", folder / "output"
            original.write_bytes(b"fixture")
            linked = folder / "link"
            linked.symlink_to(original)
            with self.assertRaises(OSError):
                verify.copy_evidence(linked, target)
            with original.open("wb") as output:
                output.truncate(8 * 1024 * 1024 + 1)
            with self.assertRaisesRegex(ValueError, "bound"):
                verify.copy_evidence(original, target)
            self.assertFalse(target.exists())

    def h2_fixture(self, folder, wrong_case=False):
        for transport in ["plain", "tls"]:
            target = folder / transport
            target.mkdir()
            for name in ["junit.xml", "h2spec.log", "server.log", "key.pem"]:
                (target / name).write_text("disposable fixture " + name)
        report_hash = {transport: verify.sha(folder / transport / "junit.xml") for transport in ["plain", "tls"]}
        receipt = {"server_sha256": "1" * 64, "tester_sha256": "2" * 64, "transports": {
            "tls": {"tests": 147, "exit": 0, "failures": 0, "errors": 0, "skipped": 0, "invalid_preface_case_passed": True, "report_sha256": report_hash["tls"]},
            "plain": {"tests": 147, "exit": 1, "failures": 0, "errors": 1, "skipped": 0, "qualified_cleartext_exception": "explicit shared-listener exception", "invalid_text_http1_status": 400, "report_sha256": report_hash["plain"],
                      "failures_detail": [{"section": "http2/5.1" if wrong_case else "http2/3.5", "case": "Sends invalid connection preface"}]},
        }}
        (folder / "receipt.json").write_text(json.dumps(receipt))

    def test_h2_evidence_preserves_raw_failure_but_never_private_keys(self):
        with tempfile.TemporaryDirectory(prefix="layerline-h2spec-", dir="/tmp") as temporary, tempfile.TemporaryDirectory() as output:
            folder, destination = Path(temporary), Path(output)
            self.h2_fixture(folder)
            runtime = destination / "runtime.log"
            runtime.write_text("evidence: " + str(folder) + "\n")
            receipt = verify.collect_h2(runtime, destination, "1" * 64, "2" * 64)
            self.assertEqual(receipt["transports"]["plain"]["errors"], 1)
            self.assertFalse(list((destination / "h2").rglob("*.pem")))
            self.assertEqual(len(list((destination / "h2").rglob("*.*"))), 7)

    def test_h2_qualification_cannot_hide_an_unrelated_failure(self):
        with tempfile.TemporaryDirectory(prefix="layerline-h2spec-", dir="/tmp") as temporary, tempfile.TemporaryDirectory() as output:
            folder, destination = Path(temporary), Path(output)
            self.h2_fixture(folder, wrong_case=True)
            runtime = destination / "runtime.log"
            runtime.write_text("evidence: " + str(folder) + "\n")
            with self.assertRaises(AssertionError):
                verify.collect_h2(runtime, destination, "1" * 64, "2" * 64)
            self.assertTrue((destination / "h2/plain/junit.xml").is_file())

    def test_h2_receipt_must_match_its_actual_report(self):
        with tempfile.TemporaryDirectory(prefix="layerline-h2spec-", dir="/tmp") as temporary, tempfile.TemporaryDirectory() as output:
            folder, destination = Path(temporary), Path(output)
            self.h2_fixture(folder)
            (folder / "tls/junit.xml").write_text("changed report")
            runtime = destination / "runtime.log"
            runtime.write_text("evidence: " + str(folder) + "\n")
            with self.assertRaises(AssertionError):
                verify.collect_h2(runtime, destination, "1" * 64, "2" * 64)


if __name__ == "__main__":
    unittest.main()
