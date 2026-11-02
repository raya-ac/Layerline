#!/usr/bin/env python3
"""Offline checks that OpenSSL failure diagnostics never become acceptance."""
import ast
import contextlib
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

source = Path(__file__).with_name("verify-https-upstreams.py")
nodes = [node for node in ast.parse(source.read_text()).body if isinstance(node, ast.FunctionDef) and node.name in ["wait_bytes", "openssl_failure_details"]]


class HTTPSFixtureTests(unittest.TestCase):
    def load(self, timeout=False):
        ticks = iter([0, 5]) if timeout else iter([0])
        namespace = {"time": mock.Mock(monotonic=lambda: next(ticks)), "hashlib": hashlib,
                     "contextlib": contextlib, "json": json, "sys": sys}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), str(source), "exec"), namespace)
        return namespace

    def test_exact_application_marker_still_passes(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "openssl.stdout"
            path.write_bytes(b"before\napplication bytes\nafter\n")
            self.load()["wait_bytes"](path, b"application bytes\n")

    def test_console_noise_is_reported_but_never_accepted(self):
        marker = b"client payload\n"
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "openssl.stdout"
            path.write_bytes(marker[:5] + b"Read BLOCK\n" + marker[5:])
            with self.assertRaises(AssertionError) as caught:
                self.load(timeout=True)["wait_bytes"](path, marker)
            details = caught.exception.args[0][1]
            self.assertEqual(details["observed_count"], 0)
            self.assertEqual(details["count_without_console_read_block"], 1)
            self.assertEqual(details["marker_sha256"], hashlib.sha256(marker).hexdigest())

    def test_missing_marker_reports_bounded_identity_not_the_payload(self):
        marker = b"x" * 32768
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "openssl.stdout"
            path.write_bytes(b"wrong bytes")
            with self.assertRaises(AssertionError) as caught:
                self.load(timeout=True)["wait_bytes"](path, marker)
            self.assertLess(len(str(caught.exception)), 700)
            self.assertEqual(caught.exception.args[0][1]["count_without_console_read_block"], 0)

    def test_file_read_has_a_limit_before_allocating_the_output(self):
        sizes = []

        class Reader:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def read(self, size=-1):
                assert 0 < size <= 4 * 1024 * 1024 + 1
                sizes.append(size)
                return b"x" * size

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "openssl.stdout"
            path.touch()
            with mock.patch.object(Path, "open", return_value=Reader()):
                with self.assertRaisesRegex(AssertionError, "unbounded OpenSSL"):
                    self.load()["wait_bytes"](path, b"not present")
        self.assertEqual(sizes, [4 * 1024 * 1024 + 1])

    def test_diagnostic_lines_are_bounded_and_escape_terminal_controls(self):
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            for name in ["openssl.stdout", "openssl.stderr", "openssl.trace"]:
                (folder / name).write_bytes((b"\x1b[31mfixture\0\n" * 10000) + b"z" * 40000)
            captured = io.StringIO()
            with contextlib.redirect_stderr(captured):
                self.load()["openssl_failure_details"](folder, mock.Mock(poll=lambda: None))
            output = captured.getvalue()
            self.assertNotIn("\x1b", output)
            self.assertNotIn("\0", output)
            self.assertLess(len(output), 32768)
            records = [json.loads(line.split(": ", 1)[1]) for line in output.splitlines() if line.startswith("OpenSSL fixture output:")]
            self.assertEqual(len(records), 3)
            for record in records:
                self.assertLessEqual(record["tail_bytes"], 65536)
                self.assertLessEqual(len(record["last_lines"]), 32)


if __name__ == "__main__":
    unittest.main()
