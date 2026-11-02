#!/usr/bin/env python3
"""Keep incomplete overload responses a failure, with bounded wire evidence."""
import ast
import hashlib
from pathlib import Path
import unittest

source = Path(__file__).with_name("verify-memory-budgets.py")
helper = next(node for node in ast.parse(source.read_text()).body
              if isinstance(node, ast.FunctionDef) and node.name == "overloaded")
namespace = {"hashlib": hashlib}
exec(compile(ast.Module(body=[helper], type_ignores=[]), str(source), "exec"), namespace)
overloaded = namespace["overloaded"]
HEAD = b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 12\r\nRetry-After: 1\r\n\r\n"
BODY = b"server busy\n"


class MemoryFixtureTests(unittest.TestCase):
    def test_complete_get_and_header_only_head_are_required(self):
        overloaded(HEAD + BODY)
        overloaded(HEAD, head_only=True)
        for output, head_only in [(HEAD, False), (HEAD + BODY, True)]:
            with self.assertRaises(AssertionError):
                overloaded(output, head_only=head_only)

    def test_missing_or_partial_headers_keep_exact_bounded_diagnostics(self):
        for output in [b"", HEAD[:20], b"\x1b\0" + b"x" * 32768]:
            with self.assertRaises(AssertionError) as caught:
                overloaded(output, head_only=True)
            label, details = caught.exception.args[0]
            self.assertEqual(label, "incomplete overload response")
            self.assertEqual(details, {
                "bytes": len(output), "sha256": hashlib.sha256(output).hexdigest(),
                "prefix_hex": output[:64].hex(), "head_only": True,
            })
            self.assertLess(len(str(caught.exception)), 400)
            self.assertNotIn("\x1b", str(caught.exception))

    def test_incorrect_status_length_and_retry_after_still_fail(self):
        for original, replacement in [(b"503", b"200"), (b"Length: 12", b"Length: 99"),
                                      (b"Retry-After: 1", b"Retry-After: 9")]:
            with self.assertRaises(AssertionError):
                overloaded(HEAD.replace(original, replacement) + BODY)

    def test_duplicate_final_and_surplus_body_bytes_still_fail(self):
        for output in [HEAD + BODY + HEAD + BODY, HEAD + BODY + b"x"]:
            with self.assertRaises(AssertionError):
                overloaded(output)


if __name__ == "__main__":
    unittest.main()
