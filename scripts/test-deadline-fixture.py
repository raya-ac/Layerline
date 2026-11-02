#!/usr/bin/env python3
"""Offline checks for a late writer observing a required terminal GOAWAY."""
import ast
import contextlib
import io
from pathlib import Path
import sys
import unittest
from unittest import mock

source = Path(__file__).with_name("verify-deadlines.py")
tree = ast.parse(source.read_text())
helper = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "slow_header_deadline")


class Clock:
    def __init__(self, delays):
        self.now = 0
        self.delays = iter(delays)

    def monotonic(self):
        return self.now

    def sleep(self, _):
        self.now += next(self.delays)


class Peer:
    def __init__(self, clock, failure=None, fail_at=4, code=11, read_error=None, received_at=.5):
        self.conn = self
        self.clock = clock
        self.failure = failure
        self.fail_at = fail_at
        self.code = code
        self.read_error = read_error
        self.received_at = received_at
        self.sent = []
        self.reads = 0

    def sendall(self, data):
        self.sent.append(data)
        if self.failure and len(self.sent) == self.fail_at:
            raise self.failure

    def until(self, predicate):
        self.reads += 1
        if self.read_error:
            raise self.read_error
        self.clock.now = max(self.clock.now, self.received_at)
        item = (7, 0, 0, b"\0" * 4 + self.code.to_bytes(4, "big"))
        assert predicate(item)
        return [item]


class DeadlineFixtureTests(unittest.TestCase):
    def run_probe(self, clock, peer):
        namespace = {"time": clock}
        exec(compile(ast.Module(body=[helper], type_ignores=[]), str(source), "exec"), namespace)
        namespace["slow_header_deadline"](peer, b"initial", [b"one", b"two", b"three"], "original deadline")

    def test_ordinary_trickle_still_requires_the_terminal_frame(self):
        clock = Clock([.15, .15, .15])
        peer = Peer(clock)
        self.run_probe(clock, peer)
        self.assertEqual(peer.sent, [b"initial", b"one", b"two", b"three"])
        self.assertEqual(peer.reads, 1)

    def test_raw_ciphertext_writer_does_not_encrypt_fragments_again(self):
        clock = Clock([.15, .15, .4])
        peer = Peer(clock)
        raw = Peer(clock, failure=BrokenPipeError())
        namespace = {"time": clock}
        exec(compile(ast.Module(body=[helper], type_ignores=[]), str(source), "exec"), namespace)
        namespace["slow_header_deadline"](peer, b"initial", [b"one", b"two", b"three"], "original deadline", writer=raw)
        self.assertEqual(peer.sent, [])
        self.assertEqual(raw.sent, [b"initial", b"one", b"two", b"three"])
        self.assertEqual(peer.reads, 1)

    def test_late_broken_pipe_reads_goaway_instead_of_accepting_the_write_error(self):
        clock = Clock([.15, .15, .4])
        peer = Peer(clock, failure=BrokenPipeError())
        self.run_probe(clock, peer)
        self.assertEqual(peer.reads, 1)
        self.assertLess(clock.now, .9)

    def test_premature_close_remains_a_failure(self):
        clock = Clock([.15])
        peer = Peer(clock, failure=BrokenPipeError(), fail_at=2)
        with self.assertRaisesRegex(AssertionError, "before its original budget"):
            self.run_probe(clock, peer)
        self.assertEqual(peer.reads, 0)

    def test_wrong_goaway_code_is_not_hidden_by_a_late_write_failure(self):
        clock = Clock([.15, .15, .4])
        peer = Peer(clock, failure=BrokenPipeError(), code=1)
        with self.assertRaisesRegex(AssertionError, "original deadline"):
            self.run_probe(clock, peer)

    def test_missing_goaway_and_unrelated_transport_errors_still_fail(self):
        for error in [EOFError(), TimeoutError()]:
            clock = Clock([.15, .15, .4])
            peer = Peer(clock, failure=BrokenPipeError(), read_error=error)
            with self.assertRaises(type(error)):
                self.run_probe(clock, peer)
        clock = Clock([.15])
        peer = Peer(clock, failure=ConnectionResetError(), fail_at=2)
        with self.assertRaises(ConnectionResetError):
            self.run_probe(clock, peer)

    def test_late_goaway_does_not_extend_the_original_upper_bound(self):
        clock = Clock([.15, .15, .15])
        peer = Peer(clock, received_at=.95)
        with self.assertRaisesRegex(AssertionError, "original deadline"):
            self.run_probe(clock, peer)


class FailureEvidenceTests(unittest.TestCase):
    def load(self, name):
        node = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == name)
        namespace = {"time": mock.Mock(monotonic=lambda: .6), "sys": sys}
        exec(compile(ast.Module(body=[node], type_ignores=[]), str(source), "exec"), namespace)
        return namespace[name]

    def test_truncated_reads_still_fail_with_exact_byte_counts(self):
        peer = mock.Mock(recv=mock.Mock(side_effect=[b"abc", b""]))
        with self.assertRaises(EOFError) as caught:
            self.load("exact")(peer, 9)
        self.assertEqual(caught.exception.args[1], {"wanted": 9, "received": 3})

    def test_complete_fragmented_reads_are_unchanged(self):
        peer = mock.Mock(recv=mock.Mock(side_effect=[b"abc", b"def"]))
        self.assertEqual(self.load("exact")(peer, 6), b"abcdef")

    def test_failure_context_is_bounded_and_contains_no_application_bytes(self):
        peer = mock.Mock(timeline=[((0, 0, number, b"private fake payload\n" * 32768), .1) for number in range(20)])
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            self.load("transfer_failure_details")(peer, 0, 16384, True)
        self.assertNotIn("private fake payload", output.getvalue())
        self.assertEqual(output.getvalue().count("'kind':"), 8)
        self.assertIn("'complete_data_bytes': 16384", output.getvalue())
        self.assertIn("'seconds': 0.6", output.getvalue())
        self.assertLess(len(output.getvalue()), 2000)


if __name__ == "__main__":
    unittest.main()
