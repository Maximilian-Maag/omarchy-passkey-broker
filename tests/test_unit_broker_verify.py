#!/usr/bin/env python3
"""Unit tests for the user-verification gate.

The three outcomes are tested separately because collapsing them is the bug that matters: a
"declined" that reads as "unavailable" (or vice versa) would either lock the owner out or —
worse — let an unverified assertion through. No real sensor is touched; the runner is injected.
"""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "bin"))
import broker_verify  # noqa: E402
from broker_verify import FprintdVerifier, NullVerifier  # noqa: E402


class Runner:
    """Records the command and returns a canned (rc, out, err)."""

    def __init__(self, rc, out="", err=""):
        self.rc, self.out, self.err = rc, out, err
        self.cmd = None

    def __call__(self, cmd):
        self.cmd = cmd
        return self.rc, self.out, self.err


class FprintdStates(unittest.TestCase):
    def setUp(self):
        self._which = broker_verify.shutil.which
        broker_verify.shutil.which = lambda name: "/usr/bin/" + name

    def tearDown(self):
        broker_verify.shutil.which = self._which

    def test_pass_is_verified(self):
        v = FprintdVerifier(username="mmaag", runner=Runner(0, "verify-match"))
        r = v.verify()
        self.assertTrue(r.ok)
        self.assertEqual(r.state, "verified")

    def test_exit_one_is_declined(self):
        v = FprintdVerifier(username="mmaag", runner=Runner(1, "", "verify-no-match"))
        r = v.verify()
        self.assertFalse(r.ok)
        self.assertEqual(r.state, "declined")

    def test_other_exit_is_unavailable(self):
        v = FprintdVerifier(runner=Runner(2, "", "no device"))
        r = v.verify()
        self.assertFalse(r.ok)
        self.assertEqual(r.state, "unavailable")

    def test_username_in_command(self):
        runner = Runner(0)
        FprintdVerifier(username="alice", runner=runner).verify()
        self.assertEqual(runner.cmd, ["fprintd-verify", "alice"])

    def test_no_username_omits_arg(self):
        runner = Runner(0)
        FprintdVerifier(runner=runner).verify()
        self.assertEqual(runner.cmd, ["fprintd-verify"])

    def test_unavailable_when_binary_absent(self):
        broker_verify.shutil.which = lambda name: None
        runner = Runner(0)
        r = FprintdVerifier(runner=runner).verify()
        self.assertFalse(r.ok)
        self.assertEqual(r.state, "unavailable")
        self.assertIsNone(runner.cmd)          # never invoked when the tool is missing


class ResultShape(unittest.TestCase):
    def test_as_dict(self):
        r = FprintdVerifier(runner=Runner(1)).verify()
        self.assertEqual(r.as_dict(), {"ok": False, "state": "declined", "detail": ""})

    def test_repr_mentions_state(self):
        self.assertIn("verified", repr(NullVerifier(True).verify()))


class NullVerifierTests(unittest.TestCase):
    def test_ok_true(self):
        r = NullVerifier(True).verify()
        self.assertTrue(r.ok)
        self.assertEqual(r.state, "verified")

    def test_ok_false(self):
        r = NullVerifier(False).verify()
        self.assertFalse(r.ok)
        self.assertEqual(r.state, "declined")

    def test_available(self):
        self.assertTrue(NullVerifier().available())


class DefaultRunner(unittest.TestCase):
    """The default runner is the one that shells out; test its error handling by patching the
    subprocess call rather than running fprintd for real."""

    def setUp(self):
        self._run = broker_verify.subprocess.run

    def tearDown(self):
        broker_verify.subprocess.run = self._run

    def test_nonzero_exit_code_propagates(self):
        def fake(cmd, **kwargs):
            class P:
                returncode = 3
                stdout = ""
                stderr = "boom"
            return P()
        broker_verify.subprocess.run = fake
        broker_verify.shutil.which = lambda name: "/usr/bin/" + name
        r = FprintdVerifier(timeout=5).verify()
        self.assertEqual(r.state, "unavailable")
        self.assertIn("boom", r.detail)

    def test_oserror_is_unavailable(self):
        def fake(cmd, **kwargs):
            raise OSError("no such file")
        broker_verify.subprocess.run = fake
        broker_verify.shutil.which = lambda name: "/usr/bin/" + name
        r = FprintdVerifier().verify()
        self.assertFalse(r.ok)
        self.assertEqual(r.state, "unavailable")

    def test_text_and_capture_output_and_timeout_are_passed(self):
        """The default runner must ask subprocess for decoded text and a captured pipe, and
        honour the configured timeout — otherwise fprintd's output arrives as bytes and the
        match is parsed from garbage."""
        seen = {}

        def fake(cmd, **kwargs):
            seen.update(kwargs)

            class P:
                returncode = 0
                stdout = "MATCH"
                stderr = ""
            return P()

        broker_verify.subprocess.run = fake
        broker_verify.shutil.which = lambda name: "/usr/bin/" + name
        r = FprintdVerifier(timeout=7).verify()
        self.assertTrue(seen["text"])
        self.assertTrue(seen["capture_output"])
        self.assertEqual(seen["timeout"], 7)
        self.assertEqual(r.detail, "MATCH")     # the match detail is surfaced, not dropped


if __name__ == "__main__":
    unittest.main()
