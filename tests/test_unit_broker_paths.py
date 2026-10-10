#!/usr/bin/env python3
"""Unit tests for state paths.

The point of these is isolation: if ``state_dir`` ever stops honouring ``XDG_STATE_HOME``, a
test (or a stray run) would read and write the user's REAL credential store. That is the kind
of bug worth a test rather than a careful habit.
"""
import os
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "bin"))
import broker_paths  # noqa: E402


class StateDir(unittest.TestCase):
    def setUp(self):
        self._old = os.environ.get("XDG_STATE_HOME")
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        if self._old is None:
            os.environ.pop("XDG_STATE_HOME", None)
        else:
            os.environ["XDG_STATE_HOME"] = self._old

    def test_honours_xdg_state_home(self):
        os.environ["XDG_STATE_HOME"] = self.tmp
        self.assertEqual(broker_paths.state_dir(), pathlib.Path(self.tmp) / broker_paths.APP)

    def test_falls_back_to_home_local_state(self):
        os.environ.pop("XDG_STATE_HOME", None)
        expected = pathlib.Path.home() / ".local" / "state" / broker_paths.APP
        self.assertEqual(broker_paths.state_dir(), expected)

    def test_children_are_under_state_dir(self):
        os.environ["XDG_STATE_HOME"] = self.tmp
        root = broker_paths.state_dir()
        for child in (broker_paths.credentials_dir(), broker_paths.token_path(),
                      broker_paths.socket_path(), broker_paths.pidfile_path(),
                      broker_paths.server_json_path()):
            self.assertEqual(child.parent, root)


class EnsureDir(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())

    def test_creates_with_restrictive_mode(self):
        target = self.tmp / "new"
        broker_paths.ensure_dir(target)
        self.assertTrue(target.is_dir())
        self.assertEqual(target.stat().st_mode & 0o777, 0o700)

    def test_tightens_existing_loose_directory(self):
        target = self.tmp / "loose"
        target.mkdir()
        os.chmod(target, 0o755)
        broker_paths.ensure_dir(target)
        self.assertEqual(target.stat().st_mode & 0o777, 0o700)

    def test_creates_missing_parent_directories(self):
        # ensure_dir must create intermediate directories (parents=True); a single-level mkdir
        # would fail the very first time the state tree does not exist
        target = self.tmp / "a" / "b" / "c"
        broker_paths.ensure_dir(target)
        self.assertTrue(target.is_dir())

    def test_idempotent(self):
        target = self.tmp / "x"
        broker_paths.ensure_dir(target)
        broker_paths.ensure_dir(target)
        self.assertTrue(target.is_dir())


if __name__ == "__main__":
    unittest.main()
