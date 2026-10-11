#!/usr/bin/env python3
"""Unit tests for the server's build stamp.

The stamp exists so a client can tell WHICH build is answering on a port — a stale daemon from
a previous version is otherwise indistinguishable from a current one. That only works if the
stamp is derived from the right files, so the source-file filter is tested against a controlled
directory rather than the real one.
"""
import os
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "bin"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))  # tests/ (for _isolation)
from _isolation import isolate  # noqa: E402

setUpModule, tearDownModule = isolate()
from broker_server import build_stamp  # noqa: E402


def write(directory, name, mtime):
    path = pathlib.Path(directory) / name
    path.write_text("x")
    os.utime(path, (mtime, mtime))
    return path


class BuildStamp(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def test_stamp_is_the_newest_source_mtime(self):
        write(self.dir, "a.py", 1000)
        self.assertEqual(build_stamp(self.dir), "b%x" % 1000)

    def test_bumped_by_a_newer_source(self):
        write(self.dir, "a.py", 1000)
        write(self.dir, "b.py", 3000)
        self.assertEqual(build_stamp(self.dir), "b%x" % 3000)

    def test_the_cli_counts_as_a_source(self):
        write(self.dir, "passkey-broker", 9000)
        self.assertEqual(build_stamp(self.dir), "b%x" % 9000)

    def test_non_source_files_are_ignored(self):
        write(self.dir, "a.py", 1000)
        write(self.dir, "notes.txt", 9000)          # newer, but not a source
        self.assertEqual(build_stamp(self.dir), "b%x" % 1000)

    def test_empty_directory_is_stamp_zero(self):
        self.assertEqual(build_stamp(self.dir), "b0")

    def test_default_directory_is_the_bin_dir(self):
        self.assertTrue(build_stamp().startswith("b"))


if __name__ == "__main__":
    unittest.main()
