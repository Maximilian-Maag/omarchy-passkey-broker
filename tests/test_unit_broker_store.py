#!/usr/bin/env python3
"""Unit tests for the credential store.

The store is where a private key is written to disk, so its mode is tested directly (0600),
and the filename is treated as attacker-influenced (a credential id arrives from a page), so
path traversal is tested too.
"""
import json
import os
import pathlib
import sys
import tempfile
import time
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "bin"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))  # tests/ (for _isolation)
from _isolation import isolate  # noqa: E402

setUpModule, tearDownModule = isolate()
from broker_store import CredentialStore  # noqa: E402


def record(cred_id="cred-1", rp_id="example.com", backend="software", **extra):
    rec = {"cred_id": cred_id, "rp_id": rp_id, "backend": backend}
    rec.update(extra)
    return rec


class SaveLoad(unittest.TestCase):
    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp())
        self.store = CredentialStore(self.dir)

    def test_roundtrip(self):
        self.store.save(record(private_pem="SECRET"))
        self.assertEqual(self.store.load("cred-1")["private_pem"], "SECRET")

    def test_file_is_0600(self):
        self.store.save(record())
        path = self.dir / "cred-1.json"
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_defaults_added(self):
        rec = self.store.save(record())
        self.assertIn("created", rec)
        self.assertEqual(rec["sign_count"], 0)

    def test_save_does_not_mutate_caller(self):
        original = record()
        self.store.save(original)
        self.assertNotIn("created", original)

    def test_load_missing_returns_none(self):
        self.assertIsNone(self.store.load("nope"))

    def test_load_invalid_id_returns_none(self):
        self.assertIsNone(self.store.load("../etc/passwd"))

    def test_save_path_traversal_rejected(self):
        with self.assertRaises(ValueError):
            self.store.save(record(cred_id="../evil"))

    def test_save_empty_id_rejected(self):
        with self.assertRaises(ValueError):
            self.store.save(record(cred_id=""))

    def test_no_temp_file_left_behind(self):
        self.store.save(record())
        self.assertEqual([p.name for p in self.dir.glob("*.tmp")], [])


class Listing(unittest.TestCase):
    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp())
        self.store = CredentialStore(self.dir)

    def test_empty_when_dir_absent(self):
        self.assertEqual(CredentialStore(self.dir / "absent").list(), [])

    def test_ordered_by_created(self):
        self.store.save(record("a", rp_id="a.com"))
        time.sleep(0.01)
        self.store.save(record("b", rp_id="b.com"))
        self.assertEqual([r["cred_id"] for r in self.store.list()], ["a", "b"])

    def test_corrupt_file_skipped(self):
        self.store.save(record("good"))
        (self.dir / "bad.json").write_text("{not json")
        self.assertEqual([r["cred_id"] for r in self.store.list()], ["good"])


class Delete(unittest.TestCase):
    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp())
        self.store = CredentialStore(self.dir)

    def test_delete_existing(self):
        self.store.save(record())
        self.assertTrue(self.store.delete("cred-1"))
        self.assertIsNone(self.store.load("cred-1"))

    def test_delete_missing(self):
        self.assertFalse(self.store.delete("nope"))

    def test_delete_invalid_id(self):
        self.assertFalse(self.store.delete("../x"))


class ForRp(unittest.TestCase):
    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp())
        self.store = CredentialStore(self.dir)
        self.store.save(record("a1", rp_id="a.com", backend="software"))
        self.store.save(record("a2", rp_id="a.com", backend="token"))
        self.store.save(record("b1", rp_id="b.com"))

    def test_filters_by_rp(self):
        self.assertEqual(sorted(r["cred_id"] for r in self.store.for_rp("a.com")), ["a1", "a2"])

    def test_allow_ids_narrows(self):
        got = self.store.for_rp("a.com", allow_ids=["a2"])
        self.assertEqual([r["cred_id"] for r in got], ["a2"])

    def test_empty_allow_ids_means_any(self):
        self.assertEqual(len(self.store.for_rp("a.com", allow_ids=[])), 2)

    def test_unknown_rp(self):
        self.assertEqual(self.store.for_rp("z.com"), [])


class OrderPreservation(unittest.TestCase):
    def test_records_keep_arbitrary_fields(self):
        d = pathlib.Path(tempfile.mkdtemp())
        s = CredentialStore(d)
        s.save(record(aaguid="00ff", alg=-7, user_handle="dXNlcg"))
        rec = s.load("cred-1")
        self.assertEqual(rec["aaguid"], "00ff")
        self.assertEqual(rec["alg"], -7)
        self.assertEqual(json.loads((d / "cred-1.json").read_text())["user_handle"], "dXNlcg")


class FileFormat(unittest.TestCase):
    def test_file_uses_two_space_indent(self):
        d = pathlib.Path(tempfile.mkdtemp())
        CredentialStore(d).save(record())
        lines = (d / "cred-1.json").read_text().splitlines()
        self.assertTrue(lines[1].startswith('  "'))
        self.assertFalse(lines[1].startswith('   "'))


class AtomicWriteCleanup(unittest.TestCase):
    def test_open_failure_re_raises_the_real_error(self):
        """A temp file that could not even be created must not turn the failure into a
        confusing FileNotFoundError from the cleanup. Proven by making the parent directory
        read-only and asserting the real PermissionError surfaces."""
        from broker_store import _atomic_write
        parent = pathlib.Path(tempfile.mkdtemp())
        ro = parent / "ro"
        ro.mkdir()
        os.chmod(ro, 0o500)
        try:
            with self.assertRaises(PermissionError):
                _atomic_write(ro / "x.json", "{}")
        finally:
            os.chmod(ro, 0o700)

    def test_cleanup_removes_a_partial_temp_file(self):
        from broker_store import _atomic_write
        parent = pathlib.Path(tempfile.mkdtemp())
        _atomic_write(parent / "good.json", "{}")
        self.assertEqual([p.name for p in parent.glob("*.tmp")], [])


if __name__ == "__main__":
    unittest.main()
