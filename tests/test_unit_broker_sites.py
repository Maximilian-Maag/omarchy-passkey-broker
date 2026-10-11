#!/usr/bin/env python3
"""Unit tests for the per-site policy.

The policy decides where the bridge may touch WebAuthn at all. It exists because some sign-in
hosts cannot tolerate an overridden WebAuthn API: Google refuses such a browser outright, and the
Microsoft sign-in flow starts a ceremony it then waits on forever when the broker has nothing to
serve — while every other site needs the bridge present for passkeys to work at all.
"""
import json
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "bin"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))  # tests/ (for _isolation)
from _isolation import isolate  # noqa: E402

setUpModule, tearDownModule = isolate()
from broker_sites import DEFAULT_BLOCKED, SitesPolicy  # noqa: E402


def policy(blocked=None):
    return SitesPolicy(path=pathlib.Path(tempfile.mkdtemp()) / "sites.json", blocked=blocked)


class Defaults(unittest.TestCase):
    def test_nothing_is_blocked_out_of_the_box(self):
        # Passkeys are served by overriding WebAuthn, and that is needed on exactly the sign-in
        # hosts that used to be blocked here: QtWebEngine cannot reach a cross-platform key on its
        # own. The override is now installed in a shape a page cannot see (a prototype patch behind
        # a Proxy - no own property, still "[native code]"), so nothing needs blocking up front.
        self.assertEqual((), tuple(DEFAULT_BLOCKED))
        for host in ("google.com", "accounts.google.com", "login.live.com",
                     "account.live.com", "login.microsoftonline.com", "login.microsoft.com",
                     "account.microsoft.com"):
            self.assertFalse(policy().is_blocked(host),
                             "%s must be reachable: that is where the passkey is used" % host)

    def test_subdomains_of_an_explicitly_blocked_host_are_blocked(self):
        p = policy()
        p.block("google.com")
        self.assertTrue(p.is_blocked("google.com"))
        self.assertTrue(p.is_blocked("accounts.google.com"))
        self.assertTrue(p.is_blocked("myaccount.google.com"))

    def test_an_unrelated_host_is_not_blocked(self):
        p = policy()
        self.assertFalse(p.is_blocked("github.com"))
        self.assertFalse(p.is_blocked("example.org"))
        self.assertFalse(p.is_blocked("accounts.youtube.com"))

    def test_the_sign_in_hosts_are_reachable(self):
        # These were blocked while the override was detectable (their flow then either refused the
        # browser or waited on a ceremony that could not complete). Now that the override is
        # invisible to the page, they are exactly where the passkey must work.
        p = policy()
        for host in ("login.live.com", "account.live.com", "login.microsoftonline.com",
                     "login.microsoft.com", "account.microsoft.com", "accounts.google.com"):
            self.assertFalse(p.is_blocked(host), "%s must NOT be blocked by default" % host)

    def test_a_lookalike_domain_is_not_blocked(self):
        # "notgoogle.com" must not be caught by the "google.com" entry: suffix matching has to
        # respect the dot boundary
        self.assertFalse(policy().is_blocked("notgoogle.com"))
        self.assertFalse(policy().is_blocked("google.com.evil.test"))

    def test_an_empty_host_is_blocked(self):
        # unknown host: stay out of the way rather than guess
        self.assertTrue(policy().is_blocked(""))


class Mutations(unittest.TestCase):
    def test_block_adds_and_persists(self):
        p = policy()
        p.block("example.com")
        self.assertTrue(p.is_blocked("example.com"))
        self.assertTrue(json.loads(p.path.read_text())["blocked"].count("example.com") == 1)
        # a fresh object sees it too
        self.assertTrue(SitesPolicy(path=p.path).is_blocked("example.com"))

    def test_block_is_idempotent(self):
        p = policy()
        p.block("example.com")
        p.block("example.com")
        self.assertEqual(p.blocked.count("example.com"), 1)

    def test_block_normalises_case_and_dots(self):
        p = policy()
        p.block(".Example.COM")
        self.assertTrue(p.is_blocked("example.com"))

    def test_block_ignores_an_empty_host(self):
        p = policy()
        before = list(p.blocked)
        p.block("")
        self.assertEqual(p.blocked, before)

    def test_unblock_removes_the_entry(self):
        p = policy(blocked=["example.com", "other.test"])
        p.unblock("example.com")
        self.assertFalse(p.is_blocked("example.com"))
        self.assertTrue(p.is_blocked("other.test"))

    def test_unblock_removes_a_matching_parent_entry(self):
        # asking to unblock a subdomain of a blocked host must lift the whole rule, or the host
        # would stay blocked via its parent
        p = policy(blocked=["google.com"])
        p.unblock("accounts.google.com")
        self.assertFalse(p.is_blocked("accounts.google.com"))

    def test_unblock_is_persisted(self):
        p = policy(blocked=["example.com"])
        p.unblock("example.com")
        self.assertFalse(SitesPolicy(path=p.path).is_blocked("example.com"))


class Loading(unittest.TestCase):
    def test_missing_file_falls_back_to_the_defaults(self):
        self.assertEqual(policy().blocked, list(DEFAULT_BLOCKED))

    def test_a_corrupt_file_falls_back_to_the_defaults(self):
        path = pathlib.Path(tempfile.mkdtemp()) / "sites.json"
        path.write_text("{not json")
        self.assertEqual(SitesPolicy(path=path).blocked, list(DEFAULT_BLOCKED))

    def test_unexpected_shapes_fall_back_to_the_defaults(self):
        path = pathlib.Path(tempfile.mkdtemp()) / "sites.json"
        path.write_text(json.dumps({"blocked": "google.com"}))  # not a list
        self.assertEqual(SitesPolicy(path=path).blocked, list(DEFAULT_BLOCKED))

    def test_a_saved_list_is_read_back(self):
        path = pathlib.Path(tempfile.mkdtemp()) / "sites.json"
        path.write_text(json.dumps({"blocked": ["A.Test", "", "b.test"]}))
        self.assertEqual(SitesPolicy(path=path).blocked, ["a.test", "b.test"])

    def test_the_file_is_not_world_readable(self):
        p = policy()
        p.block("example.com")
        self.assertEqual(p.path.stat().st_mode & 0o077, 0)


if __name__ == "__main__":
    unittest.main()
