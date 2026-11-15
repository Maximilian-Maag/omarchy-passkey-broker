#!/usr/bin/env python3
"""Unit tests for the bridge builder.

The builder is the only thing that puts the live port and the secret token into the userscript,
so the two things worth testing are: that it replaces exactly the CONFIG line (never more), and
that a missing daemon yields a disabled bridge rather than a stale one pointing at a dead port.
"""
import json
import os
import pathlib
import socket
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "bin"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))  # tests/ (for _isolation)
from _isolation import isolate  # noqa: E402

setUpModule, tearDownModule = isolate()
import bridge_build  # noqa: E402
import broker_paths  # noqa: E402


def listening_socket():
    """A bound, listening loopback socket plus its port — a live daemon stand-in.

    ``server.json`` alone is not proof of a live daemon anymore (the builder probes the port),
    so a test that means "a daemon IS running" must actually listen.
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    return srv, srv.getsockname()[1]


def dead_port():
    """A loopback port that is free right now (nothing listening), for the stale-file case."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.close()                                    # bound then released: nothing answers
    return port


class Render(unittest.TestCase):
    def test_replaces_config_once(self):
        out = bridge_build.render({"port": 1234, "token": "aa", "build": "b1"})
        self.assertIn('"port": 1234', out)
        self.assertIn('"token": "aa"', out)
        self.assertNotIn('"port": 0', out)

    def test_only_one_config_line(self):
        out = bridge_build.render({"port": 1, "token": "", "build": ""})
        self.assertEqual(out.count("var CONFIG = "), 1)

    def test_rest_of_source_preserved(self):
        out = bridge_build.render({"port": 1, "token": "", "build": ""})
        original = bridge_build.SOURCE.read_text(encoding="utf-8")
        # same number of lines, and everything but the CONFIG line identical
        self.assertEqual(len(out.splitlines()), len(original.splitlines()))
        diff = [i for i, (a, b) in enumerate(zip(out.splitlines(), original.splitlines()))
                if a != b]
        self.assertEqual(len(diff), 1)

    def test_missing_anchor_raises(self):
        original = bridge_build.CONFIG_RE
        bridge_build.CONFIG_RE = __import__("re").compile(r"NEVER_MATCHES")
        try:
            with self.assertRaises(ValueError):
                bridge_build.render({"port": 1, "token": "", "build": ""})
        finally:
            bridge_build.CONFIG_RE = original


class LiveConfig(unittest.TestCase):
    def setUp(self):
        self._old = os.environ.get("XDG_STATE_HOME")
        self.tmp = tempfile.mkdtemp()
        os.environ["XDG_STATE_HOME"] = self.tmp

    def tearDown(self):
        if self._old is None:
            os.environ.pop("XDG_STATE_HOME", None)
        else:
            os.environ["XDG_STATE_HOME"] = self._old

    def test_no_server_json_is_disabled(self):
        cfg = bridge_build.live_config()
        self.assertEqual(cfg["port"], 0)
        self.assertEqual(cfg["token"], "")
        self.assertEqual(cfg["build"], "")
        # the baked policy travels with the config even when no daemon is up
        self.assertEqual(cfg["has"], [])
        self.assertIn("google.com", cfg["blocked"])

    def test_the_baked_policy_carries_stored_rp_ids_and_the_blocked_list(self):
        import broker_sites
        from broker_store import CredentialStore
        CredentialStore().save({"cred_id": "cid-1", "rp_id": "Example.COM", "backend": "token"})
        CredentialStore().save({"cred_id": "cid-2", "rp_id": "other.test", "backend": "software"})
        broker_sites.SitesPolicy().block("extra.test")
        cfg = bridge_build.live_config()
        self.assertEqual(cfg["has"], ["example.com", "other.test"], "lowercased, sorted, distinct")
        self.assertIn("extra.test", cfg["blocked"])

    def test_render_embeds_the_baked_lists(self):
        text = bridge_build.render({"port": 1, "token": "t", "build": "b",
                                    "blocked": ["google.com"], "has": ["example.com"]})
        self.assertIn('"blocked": ["google.com"]', text)
        self.assertIn('"has": ["example.com"]', text)

    def test_reads_port_and_token(self):
        broker_paths.ensure_dir(broker_paths.state_dir())
        srv, port = listening_socket()
        try:
            broker_paths.server_json_path().write_text(json.dumps({"port": port, "build": "bX"}))
            broker_paths.token_path().write_text("secret-token\n")
            cfg = bridge_build.live_config()
            self.assertEqual(cfg["port"], port)
            self.assertEqual(cfg["token"], "secret-token")
            self.assertEqual(cfg["build"], "bX")
        finally:
            srv.close()

    def test_server_json_present_but_nothing_listening_disables_the_bridge(self):
        # A crashed daemon leaves server.json behind. Deciding "running" from the file's
        # existence alone rendered a bridge pointed at a dead port, and every passkey attempt
        # hung — the exact failure this whole plugin exists to fix. The port must be probed.
        broker_paths.ensure_dir(broker_paths.state_dir())
        port = dead_port()
        broker_paths.server_json_path().write_text(json.dumps({"port": port, "build": "b"}))
        cfg = bridge_build.live_config()
        self.assertEqual(cfg["port"], 0, "a stale server.json must not yield a live bridge")
        self.assertEqual(cfg["token"], "")
        # and the rendered CONFIG the browser sees says port 0, so the bridge disables itself
        self.assertIn('"port": 0', bridge_build.render(cfg))

    def test_server_json_without_a_port_disables_the_bridge(self):
        # A server.json carrying no port means "no usable daemon": the bridge must end up with
        # port 0 and disable itself, never point at a default that happens to be listening.
        broker_paths.ensure_dir(broker_paths.state_dir())
        broker_paths.server_json_path().write_text(json.dumps({"host": "127.0.0.1"}))
        self.assertEqual(bridge_build.live_config()["port"], 0)

    def test_corrupt_server_json_is_disabled(self):
        broker_paths.ensure_dir(broker_paths.state_dir())
        broker_paths.server_json_path().write_text("{not json")
        self.assertEqual(bridge_build.live_config()["port"], 0)

    def test_missing_token_is_empty(self):
        broker_paths.ensure_dir(broker_paths.state_dir())
        broker_paths.server_json_path().write_text(json.dumps({"port": 99}))
        self.assertEqual(bridge_build.live_config()["token"], "")


class Install(unittest.TestCase):
    def test_writes_to_target(self):
        d = pathlib.Path(tempfile.mkdtemp())
        written = bridge_build.install("// script\n", targets=[d])
        self.assertEqual(written, [str(d / "qute-passkey.js")])
        self.assertEqual((d / "qute-passkey.js").read_text(), "// script\n")

    def test_no_tmp_left(self):
        d = pathlib.Path(tempfile.mkdtemp())
        bridge_build.install("x", targets=[d])
        self.assertEqual([p.name for p in d.glob("*.tmp")], [])

    def test_multiple_targets(self):
        a, b = pathlib.Path(tempfile.mkdtemp()), pathlib.Path(tempfile.mkdtemp())
        written = bridge_build.install("y", targets=[a, b])
        self.assertEqual(len(written), 2)

    def test_install_live_returns_config_and_paths(self):
        os.environ["XDG_STATE_HOME"] = tempfile.mkdtemp()
        try:
            d = pathlib.Path(tempfile.mkdtemp())
            cfg, written = bridge_build.install_live(targets=[d])
            self.assertEqual(cfg["port"], 0)
            self.assertEqual(len(written), 1)
        finally:
            os.environ.pop("XDG_STATE_HOME", None)

    def test_reinstall_is_idempotent(self):
        d = pathlib.Path(tempfile.mkdtemp())
        bridge_build.install("// first\n", targets=[d])
        bridge_build.install("// second\n", targets=[d])       # exist_ok=False would raise
        self.assertEqual((d / "qute-passkey.js").read_text(), "// second\n")

    def test_creates_the_target_directory_tree(self):
        # the greasemonkey directory often does not exist yet, so the writer must create the
        # whole path (parents=True); a plain mkdir would be swallowed by the OSError guard and
        # silently write nothing
        d = pathlib.Path(tempfile.mkdtemp())
        target = d / "share" / "qutebrowser" / "greasemonkey"
        written = bridge_build.install("// s\n", targets=[target])
        self.assertEqual(written, [str(target / "qute-passkey.js")])
        self.assertTrue((target / "qute-passkey.js").is_file())


class GreasemonkeyDirs(unittest.TestCase):
    """The install target must be XDG-scoped. Hardcoding $HOME let the e2e test (via `serve`)
    write a dead bridge into the developer's real qutebrowser and break their sign-in."""

    def setUp(self):
        self._saved = {k: os.environ.get(k) for k in ("XDG_DATA_HOME", "XDG_CONFIG_HOME")}

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_honours_xdg(self):
        os.environ["XDG_DATA_HOME"] = "/tmp/xdgd"
        os.environ["XDG_CONFIG_HOME"] = "/tmp/xdgc"
        self.assertEqual(bridge_build.greasemonkey_dirs(),
                         [pathlib.Path("/tmp/xdgd/qutebrowser/greasemonkey"),
                          pathlib.Path("/tmp/xdgc/qutebrowser/greasemonkey")])

    def test_falls_back_to_home(self):
        os.environ.pop("XDG_DATA_HOME", None)
        os.environ.pop("XDG_CONFIG_HOME", None)
        dirs = bridge_build.greasemonkey_dirs()
        self.assertEqual(dirs[0], pathlib.Path.home() / ".local/share/qutebrowser/greasemonkey")
        self.assertEqual(dirs[1], pathlib.Path.home() / ".config/qutebrowser/greasemonkey")

    def test_default_install_stays_inside_xdg(self):
        # Patch Path.home to a throwaway dir: under MUTATION this test runs against a mutant
        # that ignores XDG, and the fallback would otherwise write into the developer's REAL
        # ~/.local/share. The assertion still fails the mutant, but the side effect must not
        # escape the test.
        fake_home = pathlib.Path(tempfile.mkdtemp())
        xdg_data = tempfile.mkdtemp()
        xdg_config = tempfile.mkdtemp()
        os.environ["XDG_DATA_HOME"] = xdg_data
        os.environ["XDG_CONFIG_HOME"] = xdg_config
        original_home = pathlib.Path.home
        pathlib.Path.home = classmethod(lambda cls: fake_home)
        try:
            written = bridge_build.install("// bridge\n")
        finally:
            pathlib.Path.home = original_home
        self.assertEqual(len(written), 2)                   # the data dir AND the config dir
        for path in written:
            self.assertTrue(pathlib.Path(path).is_file())
            self.assertNotIn(str(fake_home), path)          # never the $HOME fallback
            self.assertTrue(path.startswith(xdg_data) or path.startswith(xdg_config), path)


if __name__ == "__main__":
    unittest.main()
