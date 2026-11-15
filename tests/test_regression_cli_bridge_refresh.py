#!/usr/bin/env python3
"""Regression: the CLI's ``register`` must re-bake the bridge, like delete/block/unblock do.

The bridge decides from a snapshot of ``rp_ids`` baked into the userscript. ``passkey-broker
register`` wrote the credential but never re-rendered the script, so a credential created from
the CLI stayed invisible to the bridge: on a page whose sign-in then called ``get()``, the
bridge had no baked rp_id to match and deferred to the native engine — which hangs. The
daemon's own register route always re-baked; only the CLI command forgot to.

This drives the real CLI command against a stub broker (the store/bake path is real; only the
backends are stubbed so the test needs no cryptography/fido2 or attached key).
"""
import importlib.util
import os
import pathlib
import sys
import tempfile
import unittest

REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "bin"))
sys.path.insert(0, str(REPO / "tests"))  # for _isolation
from _isolation import isolate  # noqa: E402

setUpModule, tearDownModule = isolate()


def load_cli():
    """Import bin/passkey-broker (no .py suffix) as a module."""
    from importlib.machinery import SourceFileLoader
    loader = SourceFileLoader("passkey_broker_cli", str(REPO / "bin" / "passkey-broker"))
    spec = importlib.util.spec_from_loader("passkey_broker_cli", loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class StubBroker:
    """A broker whose register persists a record and reports success, like the real one."""

    def __init__(self):
        from broker_store import CredentialStore
        self.store = CredentialStore()

    def register(self, rp_id, client_data, user_handle="", backend=None, verify=True):
        self.store.save({"cred_id": "cid-1", "rp_id": rp_id, "backend": backend or "software"})
        return {"ok": True, "backend": backend or "software", "user_verified": False,
                "credential": {"id": "cid-1"}}


class CliRegisterRebakesTheBridge(unittest.TestCase):
    def setUp(self):
        self.cli = load_cli()
        self.saved = {k: os.environ.get(k) for k in
                      ("XDG_STATE_HOME", "XDG_DATA_HOME", "XDG_CONFIG_HOME")}
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        os.environ["XDG_STATE_HOME"] = str(self.tmp / "state")
        os.environ["XDG_DATA_HOME"] = str(self.tmp / "data")
        os.environ["XDG_CONFIG_HOME"] = str(self.tmp / "config")
        self.stub = StubBroker()
        self.cli._make_broker = lambda *a, **k: self.stub

    def tearDown(self):
        for key, value in self.saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    def installed_bridge(self):
        return self.tmp / "data" / "qutebrowser" / "greasemonkey" / "qute-passkey.js"

    def test_register_bakes_the_new_rp_id_into_the_installed_bridge(self):
        args = self.cli.build_parser().parse_args(
            ["register", "--rp-id", "example.com", "--backend", "software", "--no-verify"])
        rc = args.func(args)
        self.assertEqual(rc, 0)
        bridge = self.installed_bridge()
        self.assertTrue(bridge.is_file(),
                        "register must (re-)install the bridge, not leave the stale one")
        self.assertIn('"has": ["example.com"]', bridge.read_text(encoding="utf-8"),
                      "the CLI must re-bake the bridge after a registration")


if __name__ == "__main__":
    unittest.main()
