#!/usr/bin/env python3
"""Regression tests for the broker's safety contract.

These pin the failures that would matter most if a future change undid them: a credential
private key written world-readable, a declined fingerprint that still produced a credential, or
a loopback route that answered without the token.
"""
import json
import pathlib
import sys
import tempfile
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "bin"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))  # tests/ (for _isolation)
from _isolation import isolate  # noqa: E402

setUpModule, tearDownModule = isolate()
import webauthn_core as w  # noqa: E402
from backend_software import SoftwareBackend  # noqa: E402
from backend_token import TokenBackend  # noqa: E402
from broker import PasskeyBroker  # noqa: E402
from broker_server import BrokerServer  # noqa: E402
from broker_store import CredentialStore  # noqa: E402
from broker_verify import NullVerifier  # noqa: E402


def no_key_broker(store, verifier=None):
    """A broker with real backends whose TOKEN reports no attached key.

    Without this the broker's "prefer a security key" default would send these ceremonies to
    whatever is plugged into the machine running the tests — making them hardware-dependent.
    """
    token = TokenBackend()
    token.available = lambda: False
    return PasskeyBroker(store=store,
                         verifier=verifier if verifier is not None else NullVerifier(True),
                         backends={"software": SoftwareBackend(), "token": token})

CD = w.b64u_encode(w.client_data("webauthn.create", "Y2hhbGxlbmdl", "https://example.com"))


class PrivateKeyNeverExposed(unittest.TestCase):
    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp())
        self.broker = no_key_broker(CredentialStore(self.dir))

    def test_credential_file_is_0600(self):
        self.broker.register("example.com", CD)
        for path in self.dir.glob("*.json"):
            self.assertEqual(path.stat().st_mode & 0o777, 0o600, path)

    def test_private_key_present_on_disk_but_never_in_listing(self):
        self.broker.register("example.com", CD)
        record = json.loads(next(self.dir.glob("*.json")).read_text())
        self.assertIn("private_pem", record)                     # it IS stored (0600)
        listed = self.broker.list_credentials()[0]
        self.assertNotIn("private_pem", listed)                  # but never surfaced

    def test_token_backend_stores_no_private_key(self):
        # the token backend must never write a key to disk "for convenience"
        class T:
            name = "token"

            def register(self, rp_id, cd, user=b"", uv=True):
                return ({"cred_id": "tk", "rp_id": rp_id, "backend": "token", "sign_count": 0},
                        {"id": "tk", "rawId": "tk", "type": "public-key",
                         "response": {"clientDataJSON": "x", "attestationObject": "y"}})
        self.broker.backends = {"token": T()}
        self.broker.register("example.com", CD, backend="token")
        self.assertNotIn("private_pem", self.broker.store.load("tk"))


class DeclinedNeverPersists(unittest.TestCase):
    def test_no_credential_after_decline(self):
        store = CredentialStore(pathlib.Path(tempfile.mkdtemp()))
        broker = no_key_broker(store, verifier=NullVerifier(False))
        result = broker.register("example.com", CD)
        self.assertFalse(result["ok"])
        self.assertEqual(store.list(), [])


class TokenAlwaysRequired(unittest.TestCase):
    def setUp(self):
        self.store = CredentialStore(pathlib.Path(tempfile.mkdtemp()))
        self.server = BrokerServer(PasskeyBroker(store=self.store, verifier=NullVerifier()),
                                   token="regression-token")
        self.server.start()
        self.base = "http://127.0.0.1:%d" % self.server.port

    def tearDown(self):
        self.server.stop()

    def post(self, path, token):
        req = urllib.request.Request(self.base + path, data=b"{}", method="POST")
        if token:
            req.add_header("X-Broker-Token", token)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status
        except urllib.error.HTTPError as exc:
            code = exc.code
            exc.close()
            return code

    def test_every_write_route_needs_the_token(self):
        for path in ("/register", "/authenticate", "/list", "/delete"):
            self.assertEqual(self.post(path, None), 403, path)
            self.assertEqual(self.post(path, "wrong"), 403, path)

    def test_binds_loopback_only(self):
        self.assertEqual(self.server.host, "127.0.0.1")


class ClientDataEchoed(unittest.TestCase):
    def test_response_client_data_is_the_exact_input(self):
        broker = PasskeyBroker(store=CredentialStore(pathlib.Path(tempfile.mkdtemp())),
                               verifier=NullVerifier(True))
        result = broker.register("example.com", CD)
        echoed = w.b64u_decode(result["credential"]["response"]["clientDataJSON"])
        self.assertEqual(echoed, w.b64u_decode(CD))


if __name__ == "__main__":
    unittest.main()
