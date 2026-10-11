#!/usr/bin/env python3
"""Integration tests for the loopback HTTP server.

These boot the REAL ThreadingHTTPServer on 127.0.0.1:0 and drive it with urllib, so the
transport semantics that actually protect the broker are exercised: the health endpoint answers
without a token, every mutating route refuses without one, and a backend fault is reported
rather than allowed to kill the daemon.
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

TOKEN = "integration-test-token"


def no_key_broker(store, verifier=None):
    """A broker with real backends whose TOKEN reports no attached key.

    Otherwise the broker's "prefer a security key" default sends registrations to whatever is
    plugged into the machine running the tests — which made these tests pass or fail depending on
    whether the key happened to be responsive.
    """
    token = TokenBackend()
    token.available = lambda: False
    return PasskeyBroker(store=store,
                         verifier=verifier if verifier is not None else NullVerifier(True),
                         backends={"software": SoftwareBackend(), "token": token})


class ServerCase(unittest.TestCase):
    def setUp(self):
        self.store = CredentialStore(pathlib.Path(tempfile.mkdtemp()))
        self.broker = no_key_broker(self.store)
        self.server = BrokerServer(self.broker, token=TOKEN)
        self.server.start()
        self.base = "http://127.0.0.1:%d" % self.server.port

    def tearDown(self):
        self.server.stop()

    def call(self, path, body=None, token=TOKEN, method="POST"):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(self.base + path, data=data, method=method)
        if token is not None:
            req.add_header("X-Broker-Token", token)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            body = json.loads(exc.read().decode())
            exc.close()
            return exc.code, body

    def create(self, rp_id="example.com"):
        cd = w.b64u_encode(w.client_data("webauthn.create", "Y2hhbGxlbmdl",
                                         "https://%s" % rp_id))
        return self.call("/register", {"rp_id": rp_id, "client_data": cd, "verify": False})


class Health(unittest.TestCase):
    def setUp(self):
        self.store = CredentialStore(pathlib.Path(tempfile.mkdtemp()))
        self.server = BrokerServer(no_key_broker(self.store, verifier=NullVerifier()),
                                   token=TOKEN)
        self.server.start()
        self.base = "http://127.0.0.1:%d" % self.server.port

    def tearDown(self):
        self.server.stop()

    def test_health_needs_no_token(self):
        with urllib.request.urlopen(self.base + "/health", timeout=5) as resp:
            body = json.loads(resp.read().decode())
        self.assertTrue(body["ok"])
        self.assertIn("software", body["backends"])
        self.assertTrue(body["build"])


class Auth(ServerCase):
    def test_missing_token_forbidden(self):
        status, body = self.call("/list", token=None)
        self.assertEqual(status, 403)
        self.assertEqual(body["error"], "forbidden")
        self.assertFalse(body["ok"])

    def test_wrong_token_forbidden(self):
        status, _ = self.call("/list", token="wrong")
        self.assertEqual(status, 403)

    def test_valid_token_allowed(self):
        status, body = self.call("/list")
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])


class Routing(ServerCase):
    def test_unknown_path(self):
        status, body = self.call("/nope", {})
        self.assertEqual(status, 404)
        self.assertFalse(body["ok"])

    def test_one_byte_body_is_rejected(self):
        """A one-byte body is still a body: it must be read and fail to parse (400), not be
        mistaken for an empty request and silently accepted."""
        req = urllib.request.Request(self.base + "/list", data=b"{", method="POST")
        req.add_header("X-Broker-Token", TOKEN)
        try:
            urllib.request.urlopen(req, timeout=5)
            self.fail("expected 400")
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, 400)
            exc.close()

    def test_bad_json(self):
        req = urllib.request.Request(self.base + "/list", data=b"{not json",
                                   method="POST")
        req.add_header("X-Broker-Token", TOKEN)
        try:
            urllib.request.urlopen(req, timeout=5)
            self.fail("expected 400")
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, 400)
            exc.close()

    def test_get_on_route_without_handler(self):
        try:
            urllib.request.urlopen(self.base + "/register", timeout=5)
            self.fail("expected 404")
        except urllib.error.HTTPError as exc:
            self.assertEqual(exc.code, 404)
            self.assertFalse(json.loads(exc.read().decode())["ok"])
            exc.close()

    def test_backend_fault_is_500_not_a_crash(self):
        class Boom:
            name = "software"

            def register(self, *a, **k):
                raise RuntimeError("backend exploded")

        self.broker.backends = {"software": Boom()}
        cd = w.b64u_encode(w.client_data("webauthn.create", "Y2hhbGxlbmdl", "https://example.com"))
        status, body = self.call("/register", {"rp_id": "example.com", "client_data": cd})
        self.assertEqual(status, 500)
        self.assertEqual(body["error"], "internal")
        # the server is still alive afterwards
        self.assertEqual(self.call("/list")[0], 200)


class FullCeremony(ServerCase):
    def test_register_authenticate_list_delete_over_http(self):
        status, reg = self.create()
        self.assertEqual(status, 200)
        self.assertTrue(reg["ok"])
        cred_id = reg["credential"]["id"]

        status, listing = self.call("/list")
        self.assertEqual([c["cred_id"] for c in listing["credentials"]], [cred_id])

        cd = w.b64u_encode(w.client_data("webauthn.get", "Y2hhbGxlbmdl", "https://example.com"))
        status, auth = self.call("/authenticate", {"rp_id": "example.com", "client_data": cd,
                                                   "verify": False})
        self.assertEqual(status, 200)
        self.assertTrue(auth["ok"])
        self.assertEqual(auth["credential"]["id"], cred_id)

        status, deleted = self.call("/delete", {"cred_id": cred_id})
        self.assertTrue(deleted["ok"])
        self.assertEqual(self.call("/list")[1]["credentials"], [])

    def test_verification_declined_over_http(self):
        self.broker.verifier = NullVerifier(False)
        cd = w.b64u_encode(w.client_data("webauthn.create", "Y2hhbGxlbmdl", "https://example.com"))
        status, body = self.call("/register", {"rp_id": "example.com", "client_data": cd})
        self.assertEqual(status, 200)                 # the ceremony returns ok:false, not a 4xx
        self.assertFalse(body["ok"])
        self.assertEqual(body["error"], "declined")

    def test_user_handle_survives_the_request_boundary(self):
        """A user handle supplied to /register must reach the credential and come back on the
        assertion — so a truthiness default cannot quietly blank it."""
        cd_create = w.b64u_encode(w.client_data("webauthn.create", "Y2hhbGxlbmdl",
                                                "https://example.com"))
        status, reg = self.call("/register", {"rp_id": "example.com", "client_data": cd_create,
                                              "user_handle": w.b64u_encode(b"handle-123")})
        self.assertTrue(reg["ok"])
        cd_get = w.b64u_encode(w.client_data("webauthn.get", "Y2hhbGxlbmdl",
                                             "https://example.com"))
        status, auth = self.call("/authenticate", {"rp_id": "example.com", "client_data": cd_get,
                                                   "verify": False})
        self.assertEqual(w.b64u_decode(auth["credential"]["response"]["userHandle"]),
                         b"handle-123")


class Cors(unittest.TestCase):
    """The bridge is a page script, so its requests to this loopback server are cross-origin and
    the browser enforces CORS. Without these headers the response is blocked and the bridge
    reports 'broker unreachable' on every site (observed live before this was added)."""

    def setUp(self):
        store = CredentialStore(pathlib.Path(tempfile.mkdtemp()))
        self.server = BrokerServer(no_key_broker(store), token=TOKEN)
        self.server.start()
        self.base = "http://127.0.0.1:%d" % self.server.port

    def tearDown(self):
        self.server.stop()

    def _headers(self, path, method="GET", data=None, token=TOKEN):
        req = urllib.request.Request(self.base + path, data=data, method=method)
        if token is not None:
            req.add_header("X-Broker-Token", token)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, resp.headers
        except urllib.error.HTTPError as exc:
            headers = exc.headers
            exc.close()
            return exc.code, headers

    def test_health_allows_a_cross_origin_read(self):
        status, headers = self._headers("/health")
        self.assertEqual(status, 200)
        self.assertEqual(headers["Access-Control-Allow-Origin"], "*")

    def test_preflight_is_answered(self):
        # the bridge sends Content-Type and X-Broker-Token, so the browser preflights with OPTIONS
        status, headers = self._headers("/register", method="OPTIONS")
        self.assertEqual(status, 204)
        self.assertEqual(headers["Access-Control-Allow-Origin"], "*")
        self.assertIn("X-Broker-Token", headers["Access-Control-Allow-Headers"])
        self.assertIn("POST", headers["Access-Control-Allow-Methods"])

    def test_an_error_response_also_carries_cors(self):
        # a 403 with no CORS header reads as a network error to the page, not as a refusal
        status, headers = self._headers("/register", method="POST", data=b"{}", token=None)
        self.assertEqual(status, 403)
        self.assertEqual(headers["Access-Control-Allow-Origin"], "*")


class Has(ServerCase):
    """GET /has tells the bridge whether THIS site has a credential, so it never overrides
    WebAuthn where it cannot serve — the override is what makes Google's sign-in refuse the
    browser ("This browser or app may not be secure"). It is unauthenticated by necessity (the
    bridge must ask before it has cause to touch WebAuthn, and a page cannot read the token), so
    it must not become an oracle for which sites the user holds passkeys for."""

    def has(self, host, origin=None):
        req = urllib.request.Request(self.base + "/has?host=" + host)
        if origin:
            req.add_header("Origin", origin)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            body = json.loads(exc.read().decode())
            exc.close()
            return exc.code, body

    def test_needs_no_token(self):
        status, _ = self.has("example.com", "https://example.com")
        self.assertEqual(status, 200)

    def test_false_when_nothing_matches(self):
        status, body = self.has("example.com", "https://example.com")
        self.assertEqual(status, 200)
        self.assertFalse(body["has"])

    def test_install_is_allowed_on_a_site_with_no_credential(self):
        # REGISTRATION must be possible: a new passkey is created on a site we hold nothing for,
        # so "no credential" must never switch the bridge off.
        status, body = self.has("example.com", "https://example.com")
        self.assertEqual(status, 200)
        self.assertFalse(body["has"])
        self.assertTrue(body["install"])

    def test_install_is_false_for_a_blocked_host(self):
        # Blocking is opt-in now (nothing is blocked by default), so a host that misbehaves on
        # this machine is kept out explicitly.
        self.broker.sites.block("accounts.google.com")
        status, body = self.has("accounts.google.com", "https://accounts.google.com")
        self.assertEqual(status, 200)
        self.assertFalse(body["install"])

    def test_install_is_false_for_a_subdomain_of_a_blocked_host(self):
        self.broker.sites.block("google.com")
        _, body = self.has("myaccount.google.com", "https://myaccount.google.com")
        self.assertFalse(body["install"])

    def test_blocking_is_configurable(self):
        self.broker.sites.block("example.com")
        _, body = self.has("example.com", "https://example.com")
        self.assertFalse(body["install"])
        self.broker.sites.unblock("example.com")
        _, body = self.has("example.com", "https://example.com")
        self.assertTrue(body["install"])

    def test_true_for_the_exact_host(self):
        self.create("example.com")
        _, body = self.has("example.com", "https://example.com")
        self.assertTrue(body["has"])

    def test_true_for_a_subdomain_of_the_rp(self):
        self.create("example.com")
        _, body = self.has("accounts.example.com", "https://accounts.example.com")
        self.assertTrue(body["has"])

    def test_false_for_an_unrelated_host_that_has_credentials_elsewhere(self):
        self.create("example.com")
        _, body = self.has("evil.test", "https://evil.test")
        self.assertFalse(body["has"])

    def test_origin_mismatch_is_refused(self):
        # a page must not be able to enumerate which sites the user holds passkeys for
        self.create("example.com")
        status, body = self.has("example.com", "https://attacker.test")
        self.assertEqual(status, 403)
        self.assertEqual(body["error"], "origin_mismatch")

    def test_missing_host_is_refused(self):
        status, _ = self.has("", "https://example.com")
        self.assertEqual(status, 403)


if __name__ == "__main__":
    unittest.main()
