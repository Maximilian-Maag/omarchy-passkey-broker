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
from broker import PasskeyBroker  # noqa: E402
from broker_server import BrokerServer  # noqa: E402
from broker_store import CredentialStore  # noqa: E402
from broker_verify import NullVerifier  # noqa: E402

TOKEN = "integration-test-token"


class ServerCase(unittest.TestCase):
    def setUp(self):
        self.store = CredentialStore(pathlib.Path(tempfile.mkdtemp()))
        self.broker = PasskeyBroker(store=self.store, verifier=NullVerifier(True))
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
        self.server = BrokerServer(PasskeyBroker(store=self.store, verifier=NullVerifier()),
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
        self.server = BrokerServer(PasskeyBroker(store=store, verifier=NullVerifier(True)),
                                   token=TOKEN)
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


if __name__ == "__main__":
    unittest.main()
