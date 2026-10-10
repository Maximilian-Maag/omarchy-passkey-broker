#!/usr/bin/env python3
"""Unit tests for the broker service (the policy layer).

These pin the decisions rather than the cryptography: validation of the request, the
verification gate, and which credential answers an assertion. The backends are stubbed so a
failure points at the policy, not at ES256.
"""
import os
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "bin"))
import webauthn_core as w  # noqa: E402
from broker import PasskeyBroker  # noqa: E402
from broker_store import CredentialStore  # noqa: E402
from broker_verify import NullVerifier  # noqa: E402

CD = w.b64u_encode(w.client_data("webauthn.create", "Y2hhbGxlbmdl", "https://example.com"))


class StubBackend:
    def __init__(self, name, uv_seen=None):
        self.name = name
        self.calls = []
        self._uv_seen = uv_seen

    def register(self, rp_id, client_data, user_handle=b"", uv=True):
        self.calls.append(("register", rp_id, uv))
        rec = {"cred_id": "cred-" + self.name, "rp_id": rp_id, "backend": self.name,
               "sign_count": 0}
        if self.name == "software":
            rec["private_pem"] = "PEM"
        return rec, {"id": rec["cred_id"], "rawId": rec["cred_id"], "type": "public-key",
                     "response": {"clientDataJSON": "x", "attestationObject": "y"}}

    def authenticate(self, record, client_data, uv=True):
        self.calls.append(("authenticate", record["rp_id"], uv))
        return {"sign_count": record.get("sign_count", 0) + 1}, {
            "id": record["cred_id"], "rawId": record["cred_id"], "type": "public-key",
            "response": {"clientDataJSON": "x", "authenticatorData": "y", "signature": "z"}}


def broker(verifier=None, backends=None, cred_dir=None):
    store = CredentialStore(cred_dir or pathlib.Path(tempfile.mkdtemp()))
    return PasskeyBroker(store=store, verifier=verifier or NullVerifier(True),
                         backends=backends or {"software": StubBackend("software"),
                                               "token": StubBackend("token")})


class RegisterValidation(unittest.TestCase):
    def test_invalid_rp_id(self):
        r = broker().register("", CD)
        self.assertFalse(r["ok"])
        self.assertEqual(r["error"], "invalid_rp_id")

    def test_non_string_rp_id(self):
        r = broker().register(123, CD)
        self.assertFalse(r["ok"])
        self.assertEqual(r["error"], "invalid_rp_id")

    def test_invalid_client_data(self):
        r = broker().register("example.com", "not b64u!!")
        self.assertFalse(r["ok"])
        self.assertEqual(r["error"], "invalid_client_data")

    def test_unknown_backend(self):
        self.assertEqual(broker().register("example.com", CD, backend="nope")["error"],
                         "unknown_backend")

    def test_success_reports_backend_and_uv(self):
        r = broker().register("example.com", CD, backend="software")
        self.assertTrue(r["ok"])
        self.assertEqual(r["backend"], "software")
        self.assertTrue(r["user_verified"])


class VerifyGate(unittest.TestCase):
    def test_declined_blocks_registration(self):
        b = broker(verifier=NullVerifier(False))
        r = b.register("example.com", CD)
        self.assertFalse(r["ok"])
        self.assertEqual(r["error"], "declined")
        self.assertEqual(b.store.list(), [])          # nothing persisted

    def test_unavailable_blocks_registration(self):
        class Unavailable:
            def verify(self, message=None):
                from broker_verify import VerifyResult
                return VerifyResult(False, "unavailable", "no fprintd")

            def available(self):
                return False
        r = broker(verifier=Unavailable()).register("example.com", CD)
        self.assertEqual(r["error"], "unavailable")

    def test_no_verify_skips_gate_and_clears_uv(self):
        b = broker(verifier=NullVerifier(False))
        r = b.register("example.com", CD, verify=False)
        self.assertTrue(r["ok"])
        self.assertFalse(r["user_verified"])
        # the backend was told uv=False, so the UV flag is not set on the credential
        self.assertEqual(b.backends["software"].calls[-1], ("register", "example.com", False))

    def test_verified_sets_uv_true(self):
        b = broker(verifier=NullVerifier(True))
        b.register("example.com", CD)
        self.assertTrue(b.backends["software"].calls[-1][2])


class Authenticate(unittest.TestCase):
    def test_invalid_rp_id(self):
        r = broker().authenticate("", CD)
        self.assertFalse(r["ok"])
        self.assertEqual(r["error"], "invalid_rp_id")

    def test_no_credential(self):
        self.assertEqual(broker().authenticate("example.com", CD)["error"], "no_credential")

    def test_authenticate_without_verification(self):
        """verify=False makes the verification result None, and the user_verified computation
        must still handle that rather than dereferencing None."""
        b = broker()
        b.register("example.com", CD)
        r = b.authenticate("example.com", CD, verify=False)
        self.assertTrue(r["ok"])
        self.assertFalse(r["user_verified"])

    def test_prefers_token_backend(self):
        b = broker()
        b.store.save({"cred_id": "sw", "rp_id": "example.com", "backend": "software",
                      "sign_count": 0})
        b.store.save({"cred_id": "tk", "rp_id": "example.com", "backend": "token",
                      "sign_count": 0})
        r = b.authenticate("example.com", CD)
        self.assertTrue(r["ok"])
        self.assertEqual(r["backend"], "token")

    def test_falls_back_to_software(self):
        b = broker()
        b.store.save({"cred_id": "sw", "rp_id": "example.com", "backend": "software",
                      "sign_count": 0})
        self.assertEqual(b.authenticate("example.com", CD)["backend"], "software")

    def test_allow_ids_narrows(self):
        b = broker()
        b.store.save({"cred_id": "a", "rp_id": "example.com", "backend": "software"})
        b.store.save({"cred_id": "b", "rp_id": "example.com", "backend": "software"})
        r = b.authenticate("example.com", CD, allow_ids=["b"])
        self.assertEqual(r["credential"]["id"], "b")

    def test_declined_does_not_increment(self):
        b = broker(verifier=NullVerifier(False))
        b.store.save({"cred_id": "a", "rp_id": "example.com", "backend": "software",
                      "sign_count": 3})
        r = b.authenticate("example.com", CD)
        self.assertEqual(r["error"], "declined")
        self.assertEqual(b.store.load("a")["sign_count"], 3)

    def test_sign_count_persisted(self):
        b = broker()
        b.store.save({"cred_id": "a", "rp_id": "example.com", "backend": "software",
                      "sign_count": 0})
        b.authenticate("example.com", CD)
        self.assertEqual(b.store.load("a")["sign_count"], 1)


class Listing(unittest.TestCase):
    def test_shape(self):
        b = broker()
        b.register("example.com", CD)
        rows = b.list_credentials()
        self.assertEqual(len(rows), 1)
        self.assertEqual(set(rows[0]),
                         {"cred_id", "rp_id", "backend", "sign_count", "user_handle",
                          "created"})

    def test_delete(self):
        b = broker()
        b.register("example.com", CD)
        cred_id = b.store.list()[0]["cred_id"]
        self.assertTrue(b.delete(cred_id)["ok"])
        self.assertFalse(b.delete(cred_id)["ok"])


if __name__ == "__main__":
    unittest.main()
