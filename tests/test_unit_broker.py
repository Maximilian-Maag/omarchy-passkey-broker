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
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))  # tests/ (for _isolation)
from _isolation import isolate  # noqa: E402

setUpModule, tearDownModule = isolate()
import webauthn_core as w  # noqa: E402
from broker import PasskeyBroker  # noqa: E402
from broker_store import CredentialStore  # noqa: E402
from broker_verify import NullVerifier, VerifyResult  # noqa: E402

CD = w.b64u_encode(w.client_data("webauthn.create", "Y2hhbGxlbmdl", "https://example.com"))


class StubBackend:
    def __init__(self, name, uv_seen=None, self_verifies=False):
        self.name = name
        self.calls = []
        self._uv_seen = uv_seen
        # A token authenticator verifies the user itself (its PIN), so the broker must not
        # additionally demand the local fingerprint for it.
        self.self_verifies = self_verifies

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


class TokenFaults(unittest.TestCase):
    """A token that refuses (no device, or a PIN the key wants and the broker lacks) must come
    back as a clean error dict, not an exception that takes down the daemon request."""

    class BoomBackend:
        name = "token"

        def register(self, *a, **k):
            from backend_token import TokenError
            raise TokenError("the token requires a PIN")

        def authenticate(self, *a, **k):
            from backend_token import TokenError
            raise TokenError("the token requires a PIN")

    def test_register_reports_token_error(self):
        b = broker(backends={"token": self.BoomBackend()})
        r = b.register("example.com", CD, backend="token")
        self.assertFalse(r["ok"])
        self.assertEqual(r["error"], "token_error")
        self.assertIn("PIN", r["detail"])

    def test_authenticate_reports_token_error(self):
        b = broker(backends={"token": self.BoomBackend()})
        b.store.save({"cred_id": "tk", "rp_id": "example.com", "backend": "token",
                      "sign_count": 0})
        r = b.authenticate("example.com", CD)
        self.assertFalse(r["ok"])
        self.assertEqual(r["error"], "token_error")


class UvReporting(unittest.TestCase):
    """`user_verified` must reflect the authenticator's UV when it reports one, and only fall
    back to the broker's local verification otherwise."""

    def setUp(self):
        from broker import _uv_reported
        self.report = _uv_reported

    def test_authenticator_flag_wins_over_local_result(self):
        from broker_verify import VerifyResult
        self.assertTrue(self.report({"uv": True}, VerifyResult(False, "declined")))
        self.assertFalse(self.report({"uv": False}, VerifyResult(True, "verified")))

    def test_falls_back_to_local_verification(self):
        from broker_verify import VerifyResult
        self.assertTrue(self.report({}, VerifyResult(True, "verified")))
        self.assertFalse(self.report({}, VerifyResult(False, "declined")))

    def test_no_result_and_no_flag_is_false(self):
        self.assertFalse(self.report({}, None))


class CountingVerifier:
    """A verifier that records whether the broker consulted it at all."""

    def __init__(self, ok=True, state=None):
        self.calls = 0
        self._ok = ok
        self.state = state or ("verified" if ok else "declined")

    def verify(self, message=None):
        self.calls += 1
        return VerifyResult(self._ok, self.state, "counting verifier")


class BackendAwareVerification(unittest.TestCase):
    """A FIDO2 token verifies the user with its OWN PIN, so the broker must not additionally
    demand the local fingerprint for it. Requiring both made an attached security key unusable
    on a machine whose fingerprint sensor the owner cannot use — the bug this fix exists for.
    A software credential keeps its key in a file, so there the fingerprint check still stands."""

    def test_software_still_needs_the_fingerprint(self):
        v = CountingVerifier(ok=False)
        r = broker(verifier=v).register("example.com", CD, backend="software")
        self.assertFalse(r["ok"])
        self.assertEqual(r["error"], "declined")
        self.assertEqual(v.calls, 1, "a software key must still be gated by the fingerprint")

    def test_a_self_verifying_token_does_not_consult_the_fingerprint(self):
        v = CountingVerifier(ok=False)  # a sensor that would refuse everything
        b = broker(verifier=v, backends={"token": StubBackend("token", self_verifies=True)})
        r = b.register("example.com", CD, backend="token")
        self.assertTrue(r["ok"], r)
        self.assertEqual(v.calls, 0, "the token verifies itself; the sensor must not be asked")
        self.assertTrue(r["user_verified"], "the token's own UV counts as verified")

    def test_the_token_is_told_to_use_its_own_uv(self):
        tok = StubBackend("token", self_verifies=True)
        broker(backends={"token": tok}).register("example.com", CD, backend="token")
        self.assertEqual(tok.calls, [("register", "example.com", True)])

    def test_authenticate_also_skips_the_fingerprint_for_a_token(self):
        v = CountingVerifier(ok=False)
        b = broker(verifier=v, backends={"token": StubBackend("token", self_verifies=True)})
        b.store.save({"cred_id": "tk", "rp_id": "example.com", "backend": "token",
                      "sign_count": 0})
        r = b.authenticate("example.com", CD)
        self.assertTrue(r["ok"], r)
        self.assertEqual(v.calls, 0)
        self.assertTrue(r["user_verified"])

    def test_an_unavailable_sensor_does_not_block_a_token(self):
        v = CountingVerifier(ok=False, state="unavailable")
        b = broker(verifier=v, backends={"token": StubBackend("token", self_verifies=True)})
        self.assertTrue(b.register("example.com", CD, backend="token")["ok"])

    def test_the_software_path_still_refuses_an_unavailable_sensor(self):
        # "we could not check" must never be indistinguishable from "checked"
        v = CountingVerifier(ok=False, state="unavailable")
        r = broker(verifier=v).register("example.com", CD, backend="software")
        self.assertFalse(r["ok"])
        self.assertEqual(r["error"], "unavailable")

    def test_a_verify_opt_out_is_unchanged(self):
        v = CountingVerifier(ok=False)
        r = broker(verifier=v).register("example.com", CD, backend="software", verify=False)
        self.assertTrue(r["ok"])
        self.assertEqual(v.calls, 0)
        self.assertFalse(r["user_verified"], "an opt-out must not look verified")


class BackendPreference(unittest.TestCase):
    """Which backend a ceremony uses when the caller does not insist.

    This is the bug that made passkeys fail with a security key attached: the browser bridge
    pinned 'software', whose gate is the LOCAL fingerprint — unsatisfiable on a machine whose
    sensor the owner cannot use. The preference must therefore be "key first".
    """

    def test_prefers_the_token_when_a_key_is_attached(self):
        tok = StubBackend("token")
        tok.available = lambda: True
        self.assertEqual(broker(backends={"token": tok}).preferred_backend(), "token")

    def test_falls_back_to_software_without_a_key(self):
        tok = StubBackend("token")
        tok.available = lambda: False
        self.assertEqual(broker(backends={"token": tok}).preferred_backend(), "software")

    def test_falls_back_to_software_without_a_token_backend(self):
        self.assertEqual(broker(backends={}).preferred_backend(), "software")

    def test_a_backend_without_an_available_probe_is_not_preferred(self):
        # StubBackend has no `available`; it must not be mistaken for an attached key
        self.assertEqual(broker().preferred_backend(), "software")

    def test_register_without_a_backend_uses_the_preference(self):
        tok = StubBackend("token", self_verifies=True)
        tok.available = lambda: True
        b = broker(backends={"software": StubBackend("software"), "token": tok})
        r = b.register("example.com", CD)
        self.assertTrue(r["ok"], r)
        self.assertEqual(r["backend"], "token", "an attached key must win over software")

    def test_an_explicit_backend_still_overrides_the_preference(self):
        tok = StubBackend("token", self_verifies=True)
        tok.available = lambda: True
        b = broker(backends={"software": StubBackend("software"), "token": tok})
        self.assertEqual(b.register("example.com", CD, backend="software")["backend"],
                         "software")


if __name__ == "__main__":
    unittest.main()
