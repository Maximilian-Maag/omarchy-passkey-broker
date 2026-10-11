#!/usr/bin/env python3
"""Unit tests for the software (fingerprint-gated) backend.

The backend is where the real cryptography happens, so these tests verify a real ES256
signature against the registered public key rather than only asserting the shape. A "plausible
but mis-encoded" authenticator is the failure mode this whole component exists to avoid.
"""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "bin"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))  # tests/ (for _isolation)
from _isolation import isolate  # noqa: E402

setUpModule, tearDownModule = isolate()
import webauthn_core as w  # noqa: E402
from backend_software import SoftwareBackend  # noqa: E402
from fido2 import cbor  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

CLIENT_CREATE = w.client_data("webauthn.create", "Y2hhbGxlbmdl", "https://example.com")
CLIENT_GET = w.client_data("webauthn.get", "Y2hhbGxlbmdl", "https://example.com")


def public_key_from_attestation(att_obj_bytes):
    """Recover the COSE public key an RP would read out of the attestation object."""
    att = cbor.decode(att_obj_bytes)
    auth_data = att["authData"]
    cose = auth_data[32 + 1 + 4 + 16 + 2 + 32:]
    key = cbor.decode(cose)
    numbers = ec.EllipticCurvePublicNumbers(int.from_bytes(key[-2], "big"),
                                            int.from_bytes(key[-3], "big"), ec.SECP256R1())
    return numbers.public_key()


class Register(unittest.TestCase):
    def setUp(self):
        self.be = SoftwareBackend()

    def test_record_has_secret_and_metadata(self):
        rec, _ = self.be.register("example.com", CLIENT_CREATE, b"user-1")
        self.assertIn("private_pem", rec)
        self.assertEqual(rec["rp_id"], "example.com")
        self.assertEqual(rec["backend"], "software")
        self.assertEqual(rec["alg"], -7)
        self.assertEqual(rec["sign_count"], 0)
        self.assertEqual(rec["aaguid"], w.AAGUID_SOFTWARE.hex())

    def test_response_shape(self):
        _, resp = self.be.register("example.com", CLIENT_CREATE, b"user-1")
        self.assertEqual(resp["type"], "public-key")
        self.assertEqual(resp["id"], resp["rawId"])
        self.assertIn("attestationObject", resp["response"])
        # clientDataJSON is echoed verbatim — the RP hashes this exact byte string.
        self.assertEqual(w.b64u_decode(resp["response"]["clientDataJSON"]), CLIENT_CREATE)

    def test_transports_internal(self):
        _, resp = self.be.register("example.com", CLIENT_CREATE)
        self.assertIn("internal", resp["response"]["transports"])

    def test_attestation_is_none_fmt(self):
        _, resp = self.be.register("example.com", CLIENT_CREATE)
        att = cbor.decode(w.b64u_decode(resp["response"]["attestationObject"]))
        self.assertEqual(att["fmt"], "none")
        self.assertEqual(att["attStmt"], {})

    def test_credential_id_is_32_bytes(self):
        _, resp = self.be.register("example.com", CLIENT_CREATE)
        self.assertEqual(len(w.b64u_decode(resp["id"])), 32)

    def test_user_handle_stored_and_omitted_when_absent(self):
        rec, _ = self.be.register("example.com", CLIENT_CREATE, b"user-1")
        self.assertEqual(w.b64u_decode(rec["user_handle"]), b"user-1")
        rec2, _ = self.be.register("example.com", CLIENT_CREATE)
        self.assertIsNone(rec2["user_handle"])

    def test_rp_id_hash_matches(self):
        _, resp = self.be.register("example.com", CLIENT_CREATE)
        att = cbor.decode(w.b64u_decode(resp["response"]["attestationObject"]))
        self.assertEqual(att["authData"][:32], w.rp_id_hash("example.com"))


class Authenticate(unittest.TestCase):
    def setUp(self):
        self.be = SoftwareBackend()
        self.record, self.reg = self.be.register("example.com", CLIENT_CREATE, b"user-1")
        self.pub = public_key_from_attestation(w.b64u_decode(
            self.reg["response"]["attestationObject"]))

    def test_signature_verifies(self):
        _, resp = self.be.authenticate(self.record, CLIENT_GET)
        self.assertTrue(w.verify_assertion(
            self.pub, w.b64u_decode(resp["response"]["authenticatorData"]),
            w.b64u_decode(resp["response"]["clientDataJSON"]),
            w.b64u_decode(resp["response"]["signature"])))

    def test_signature_over_wrong_data_fails(self):
        _, resp = self.be.authenticate(self.record, CLIENT_GET)
        tampered = CLIENT_GET.replace(b"webauthn.get", b"webauthn.xxx")
        self.assertFalse(w.verify_assertion(
            self.pub, w.b64u_decode(resp["response"]["authenticatorData"]), tampered,
            w.b64u_decode(resp["response"]["signature"])))

    def test_sign_count_increments(self):
        updates, resp = self.be.authenticate(self.record, CLIENT_GET)
        self.assertEqual(updates["sign_count"], 1)
        auth_data = w.b64u_decode(resp["response"]["authenticatorData"])
        self.assertEqual(int.from_bytes(auth_data[33:37], "big"), 1)

    def test_user_handle_returned(self):
        _, resp = self.be.authenticate(self.record, CLIENT_GET)
        self.assertEqual(w.b64u_decode(resp["response"]["userHandle"]), b"user-1")

    def test_no_user_handle_omitted(self):
        rec, _ = self.be.register("example.com", CLIENT_CREATE)
        _, resp = self.be.authenticate(rec, CLIENT_GET)
        self.assertNotIn("userHandle", resp["response"])

    def test_credential_id_matches_registration(self):
        _, resp = self.be.authenticate(self.record, CLIENT_GET)
        self.assertEqual(resp["id"], self.reg["id"])


class Flags(unittest.TestCase):
    def setUp(self):
        self.be = SoftwareBackend()

    def reg_flags(self, resp):
        att = cbor.decode(w.b64u_decode(resp["response"]["attestationObject"]))
        return att["authData"][32]

    def auth_flags(self, resp):
        return w.b64u_decode(resp["response"]["authenticatorData"])[32]

    def test_up_and_uv_set_when_verified(self):
        _, resp = self.be.register("example.com", CLIENT_CREATE, uv=True)
        self.assertEqual(self.reg_flags(resp), w.FLAG_UP | w.FLAG_UV)

    def test_uv_cleared_when_not_verified(self):
        _, resp = self.be.register("example.com", CLIENT_CREATE, uv=False)
        self.assertEqual(self.reg_flags(resp), w.FLAG_UP)

    def test_authenticate_uv_flag(self):
        rec, _ = self.be.register("example.com", CLIENT_CREATE, uv=False)
        _, resp = self.be.authenticate(rec, CLIENT_GET, uv=False)
        self.assertEqual(self.auth_flags(resp), w.FLAG_UP)
        _, resp2 = self.be.authenticate(rec, CLIENT_GET, uv=True)
        self.assertEqual(self.auth_flags(resp2), w.FLAG_UP | w.FLAG_UV)


class DefaultUserVerification(unittest.TestCase):
    """When no `uv` argument is given the default is to mark the credential user-verified.
    Silently defaulting to uv=False would produce credentials a UV-requiring relying party
    rejects, so the default is pinned here."""

    def setUp(self):
        self.be = SoftwareBackend()

    def reg_flags(self, resp):
        return cbor.decode(w.b64u_decode(resp["response"]["attestationObject"]))["authData"][32]

    def auth_flags(self, resp):
        return w.b64u_decode(resp["response"]["authenticatorData"])[32]

    def test_register_defaults_to_uv(self):
        _, resp = self.be.register("example.com", CLIENT_CREATE)
        self.assertEqual(self.reg_flags(resp), w.FLAG_UP | w.FLAG_UV)

    def test_authenticate_defaults_to_uv(self):
        rec, _ = self.be.register("example.com", CLIENT_CREATE)
        _, resp = self.be.authenticate(rec, CLIENT_GET)
        self.assertEqual(self.auth_flags(resp), w.FLAG_UP | w.FLAG_UV)


if __name__ == "__main__":
    unittest.main()
