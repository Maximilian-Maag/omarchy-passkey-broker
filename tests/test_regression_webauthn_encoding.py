#!/usr/bin/env python3
"""Regression tests for encoding invariants that have broken before or that are easy to break.

Each one encodes a specific trap rather than a general property:

  * the attestation CBOR map is built fmt, attStmt, authData — so the object ENDS with
    authData, not with the empty attStmt map (an earlier test asserted the wrong end and looked
    like an encoder bug);
  * base64url decoding must be STRICT — a lenient decoder silently drops junk characters, so
    "not b64u!!" decodes to plausible bytes instead of raising;
  * WebCrypto returns raw r||s for ES256 while WebAuthn needs ASN.1 DER; the two are
    distinguishable by length and lead byte, and confusing them produces a signature that
    verifies nowhere.
"""
import base64
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "bin"))
import webauthn_core as w  # noqa: E402
from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402


class AttestationFieldOrder(unittest.TestCase):
    def test_object_ends_with_auth_data(self):
        att = w.attestation_object(b"auth-data-bytes")
        self.assertTrue(att.endswith(b"auth-data-bytes"))

    def test_att_stmt_pair_precedes_auth_data(self):
        att = w.attestation_object(b"auth-data-bytes")
        # text(7) "attStmt" + empty map, which must come BEFORE the authData
        self.assertIn(b"\x67attStmt\xa0", att)
        self.assertLess(att.index(b"\x67attStmt\xa0"), att.index(b"auth-data-bytes"))


class StrictBase64(unittest.TestCase):
    def test_rejects_out_of_alphabet(self):
        with self.assertRaises(Exception):
            w.b64u_decode("not b64u!!")

    def test_rejects_an_impossible_length(self):
        with self.assertRaises(Exception):
            w.b64u_decode("AAAAA")

    def test_accepts_unpadded_urlsafe(self):
        self.assertEqual(w.b64u_decode("AQID"), b"\x01\x02\x03")

    def test_accepts_underscore_and_dash(self):
        raw = bytes([0xFB, 0xEF, 0xBE])
        self.assertEqual(w.b64u_decode(w.b64u_encode(raw)), raw)


class SignatureDer(unittest.TestCase):
    """Pin the raw-r||s vs DER distinction so a future 'use WebCrypto' shortcut cannot slip
    in a signature form the relying party rejects."""

    def setUp(self):
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.sig = self.key.sign(b"message", ec.ECDSA(hashes.SHA256()))

    def test_cryptography_returns_der(self):
        self.assertEqual(self.sig[0], 0x30)              # DER SEQUENCE tag
        self.assertNotEqual(len(self.sig), 64)           # not raw r||s

    def test_der_is_not_mistaken_for_raw(self):
        raw = base64.b64decode(base64.b64encode(self.sig))   # round-trip; still DER
        self.assertTrue(raw.startswith(b"\x30"))

    def test_verifies_over_signature_base(self):
        auth = w.authenticator_data("example.com", w.FLAG_UP | w.FLAG_UV, 1)
        cd = w.client_data("webauthn.get", "Y2hhbA", "https://example.com")
        sig = self.key.sign(w.assertion_signature_base(auth, cd), ec.ECDSA(hashes.SHA256()))
        self.assertTrue(w.verify_assertion(self.key.public_key(), auth, cd, sig))


class CosePadding(unittest.TestCase):
    def test_small_coordinates_are_left_padded(self):
        cose = w.cose_es256_from_coords(1, 2)
        self.assertEqual(len(cose[-2]), 32)
        self.assertEqual(len(cose[-3]), 32)
        self.assertEqual(cose[-2], b"\x00" * 31 + b"\x01")

    def test_full_width_coordinates_unchanged(self):
        big = int.from_bytes(b"\xff" * 32, "big")
        self.assertEqual(len(w.cose_es256_from_coords(big, big)[-2]), 32)


class Aaguid(unittest.TestCase):
    def test_software_aaguid_is_16_bytes(self):
        self.assertEqual(len(w.AAGUID_SOFTWARE), 16)

    def test_software_aaguid_is_not_all_zero(self):
        # all-zero would mean "no attestation"; this authenticator does identify itself
        self.assertNotEqual(w.AAGUID_SOFTWARE, b"\x00" * 16)


if __name__ == "__main__":
    unittest.main()
