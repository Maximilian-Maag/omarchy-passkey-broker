#!/usr/bin/env python3
"""Unit tests for the WebAuthn encoding core.

These are byte-level assertions on purpose. An assertion that is structurally plausible but
mis-encoded verifies nowhere, and the failure shows up at a relying party rather than here —
so the tests build real values and, where a key is available, verify a real ES256 signature.
"""
import os
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "bin"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))  # tests/ (for _isolation)
from _isolation import isolate  # noqa: E402

setUpModule, tearDownModule = isolate()
import webauthn_core as w  # noqa: E402

try:
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False


class Base64Url(unittest.TestCase):
    def test_roundtrip(self):
        raw = os.urandom(32)
        self.assertEqual(w.b64u_decode(w.b64u_encode(raw)), raw)

    def test_encode_has_no_padding(self):
        self.assertNotIn("=", w.b64u_encode(b"a" * 32))

    def test_decode_accepts_unpadded_input(self):
        self.assertEqual(w.b64u_decode("AQID"), b"\x01\x02\x03")

    def test_url_safe_alphabet(self):
        raw = bytes([0xFB, 0xEF, 0xBE])
        self.assertNotIn("+", w.b64u_encode(raw))
        self.assertNotIn("/", w.b64u_encode(raw))


class Cbor(unittest.TestCase):
    def test_small_uint(self):
        self.assertEqual(w.cbor_encode(0), b"\x00")
        self.assertEqual(w.cbor_encode(23), b"\x17")

    def test_uint_boundaries(self):
        self.assertEqual(w.cbor_encode(24), b"\x18\x18")
        self.assertEqual(w.cbor_encode(255), b"\x18\xff")
        self.assertEqual(w.cbor_encode(256), b"\x19\x01\x00")
        self.assertEqual(w.cbor_encode(65536), b"\x1a\x00\x01\x00\x00")

    def test_negative_int(self):
        self.assertEqual(w.cbor_encode(-1), b"\x20")
        self.assertEqual(w.cbor_encode(-7), b"\x26")

    def test_bytes_carry_their_length(self):
        self.assertEqual(w.cbor_encode(b"abc"), b"\x43abc")
        self.assertEqual(w.cbor_encode(b"a" * 24), b"\x58\x18" + b"a" * 24)

    def test_text_string(self):
        self.assertEqual(w.cbor_encode("a"), b"\x61a")

    def test_literals(self):
        self.assertEqual(w.cbor_encode(True), b"\xf5")
        self.assertEqual(w.cbor_encode(False), b"\xf4")
        self.assertEqual(w.cbor_encode(None), b"\xf6")

    def test_list_and_map(self):
        self.assertEqual(w.cbor_encode([1, 2]), b"\x82\x01\x02")
        self.assertEqual(w.cbor_encode({"a": 1}), b"\xa1\x61a\x01")

    def test_map_order_is_preserved(self):
        self.assertEqual(w.cbor_encode({"b": 1, "a": 2}), b"\xa2\x61b\x01\x61a\x02")

    def test_unencodable_type_is_refused(self):
        with self.assertRaises(TypeError):
            w.cbor_encode(object())

    def test_map_length_readback(self):
        n, hdr = w.cbor_map_length(w.cbor_encode({"a": 1, "b": 2}))
        self.assertEqual((n, hdr), (2, 1))

    def test_map_length_rejects_non_map(self):
        with self.assertRaises(ValueError):
            w.cbor_map_length(b"\x01")


class AuthenticatorData(unittest.TestCase):
    def test_shape_and_rp_id_hash(self):
        data = w.authenticator_data("example.com", w.FLAG_UP, 0)
        self.assertEqual(len(data), 37)
        self.assertEqual(data[:32], w.rp_id_hash("example.com"))
        self.assertEqual(data[32], 0x01)
        self.assertEqual(data[33:], b"\x00\x00\x00\x00")

    def test_sign_count_is_big_endian(self):
        data = w.authenticator_data("x", w.FLAG_UP, 0x01020304)
        self.assertEqual(data[33:], b"\x01\x02\x03\x04")

    def test_different_rp_ids_hash_differently(self):
        self.assertNotEqual(w.rp_id_hash("a.com"), w.rp_id_hash("b.com"))

    def test_attested_credential_data_layout(self):
        cred = b"c" * 16
        data = w.authenticator_data("example.com", w.FLAG_UP | w.FLAG_AT, 0,
                                    attested=(b"\x00" * 16, cred, w.cose_es256(b"xx", b"yy")))
        self.assertEqual(data[37:53], b"\x00" * 16)
        self.assertEqual(int.from_bytes(data[53:55], "big"), 16)
        self.assertEqual(data[55:71], cred)

    def test_aaguid_must_be_16_bytes(self):
        with self.assertRaises(ValueError):
            w.authenticator_data("x", w.FLAG_UP, 0, attested=(b"short", b"c", {}))

    def test_credential_id_length_is_capped(self):
        with self.assertRaises(ValueError):
            w.authenticator_data("x", w.FLAG_UP, 0, attested=(b"\x00" * 16, b"c" * 1024, {}))

    def test_extensions_appended(self):
        self.assertTrue(w.authenticator_data("x", w.FLAG_UP, 0, extensions={"a": 1})
                        .endswith(w.cbor_encode({"a": 1})))


class CoseKey(unittest.TestCase):
    def test_es256_key_fields(self):
        k = w.cose_es256(b"x" * 32, b"y" * 32)
        self.assertEqual(k[1], 2)     # kty: EC2
        self.assertEqual(k[3], -7)    # alg: ES256
        self.assertEqual(k[-1], 1)    # crv: P-256


class Attestation(unittest.TestCase):
    def test_none_attestation_shape(self):
        obj = w.attestation_object(b"authdata")
        n, hdr = w.cbor_map_length(obj)
        self.assertEqual(n, 3)
        self.assertIn(b"\x63fmt", obj)          # "fmt"
        self.assertIn(b"none", obj)
        self.assertIn(b"authData", obj)

    def test_empty_att_stmt(self):
        # The map is built fmt, attStmt, authData — so authData comes LAST and the
        # object cannot end with the empty attStmt map. Assert the pair explicitly:
        # text(7) "attStmt" followed by the empty map. (My first version asserted
        # endswith(b"\xa0") and was wrong about the order, not the encoder.)
        self.assertIn(b"\x67attStmt\xa0", w.attestation_object(b"a"))

    def test_fmt_is_overridable(self):
        self.assertIn(b"packed", w.attestation_object(b"a", fmt="packed"))


class ClientData(unittest.TestCase):
    def test_fields_and_compact_separators(self):
        raw = w.client_data("webauthn.get", "CH", "https://example.com")
        self.assertEqual(raw, b'{"type":"webauthn.get","challenge":"CH",'
                              b'"origin":"https://example.com"}')

    def test_challenge_is_echoed_verbatim(self):
        self.assertIn(b'"challenge":"a-b_c"', w.client_data("webauthn.get", "a-b_c", "o"))

    def test_token_binding_included_only_when_given(self):
        self.assertNotIn(b"tokenBinding", w.client_data("t", "c", "o"))
        self.assertIn(b"tokenBinding", w.client_data("t", "c", "o", {"status": "supported"}))

    def test_signature_base_hashes_the_client_data(self):
        cd = b'{"x":1}'
        base = w.assertion_signature_base(b"AD", cd)
        self.assertEqual(base, b"AD" + __import__("hashlib").sha256(cd).digest())
        self.assertEqual(len(base), 2 + 32)


class ResponseShapes(unittest.TestCase):
    def test_create_response(self):
        out = w.public_key_credential(b"id", b"att", b"cd")
        self.assertEqual(out["type"], "public-key")
        self.assertEqual(out["rawId"], out["id"])
        self.assertIn("attestationObject", out["response"])

    def test_create_response_omits_transports_when_unset(self):
        self.assertNotIn("transports", w.public_key_credential(b"i", b"a", b"c")["response"])

    def test_create_response_includes_transports_when_set(self):
        out = w.public_key_credential(b"i", b"a", b"c", transports=["usb"])
        self.assertEqual(out["response"]["transports"], ["usb"])

    def test_get_response(self):
        out = w.assertion_response(b"id", b"ad", b"cd", b"sig")
        self.assertIn("authenticatorData", out["response"])
        self.assertIn("signature", out["response"])
        self.assertNotIn("userHandle", out["response"])

    def test_get_response_includes_user_handle(self):
        self.assertEqual(w.assertion_response(b"i", b"a", b"c", b"s", user_handle=b"u")
                         ["response"]["userHandle"], w.b64u_encode(b"u"))

    def test_credential_ids_are_random_and_32_bytes(self):
        a, b = w.make_credential_id(), w.make_credential_id()
        self.assertEqual(len(a), 32)
        self.assertNotEqual(a, b)


@unittest.skipUnless(HAVE_CRYPTO, "cryptography not installed")
class RealSignatureRoundTrip(unittest.TestCase):
    """The test that actually matters: sign, then verify the way a relying party would."""

    def _sign(self, private_key, auth_data, cd):
        return private_key.sign(w.assertion_signature_base(auth_data, cd),
                                ec.ECDSA(hashes.SHA256()))

    def test_a_signature_over_correctly_encoded_data_verifies(self):
        key = ec.generate_private_key(ec.SECP256R1())
        auth = w.authenticator_data("example.com", w.FLAG_UP | w.FLAG_UV, 1)
        cd = w.client_data("webauthn.get", w.b64u_encode(os.urandom(32)), "https://example.com")
        self.assertTrue(w.verify_assertion(key.public_key(), auth, cd, self._sign(key, auth, cd)))

    def test_wrong_rp_id_breaks_verification(self):
        key = ec.generate_private_key(ec.SECP256R1())
        auth = w.authenticator_data("example.com", w.FLAG_UP, 1)
        cd = w.client_data("webauthn.get", "c", "o")
        sig = self._sign(key, auth, cd)
        # re-encode the authData for a DIFFERENT rp: the signature must no longer verify
        other = w.authenticator_data("evil.com", w.FLAG_UP, 1)
        self.assertFalse(w.verify_assertion(key.public_key(), other, cd, sig))

    def test_tampered_challenge_breaks_verification(self):
        key = ec.generate_private_key(ec.SECP256R1())
        auth = w.authenticator_data("example.com", w.FLAG_UP, 1)
        cd = w.client_data("webauthn.get", "real-challenge", "o")
        sig = self._sign(key, auth, cd)
        tampered = w.client_data("webauthn.get", "other-challenge", "o")
        self.assertFalse(w.verify_assertion(key.public_key(), auth, tampered, sig))

    def test_a_cose_encoded_public_key_matches_the_signer(self):
        key = ec.generate_private_key(ec.SECP256R1())
        nums = key.public_key().public_numbers()
        cose = w.cose_es256(nums.x.to_bytes(32, "big"), nums.y.to_bytes(32, "big"))
        self.assertEqual(len(cose[-2]), 32)
        self.assertEqual(int.from_bytes(cose[-2], "big"), nums.x)

    def test_signer_counter_is_bound_into_the_signature(self):
        key = ec.generate_private_key(ec.SECP256R1())
        cd = w.client_data("webauthn.get", "c", "o")
        sig = self._sign(key, w.authenticator_data("e", w.FLAG_UP, 5), cd)
        self.assertFalse(w.verify_assertion(
            key.public_key(), w.authenticator_data("e", w.FLAG_UP, 6), cd, sig))

    def test_uv_flag_is_bound_into_the_signature(self):
        key = ec.generate_private_key(ec.SECP256R1())
        cd = w.client_data("webauthn.get", "c", "o")
        sig = self._sign(key, w.authenticator_data("e", w.FLAG_UP | w.FLAG_UV, 1), cd)
        self.assertFalse(w.verify_assertion(
            key.public_key(), w.authenticator_data("e", w.FLAG_UP, 1), cd, sig))


class StrictDecoding(unittest.TestCase):
    def test_rejects_characters_outside_the_alphabet(self):
        # a lenient decoder silently DROPS junk, so "not b64u!!" would decode to plausible
        # bytes and a page could smuggle a wrong challenge past the broker
        with self.assertRaises(Exception):
            w.b64u_decode("not b64u!!")

    def test_rejects_an_impossible_length(self):
        # 5 data characters cannot form base64 (1 more than a multiple of 4)
        with self.assertRaises(Exception):
            w.b64u_decode("AAAAA")


class CborMapLengthHeader(unittest.TestCase):
    """cbor_map_length reads back the header the encoder wrote. 23 entries still fit the
    one-byte form; 24 is the boundary where the two-byte form (additional info = 24) begins."""

    def test_23_entries_use_the_single_byte_form(self):
        self.assertEqual(w.cbor_map_length(w.cbor_encode({i: i for i in range(23)})), (23, 1))

    def test_24_entries_use_the_two_byte_form(self):
        self.assertEqual(w.cbor_map_length(w.cbor_encode({i: i for i in range(24)})), (24, 2))


class CredentialIdLengthBoundary(unittest.TestCase):
    """authenticatorData carries the credential id with a 2-byte length prefix, so the spec
    caps it at 1023 bytes. 1023 must be accepted and 1024 rejected — the boundary, not the
    neighbourhood."""

    def _attested(self, cred_len):
        return w.authenticator_data(
            "example.com", w.FLAG_UP, 0,
            attested=(b"\x00" * 16, b"x" * cred_len, w.cose_es256(b"a" * 32, b"b" * 32)))

    def test_1023_bytes_accepted(self):
        self.assertIsInstance(self._attested(1023), bytes)

    def test_1024_bytes_rejected(self):
        with self.assertRaises(ValueError):
            self._attested(1024)


if __name__ == "__main__":
    unittest.main(verbosity=2)
