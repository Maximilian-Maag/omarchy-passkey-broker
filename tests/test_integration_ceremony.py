#!/usr/bin/env python3
"""Integration tests for the full WebAuthn ceremony, verified as a relying party would.

The unit tests check the pieces; this checks the thing that matters to a real login — that the
bytes the broker produces verify against the public key a relying party would have stored, with
the exact clientDataJSON echoed, and that sign_count moves the way a replay check expects.
"""
import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "bin"))
import webauthn_core as w  # noqa: E402
from broker import PasskeyBroker  # noqa: E402
from broker_store import CredentialStore  # noqa: E402
from broker_verify import NullVerifier  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from fido2 import cbor  # noqa: E402


def cose_to_public_key(att_obj):
    att = cbor.decode(att_obj)
    auth_data = att["authData"]
    cose = cbor.decode(auth_data[32 + 1 + 4 + 16 + 2 + 32:])
    return ec.EllipticCurvePublicNumbers(int.from_bytes(cose[-2], "big"),
                                         int.from_bytes(cose[-3], "big"),
                                         ec.SECP256R1()).public_key()


class Ceremony(unittest.TestCase):
    def setUp(self):
        self.broker = PasskeyBroker(store=CredentialStore(pathlib.Path(tempfile.mkdtemp())),
                                    verifier=NullVerifier(True))

    def client_data(self, typ, challenge=b"challenge-bytes", rp="example.com"):
        return w.client_data(typ, w.b64u_encode(challenge), "https://%s" % rp)

    def register(self, rp="example.com", user=b"user-1"):
        cd = self.client_data("webauthn.create", rp=rp)
        result = self.broker.register(rp, w.b64u_encode(cd), w.b64u_encode(user))
        self.assertTrue(result["ok"], result)
        return result, cd

    def authenticate(self, rp="example.com", **kw):
        cd = self.client_data("webauthn.get", rp=rp)
        result = self.broker.authenticate(rp, w.b64u_encode(cd), **kw)
        self.assertTrue(result["ok"], result)
        return result, cd

    def test_registration_attestation_verifies(self):
        result, cd = self.register()
        att = cbor.decode(w.b64u_decode(result["credential"]["response"]["attestationObject"]))
        self.assertEqual(att["fmt"], "none")
        # the clientDataJSON the RP hashed is exactly the one it sent
        self.assertEqual(w.b64u_decode(result["credential"]["response"]["clientDataJSON"]), cd)
        # rpIdHash inside authenticatorData matches the rp the RP expects
        self.assertEqual(att["authData"][:32], w.rp_id_hash("example.com"))

    def test_assertion_verifies_as_rp(self):
        reg, _ = self.register()
        pub = cose_to_public_key(w.b64u_decode(reg["credential"]["response"]["attestationObject"]))
        auth, cd = self.authenticate()
        r = auth["credential"]["response"]
        self.assertEqual(w.b64u_decode(r["clientDataJSON"]), cd)
        self.assertTrue(w.verify_assertion(pub, w.b64u_decode(r["authenticatorData"]),
                                           w.b64u_decode(r["clientDataJSON"]),
                                           w.b64u_decode(r["signature"])))

    def test_assertion_for_wrong_rp_fails(self):
        reg, _ = self.register()
        pub = cose_to_public_key(w.b64u_decode(reg["credential"]["response"]["attestationObject"]))
        auth, cd = self.authenticate()
        r = auth["credential"]["response"]
        # swap in authenticatorData for a different rp — the signature must no longer verify
        other_ad = w.authenticator_data("evil.com", w.FLAG_UP | w.FLAG_UV, 1)
        self.assertFalse(w.verify_assertion(pub, other_ad, w.b64u_decode(r["clientDataJSON"]),
                                            w.b64u_decode(r["signature"])))

    def test_sign_count_is_monotonic(self):
        self.register()
        counts = []
        for _ in range(3):
            auth, _ = self.authenticate()
            counts.append(int.from_bytes(
                w.b64u_decode(auth["credential"]["response"]["authenticatorData"])[33:37], "big"))
        self.assertEqual(counts, [1, 2, 3])

    def test_allow_credentials_selects_credential(self):
        first, _ = self.register(user=b"a")
        second, _ = self.register(user=b"b")
        want = second["credential"]["id"]
        auth, _ = self.authenticate(allow_ids=[want])
        self.assertEqual(auth["credential"]["id"], want)
        self.assertNotEqual(auth["credential"]["id"], first["credential"]["id"])

    def test_user_handle_round_trips(self):
        self.register(user=b"the-user")
        auth, _ = self.authenticate()
        self.assertEqual(w.b64u_decode(auth["credential"]["response"]["userHandle"]),
                         b"the-user")

    def test_unknown_rp_cannot_authenticate(self):
        self.register(rp="example.com")
        cd = self.client_data("webauthn.get", rp="other.com")
        self.assertEqual(self.broker.authenticate("other.com", w.b64u_encode(cd))["error"],
                         "no_credential")


if __name__ == "__main__":
    unittest.main()
