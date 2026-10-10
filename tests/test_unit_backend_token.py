#!/usr/bin/env python3
"""Unit tests for the CTAP2 token backend, driven by a fake CTAP device.

The real security key is not attached most of the time — and never in CI — so the backend is
written to be exercised through an injected Ctap2-like object. The fake is built from real
python-fido2 data classes (AttestedCredentialData / AuthenticatorData) so the shapes match what
the hardware actually returns, rather than from ad-hoc dicts that would let a real mismatch
through.
"""
import hashlib
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "bin"))
import webauthn_core as w  # noqa: E402
from backend_token import TokenBackend, TokenError, _uv_supported  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from fido2.cose import ES256  # noqa: E402
from fido2.webauthn import AttestedCredentialData, AuthenticatorData  # noqa: E402

CLIENT_CREATE = w.client_data("webauthn.create", "Y2hhbGxlbmdl", "https://example.com")
CLIENT_GET = w.client_data("webauthn.get", "Y2hhbGxlbmdl", "https://example.com")


def make_credential_data(cred_id=b"token-cred-id"):
    key = ec.generate_private_key(ec.SECP256R1())
    cose = ES256.from_cryptography_key(key.public_key())
    return AttestedCredentialData.create(b"\xaa" * 16, cred_id, cose)


class FakeInfo:
    def __init__(self, options):
        self.options = options


class FakeAttestation:
    def __init__(self, auth_data, fmt="packed", att_stmt=None):
        self.auth_data = auth_data
        self.fmt = fmt
        self.att_stmt = att_stmt if att_stmt is not None else {"alg": -7, "sig": b"x"}


class FakeAssertion:
    def __init__(self, auth_data, signature, user=None):
        self.auth_data = auth_data
        self.signature = signature
        self.user = user


class FakeCtap:
    def __init__(self, options=None, user_handle=b"\x01\x02", fmt="packed"):
        self.info = FakeInfo(options if options is not None else {"rk": True})
        self.calls = []
        self._cred_data = make_credential_data()
        self._user_handle = user_handle
        self._fmt = fmt

    def make_credential(self, client_data_hash, rp, user, key_params, exclude_list=None,
                        extensions=None, options=None, **kwargs):
        self.calls.append(("make_credential", rp, user, key_params, options))
        ad = AuthenticatorData.create(
            w.rp_id_hash(rp["id"]),
            AuthenticatorData.FLAG.UP | AuthenticatorData.FLAG.AT, 0, bytes(self._cred_data))
        return FakeAttestation(ad, self._fmt)

    def get_assertion(self, rp_id, client_data_hash, allow_list=None, options=None, **kwargs):
        self.calls.append(("get_assertion", rp_id, allow_list, options))
        ad = AuthenticatorData.create(w.rp_id_hash(rp_id), AuthenticatorData.FLAG.UP, 4, b"")
        return FakeAssertion(ad, b"signature-bytes", {"id": self._user_handle, "name": "u"})


class UvSupport(unittest.TestCase):
    def test_uv_option(self):
        self.assertTrue(_uv_supported(FakeCtap({"uv": True})))

    def test_client_pin_option(self):
        self.assertTrue(_uv_supported(FakeCtap({"clientPin": True})))

    def test_rk_only_is_not_uv(self):
        self.assertFalse(_uv_supported(FakeCtap({"rk": True})))

    def test_missing_options_is_false(self):
        self.assertFalse(_uv_supported(FakeCtap(None)))

    def test_no_info_attribute_is_false(self):
        class Bare:
            pass
        self.assertFalse(_uv_supported(Bare()))


class Register(unittest.TestCase):
    def test_record_has_no_private_key(self):
        be = TokenBackend(ctap=FakeCtap())
        rec, _ = be.register("example.com", CLIENT_CREATE, b"user-1")
        self.assertNotIn("private_pem", rec)          # the whole point of the token backend
        self.assertEqual(rec["backend"], "token")

    def test_record_metadata(self):
        be = TokenBackend(ctap=FakeCtap())
        rec, _ = be.register("example.com", CLIENT_CREATE, b"user-1")
        self.assertEqual(rec["rp_id"], "example.com")
        self.assertEqual(rec["alg"], -7)
        self.assertEqual(rec["aaguid"], "aa" * 16)

    def test_rk_requested(self):
        ctap = FakeCtap()
        TokenBackend(ctap=ctap).register("example.com", CLIENT_CREATE, b"user-1")
        method, rp, user, key_params, options = ctap.calls[0]
        self.assertEqual(method, "make_credential")
        self.assertTrue(options["rk"])
        self.assertEqual(key_params[0]["alg"], -7)

    def test_uv_only_requested_when_supported(self):
        plain = FakeCtap({"rk": True})
        TokenBackend(ctap=plain).register("example.com", CLIENT_CREATE, uv=True)
        self.assertNotIn("uv", plain.calls[0][4])
        capable = FakeCtap({"rk": True, "uv": True})
        TokenBackend(ctap=capable).register("example.com", CLIENT_CREATE, uv=True)
        self.assertTrue(capable.calls[0][4]["uv"])

    def test_uv_flag_false_never_requested(self):
        capable = FakeCtap({"rk": True, "uv": True})
        TokenBackend(ctap=capable).register("example.com", CLIENT_CREATE, uv=False)
        self.assertNotIn("uv", capable.calls[0][4])

    def test_response_shape(self):
        be = TokenBackend(ctap=FakeCtap())
        _, resp = be.register("example.com", CLIENT_CREATE, b"user-1")
        self.assertEqual(resp["type"], "public-key")
        self.assertEqual(resp["response"]["transports"], ["usb"])
        self.assertEqual(w.b64u_decode(resp["response"]["clientDataJSON"]), CLIENT_CREATE)

    def test_attestation_object_format_preserved(self):
        be = TokenBackend(ctap=FakeCtap(fmt="packed"))
        _, resp = be.register("example.com", CLIENT_CREATE)
        from fido2 import cbor
        att = cbor.decode(w.b64u_decode(resp["response"]["attestationObject"]))
        self.assertEqual(att["fmt"], "packed")
        self.assertEqual(att["attStmt"], {"alg": -7, "sig": b"x"})

    def test_client_data_hash_is_sha256(self):
        seen = {}

        class C(FakeCtap):
            def make_credential(self, cdh, rp, user, kp, **kw):
                seen["cdh"] = cdh
                return super().make_credential(cdh, rp, user, kp, **kw)
        TokenBackend(ctap=C()).register("example.com", CLIENT_CREATE)
        self.assertEqual(seen["cdh"], hashlib.sha256(CLIENT_CREATE).digest())


class Authenticate(unittest.TestCase):
    def test_response_uses_record_cred_id(self):
        be = TokenBackend(ctap=FakeCtap())
        rec, _ = be.register("example.com", CLIENT_CREATE, b"user-1")
        _, resp = be.authenticate(rec, CLIENT_GET)
        self.assertEqual(resp["id"], rec["cred_id"])

    def test_sign_count_from_counter(self):
        be = TokenBackend(ctap=FakeCtap())
        rec, _ = be.register("example.com", CLIENT_CREATE, b"user-1")
        updates, resp = be.authenticate(rec, CLIENT_GET)
        self.assertEqual(updates["sign_count"], 4)

    def test_user_handle_from_assertion(self):
        be = TokenBackend(ctap=FakeCtap(user_handle=b"\x09\x08"))
        rec, _ = be.register("example.com", CLIENT_CREATE, b"user-1")
        _, resp = be.authenticate(rec, CLIENT_GET)
        self.assertEqual(w.b64u_decode(resp["response"]["userHandle"]), b"\x09\x08")

    def test_no_user_omits_handle(self):
        be = TokenBackend(ctap=FakeCtap())
        rec, _ = be.register("example.com", CLIENT_CREATE, b"user-1")

        class NoUser(FakeCtap):
            def get_assertion(self, rp_id, cdh, allow_list=None, options=None, **kw):
                self.calls.append(("get_assertion", rp_id, allow_list, options))
                ad = AuthenticatorData.create(w.rp_id_hash(rp_id),
                                              AuthenticatorData.FLAG.UP, 1, b"")
                return FakeAssertion(ad, b"sig", None)
        rec2, _ = TokenBackend(ctap=NoUser()).register("example.com", CLIENT_CREATE)
        _, resp = TokenBackend(ctap=NoUser()).authenticate(rec2, CLIENT_GET)
        self.assertNotIn("userHandle", resp["response"])
        self.assertEqual(rec["cred_id"], rec["cred_id"])   # silence unused

    def test_allow_list_uses_stored_cred_id(self):
        ctap = FakeCtap()
        be = TokenBackend(ctap=ctap)
        rec, _ = be.register("example.com", CLIENT_CREATE, b"user-1")
        ctap.calls.clear()
        be.authenticate(rec, CLIENT_GET)
        method, rp_id, allow, options = ctap.calls[0]
        self.assertEqual(method, "get_assertion")
        self.assertEqual(rp_id, "example.com")
        self.assertEqual(allow[0]["id"], w.b64u_decode(rec["cred_id"]))


class NoDevice(unittest.TestCase):
    def test_missing_device_raises_token_error(self):
        import fido2.hid
        original = fido2.hid.CtapHidDevice.list_devices
        fido2.hid.CtapHidDevice.list_devices = staticmethod(lambda: [])
        try:
            with self.assertRaises(TokenError):
                TokenBackend().register("example.com", CLIENT_CREATE)
        finally:
            fido2.hid.CtapHidDevice.list_devices = original


class RealDevicePath(unittest.TestCase):
    """Exercise the non-injected path: the code that opens the real HID device and wraps it in
    Ctap2. Both the device list lookup and the Ctap2 constructor are faked, so the code path
    runs without hardware — which is also the only way to catch an off-by-one in the device
    selection."""

    def test_the_one_attached_device_is_the_one_used(self):
        import fido2.ctap2
        import fido2.hid

        class FakeDev:
            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        fake = FakeCtap({"rk": True})
        orig_list = fido2.hid.CtapHidDevice.list_devices
        orig_ctap = fido2.ctap2.Ctap2
        fido2.hid.CtapHidDevice.list_devices = staticmethod(lambda: [FakeDev()])
        fido2.ctap2.Ctap2 = lambda dev: fake
        try:
            rec, _ = TokenBackend().register("example.com", CLIENT_CREATE)
            self.assertEqual(rec["backend"], "token")
        finally:
            fido2.hid.CtapHidDevice.list_devices = orig_list
            fido2.ctap2.Ctap2 = orig_ctap

    def test_register_defaults_to_requesting_uv_when_capable(self):
        capable = FakeCtap({"rk": True, "uv": True})
        TokenBackend(ctap=capable).register("example.com", CLIENT_CREATE)   # no uv arg
        self.assertTrue(capable.calls[0][4]["uv"])


class AuthenticateUv(unittest.TestCase):
    """The uv decision on the assertion path, against a token that COULD verify: it must be
    requested exactly when asked for, and not otherwise."""

    def _assertion_options(self, uv):
        capable = FakeCtap({"rk": True, "uv": True})
        be = TokenBackend(ctap=capable)
        rec, _ = be.register("example.com", CLIENT_CREATE)
        capable.calls.clear()
        be.authenticate(rec, CLIENT_GET, uv=uv)
        return capable.calls[0][3]

    def test_uv_requested_when_capable(self):
        self.assertEqual(self._assertion_options(True), {"uv": True})

    def test_uv_not_requested_when_false(self):
        self.assertIsNone(self._assertion_options(False))


if __name__ == "__main__":
    unittest.main()
