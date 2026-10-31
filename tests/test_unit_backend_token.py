#!/usr/bin/env python3
"""Unit tests for the CTAP2 token backend, driven by a fake CTAP device.

The real security key is not attached most of the time — and never in CI — so the backend is
written to be exercised through an injected Ctap2-like object. The fake is built from real
python-fido2 data classes (AttestedCredentialData / AuthenticatorData) so the shapes match what
the hardware actually returns, rather than from ad-hoc dicts that would let a real mismatch
through.
"""
import builtins
import hashlib
import os
import pathlib
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "bin"))
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))  # tests/ (for _isolation)
from _isolation import isolate  # noqa: E402

setUpModule, tearDownModule = isolate()
import webauthn_core as w  # noqa: E402
from backend_token import TokenBackend, TokenError, _has_builtin_uv  # noqa: E402
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
        self.assertTrue(_has_builtin_uv(FakeCtap({"uv": True})))

    def test_client_pin_is_not_builtin_uv(self):
        # clientPin alone means a PIN, which is supplied via pin_uv_param, NOT options.uv;
        # treating it as built-in UV makes makeCredential fail with UNSUPPORTED_OPTION
        self.assertFalse(_has_builtin_uv(FakeCtap({"clientPin": True})))

    def test_rk_only_is_not_uv(self):
        self.assertFalse(_has_builtin_uv(FakeCtap({"rk": True})))

    def test_missing_options_is_false(self):
        self.assertFalse(_has_builtin_uv(FakeCtap(None)))

    def test_no_info_attribute_is_false(self):
        class Bare:
            pass
        self.assertFalse(_has_builtin_uv(Bare()))


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

    def test_user_handle_is_preserved(self):
        be = TokenBackend(ctap=FakeCtap())
        rec, _ = be.register("example.com", CLIENT_CREATE, b"u1")
        self.assertEqual(w.b64u_decode(rec["user_handle"]), b"u1")

    def test_absent_user_handle_gets_a_generated_one(self):
        # with no handle the token must still be given a NON-empty user id (an empty id is
        # rejected / meaningless), so this is not allowed to collapse to the empty bytes
        be = TokenBackend(ctap=FakeCtap())
        rec, _ = be.register("example.com", CLIENT_CREATE)
        self.assertTrue(rec["user_handle"])
        self.assertEqual(len(w.b64u_decode(rec["user_handle"])), 16)

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


class PinPrompt(unittest.TestCase):
    """The interactive PIN prompt: offered once, only when the token has a client PIN, and the
    value is cached for the process — never taken from argv."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.bindir = pathlib.Path(self.tmp.name)
        self.calls = pathlib.Path(self.tmp.name) / "prompts"
        stub = self.bindir / "systemd-ask-password"
        stub.write_text('#!/bin/bash\necho "$@" >> "%s"\nprintf "%%s\\n" "246810"\n'
                        % self.calls)
        stub.chmod(0o755)
        saved = os.environ.get("PATH")
        self.addCleanup(lambda: os.environ.__setitem__("PATH", saved) if saved is not None
                        else os.environ.pop("PATH", None))
        os.environ["PATH"] = "%s:%s" % (self.bindir, saved or "")
        for var in ("PASSKEY_TOKEN_PIN", "PASSKEY_BROKER_NO_PROMPT"):
            prev = os.environ.pop(var, None)
            self.addCleanup(lambda v=var, p=prev: os.environ.__setitem__(v, p) if p is not None
                            else os.environ.pop(v, None))

    def prompts(self):
        return self.calls.read_text().splitlines() if self.calls.exists() else []

    def test_a_client_pin_token_is_prompted_once_and_cached(self):
        # The prompt is asked through the token's advert, so it is exercised directly rather
        # than through a full CTAP PIN exchange the fake device does not implement.
        ctap = FakeCtap({"rk": True, "clientPin": True})
        be = TokenBackend(ctap=ctap)
        self.assertEqual(be._effective_pin(ctap), "246810")
        self.assertEqual(be._effective_pin(ctap), "246810", "the second call uses the cache")
        self.assertEqual(len(self.prompts()), 1, "the user is asked exactly once")
        self.assertEqual(be._pin, "246810")
        self.assertIn("--timeout=120", self.prompts()[0],
                      "the prompt carries the helper's own timeout")

    def test_a_token_without_client_pin_is_never_prompted(self):
        ctap = FakeCtap({"rk": True})
        self.assertIsNone(TokenBackend(ctap=ctap)._effective_pin(ctap))
        self.assertEqual(self.prompts(), [], "a PIN-less token must not prompt")

    def test_a_configured_pin_is_used_without_prompting(self):
        ctap = FakeCtap({"rk": True, "clientPin": True})
        be = TokenBackend(ctap=ctap, pin="999999")
        self.assertEqual(be._effective_pin(ctap), "999999")
        self.assertEqual(self.prompts(), [])

    def test_prompting_can_be_forbidden(self):
        os.environ["PASSKEY_BROKER_NO_PROMPT"] = "1"
        ctap = FakeCtap({"rk": True, "clientPin": True})
        self.assertIsNone(TokenBackend(ctap=ctap)._effective_pin(ctap))
        self.assertEqual(self.prompts(), [], "the opt-out must be honoured")

    def test_no_askpass_helper_means_no_prompt_and_no_crash(self):
        os.environ["PATH"] = str(self.bindir / "empty")
        be = TokenBackend(ctap=FakeCtap({"rk": True, "clientPin": True}))
        rec, _ = be.register("example.com", CLIENT_CREATE, b"u1")   # must not raise
        self.assertIsNone(be._pin)
        self.assertEqual(rec["uv"], False, "with no PIN there is no token-verified UV")


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


class PinSupport(unittest.TestCase):
    """The token's PIN path. This key (clientPin set) refuses a ceremony with PUAT_REQUIRED
    until a PIN/UV auth token is supplied, so the backend must obtain one and pass it through,
    and report a missing/incorrect PIN clearly rather than as an opaque CTAP code."""

    class RecordingCtap(FakeCtap):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.kwargs = []

        def make_credential(self, *a, **kw):
            self.kwargs.append(kw)
            return super().make_credential(*a, **kw)

        def get_assertion(self, *a, **kw):
            self.kwargs.append(kw)
            return super().get_assertion(*a, **kw)

    def test_no_pin_yields_no_uv_params(self):
        self.assertEqual(TokenBackend()._uv_params(FakeCtap(), None), (None, None))

    def test_pin_auth_signs_the_client_data_hash(self):
        class Proto:
            VERSION = 1

            @staticmethod
            def authenticate(token, message):
                return b"SIG(" + token + b"," + message + b")"

        param, protocol = TokenBackend._pin_auth(Proto(), b"tok", b"hash")
        self.assertEqual(param, b"SIG(tok,hash)")
        self.assertEqual(protocol, 1)

    def test_pin_auth_is_absent_without_a_token(self):
        # no token -> no pinUvAuthParam at all (not the raw None-as-value)
        self.assertEqual(TokenBackend._pin_auth(object(), None, b"hash"), (None, None))

    def test_pin_produces_a_token_and_protocol(self):
        import fido2.ctap2.pin as pinmod

        class FakeClientPin:
            PERMISSION = pinmod.ClientPin.PERMISSION

            def __init__(self, ctap):
                self.protocol = type("P", (), {"VERSION": 3})()
                self.seen = {}

            def get_pin_token(self, value, permissions=None):
                self.seen["pin"] = value
                self.seen["permissions"] = permissions
                return b"pin-token"

        original = pinmod.ClientPin
        pinmod.ClientPin = FakeClientPin
        try:
            proto, token = TokenBackend()._uv_params(FakeCtap(), "123456")
        finally:
            pinmod.ClientPin = original
        self.assertEqual(token, b"pin-token")
        self.assertEqual(proto.VERSION, 3)

    def test_register_passes_the_pin_token(self):
        import fido2.ctap2.pin as pinmod

        class Proto:
            VERSION = 2

            @staticmethod
            def authenticate(token, message):
                return b"auth"

        class FakeClientPin:
            PERMISSION = pinmod.ClientPin.PERMISSION

            def __init__(self, ctap):
                self.protocol = Proto()

            def get_pin_token(self, value, permissions=None):
                return b"tok"

        ctap = self.RecordingCtap({"rk": True, "clientPin": True})
        original = pinmod.ClientPin
        pinmod.ClientPin = FakeClientPin
        try:
            TokenBackend(ctap=ctap, pin="123456").register("example.com", CLIENT_CREATE)
        finally:
            pinmod.ClientPin = original
        self.assertEqual(ctap.kwargs[0]["pin_uv_param"], b"auth")
        self.assertEqual(ctap.kwargs[0]["pin_uv_protocol"], 2)
        # with a PIN the UV flag is set by pinUvAuthParam — options.uv must NOT be sent, or a
        # key without built-in UV answers UNSUPPORTED_OPTION
        self.assertNotIn("uv", ctap.calls[0][4])

    def test_authenticate_passes_the_pin_token(self):
        import fido2.ctap2.pin as pinmod

        class Proto:
            VERSION = 2

            @staticmethod
            def authenticate(token, message):
                return b"auth"

        class FakeClientPin:
            PERMISSION = pinmod.ClientPin.PERMISSION

            def __init__(self, ctap):
                self.protocol = Proto()

            def get_pin_token(self, value, permissions=None):
                return b"tok"

        ctap = self.RecordingCtap({"rk": True, "clientPin": True})
        original = pinmod.ClientPin
        pinmod.ClientPin = FakeClientPin
        try:
            be = TokenBackend(ctap=ctap, pin="123456")
            rec, _ = be.register("example.com", CLIENT_CREATE)
            ctap.kwargs.clear()
            be.authenticate(rec, CLIENT_GET)
        finally:
            pinmod.ClientPin = original
        self.assertEqual(ctap.kwargs[0]["pin_uv_param"], b"auth")


class ErrorTranslation(unittest.TestCase):
    def _err(self, code):
        from fido2.ctap import CtapError
        return CtapError(code)

    def test_puat_required_without_pin_names_the_env_var(self):
        from backend_token import PIN_ENV
        exc = TokenBackend._explain(self._err(0x36), None)
        self.assertIsInstance(exc, TokenError)
        self.assertIn(PIN_ENV, str(exc))

    def test_puat_required_with_a_pin_is_not_blamed_on_the_pin(self):
        exc = TokenBackend._explain(self._err(0x36), b"tok")
        self.assertNotIn("set PASSKEY", str(exc))

    def test_pin_invalid_is_reported(self):
        exc = TokenBackend._explain(self._err(0x31), b"tok")
        self.assertIn("PIN_INVALID", str(exc))

    def test_pin_auth_blocked_is_reported(self):
        exc = TokenBackend._explain(self._err(0x34), b"tok")
        self.assertIn("blocked", str(exc))

    def test_other_errors_are_generic(self):
        exc = TokenBackend._explain(self._err(0x01), None)
        self.assertIn("refused", str(exc))


class TokenUvReporting(unittest.TestCase):
    """The record/updates the token backend returns must carry the token's OWN uv outcome, so
    the broker reports what the authenticator did rather than the local fingerprint check."""

    @staticmethod
    def _client_pin():
        import fido2.ctap2.pin as pinmod

        class Proto:
            VERSION = 1

            @staticmethod
            def authenticate(token, message):
                return b"auth"

        class FakeClientPin:
            PERMISSION = pinmod.ClientPin.PERMISSION

            def __init__(self, ctap):
                self.protocol = Proto()

            def get_pin_token(self, value, permissions=None):
                return b"tok"

        return pinmod, FakeClientPin

    def test_register_with_pin_records_uv(self):
        pinmod, fake = self._client_pin()
        original = pinmod.ClientPin
        pinmod.ClientPin = fake
        try:
            rec, _ = TokenBackend(ctap=FakeCtap({"rk": True}), pin="123456").register(
                "example.com", CLIENT_CREATE)
        finally:
            pinmod.ClientPin = original
        self.assertTrue(rec["uv"])

    def test_register_without_pin_records_no_uv(self):
        rec, _ = TokenBackend(ctap=FakeCtap({"rk": True})).register("example.com",
                                                                    CLIENT_CREATE)
        self.assertFalse(rec["uv"])

    def test_authenticate_reports_token_uv(self):
        pinmod, fake = self._client_pin()
        original = pinmod.ClientPin
        pinmod.ClientPin = fake
        try:
            be = TokenBackend(ctap=FakeCtap({"rk": True}), pin="123456")
            rec, _ = be.register("example.com", CLIENT_CREATE)
            updates, _ = be.authenticate(rec, CLIENT_GET)
        finally:
            pinmod.ClientPin = original
        self.assertTrue(updates["uv"])

    def test_authenticate_without_pin_reports_no_uv(self):
        be = TokenBackend(ctap=FakeCtap({"rk": True}))
        rec, _ = be.register("example.com", CLIENT_CREATE)
        updates, _ = be.authenticate(rec, CLIENT_GET)
        self.assertFalse(updates["uv"])


class VerificationContract(unittest.TestCase):
    """The broker reads ``self_verifies`` to decide whether to run the LOCAL fingerprint check.
    A token validates the user itself (its PIN, which sets the UV flag), so requiring fprintd as
    well made an attached key unusable on a machine whose sensor the owner cannot use — the bug
    this flags against. Getting it wrong the other way would report unverified keys as verified.
    """

    def test_the_token_verifies_itself(self):
        self.assertTrue(TokenBackend().self_verifies)


class Availability(unittest.TestCase):
    """``available()`` decides whether a browser ceremony is sent to the KEY. Getting it wrong in
    either direction breaks the user: claiming a key that is not there fails the ceremony, and
    missing one that IS attached sends them to the fingerprint gate they cannot satisfy."""

    def test_true_when_a_key_was_injected(self):
        self.assertTrue(TokenBackend(ctap=object()).available())

    def test_true_when_a_device_is_attached(self):
        from fido2.hid import CtapHidDevice
        with mock.patch.object(CtapHidDevice, "list_devices", staticmethod(lambda: [object()])):
            self.assertTrue(TokenBackend().available())

    def test_false_when_no_device_is_attached(self):
        from fido2.hid import CtapHidDevice
        with mock.patch.object(CtapHidDevice, "list_devices", staticmethod(lambda: [])):
            self.assertFalse(TokenBackend().available())

    def test_false_when_the_device_list_errors(self):
        from fido2.hid import CtapHidDevice

        def boom():
            raise OSError("no hidraw")

        with mock.patch.object(CtapHidDevice, "list_devices", staticmethod(boom)):
            self.assertFalse(TokenBackend().available())

    def test_false_when_fido2_is_not_installed(self):
        real_import = builtins.__import__

        def fake(name, *args, **kwargs):
            if name == "fido2.hid":
                raise ImportError("python-fido2 is not installed")
            return real_import(name, *args, **kwargs)

        with mock.patch.object(builtins, "__import__", fake):
            self.assertFalse(TokenBackend().available())


if __name__ == "__main__":
    unittest.main()
