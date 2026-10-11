#!/usr/bin/env python3
"""The hardware token backend: a FIDO2 security key via CTAP2.

The point of this backend is that the private key is generated on the token and never leaves
it — the assertion is produced by the hardware, and the broker only ever sees a credential id
and a signature. That is strictly stronger than the software backend, so the broker prefers a
token credential when one exists.

Two device facts shape the code:

  * **User verification is the TOKEN's job, not the broker's.** A "Security Key by Yubico"
    with a PIN set answers a credential creation with CTAP2 ``PUAT_REQUIRED`` (0x36) until a
    PIN/UV auth token is supplied — proven by probe, not assumed. The local fprintd check
    cannot substitute for that; the token must be given its PIN, and only then does it set the
    UV flag in the authenticator data a relying party checks.
  * Every device interaction is funnelled through ``_ctap()`` so the whole backend can be
    exercised in tests with a fake CTAP object: the hardware is absent most of the time (and
    always in CI), and a backend that can only be tested with a security key plugged in would
    never be tested at all.
"""
import contextlib
import hashlib
import os

import webauthn_core as w

ALG_ES256 = -7

# Where the token's PIN is read from. Not a CLI flag: a secret in argv shows up in `ps` and in
# shell history, so it comes from the environment (or, later, an interactive pinentry).
PIN_ENV = "PASSKEY_TOKEN_PIN"


class TokenError(Exception):
    """No usable token, or the token refused the operation."""


def _has_builtin_uv(ctap):
    """Whether the token has BUILT-IN user verification (a fingerprint/face sensor).

    This is NOT the same as ``clientPin``, and conflating them is a real bug: passing
    ``options.uv`` to a key that lacks built-in UV is answered with
    CTAP2_ERR_UNSUPPORTED_OPTION (0x2B) — proven against a "Security Key by Yubico", which has
    ``clientPin`` set but no ``uv`` option. On a PIN-only key the UV flag is set by providing
    ``pinUvAuthParam`` instead, so this only ever decides whether to ask for *built-in* UV.
    """
    try:
        return bool((ctap.info.options or {}).get("uv"))
    except AttributeError:
        return False


class TokenBackend:
    name = "token"
    # The token verifies the user ITSELF: it validates the PIN and sets the UV flag from it.
    # So the broker must not also demand the local fingerprint — on a machine whose fingerprint
    # sensor the owner cannot use, that made an attached security key completely unusable.
    self_verifies = True

    def __init__(self, ctap=None, pin=None):
        self._injected = ctap
        self._pin = pin

    def available(self):
        """Is a usable security key attached? (An injected one counts, for tests.)

        Used to pick the backend for a browser ceremony. A token beats a key on disk, and — the
        part that actually bit — the software backend is gated by the LOCAL fingerprint, which a
        machine whose sensor the owner cannot use can never satisfy.
        """
        if self._injected is not None:
            return True
        try:
            from fido2.hid import CtapHidDevice
        except ImportError:
            return False
        try:
            return bool(list(CtapHidDevice.list_devices()))
        except Exception:
            return False

    @contextlib.contextmanager
    def _ctap(self):
        """Yield a Ctap2 object. An injected object (tests) is yielded as-is; otherwise the
        real HID device is opened for the duration of the operation, so the token is released
        as soon as the ceremony ends rather than held open by the daemon."""
        if self._injected is not None:
            yield self._injected
            return
        try:
            from fido2.ctap2 import Ctap2
            from fido2.hid import CtapHidDevice
        except ImportError as exc:                       # pragma: no cover - import guard
            raise TokenError("python-fido2 is not installed: %s" % (exc,))
        devices = list(CtapHidDevice.list_devices())
        if not devices:
            raise TokenError("no FIDO2 security key attached")
        with devices[0] as dev:
            yield Ctap2(dev)

    @staticmethod
    def _uv_params(ctap, pin):
        """(protocol, pin_uv_auth_token) for on-device UV, or (None, None) without a PIN.

        The token is asked for a PIN/UV auth token carrying the permissions this broker needs
        (make-credential and get-assertion); the token — never the broker — validates the PIN,
        and a wrong one comes back from the device as PIN_INVALID.

        Returns the *protocol* object, not just its version: the value the authenticator
        actually wants as ``pinUvAuthParam`` is the token authenticating the clientDataHash
        (``protocol.authenticate(token, client_data_hash)``). Sending the raw token is answered
        with CTAP2_ERR_PIN_AUTH_INVALID — proven against real hardware.
        """
        if not pin:
            return None, None
        from fido2.ctap2.pin import ClientPin
        client_pin = ClientPin(ctap)
        permissions = (ClientPin.PERMISSION.MAKE_CREDENTIAL
                       | ClientPin.PERMISSION.GET_ASSERTION)
        token = client_pin.get_pin_token(pin, permissions=permissions)
        return client_pin.protocol, token

    @staticmethod
    def _pin_auth(protocol, token, client_data_hash):
        """(pin_uv_param, pin_uv_protocol): the token signing this ceremony's clientDataHash."""
        if not token:
            return None, None
        return protocol.authenticate(token, client_data_hash), protocol.VERSION

    @staticmethod
    def _explain(exc, had_token):
        """Turn a CTAP refusal into something the user can act on."""
        from fido2.ctap import CtapError
        if exc.code == CtapError.ERR.PUAT_REQUIRED and not had_token:
            return TokenError(
                "the token requires a PIN to complete this ceremony; set %s and retry "
                "(the local fingerprint check is not a substitute — the token does the UV)"
                % PIN_ENV)
        if exc.code == CtapError.ERR.PIN_INVALID:
            return TokenError("the token rejected the PIN (PIN_INVALID)")
        if exc.code == CtapError.ERR.PIN_AUTH_BLOCKED:
            return TokenError("the token has blocked PIN authentication (too many attempts)")
        return TokenError("token refused the ceremony: %s" % (exc,))

    def register(self, rp_id, client_data_bytes, user_handle=b"", uv=True):
        from fido2.ctap import CtapError
        client_data_hash = hashlib.sha256(client_data_bytes).digest()
        user = {"id": user_handle or os.urandom(16), "name": "passkey"}
        with self._ctap() as ctap:
            protocol, token = self._uv_params(ctap, self._pin)
            options = {"rk": True}
            # A PIN supplies UV through pin_uv_param and the authenticator sets the UV flag
            # itself; asking for options.uv as well is rejected on a key without built-in UV.
            # options.uv is therefore only ever for a genuine built-in sensor.
            if not token and uv and _has_builtin_uv(ctap):
                options["uv"] = True
            pin_uv_param, pin_uv_protocol = self._pin_auth(protocol, token, client_data_hash)
            try:
                att = ctap.make_credential(client_data_hash, {"id": rp_id, "name": rp_id}, user,
                                           [{"type": "public-key", "alg": ALG_ES256}],
                                           options=options,
                                           pin_uv_param=pin_uv_param,
                                           pin_uv_protocol=pin_uv_protocol)
            except CtapError as exc:
                raise self._explain(exc, token)
        cred_data = att.auth_data.credential_data
        att_obj = w.attestation_object(bytes(att.auth_data), fmt=att.fmt, att_stmt=att.att_stmt)
        record = {
            "cred_id": w.b64u_encode(cred_data.credential_id),
            "rp_id": rp_id,
            "backend": self.name,
            "alg": ALG_ES256,
            "aaguid": bytes(cred_data.aaguid).hex(),
            "sign_count": int(att.auth_data.counter),
            "user_handle": w.b64u_encode(user["id"]),
            # Whether the TOKEN performed user verification (it did iff a PIN/UV auth token was
            # used). This is what the credential's UV flag actually is — distinct from the
            # broker's local fingerprint check, and previously mis-reported as the latter.
            "uv": bool(token),
            # No private key: it lives on the token. That absence is the whole point.
        }
        response = w.public_key_credential(cred_data.credential_id, att_obj, client_data_bytes,
                                           transports=["usb"])
        return record, response

    def authenticate(self, record, client_data_bytes, uv=True):
        from fido2.ctap import CtapError
        client_data_hash = hashlib.sha256(client_data_bytes).digest()
        cred_id = w.b64u_decode(record["cred_id"])
        allow = [{"type": "public-key", "id": cred_id}]
        with self._ctap() as ctap:
            protocol, token = self._uv_params(ctap, self._pin)
            if not token and uv and _has_builtin_uv(ctap):
                options = {"uv": True}
            else:
                options = None
            pin_uv_param, pin_uv_protocol = self._pin_auth(protocol, token, client_data_hash)
            try:
                assertion = ctap.get_assertion(record["rp_id"], client_data_hash,
                                               allow_list=allow, options=options or None,
                                               pin_uv_param=pin_uv_param,
                                               pin_uv_protocol=pin_uv_protocol)
            except CtapError as exc:
                raise self._explain(exc, token)
        auth_data = bytes(assertion.auth_data)
        handle = assertion.user.get("id") if assertion.user else None
        response = w.assertion_response(cred_id, auth_data, client_data_bytes,
                                        assertion.signature, user_handle=handle)
        return {"sign_count": int(assertion.auth_data.counter),
                "uv": bool(token)}, response
