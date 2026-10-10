#!/usr/bin/env python3
"""The hardware token backend: a FIDO2 security key via CTAP2.

The point of this backend is that the private key is generated on the token and never leaves
it — the assertion is produced by the hardware, and the broker only ever sees a credential id
and a signature. That is strictly stronger than the software backend, so the broker prefers a
token credential when one exists.

The device is reached through python-fido2. Every device interaction is funnelled through
``_ctap()`` so the whole backend can be exercised in tests with a fake CTAP object: the
hardware is absent most of the time (and always in CI), and a backend that can only be tested
with a security key plugged in would never be tested at all.
"""
import contextlib
import hashlib
import os

import webauthn_core as w

ALG_ES256 = -7


class TokenError(Exception):
    """No usable token, or the token refused the operation."""


def _uv_supported(ctap):
    """Whether the token can do on-device user verification (a PIN, not a touch).

    A plain Security Key advertises ``rk`` but not ``uv``/``clientPin``; on one of those the
    broker's own fingerprint check supplies user verification locally and the token only
    proves presence. Reported honestly so the broker does not claim UV the token did not set.
    """
    try:
        options = ctap.info.options or {}
    except AttributeError:
        return False
    return bool(options.get("uv") or options.get("clientPin"))


class TokenBackend:
    name = "token"

    def __init__(self, ctap=None):
        self._injected = ctap

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

    def register(self, rp_id, client_data_bytes, user_handle=b"", uv=True):
        client_data_hash = hashlib.sha256(client_data_bytes).digest()
        user = {"id": user_handle or os.urandom(16), "name": "passkey"}
        with self._ctap() as ctap:
            options = {"rk": True}
            if uv and _uv_supported(ctap):
                options["uv"] = True
            att = ctap.make_credential(client_data_hash, {"id": rp_id, "name": rp_id}, user,
                                       [{"type": "public-key", "alg": ALG_ES256}],
                                       options=options)
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
            # No private key: it lives on the token. That absence is the whole point.
        }
        response = w.public_key_credential(cred_data.credential_id, att_obj, client_data_bytes,
                                           transports=["usb"])
        return record, response

    def authenticate(self, record, client_data_bytes, uv=True):
        client_data_hash = hashlib.sha256(client_data_bytes).digest()
        cred_id = w.b64u_decode(record["cred_id"])
        allow = [{"type": "public-key", "id": cred_id}]
        with self._ctap() as ctap:
            options = {}
            if uv and _uv_supported(ctap):
                options["uv"] = True
            assertion = ctap.get_assertion(record["rp_id"], client_data_hash,
                                           allow_list=allow, options=options or None)
        auth_data = bytes(assertion.auth_data)
        handle = assertion.user.get("id") if assertion.user else None
        response = w.assertion_response(cred_id, auth_data, client_data_bytes,
                                        assertion.signature, user_handle=handle)
        return {"sign_count": int(assertion.auth_data.counter)}, response
