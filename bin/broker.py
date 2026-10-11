#!/usr/bin/env python3
"""The broker service: the policy layer that ties store, verifier and backends together.

This is deliberately the place where the *decisions* live — who may register, whether a
fingerprint is required, which credential answers an assertion — so the backends can stay
about cryptography and the server can stay about transport. Nothing here talks to a socket or
prints; the CLI and the HTTP server both call into this.
"""
import os

import webauthn_core as w
from backend_software import SoftwareBackend
from backend_token import PIN_ENV, TokenBackend, TokenError
from broker_sites import SitesPolicy
from broker_store import CredentialStore
from broker_verify import FprintdVerifier, VerifyResult


def _uv_flag(result):
    """Whether the authenticator should claim user verification for this outcome.

    ``delegated`` means verification was handed to the credential's OWN authenticator (a FIDO2
    token validating its PIN/UV) — that counts exactly like a local fingerprint match, and is
    strictly stronger than a key sitting on disk.
    """
    return bool(result and result.state in ("verified", "delegated"))


def _uv_reported(payload, result):
    """The user-verification outcome to report to the caller.

    Prefer what the AUTHENTICATOR reported (a token sets ``uv`` from its PIN/UV auth token);
    fall back to the broker's own verification result. Reporting only the local fingerprint
    check made a token that genuinely performed UV show up as ``user_verified: false`` — the
    opposite of the truth.
    """
    flag = payload.get("uv")
    if flag is None:
        return _uv_flag(result)
    return bool(flag)


class PasskeyBroker:
    def __init__(self, store=None, verifier=None, backends=None, sites=None):
        self.store = store if store is not None else CredentialStore()
        self.verifier = verifier if verifier is not None else FprintdVerifier()
        self.sites = sites if sites is not None else SitesPolicy()
        self.backends = backends if backends is not None else {
            "software": SoftwareBackend(),
            # The token's PIN comes from the environment, never argv (argv is visible in `ps`
            # and lands in shell history). Absent it, a key that requires UV reports a clear
            # error rather than failing obscurely.
            "token": TokenBackend(pin=os.environ.get(PIN_ENV)),
        }

    # ── helpers ──────────────────────────────────────────────────────────────

    def _backend(self, name):
        be = self.backends.get(name)
        if be is None:
            raise KeyError("no such backend: %r" % (name,))
        return be

    def _decide_uv(self, verify, backend=None):
        """Run user verification when asked. Returns (ok, VerifyResult).

        When the backend verifies the user ITSELF — a FIDO2 token validating its own PIN — the
        broker must NOT additionally demand the local fingerprint: the token's check is the
        stronger one, and requiring fprintd made a security key unusable on a machine whose
        fingerprint sensor the owner cannot use. That outcome is reported as ``delegated``.
        """
        if not verify:
            # Explicit opt-out (used by tests and by a headless registration flow). The UV flag
            # is then NOT set on the authenticator data, so a relying party that requires user
            # verification will still reject the assertion — the opt-out cannot silently
            # produce a verified-looking credential.
            return True, None
        if backend is not None and getattr(backend, "self_verifies", False):
            return True, VerifyResult(True, "delegated",
                                      "user verification delegated to the token")
        result = self.verifier.verify()
        return result.ok, result

    # ── operations ───────────────────────────────────────────────────────────

    def register(self, rp_id, client_data_b64u, user_handle_b64u="", backend="software",
                 verify=True):
        if not rp_id or not isinstance(rp_id, str):
            return {"ok": False, "error": "invalid_rp_id"}
        try:
            client_data = w.b64u_decode(client_data_b64u)
            user_handle = w.b64u_decode(user_handle_b64u) if user_handle_b64u else b""
        except Exception:
            return {"ok": False, "error": "invalid_client_data"}
        try:
            be = self._backend(backend)
        except KeyError as exc:
            return {"ok": False, "error": "unknown_backend", "detail": str(exc)}
        ok, result = self._decide_uv(verify, be)
        if not ok:
            return {"ok": False, "error": result.state, "detail": result.detail}
        try:
            record, response = be.register(
                rp_id, client_data, user_handle, uv=_uv_flag(result))
        except TokenError as exc:
            return {"ok": False, "error": "token_error", "detail": str(exc)}
        self.store.save(record)
        return {"ok": True, "backend": backend,
                "user_verified": _uv_reported(record, result),
                "credential": response}

    def authenticate(self, rp_id, client_data_b64u, allow_ids=None, verify=True):
        if not rp_id or not isinstance(rp_id, str):
            return {"ok": False, "error": "invalid_rp_id"}
        try:
            client_data = w.b64u_decode(client_data_b64u)
        except Exception:
            return {"ok": False, "error": "invalid_client_data"}
        candidates = self.store.for_rp(rp_id, allow_ids)
        if not candidates:
            return {"ok": False, "error": "no_credential"}
        # Prefer a hardware-backed credential when one exists: the key stays in the token, and
        # a fingerprint-gated software key is the fallback rather than the first choice.
        record = next((c for c in candidates if c.get("backend") != "software"), candidates[0])
        # The backend must be known BEFORE deciding verification: a token credential verifies
        # the user with its own PIN, so the local fingerprint check is skipped for it.
        be = self._backend(record.get("backend", "software"))
        ok, result = self._decide_uv(verify, be)
        if not ok:
            return {"ok": False, "error": result.state, "detail": result.detail}
        try:
            updates, response = be.authenticate(
                record, client_data, uv=_uv_flag(result))
        except TokenError as exc:
            return {"ok": False, "error": "token_error", "detail": str(exc)}
        record.update(updates)
        self.store.save(record)
        return {"ok": True, "backend": record.get("backend"),
                "user_verified": _uv_reported(updates, result),
                "credential": response}

    def has_credential_for(self, host):
        """Is there a stored credential usable on this host (exact domain or a parent of it)?"""
        host = (host or "").strip().lower()
        if not host:
            return False
        for row in self.list_credentials():
            rp_id = (row.get("rp_id") or "").lower()
            if rp_id and (host == rp_id or host.endswith("." + rp_id)):
                return True
        return False

    def site_policy(self, host):
        """What the browser bridge must know about a host before touching WebAuthn.

        install: False for a host whose sign-in refuses an overridden WebAuthn API (see
                 broker_sites). The bridge then leaves the page completely alone — that is the
                 fix for "This browser or app may not be secure".
        has:     whether a credential exists for this host. The bridge uses this to decide
                 whether to ADVERTISE a platform authenticator: claiming one for a site we hold
                 nothing for steers a sign-in into a ceremony that cannot complete.

        Note the two are deliberately independent: install must be true on a site with no
        credential yet, or a NEW passkey could never be registered there.
        """
        return {"has": self.has_credential_for(host),
                "install": not self.sites.is_blocked(host)}

    def list_credentials(self):
        return [{"cred_id": r.get("cred_id"), "rp_id": r.get("rp_id"),
                 "backend": r.get("backend"), "sign_count": r.get("sign_count"),
                 "user_handle": r.get("user_handle"), "created": r.get("created")}
                for r in self.store.list()]

    def delete(self, cred_id):
        return {"ok": self.store.delete(cred_id)}
