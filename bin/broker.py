#!/usr/bin/env python3
"""The broker service: the policy layer that ties store, verifier and backends together.

This is deliberately the place where the *decisions* live — who may register, whether a
fingerprint is required, which credential answers an assertion — so the backends can stay
about cryptography and the server can stay about transport. Nothing here talks to a socket or
prints; the CLI and the HTTP server both call into this.
"""
import webauthn_core as w
from backend_software import SoftwareBackend
from backend_token import TokenBackend
from broker_store import CredentialStore
from broker_verify import FprintdVerifier


class PasskeyBroker:
    def __init__(self, store=None, verifier=None, backends=None):
        self.store = store if store is not None else CredentialStore()
        self.verifier = verifier if verifier is not None else FprintdVerifier()
        self.backends = backends if backends is not None else {
            "software": SoftwareBackend(),
            "token": TokenBackend(),
        }

    # ── helpers ──────────────────────────────────────────────────────────────

    def _backend(self, name):
        be = self.backends.get(name)
        if be is None:
            raise KeyError("no such backend: %r" % (name,))
        return be

    def _decide_uv(self, verify):
        """Run user verification when asked. Returns (ok, VerifyResult)."""
        if not verify:
            # Explicit opt-out (used by tests and by a headless registration flow). The UV flag
            # is then NOT set on the authenticator data, so a relying party that requires user
            # verification will still reject the assertion — the opt-out cannot silently
            # produce a verified-looking credential.
            return True, None
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
        ok, result = self._decide_uv(verify)
        if not ok:
            return {"ok": False, "error": result.state, "detail": result.detail}
        record, response = be.register(rp_id, client_data, user_handle,
                                       uv=(result.state == "verified") if result else False)
        self.store.save(record)
        return {"ok": True, "backend": backend,
                "user_verified": bool(result and result.state == "verified"),
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
        ok, result = self._decide_uv(verify)
        if not ok:
            return {"ok": False, "error": result.state, "detail": result.detail}
        be = self._backend(record.get("backend", "software"))
        updates, response = be.authenticate(record, client_data,
                                            uv=(result.state == "verified") if result else False)
        record.update(updates)
        self.store.save(record)
        return {"ok": True, "backend": record.get("backend"),
                "user_verified": bool(result and result.state == "verified"),
                "credential": response}

    def list_credentials(self):
        return [{"cred_id": r.get("cred_id"), "rp_id": r.get("rp_id"),
                 "backend": r.get("backend"), "sign_count": r.get("sign_count"),
                 "user_handle": r.get("user_handle"), "created": r.get("created")}
                for r in self.store.list()]

    def delete(self, cred_id):
        return {"ok": self.store.delete(cred_id)}
