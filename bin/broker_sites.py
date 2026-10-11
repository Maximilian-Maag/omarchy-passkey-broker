#!/usr/bin/env python3
"""Per-site policy: where may the bridge touch WebAuthn at all?

The bridge is a userscript that replaces ``navigator.credentials``. That is exactly what lets
passkeys work in QtWebEngine — and exactly what Google's sign-in refuses: it reads a tampered
WebAuthn API as an insecure browser and answers *"This browser or app may not be secure"*. That
was proven by a controlled A/B (stock profile accepted, bridge profile rejected, Microsoft
unaffected), so the policy cannot be a blanket "always install".

Two facts have to hold at once:

  * **Registration must work.** The bridge has to be present on a site we hold NOTHING for, or a
    brand-new passkey could never be created (the daemon would answer "no credential" for the
    very site you are trying to register on). So "install" cannot mean "a credential exists".
  * **Some hosts must never be touched.** Google's sign-in is refused the moment the API is
    overridden, so those hosts are blocked and the bridge stays out of the way entirely.

Hence: ``install`` is a property of the HOST (blocked or not), and ``has`` is the separate fact
the bridge uses to decide whether to advertise a platform authenticator. Blocked hosts default to
the sign-in flows observed to break under an overridden API (see DEFAULT_BLOCKED), and the list is
the user's to edit with ``passkey-broker block|unblock`` — unblocking is what you do before
registering a passkey on a host that is blocked by default.
"""
import json
import os
import pathlib

import broker_paths

# Hosts whose sign-in flow must not be touched. Two independent observations on this machine:
#
#   google.com      refuses a browser whose WebAuthn API has been overridden — "This browser or
#                   app may not be secure" — proven by a controlled A/B (stock profile accepted,
#                   bridge profile rejected).
#   the Microsoft sign-in hosts
#                   start a WebAuthn ceremony and WAIT for it ("a security window will open...")
#                   with the page left loading. With the bridge installed and no credential
#                   stored for the site, that ceremony can never complete, so the flow hangs.
#                   Leaving those hosts alone lets Microsoft offer its password flow instead.
#
# Suffix-matched: "google.com" also covers accounts.google.com and myaccount.google.com.
DEFAULT_BLOCKED = (
    "google.com",
    "login.live.com",
    "account.live.com",
    "login.microsoftonline.com",
    "login.microsoft.com",
    "account.microsoft.com",
)


def _normalise(host):
    return (host or "").strip().lower().lstrip(".")


def _matches(host, entry):
    """True when `entry` covers `host` — either exactly, or as its parent domain."""
    return bool(entry) and (host == entry or host.endswith("." + entry))


class SitesPolicy:
    """The blocked-host list, persisted next to the credentials it protects."""

    def __init__(self, path=None, blocked=None):
        self.path = pathlib.Path(path) if path else broker_paths.state_dir() / "sites.json"
        self._blocked = list(blocked) if blocked is not None else None

    # ── persistence ──────────────────────────────────────────────────────────

    @property
    def blocked(self):
        if self._blocked is None:
            self._blocked = self._load()
        return self._blocked

    def _load(self):
        try:
            data = json.loads(self.path.read_text())
            entries = data.get("blocked")
            if isinstance(entries, list):
                return [_normalise(e) for e in entries if _normalise(e)]
        except (OSError, ValueError):
            pass
        return list(DEFAULT_BLOCKED)

    def _save(self):
        broker_paths.ensure_dir(self.path.parent)
        tmp = self.path.with_suffix(".tmp")
        # 0600: this names the sites the user uses, so it is not world-readable.
        tmp.write_text(json.dumps({"blocked": self.blocked}, indent=2) + "\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, self.path)

    # ── policy ───────────────────────────────────────────────────────────────

    def is_blocked(self, host):
        """May the bridge touch WebAuthn on this host? False means: leave the page alone."""
        host = _normalise(host)
        if not host:
            return True  # unknown host: stay out of the way
        return any(_matches(host, entry) for entry in self.blocked)

    def block(self, host):
        host = _normalise(host)
        if host and not self.is_blocked(host):
            self._blocked = self.blocked + [host]
            self._save()
        return self.blocked

    def unblock(self, host):
        host = _normalise(host)
        self._blocked = [e for e in self.blocked
                         if not _matches(host, e) and not _matches(e, host)]
        self._save()
        return self.blocked
