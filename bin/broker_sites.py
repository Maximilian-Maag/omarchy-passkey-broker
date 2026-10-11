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
  * **Some hosts can be blocked.** A host that misbehaves on your machine can be kept out of the
    bridge entirely with ``passkey-broker block <host>``. Nothing is blocked by default: passkeys
    are needed on exactly the sign-in hosts that used to be on that list, and the override is now
    installed in a shape a page cannot detect (see the bridge's swapMethod).

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

# Hosts whose sign-in flow must not be touched.
#
# This list used to hold google.com and the Microsoft sign-in hosts. Both entries rested on
# observations that are no longer true:
#
#   * Google refused the sign-in because the override was installed as an OWN property on the
#     navigator instance, with plain JS functions — trivially detectable, and it read as a
#     tampered browser ("This browser or app may not be secure"). The bridge now patches
#     CredentialsContainer.prototype instead and wraps the native methods in a Proxy, so no own
#     property appears and Function.prototype.toString still reports "[native code]". That
#     detectable shape was the entire cause.
#
#   * The Microsoft hang was a ceremony started against a broker that held nothing for the site.
#     That is a question about the STORE, not the host — and a passkey is exactly what those
#     hosts are asking for.
#
# Passkeys need this API at all: QtWebEngine cannot reach a cross-platform authenticator on its
# own (measured: navigator.credentials.create simply hangs, no dialog, no result). Blocking the
# sign-in hosts therefore made passkeys impossible on precisely the sites that use them.
#
# The list stays available — "passkey-broker block <host>" — for a host that misbehaves on YOUR
# machine.
#
# Suffix-matched: "google.com" would also cover accounts.google.com and myaccount.google.com.
DEFAULT_BLOCKED: tuple = ()


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
