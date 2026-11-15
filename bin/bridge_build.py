#!/usr/bin/env python3
"""Render the browser bridge with the live daemon port and token, and install it.

The bridge runs inside the page and cannot read the 0600 token file, so the only way it can
learn the port and token is for someone outside the page to write them in. This module does
that: it reads ``server.json`` and ``token`` and rewrites the ``CONFIG`` line of the userscript
before copying it into qutebrowser's greasemonkey directory.

If no daemon is running the bridge is rendered with an empty port, which makes it disable
itself — a bridge pointing at a dead port would make every passkey attempt hang, which is
exactly the failure this whole plugin exists to fix.
"""
import argparse
import json
import os
import pathlib
import re
import socket
import sys

import broker_paths

REPO = pathlib.Path(__file__).resolve().parent.parent
SOURCE = REPO / "userscripts" / "qute-passkey.js"

# The exact line the source ships with; replaced wholesale with the live config.
CONFIG_RE = re.compile(r"^(\s*var CONFIG = )\{.*?\};", re.M)


def greasemonkey_dirs():
    """Where qutebrowser looks for Greasemonkey scripts.

    Honours ``XDG_DATA_HOME``/``XDG_CONFIG_HOME`` rather than hardcoding ``$HOME``, so a test
    (or a session with a redirected config) never writes into the developer's REAL browser
    profile. This is not hypothetical: with the paths hardcoded, the end-to-end test's
    ``passkey-broker serve`` installed a bridge pointing at a throwaway daemon into the user's
    own qutebrowser, breaking their sign-in.
    """
    data = os.environ.get("XDG_DATA_HOME") or str(pathlib.Path.home() / ".local" / "share")
    config = os.environ.get("XDG_CONFIG_HOME") or str(pathlib.Path.home() / ".config")
    return [pathlib.Path(data) / "qutebrowser" / "greasemonkey",
            pathlib.Path(config) / "qutebrowser" / "greasemonkey"]


def policy_snapshot(store=None):
    """(blocked_hosts, rp_ids_with_credentials) for baking into the script.

    The bridge would otherwise have to ask the daemon `GET /has` from the PAGE, and a page whose
    Content-Security-Policy forbids the loopback origin blocks that request. The bridge then
    cannot tell "the broker has nothing here" from "the ask was refused", and a ceremony it was
    meant to serve is silently handed back to an engine that cannot complete it. Baking the two
    lists in removes the page request entirely.

    Both lists are snapshots: the daemon re-renders the bridge after a registration and the CLI
    after `block`/`unblock`, so they stay current.
    """
    import broker_sites
    from broker_store import CredentialStore
    store = store if store is not None else CredentialStore()
    blocked = sorted({h for h in broker_sites.SitesPolicy().blocked if h})
    has = sorted({(r.get("rp_id") or "").lower() for r in store.list() if r.get("rp_id")})
    return blocked, has


def _daemon_listening(port, host="127.0.0.1", timeout=1.0):
    """Is something actually accepting connections on the loopback port?

    A ``server.json`` only proves a daemon ONCE wrote it — the file survives a crash, so its
    mere existence is not a liveness signal. Actually connect: a refused or timed-out connect
    means nothing is listening, and the caller then treats the daemon as down. Opening the
    connection is enough (the accept happens before the daemon reads anything).
    """
    try:
        with socket.create_connection((host, int(port)), timeout=timeout):
            return True
    except (OSError, ValueError):
        return False


def live_config(store=None):
    """The port+token of the running daemon (empty port if none) plus the baked host policy.

    ``store`` is the credential store whose rp_ids go into the baked list; it defaults to the
    process's own store, which is what the CLI wants. The daemon passes ITS store so a broker
    constructed over a different directory still bakes the right list.

    The port is probed, not trusted from the file: a stale ``server.json`` left by a crashed
    daemon would otherwise render a bridge pointed at a dead port, and every passkey attempt
    would hang — the exact failure this module exists to prevent.
    """
    blocked, has = policy_snapshot(store)
    empty = {"port": 0, "token": "", "build": "", "blocked": blocked, "has": has}
    server = broker_paths.server_json_path()
    if not server.exists():
        return empty
    try:
        info = json.loads(server.read_text(encoding="utf-8"))
        port = int(info.get("port", 0) or 0)
    except (ValueError, OSError, TypeError):
        return empty
    if not port or not _daemon_listening(port):
        return empty
    token_path = broker_paths.token_path()
    token = ""
    if token_path.exists():
        token = token_path.read_text(encoding="utf-8").strip()
    return {"port": port, "token": token, "build": info.get("build", ""),
            "blocked": blocked, "has": has}


def render(config):
    """Return the userscript source with CONFIG replaced. Exactly one line must match, so a
    source that drifted is an error rather than a silent no-op."""
    source = SOURCE.read_text(encoding="utf-8")
    payload = json.dumps(config, separators=(", ", ": "))
    new, count = CONFIG_RE.subn(lambda m: m.group(1) + payload + ";", source, count=1)
    if count != 1:
        raise ValueError("could not find the CONFIG line to replace")
    return new


def install(text, targets=None):
    """Write the rendered script into every greasemonkey dir. Returns the paths written."""
    written = []
    for target_dir in (targets if targets is not None else greasemonkey_dirs()):
        target_dir = pathlib.Path(target_dir)
        try:
            target_dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            continue
        dest = target_dir / "qute-passkey.js"
        # Write atomically: qutebrowser may reload scripts at any moment, and a half-written
        # userscript is a syntax error that disables the bridge with no obvious cause.
        tmp = dest.with_suffix(".js.tmp")
        tmp.write_text(text, encoding="utf-8")
        tmp.replace(dest)
        written.append(str(dest))
    return written


def install_live(targets=None, store=None):
    config = live_config(store)
    return config, install(render(config), targets=targets)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="passkey-bridge-build")
    ap.add_argument("--print", dest="print_only", action="store_true",
                    help="write the rendered script to stdout instead of installing it")
    args = ap.parse_args(argv if argv is not None else sys.argv[1:])
    config = live_config()
    text = render(config)
    if args.print_only:
        sys.stdout.write(text)
        return 0
    written = install(text)
    state = "live" if config["port"] else "disabled (no daemon running)"
    print("passkey-bridge-build: bridge %s" % state)
    for path in written:
        print("  wrote %s" % path)
    return 0


if __name__ == "__main__":
    sys.exit(main())
