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
import pathlib
import re
import sys

import broker_paths

REPO = pathlib.Path(__file__).resolve().parent.parent
SOURCE = REPO / "userscripts" / "qute-passkey.js"

# The exact line the source ships with; replaced wholesale with the live config.
CONFIG_RE = re.compile(r"^(\s*var CONFIG = )\{.*?\};", re.M)

GREASEMONKEY_DIRS = [
    pathlib.Path.home() / ".local" / "share" / "qutebrowser" / "greasemonkey",
    pathlib.Path.home() / ".config" / "qutebrowser" / "greasemonkey",
]


def live_config():
    """The port+token of the running daemon, or an empty port if none is running."""
    server = broker_paths.server_json_path()
    if not server.exists():
        return {"port": 0, "token": "", "build": ""}
    try:
        info = json.loads(server.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return {"port": 0, "token": "", "build": ""}
    token_path = broker_paths.token_path()
    token = ""
    if token_path.exists():
        token = token_path.read_text(encoding="utf-8").strip()
    return {"port": int(info.get("port", 0)), "token": token, "build": info.get("build", "")}


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
    for target_dir in (targets if targets is not None else GREASEMONKEY_DIRS):
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


def install_live(targets=None):
    config = live_config()
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
