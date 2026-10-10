#!/usr/bin/env python3
"""Where the broker keeps its state.

Every path is derived from XDG state so a test can point the whole service at a throwaway
directory by setting ``XDG_STATE_HOME`` — the daemon then has no way to touch the real store.
Permissions are set here rather than at each call site: a credential store that is world
readable is a credential store that has already leaked its private keys.
"""
import os
import pathlib

APP = "omarchy-passkey-broker"


def state_dir():
    """The broker's state root. ``XDG_STATE_HOME`` wins so tests can isolate the store."""
    base = os.environ.get("XDG_STATE_HOME") or str(pathlib.Path.home() / ".local" / "state")
    return pathlib.Path(base) / APP


def credentials_dir():
    return state_dir() / "credentials"


def token_path():
    """The loopback auth token. The bridge reads it to prove it is the same user."""
    return state_dir() / "token"


def socket_path():
    """The unix socket the daemon listens on; also the liveness signal."""
    return state_dir() / "broker.sock"


def pidfile_path():
    return state_dir() / "broker.pid"


def server_json_path():
    """Mirrors reader-server's build-stamped server.json: how a client learns the live
    port/build without guessing. Written atomically so a reader never sees a half file."""
    return state_dir() / "server.json"


def ensure_dir(path, mode=0o700):
    """Create a directory with a restrictive mode, tightening it if it already exists.

    ``mkdir(mode=...)`` is masked by the umask, so the chmod is what actually guarantees the
    mode; a pre-existing looser directory is corrected rather than trusted.
    """
    path = pathlib.Path(path)
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, mode)
    return path
