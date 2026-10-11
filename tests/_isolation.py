#!/usr/bin/env python3
"""Module-level test isolation: keep every test off the developer's real directories.

The production code honours ``XDG_STATE_HOME``/``XDG_DATA_HOME``/``XDG_CONFIG_HOME``, and the
tests pass explicit temp directories — but a MUTANT can ignore both. Without this, a mutant of
``CredentialStore``'s or ``PasskeyBroker``'s constructor falls back to ``$HOME`` and writes test
credentials into the developer's real store, and a mutant that starts a ``BrokerServer`` writes
``server.json`` into the real state dir. That is not hypothetical: it happened, repeatedly,
during a mutation pass, and the greasemonkey equivalent wrote a dead bridge into a real
qutebrowser profile and broke sign-in.

Usage, once per test module::

    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent / "bin"))
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
    from _isolation import isolate  # noqa: E402

    setUpModule, tearDownModule = isolate()

Every XDG variable and ``pathlib.Path.home`` are then redirected into a throwaway tree for the
whole module, so a test cannot reach the real dirs even when the code under test misbehaves.
"""
import os
import pathlib
import tempfile


def isolate(prefix="passkey-test-"):
    """Return ``(setUpModule, tearDownModule)`` that pin XDG dirs and $HOME to a temp tree."""
    saved_env = {}
    saved_home = []

    def setUpModule():
        tmp = pathlib.Path(tempfile.mkdtemp(prefix=prefix))
        for key in ("XDG_STATE_HOME", "XDG_DATA_HOME", "XDG_CONFIG_HOME"):
            saved_env[key] = os.environ.get(key)
            os.environ[key] = str(tmp / key)
        saved_home.append(pathlib.Path.home)
        pathlib.Path.home = classmethod(lambda cls: tmp / "home")

    def tearDownModule():
        for key, value in saved_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        if saved_home:
            pathlib.Path.home = saved_home.pop()

    return setUpModule, tearDownModule
