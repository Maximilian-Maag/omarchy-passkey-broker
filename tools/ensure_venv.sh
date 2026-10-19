#!/bin/bash
# Keep the broker's private venv usable — rebuild it the moment it is not.
#
# Why this is not just `python3 -m venv` behind a file test:
#
# The venv's `bin/python` is a SYMLINK to whatever interpreter built the venv, and a version
# manager (mise, pyenv, asdf) keeps that path behind a moving alias (`.../python/latest`). A bump
# of the alias — 3.14 to 3.15 on this machine — leaves the symlink pointing at a NEW interpreter
# that cannot see the venv's own site-packages (they live in lib/python3.14). `bin/python` is
# still executable, so an existence test like `[[ -x "$VENV/bin/python" ]]` passes, nothing is
# repaired, and the daemon then dies at import time with
# `ModuleNotFoundError: No module named 'cryptography'`.
#
# With `Restart=on-failure` that is not a one-off failure but an endless crash loop: measured
# here at ~18000 restarts, a 2-second CPU burn all night, and the passkey service silently down
# the whole time. It is also invisible from the outside — the bridge simply stops being served.
#
# So the health test is FUNCTIONAL (can this interpreter import its deps?), and a rebuild uses a
# resolved interpreter path rather than the `python3` name, so the rebuilt venv does not just
# follow the same alias into the next bump.
#
# Sourced by install.sh; also sourced directly by tests/shell/test_ensure_venv.sh.

# venv_healthy <venv-dir> [module,module,...]
# True when <venv-dir>/bin/python runs AND can import every requested module. The module list is
# a parameter so a test can ask about anything importable without needing the runtime deps.
venv_healthy() {
  local venv="$1"
  local mods="${2:-cryptography,fido2}"
  [[ -x "$venv/bin/python" ]] || return 1
  "$venv/bin/python" -c "import ${mods//,/, }" >/dev/null 2>&1
}

# ensure_venv <venv-dir>
# Make the venv exist, be healthy, and carry the runtime deps (cryptography, fido2). Idempotent:
# a healthy venv is left exactly as it is, so re-running install.sh after a routine update is a
# no-op rather than a rebuild.
ensure_venv() {
  local venv="$1"
  if ! venv_healthy "$venv"; then
    echo "  rebuilding venv at $venv (its interpreter cannot import its packages)"
    rm -rf "$venv"
    local py
    py="$(readlink -f "$(command -v python3)" || true)"
    [[ -n "$py" ]] || py="$(command -v python3)"
    "$py" -m venv "$venv"
  fi
  "$venv/bin/pip" install --quiet --upgrade pip
  "$venv/bin/pip" install --quiet cryptography fido2
  venv_healthy "$venv" || {
    echo "ERROR: $venv still cannot import cryptography/fido2" >&2
    return 1
  }
}
