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

# venv_interpreter
# Print a concrete, version-manager-independent python3, or fail.
#
# The trap this exists for, measured on this machine: `command -v python3` resolves to a
# mise SHIM, and `readlink -f` on that shim resolves to the version manager's own binary
# (/usr/bin/mise). A rebuild that used it ran `mise -m venv <dir>`, which mise answers with
# "error: unexpected argument '-m' found" — leaving the broker with no interpreter at all and
# its service down. Even the real path behind a shim is not safe on its own: mise keeps it
# behind a moving alias (…/installs/python/latest), which is exactly the alias-bump trap above.
#
# So try, in order: an explicit override (tests stay hermetic; an operator can pin a build),
# the system interpreter (a package at a stable path), the path the interpreter reports for
# itself, and finally the bare name — skipping anything that IS a version manager.
venv_interpreter() {
  local candidate reported
  reported="$(python3 -c 'import os, sys; print(os.path.realpath(sys.executable))' 2>/dev/null || true)"
  for candidate in "${VENV_PYTHON:-}" /usr/bin/python3 "$reported" "$(command -v python3 || true)"; do
    [[ -n $candidate && -x $candidate ]] || continue
    case "$(basename "$candidate")" in
      mise | asdf | pyenv | rbenv | nodenv | jenv | plenv) continue ;;
    esac
    # It has to actually run: a shim that answers with garbage must not become the interpreter.
    if ! "$candidate" -c 'import sys' >/dev/null 2>&1; then
      continue
    fi
    printf '%s\n' "$candidate"
    return 0
  done
  return 1
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
    if ! py="$(venv_interpreter)"; then
      echo "ERROR: no usable python3 to rebuild $venv (set VENV_PYTHON)" >&2
      return 1
    fi
    "$py" -m venv "$venv"
  fi
  "$venv/bin/pip" install --quiet --upgrade pip
  "$venv/bin/pip" install --quiet cryptography fido2
  venv_healthy "$venv" || {
    echo "ERROR: $venv still cannot import cryptography/fido2" >&2
    return 1
  }
}
