#!/bin/bash
# Tests for tools/ensure_venv.sh — the venv health test and the rebuild it triggers.
#
# The bug guarded here: a version manager moving its `latest` alias left the broker venv's
# interpreter unable to import its own packages, while `bin/python` stayed executable. An
# existence test said "fine", the daemon died at import, and Restart=on-failure turned that into
# an ~18000-restart crash loop. So the health test must be FUNCTIONAL, and ensure_venv must
# actually rebuild — without touching a venv that is already healthy.
#
# Hermetic: no network. A stubbed `python3` fabricates venvs so the rebuild path can run.
set -uo pipefail
cd "$(dirname "$(readlink -f "$0")")/../.." || exit 1
source tools/ensure_venv.sh

fail=0
pass() { printf '  PASS: %s\n' "$1"; }
bad()  { printf '  FAIL: %s\n' "$1"; fail=1; }
expect_true()  { if "$@" >/dev/null 2>&1; then pass "true:  $*"; else bad "true:  $*"; fi; }
expect_false() { if "$@" >/dev/null 2>&1; then bad "false: $*"; else pass "false: $*"; fi; }

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

# a real venv from the current interpreter — present, runnable, carrying no extra deps
python3 -m venv "$tmp/good"

expect_true  venv_healthy "$tmp/good" sys
# the DEFAULT check is cryptography,fido2 — absent from a bare venv, so this is the guarded case
expect_false venv_healthy "$tmp/good"
expect_false venv_healthy "$tmp/good" this_module_is_not_installed_zz9
expect_false venv_healthy "$tmp/absent" sys

# An executable interpreter that cannot import is unhealthy, NOT "fine" — the whole point.
cp -r "$tmp/good" "$tmp/broken"
rm -f "$tmp/broken/bin/python"
printf '#!/bin/bash\nexit 1\n' > "$tmp/broken/bin/python"
chmod +x "$tmp/broken/bin/python"
expect_false venv_healthy "$tmp/broken" sys

# ── ensure_venv: rebuild a broken venv, leave a healthy one alone (stubbed, no network) ──
mkdir -p "$tmp/fakebin"
cat > "$tmp/fakebin/python3" <<'STUB'
#!/bin/bash
# fake `python3 -m venv <dir>`: make a venv whose interpreter imports anything, and a no-op pip
if [ "$1" = "-m" ] && [ "$2" = "venv" ]; then
  mkdir -p "$3/bin"
  printf '#!/bin/bash\nexit 0\n' > "$3/bin/python"
  printf '#!/bin/bash\nexit 0\n' > "$3/bin/pip"
  chmod +x "$3/bin/python" "$3/bin/pip"
fi
exit 0
STUB
chmod +x "$tmp/fakebin/python3"

mkdir -p "$tmp/recreate"
printf 'old\n' > "$tmp/recreate/REMNANT"
# VENV_PYTHON pins the interpreter ensure_venv rebuilds with, so this stays hermetic: the
# choice of interpreter is asserted separately below, with a hostile shim and no rebuild.
VENV_PYTHON="$tmp/fakebin/python3" ensure_venv "$tmp/recreate" >/dev/null 2>&1
if [[ -e "$tmp/recreate/REMNANT" ]]; then
  bad "a broken venv must be rebuilt (the old dir removed)"
else
  pass "a broken venv is rebuilt (the old dir removed)"
fi
expect_true venv_healthy "$tmp/recreate"

mkdir -p "$tmp/keep/bin"
printf '#!/bin/bash\nexit 0\n' > "$tmp/keep/bin/python"
printf '#!/bin/bash\nexit 0\n' > "$tmp/keep/bin/pip"
chmod +x "$tmp/keep/bin/python" "$tmp/keep/bin/pip"
printf 'keep\n' > "$tmp/keep/KEEPME"
VENV_PYTHON="$tmp/fakebin/python3" ensure_venv "$tmp/keep" >/dev/null 2>&1
if [[ -e "$tmp/keep/KEEPME" ]]; then
  pass "a healthy venv is left untouched (never rebuilt)"
else
  bad "a healthy venv is left untouched (never rebuilt)"
fi

# ── the version-manager shim must never become the interpreter ────────────────
# Measured on this machine: `command -v python3` is a mise shim, `readlink -f` on it resolved
# to /usr/bin/mise, and the rebuild therefore ran `mise -m venv` — "error: unexpected argument
# '-m' found" — leaving the broker with no interpreter at all (service down). venv_interpreter
# must skip the manager itself and land on an interpreter that actually runs.
mkdir -p "$tmp/shimdir"
printf '#!/bin/bash\nprintf "%%s\\n" "$*" >> "%s"\nexit 1\n' "$tmp/shim-calls" > "$tmp/shimdir/fake-manager"
chmod +x "$tmp/shimdir/fake-manager"
ln -sf "$tmp/shimdir/fake-manager" "$tmp/shimdir/python3"   # the shim IS the manager binary

if [[ "$(readlink -f "$tmp/shimdir/python3")" == "$tmp/shimdir/fake-manager" ]]; then
  pass "the trap is reproduced: resolving the shim lands on the manager binary"
else
  bad "could not reproduce the shim trap"
fi

resolved="$(PATH="$tmp/shimdir:$PATH" venv_interpreter 2>/dev/null || true)"
if [[ -z $resolved ]]; then
  bad "venv_interpreter found no interpreter behind a shim"
elif [[ $resolved == "$tmp/shimdir/fake-manager" || $resolved == "$tmp/shimdir/python3" ]]; then
  bad "venv_interpreter resolved to the version manager's own binary ($resolved)"
elif ! "$resolved" -c 'import sys' >/dev/null 2>&1; then
  bad "venv_interpreter returned something that is not a working interpreter ($resolved)"
else
  pass "venv_interpreter skips the shim and returns a working interpreter (${resolved##*/})"
fi
# Being ASKED for its interpreter path is fine (a real shim answers with the real path). Being
# used to build the venv is not: that is what produced `mise -m venv`.
if [[ -f "$tmp/shim-calls" ]] && grep -q -- "-m venv" "$tmp/shim-calls"; then
  bad "the version manager was used to build the venv: $(tr '\n' ';' < "$tmp/shim-calls")"
else
  pass "the version manager was never used to build a venv"
fi

printf '\n'
if (( fail == 0 )); then
  echo "ensure_venv: all checks passed"
else
  echo "ensure_venv: FAILURES"
fi
exit "$fail"
