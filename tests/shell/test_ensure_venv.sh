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
PATH="$tmp/fakebin:$PATH" ensure_venv "$tmp/recreate" >/dev/null 2>&1
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
PATH="$tmp/fakebin:$PATH" ensure_venv "$tmp/keep" >/dev/null 2>&1
if [[ -e "$tmp/keep/KEEPME" ]]; then
  pass "a healthy venv is left untouched (never rebuilt)"
else
  bad "a healthy venv is left untouched (never rebuilt)"
fi

printf '\n'
if (( fail == 0 )); then
  echo "ensure_venv: all checks passed"
else
  echo "ensure_venv: FAILURES"
fi
exit "$fail"
