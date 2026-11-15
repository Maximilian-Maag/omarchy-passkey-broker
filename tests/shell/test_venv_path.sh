#!/bin/bash
# Tests for tools/venv_path.sh — the venv must live OUTSIDE the plugin folder.
#
# The bug guarded here: the venv was installed at <plugin-dir>/.venv, and `omarchy-plugin-validate`
# refuses symlinks inside a plugin folder (a venv always has .venv/lib64). So the manager merged an
# update and then rolled it back — "update of '…' failed validation" — and the plugin silently
# stopped updating, while every install also dirtied the git checkout it lives in.
set -uo pipefail
cd "$(dirname "$(readlink -f "$0")")/../.." || exit 1
source tools/venv_path.sh

fail=0
pass() { printf '  PASS: %s\n' "$1"; }
bad()  { printf '  FAIL: %s\n' "$1"; fail=1; }

# An XDG-relative placeholder for a plugin installed under the user's config dir. A literal
# /home/<user>/... path here tripped the repo's own hygiene/no-absolute-home-paths check.
plugin_dir="${XDG_CONFIG_HOME:-$HOME/.config}/omarchy/plugins/Maximilian-Maag.passkey-broker"

venv="$(broker_venv_dir)"
case "$venv" in
  "$plugin_dir"/*) bad "the venv must not live inside the plugin folder ($venv)" ;;
  *) pass "the venv is outside the plugin folder ($venv)" ;;
esac
case "$venv" in
  */omarchy-passkey-broker/venv) pass "the venv sits under the plugin's own data dir" ;;
  *) bad "unexpected venv location: $venv" ;;
esac

XDG_DATA_HOME=/tmp/xdg-venv-test
export XDG_DATA_HOME
if [[ "$(broker_venv_dir)" == "/tmp/xdg-venv-test/omarchy-passkey-broker/venv" ]]; then
  pass "XDG_DATA_HOME is honoured"
else
  bad "XDG_DATA_HOME ignored: $(broker_venv_dir)"
fi
unset XDG_DATA_HOME

PASSKEY_BROKER_VENV=/tmp/pinned-venv
export PASSKEY_BROKER_VENV
if [[ "$(broker_venv_dir)" == "/tmp/pinned-venv" ]]; then
  pass "an explicit override wins (tests and operators can pin it)"
else
  bad "override ignored: $(broker_venv_dir)"
fi
unset PASSKEY_BROKER_VENV

if [[ "$(broker_legacy_venv "$plugin_dir")" == "$plugin_dir/.venv" ]]; then
  pass "the legacy in-checkout location is still identified so install.sh can remove it"
else
  bad "legacy location wrong: $(broker_legacy_venv "$plugin_dir")"
fi

printf '\n'
if (( fail == 0 )); then
  echo "venv_path: all checks passed"
else
  echo "venv_path: FAILURES"
fi
exit "$fail"
