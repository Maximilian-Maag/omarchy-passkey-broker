#!/bin/bash
# Round-trip test for `install.sh --uninstall`.
#
# Runs the real install.sh over a throwaway HOME/XDG with a stub `systemctl` and a stand-in venv,
# then `--uninstall`, and asserts that every artifact install.sh created is gone, that the user's
# own files (other plugins, other greasemonkey scripts, other bin tools) are byte-identical, and
# that a file which is not ours is left alone. Each assertion below fails if the matching removal
# is reverted in install.sh.
set -uo pipefail

ROOT="$(cd "$(dirname "$(readlink -f "$0")")/../.." && pwd)"
INSTALL="$ROOT/install.sh"

pass=0
fail=0
ok() { printf '  PASS %s\n' "$1"; pass=$((pass + 1)); }
bad() { printf '  FAIL %s\n' "$1"; fail=$((fail + 1)); }
check() { # desc expected actual
  if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1 (want '$2' got '$3')"; fi
}
sha() { sha256sum "$1" | cut -d' ' -f1; }

# The broker's real venv carries cryptography + fido2. A no-network stand-in for the private venv
# install.sh would build wraps that interpreter, so the bridge is really rendered. Any ambient
# override of the venv location is cleared first, so the path is the installed one.
unset PASSKEY_BROKER_VENV XDG_DATA_HOME
VENV_PY="$(source "$ROOT/tools/venv_path.sh"; broker_venv_dir)/bin/python"
PY=""
for candidate in "$VENV_PY" /usr/bin/python3 "$(command -v python3 || true)"; do
  if [[ -n $candidate && -x $candidate ]] && "$candidate" -c 'import cryptography, fido2' >/dev/null 2>&1; then
    PY="$candidate"
    break
  fi
done
if [[ -z $PY ]]; then
  echo "shell test_install: no interpreter with cryptography+fido2 — skipping"
  exit 0
fi

SANDBOX="$(mktemp -d)"
STUBS="$(mktemp -d)"
trap 'rm -rf "$SANDBOX" "$STUBS"' EXIT

export HOME="$SANDBOX/home"
export XDG_CONFIG_HOME="$SANDBOX/config"
export XDG_DATA_HOME="$SANDBOX/data"
export XDG_STATE_HOME="$SANDBOX/state"
export PASSKEY_BROKER_VENV="$SANDBOX/broker-venv"
mkdir -p "$HOME" "$XDG_CONFIG_HOME" "$XDG_DATA_HOME" "$XDG_STATE_HOME"

# A stand-in venv: the interpreter imports the runtime deps, pip is a no-op (no network).
mkdir -p "$PASSKEY_BROKER_VENV/bin"
printf '#!/bin/bash\nexec "%s" "$@"\n' "$PY" > "$PASSKEY_BROKER_VENV/bin/python"
printf '#!/bin/bash\nexit 0\n' > "$PASSKEY_BROKER_VENV/bin/pip"
chmod +x "$PASSKEY_BROKER_VENV/bin/python" "$PASSKEY_BROKER_VENV/bin/pip"

# A stub systemctl that records its calls, so the disable/daemon-reload are observable.
SYSTEMCTL_LOG="$SANDBOX/systemctl.log"
printf '#!/bin/bash\nprintf "%%s\\n" "$*" >> "%s"\nexit 0\n' "$SYSTEMCTL_LOG" > "$STUBS/systemctl"
chmod +x "$STUBS/systemctl"

# Hermetic PATH: the stub first, then system binaries — no mise, no omarchy.
export PATH="$STUBS:/usr/bin:/bin:/usr/local/bin"

DEST="$XDG_CONFIG_HOME/omarchy/plugins/Maximilian-Maag.passkey-broker"
UNIT="$XDG_CONFIG_HOME/systemd/user/passkey-broker.service"
BIN="$HOME/.local/bin"
GREASE_DATA="$XDG_DATA_HOME/qutebrowser/greasemonkey"
GREASE_CONFIG="$XDG_CONFIG_HOME/qutebrowser/greasemonkey"

# The user's own files, in every directory install.sh touches — their hashes must not move.
mkdir -p "$XDG_CONFIG_HOME/omarchy/plugins/Other.plugin"
printf '{"id":"Other.plugin"}\n' > "$XDG_CONFIG_HOME/omarchy/plugins/Other.plugin/manifest.json"
OTHER_PLUGIN_SHA="$(sha "$XDG_CONFIG_HOME/omarchy/plugins/Other.plugin/manifest.json")"
mkdir -p "$BIN"
printf '#!/bin/bash\necho other\n' > "$BIN/other-tool"
chmod +x "$BIN/other-tool"
OTHER_TOOL_SHA="$(sha "$BIN/other-tool")"
mkdir -p "$GREASE_DATA" "$GREASE_CONFIG"
printf '// the user own greasemonkey script\n' > "$GREASE_DATA/user-script.js"
USER_JS_SHA="$(sha "$GREASE_DATA/user-script.js")"
mkdir -p "$XDG_CONFIG_HOME/omarchy"
printf 'setting = 1\n' > "$XDG_CONFIG_HOME/omarchy/other-setting"
SETTING_SHA="$(sha "$XDG_CONFIG_HOME/omarchy/other-setting")"

# ── install ────────────────────────────────────────────────────────────────
if "$INSTALL" >/dev/null 2>&1; then ok "install exits 0"; else bad "install exits 0"; fi
check "the plugin copy exists" "yes" "$([[ -f $DEST/bin/passkey-broker ]] && echo yes || echo no)"
check "the systemd unit exists" "yes" "$([[ -f $UNIT ]] && echo yes || echo no)"
check "the broker wrapper exists with our marker" "yes" \
  "$(grep -qF 'omarchy-passkey-broker: wrapper' "$BIN/passkey-broker" && echo yes || echo no)"
check "the bridge-build wrapper exists" "yes" "$([[ -x $BIN/passkey-bridge-build ]] && echo yes || echo no)"
check "the bridge is rendered (data dir)" "yes" "$([[ -f $GREASE_DATA/qute-passkey.js ]] && echo yes || echo no)"
check "the bridge is rendered (config dir)" "yes" "$([[ -f $GREASE_CONFIG/qute-passkey.js ]] && echo yes || echo no)"

# Plant foreign artifacts where ours were, to model files that are NOT ours.
printf '// someone else bridge\n' > "$GREASE_CONFIG/qute-passkey.js"
printf '#!/bin/bash\necho not ours\n' > "$BIN/passkey-bridge-build"

# ── uninstall ──────────────────────────────────────────────────────────────
if "$INSTALL" --uninstall >/dev/null 2>&1; then ok "uninstall exits 0"; else bad "uninstall exits 0"; fi
check "the plugin copy is gone" "no" "$([[ -e $DEST ]] && echo yes || echo no)"
check "our broker wrapper is gone" "no" "$([[ -e $BIN/passkey-broker ]] && echo yes || echo no)"
check "the data-dir bridge is gone" "no" "$([[ -e $GREASE_DATA/qute-passkey.js ]] && echo yes || echo no)"
check "a foreign bridge is left alone" "yes" \
  "$([[ -f $GREASE_CONFIG/qute-passkey.js ]] && grep -q 'someone else' "$GREASE_CONFIG/qute-passkey.js" && echo yes || echo no)"
check "a foreign wrapper is left alone" "yes" \
  "$([[ -f $BIN/passkey-bridge-build ]] && grep -q 'not ours' "$BIN/passkey-bridge-build" && echo yes || echo no)"
check "the unit is gone" "no" "$([[ -e $UNIT ]] && echo yes || echo no)"
check "the other plugin is byte-identical" "$OTHER_PLUGIN_SHA" \
  "$(sha "$XDG_CONFIG_HOME/omarchy/plugins/Other.plugin/manifest.json")"
check "the other bin tool is byte-identical" "$OTHER_TOOL_SHA" "$(sha "$BIN/other-tool")"
check "the user greasemonkey script is byte-identical" "$USER_JS_SHA" "$(sha "$GREASE_DATA/user-script.js")"
check "the unrelated setting is byte-identical" "$SETTING_SHA" "$(sha "$XDG_CONFIG_HOME/omarchy/other-setting")"
check "systemd was told to disable --now" "yes" \
  "$(grep -q 'disable --now passkey-broker.service' "$SYSTEMCTL_LOG" && echo yes || echo no)"
check "systemd was told to daemon-reload" "yes" \
  "$(grep -q 'daemon-reload' "$SYSTEMCTL_LOG" && echo yes || echo no)"

# ── uninstall alone leaves foreign artifacts alone ─────────────────────────
# Nothing of ours installed: a real file where each of our targets would be must survive.
printf 'foreign\n' > "$BIN/passkey-broker"
printf 'foreign unit\n' > "$UNIT"
printf 'foreign bridge\n' > "$GREASE_DATA/qute-passkey.js"
"$INSTALL" --uninstall >/dev/null 2>&1
check "uninstall leaves a foreign broker wrapper" "yes" "$([[ -f $BIN/passkey-broker ]] && echo yes || echo no)"
check "uninstall leaves a foreign unit" "yes" "$([[ -f $UNIT ]] && echo yes || echo no)"
check "uninstall leaves a foreign bridge" "yes" "$([[ -f $GREASE_DATA/qute-passkey.js ]] && echo yes || echo no)"

# ── sensitivity: with one removal reverted, the round trip must FAIL ────────
# Neutralise the plugin-copy removal in a copy of install.sh and show the "plugin copy is gone"
# assertion is exactly what catches a reverted removal.
MUTANT="$SANDBOX/install-mutant.sh"
sed 's|rm -rf "\$DEST"|:|' "$INSTALL" > "$MUTANT"
chmod +x "$MUTANT"
"$INSTALL" >/dev/null 2>&1
"$MUTANT" --uninstall >/dev/null 2>&1
check "a reverted removal would fail the round-trip assertion" "yes" \
  "$([[ -e $DEST ]] && echo yes || echo no)"

printf '\nshell test_install: %s passed, %s failed\n' "$pass" "$fail"
(( fail == 0 ))
