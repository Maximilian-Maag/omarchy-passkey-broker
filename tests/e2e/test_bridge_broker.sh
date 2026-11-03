#!/bin/bash
# End-to-end: the real browser bridge, over a real socket, against the real daemon.
#
#   bridge JS (node:vm page stand-in, XHR over node http)
#     -> passkey-broker serve  (loopback + token)
#       -> software ES256 backend
#   -> verify_ceremony.py verifies the result as a relying party
#
# This is the one test that would catch a JSON-contract drift between the userscript and the
# server — the two halves are written in different languages and are only ever joined here.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
source "$REPO/tools/ensure_venv.sh"
source "$REPO/tools/venv_path.sh"
NODE="${NODE:-node}"
# Resolved BEFORE the XDG redirects below, which would otherwise move the data dir out from under
# this lookup: the plugin's venv lives in the user's real data dir, not in the test's throwaway one.
INSTALLED_VENV_PY="$(broker_venv_dir)/bin/python"

export XDG_STATE_HOME="$(mktemp -d)"
# Redirect DATA/CONFIG too: `serve` installs the bridge into the greasemonkey dir, and without
# this it lands in the developer's REAL qutebrowser profile (a stale bridge pointing at this
# throwaway daemon). The install target must be XDG-scoped for the test to be safe.
export XDG_DATA_HOME="$(mktemp -d)"
export XDG_CONFIG_HOME="$(mktemp -d)"

# Tools are resolved AFTER the redirects, and must actually run under them:
#   * a version-manager shim (mise) cannot: with XDG_STATE_HOME redirected it cannot find its own
#     trust state and refuses — "Config files in ~/Work/.mise.toml are not trusted" — which made a
#     real ceremony look like a broken server. Prefer a real binary; MISE_TRUSTED_CONFIG_PATHS keeps
#     the shim path working on a machine that only has shims (it is ignored where mise is absent).
#   * the daemon needs cryptography + fido2, so its venv (the interpreter it really runs under) is
#     preferred over any python3 on PATH.
export MISE_TRUSTED_CONFIG_PATHS="$HOME/.config/mise/config.toml:$(dirname "$REPO")/.mise.toml"

can_serve() { [[ -n ${1:-} ]] && "$1" -c 'import cryptography, fido2' >/dev/null 2>&1; }
PY=""
for candidate in "${PYTHON:-}" "$INSTALLED_VENV_PY" "$(command -v python3 || true)"; do
  if can_serve "$candidate"; then
    PY="$candidate"
    break
  fi
done
[[ -n $PY ]] || {
  echo "FAIL: no interpreter can import cryptography and fido2 — run ./install.sh, or set PYTHON" >&2
  exit 1
}

can_run_node() { [[ -n ${1:-} ]] && "$1" --version >/dev/null 2>&1; }
if ! can_run_node "${NODE:-}"; then
  NODE=""
  for candidate in /usr/bin/node "$(command -v node || true)"; do
    if can_run_node "$candidate"; then
      NODE="$candidate"
      break
    fi
  done
fi
[[ -n $NODE ]] || {
  echo "FAIL: no node that runs here — install node, or set NODE" >&2
  exit 1
}
# Guard the failure mode that actually bit us: a bridge written into the developer's REAL
# qutebrowser profile (a stale bridge pointing at this throwaway daemon). Fail loudly if it appears.
REAL_BRIDGE="$HOME/.local/share/qutebrowser/greasemonkey/qute-passkey.js"
REAL_BRIDGE_EXISTED=0; [ -e "$REAL_BRIDGE" ] && REAL_BRIDGE_EXISTED=1
STATE="$XDG_STATE_HOME/omarchy-passkey-broker"
SRV=""
cleanup() { [ -n "$SRV" ] && kill "$SRV" 2>/dev/null; }
trap cleanup EXIT

fail() { echo "FAIL: $*"; exit 1; }

# --no-verify is the headless test hook; the fingerprint gate is exercised elsewhere.
# PASSKEY_BROKER_BACKEND pins the software backend: the bridge sends no backend (the daemon
# picks), and "pick the best" means an attached security key — which would need a real touch.
PASSKEY_BROKER_BACKEND=software \
"$PY" "$REPO/bin/passkey-broker" serve --no-verify >"$XDG_STATE_HOME/serve.log" 2>&1 &
SRV=$!

for _ in $(seq 1 50); do
    [ -s "$STATE/server.json" ] && break
    sleep 0.1
done
[ -s "$STATE/server.json" ] || { cat "$XDG_STATE_HOME/serve.log"; fail "daemon did not start"; }

PORT=$("$PY" -c "import json;print(json.load(open('$STATE/server.json'))['port'])")
TOKEN=$(cat "$STATE/token")
echo "daemon on port $PORT (pid $SRV)"

OUT="$XDG_STATE_HOME/ceremony.json"
BROKER_PORT="$PORT" BROKER_TOKEN="$TOKEN" "$NODE" "$REPO/tests/js/e2e_bridge_driver.js" >"$OUT" \
    || fail "bridge driver failed"

"$PY" "$REPO/tests/e2e/verify_ceremony.py" "$OUT" || fail "ceremony verification failed"

# Nothing may have leaked into the real browser profile.
[ "$REAL_BRIDGE_EXISTED" -eq 0 ] && [ -e "$REAL_BRIDGE" ] \
    && fail "the e2e wrote into the real qutebrowser profile: $REAL_BRIDGE"

echo "e2e bridge <-> broker: PASS"
