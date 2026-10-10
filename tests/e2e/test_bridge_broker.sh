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
PY="${PYTHON:-python3}"
NODE="${NODE:-node}"

export XDG_STATE_HOME="$(mktemp -d)"
STATE="$XDG_STATE_HOME/omarchy-passkey-broker"
SRV=""
cleanup() { [ -n "$SRV" ] && kill "$SRV" 2>/dev/null; }
trap cleanup EXIT

fail() { echo "FAIL: $*"; exit 1; }

# --no-verify is the headless test hook; the fingerprint gate is exercised elsewhere.
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

echo "e2e bridge <-> broker: PASS"
