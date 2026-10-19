#!/bin/bash
# omarchy-passkey-broker install script.
#
# Installs a single-user daemon that any local app can ask for a passkey, plus the qutebrowser
# bridge. The daemon runs as a systemd --user service so a passkey is available the moment the
# session is up, without a per-app integration.
#
# Re-run this script to update: it is idempotent.

set -euo pipefail

PLUGIN_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ID="Maximilian-Maag.passkey-broker"
DEST="${XDG_CONFIG_HOME:-$HOME/.config}/omarchy/plugins/$ID"
BIN="${HOME}/.local/bin"
UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
VENV="$DEST/.venv"

echo "omarchy-passkey-broker: installing from $PLUGIN_DIR"

# ── 0. Validate the manifest ──────────────────────────────────────────────────
if command -v omarchy >/dev/null 2>&1; then
  omarchy plugin validate "$PLUGIN_DIR"
fi

# ── 1. Copy plugin files ──────────────────────────────────────────────────────
mkdir -p "$DEST"
cp -r "$PLUGIN_DIR/bin" "$PLUGIN_DIR/userscripts" "$DEST/"
cp "$PLUGIN_DIR/manifest.json" "$PLUGIN_DIR/README.md" "$DEST/"
cp "$PLUGIN_DIR/policy.json" "$DEST/" 2>/dev/null || true
chmod +x "$DEST/bin/passkey-broker" "$DEST/bin/passkey-bridge-build"
echo "  Plugin files -> $DEST"

# ── 2. Runtime dependencies in a private venv ─────────────────────────────────
# The daemon needs 'cryptography' (ES256) and 'fido2' (CTAP2). The system Python on Omarchy
# ships neither, and a systemd --user service cannot rely on a shell PATH that might point at
# a mise/pyenv interpreter, so the deps go in a venv beside the plugin and everything points at
# it explicitly. That is also what CI does, so the two stay in step.
#
# ensure_venv REBUILDS the venv when its interpreter can no longer import those deps — the trap
# a version manager springing its `latest` alias onto a new Python creates. A bare existence
# test is not enough and cost a night of crash-looping here; see tools/ensure_venv.sh.
source "$PLUGIN_DIR/tools/ensure_venv.sh"
ensure_venv "$VENV"
echo "  Dependencies OK: $("$VENV/bin/python" -c 'import cryptography;print("cryptography", cryptography.__version__)')"

# ── 3. CLI wrappers on PATH ───────────────────────────────────────────────────
mkdir -p "$BIN"
write_wrapper() {                       # write_wrapper <name>
  cat > "$BIN/$1" <<EOF
#!/bin/bash
exec "$VENV/bin/python" "$DEST/bin/$1" "\$@"
EOF
  chmod +x "$BIN/$1"
}
write_wrapper passkey-broker
write_wrapper passkey-bridge-build
echo "  CLI wrappers -> $BIN/passkey-broker, $BIN/passkey-bridge-build"

# ── 4. systemd --user service ─────────────────────────────────────────────────
mkdir -p "$UNIT_DIR"
cat > "$UNIT_DIR/passkey-broker.service" <<EOF
[Unit]
Description=Omarchy passkey broker (WebAuthn authenticator)
After=graphical-session.target
# A broken daemon must FAIL, not spin. Without a limit, Restart=on-failure retries forever, so a
# start-time error (a venv that cannot import its deps, say) becomes an invisible 2-second crash
# loop that burns CPU for hours and leaves passkeys silently dead. Five tries in a minute is
# enough to ride out a real transient; past that the unit goes failed and \`systemctl --user
# status passkey-broker\` says so.
StartLimitIntervalSec=60
StartLimitBurst=5

[Service]
ExecStart=$VENV/bin/python $DEST/bin/passkey-broker serve
Restart=on-failure
RestartSec=2

[Install]
WantedBy=default.target
EOF
systemctl --user daemon-reload
systemctl --user enable --now passkey-broker.service
echo "  Service enabled: passkey-broker.service"

# ── 5. Build the browser bridge with the live port/token ──────────────────────
"$BIN/passkey-bridge-build"

# ── Done ──────────────────────────────────────────────────────────────────────
echo ""
echo "Done. The broker is running; check it with:"
echo "  passkey-broker status"
echo "  passkey-broker info"
echo ""
echo "In qutebrowser, reload Greasemonkey scripts once with  :greasemonkey-reload"
echo "Then sign in to a site normally and register a NEW passkey when it offers one."
echo ""
echo "Note: an EXISTING passkey cannot be used \u2014 its private key is non-exportable by"
echo "design. Register a new passkey with the broker, then every later sign-in is passwordless."
