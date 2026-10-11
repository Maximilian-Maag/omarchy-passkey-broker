# Changelog

## 1.0.0

First complete release of the passkey broker.

- **Daemon** (`bin/passkey-broker serve`): a token-gated loopback HTTP API on 127.0.0.1, with
  `register`, `authenticate`, `list`, `delete`, `info` and `status` commands.
- **Software backend**: an ES256 key per credential, stored 0600, with a live fprintd
  fingerprint check gating every use.
- **Token backend**: CTAP2 via python-fido2, so an attached FIDO2 security key can hold the
  private key in hardware. Supports a key with a PIN set: `PASSKEY_TOKEN_PIN` supplies it, the
  token performs user verification, and the UV flag is set by `pinUvAuthParam`. Proven against
  a real "Security Key by Yubico" (packed attestation, `UP|UV` assertion that verifies).
- **Browser bridge** (`userscripts/qute-passkey.js`): replaces `navigator.credentials.create`
  and `.get` and the `isUserVerifyingPlatformAuthenticatorAvailable` probe, so passkeys work in
  qutebrowser despite QtWebEngine having no authenticator of its own.
- **Tests**: unit, regression, integration, e2e and JS kinds, mutation testing (floor 0.80) and
  policy as code.
