# Changelog

## 1.1.0

### Fixed
- **Google sign-in was refused ("This browser or app may not be secure") whenever the bridge was
  installed.** Overriding `navigator.credentials` on a site the broker holds no credential for
  makes Google read the browser as tampered and block the login. Reproduced against an isolated
  stock profile: bridge present with no matching credential → sign-in refused; the same profile
  with the bridge absent → sign-in fine; Microsoft was unaffected either way. The bridge now asks
  the daemon's new `GET /has` before touching WebAuthn, and leaves the page's WebAuthn completely
  untouched when it has nothing to serve there.

### Added
- `GET /has?host=<host>` — does the broker hold a credential for the asking site? Unauthenticated
  by necessity (the bridge must ask before it has cause to touch WebAuthn, and a page cannot read
  the 0600 token), but Origin-scoped: the `Origin` header must name the same host, so a page
  cannot enumerate which sites the user holds passkeys for.

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
