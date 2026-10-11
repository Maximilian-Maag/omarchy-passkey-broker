# Changelog

## 1.2.2

### Fixed
- **The Microsoft sign-in flow hung — it said a security window would open, and never did.** The
  bridge installed on the Microsoft sign-in hosts, Microsoft started a WebAuthn ceremony it then
  waited on, and the broker holds no credential for those sites, so the ceremony could never
  complete: the page just sat there loading. Those hosts (`login.live.com`, `account.live.com`,
  `login.microsoftonline.com`, `login.microsoft.com`, `account.microsoft.com`) are now blocked by
  default, exactly like Google. The bridge leaves them alone, Microsoft sees an ordinary browser
  with no platform authenticator, and its password flow is offered instead.
  To put a passkey on such a host, unblock it first (`passkey-broker unblock login.live.com`),
  register, then it can be blocked again.

## 1.2.1

### Fixed
- **Passkeys still failed with a security key attached — the browser asked for the wrong
  backend.** The bridge pinned `backend: 'software'` on every registration, so each browser
  ceremony went to the fingerprint-gated software backend, which a machine whose sensor the owner
  cannot use can never satisfy. The YubiKey was never consulted, which is why 1.2.0's token fix
  alone changed nothing in the browser. The bridge now sends **no** `backend` and the daemon
  chooses: a security key when one is attached, else the software key.

### Added
- `PasskeyBroker.preferred_backend()` and `TokenBackend.available()` — the key wins over a key on
  disk. `passkey-broker register/authenticate --backend` accepts `auto` (now the default), meaning
  the same thing; `--backend software|token` still forces a choice.

## 1.2.0

### Fixed
- **A FIDO2 security key no longer needs the machine's fingerprint sensor.** The broker ran the
  local fprintd check before *every* operation, token-backed ones included, so on a machine whose
  fingerprint sensor the owner cannot use, an attached security key was completely unusable. A
  token verifies the user itself — it validates the PIN and sets the UV flag from it — so the
  local check is now skipped for token credentials (reported as `delegated`) and still required
  for software ones, whose private key is a file on disk. Verified against the real hardware: a
  token registration consults the fingerprint verifier **0** times.
- **A new passkey could not be registered on a site that had none.** The 1.1.0 gate installed the
  bridge only where the broker already held a credential for the site — false precisely on the
  sites where a new passkey must be created, so registration was impossible. Installation is now a
  property of the HOST, not of the store.

### Added
- **Per-site policy** — `passkey-broker sites`, `block <host>`, `unblock <host>`. The browser
  bridge is kept out of hosts whose sign-in refuses an overridden WebAuthn API. `google.com` is
  blocked out of the box (suffix-matched, so `accounts.google.com` is covered) because Google
  answers such a browser with *"This browser or app may not be secure"*.
- `GET /has` now returns `has` (does a credential exist for this site) **and** `install` (may the
  bridge operate on this host). They are independent on purpose: installation has to stay on where
  registration happens, so it must never be gated on a credential already existing.

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
