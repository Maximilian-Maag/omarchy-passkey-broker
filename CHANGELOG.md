# Changelog

## 1.2.7

### Fixed
- **The daemon follows `sites.json` when it changes, so `passkey-broker block|unblock` takes effect
  without a restart.** The block list was read once and cached in memory for the life of the
  daemon, while the CLI - a separate process - only writes the file. A host added to the block list
  therefore stayed overridable until someone restarted the service: exactly the window in which the
  bridge overrides WebAuthn on Google's sign-in and it is refused with "This browser or app may not
  be secure". The policy now re-reads the file when its mtime/size changed. A policy handed an
  explicit list (the tests, and any caller wanting a fixed policy) still owns its value. Covered by
  four tests in `tests/test_unit_broker_sites.py` (including that `block` merges an external edit
  instead of clobbering it).
- **`install.sh` restarts the daemon instead of `enable --now`.** `enable --now` starts an inactive
  unit but leaves a RUNNING one on its old code, so re-running the script (the documented way to
  update) could leave a fix looking applied while the daemon still served the previous build. It
  now enables and restarts, so an update is actually live.

## 1.2.6

### Fixed
- **An existing security key reaches the engine again; the bridge no longer swallows it.** The
  bridge overrode `navigator.credentials.get()` on every allowed host and answered only from the
  broker's own store. A credential registered elsewhere - one whose private key lives on the
  token - has no broker record, so the override turned every such ceremony into `NotAllowedError`.
  Measured: a YubiKey used as second factor on **discord.com** stopped working the moment the
  bridge installed there.

  `get()` now captures the engine's own getter before patching and, when the broker holds no
  credential for the host, defers to it - the engine drives the token directly (touch, and PIN
  where the key requires one). `create()` still goes to the broker, so registering a NEW passkey
  is unchanged. Covered by three tests in `tests/js/bridge.test.js`.

## 1.2.5

### Fixed
- **The daemon can no longer crash-loop forever on a broken venv, and the venv repairs itself.**
  `install.sh` created the venv once and thereafter only checked that `$VENV/bin/python` *exists*.
  But that file is a SYMLINK to whatever interpreter built the venv, and a version manager (mise,
  pyenv, asdf) keeps it behind a moving alias: when `.../python/latest` moved 3.14 -> 3.15, the
  symlink followed onto a 3.15 interpreter that could not see the venv's `lib/python3.14`
  site-packages. `bin/python` was still executable, so the existence test passed, nothing was
  repaired, and the daemon died at import with `ModuleNotFoundError: No module named
  'cryptography'`. `Restart=on-failure` then turned that into an **~18000-restart crash loop** -
  measured here, a 2-second CPU burn all night with the passkey service silently down.

  `tools/ensure_venv.sh` replaces the existence test with a FUNCTIONAL one (can the interpreter
  `import cryptography, fido2`?) and rebuilds the venv when it cannot, from a *resolved*
  interpreter path so the fresh venv does not follow the same alias into the next bump. A healthy
  venv is left untouched, so re-running `install.sh` stays a no-op. Covered by
  `tests/shell/test_ensure_venv.sh`.

- **The systemd unit fails instead of spinning.** `Restart=on-failure` with no limit retried a
  start-time error forever. `StartLimitIntervalSec=60` / `StartLimitBurst=5` now cap it: past five
  failed starts in a minute the unit goes `failed`, which `systemctl --user status passkey-broker`
  reports, rather than looping invisibly.

## 1.2.4

### Changed
- **The sign-in hosts are blocked again, because the bridge is refused there whatever shape it
  takes.** 1.2.3 removed that block on the theory that the refusal came from the override being
  detectable — an own property on `navigator`, plain JS functions. That theory was measured wrong:
  with the prototype-level, Proxy-wrapped override (no own property anywhere, `name`/`length`
  intact, `Function.prototype.toString` still reporting `[native code]`) Google's sign-in still
  answers **"This browser or app may not be secure"**. Whatever signal that check reads, the
  override is what trips it.

  The honest position, now written into the code and its tests: **passkeys cannot be used on the
  Google or Microsoft sign-in in this browser.** QtWebEngine cannot reach a cross-platform
  authenticator on its own (`navigator.credentials.create()` hangs, no dialog, no result), and it
  cannot override the WebAuthn API on those hosts without being refused. Password sign-in is the
  supported path there; passkeys keep working on hosts that do not check, github included.

  On an existing machine the store is set with `passkey-broker block <host>`, which needs a broker
  restart — the policy is cached in memory and the CLI writes the file.

## 1.2.3

### Fixed
- **The bridge is no longer detectable, so the sign-in hosts no longer have to be blocked.** The
  override used to be an OWN property on the navigator instance, with plain JavaScript functions:
  a page could find it with `hasOwnProperty`, and a sign-in page read it as a tampered browser
  ("This browser or app may not be secure"). It now patches `CredentialsContainer.prototype` and
  wraps the engine's own methods in a Proxy, so there is no own property to find, `name`/`length`
  are preserved, and `Function.prototype.toString` still reports `[native code]` (measured in the
  engine: the source-text form differs, `[native code]` does not). The `PublicKeyCredential`
  statics are swapped the same way instead of being overwritten with plain functions.

  The tests now model the engine faithfully: those statics EXIST (resolving false) rather than
  being absent, and `navigator.credentials` lives on a prototype, never as an own property.

- **Nothing is blocked by default any more.** `google.com` and the Microsoft sign-in hosts were on
  `DEFAULT_BLOCKED`, which made a passkey impossible on exactly the sites that use one. QtWebEngine
  cannot reach a cross-platform authenticator by itself — measured: `navigator.credentials.create()`
  against the YubiKey hangs, with no dialog and no result — so the bridge is required there, not
  forbidden. The list is still available with `passkey-broker block <host>` for a host that
  misbehaves on a given machine.

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
