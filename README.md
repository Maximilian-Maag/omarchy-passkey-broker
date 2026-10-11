# omarchy-passkey-broker

A system-wide passkey (WebAuthn) authenticator for Omarchy.

## Why this exists

QtWebEngine **advertises** WebAuthn and provides no authenticator behind it: a probe shows
`PublicKeyCredential` as a function, `credentials.create()` as a function, and the ceremony
**never settles** — it hangs forever. `isUserVerifyingPlatformAuthenticatorAvailable()`
resolves `false`. So every Chromium-based app on such a system (qutebrowser, Electron apps,
anything embedded) has no way to run a WebAuthn ceremony. That is not a qutebrowser bug; it is
a missing system capability, which is why the fix belongs here rather than in one browser.

## What the hardware has to provide

    fido2-token -I /dev/hidraw1
      proto: 0x02 (CTAP2)      algorithms: es256, eddsa
      caps: wink, cbor, msg    options: rk        maxcredcntlst: 8
      version strings: U2F_V2, FIDO_2_0, FIDO_2_1_PRE

`rk` = resident keys, i.e. the token can store passkeys. ES256 is WebAuthn's default
algorithm. For the software backend, fprintd needs at least one enrolled fingerprint (a
"Security Key by Yubico" is used as the reference token). Both backends are physically viable;
nothing here is theoretical.

## Scope, and the one wall

An **existing** passkey cannot be used: its private key is non-exportable by design, which is
the property passkeys exist for. The broker can only serve **new** registrations. The order is
therefore: sign in once by other means, register a passkey onto the token or the
fingerprint-gated software authenticator, and every subsequent passkey sign-in goes through
the broker.

## Architecture

    app (qutebrowser bridge userscript, …)
      │  reimplements navigator.credentials.create/get, speaks JSON over loopback
      ▼
    passkey-broker daemon   (bin/broker_server.py: 127.0.0.1 + 0600 token)
      │
      ├── bin/broker.py            the policy layer (who may register, is a fingerprint required,
      │                            which credential answers an assertion)
      ├── bin/backend_token.py     CTAP2 via python-fido2; the key never leaves the hardware
      ├── bin/backend_software.py  software ES256 key (0600), user verification via fprintd
      └── bin/broker_store.py      one 0600 JSON record per credential
      ▼
    WebAuthn ceremony: CBOR, ES256, fmt "none" attestation

### Security model

- The daemon binds **127.0.0.1 only** and every mutating route requires the token from the
  0600 `token` file. A per-user daemon plus that token is the boundary; a system-wide polkit
  daemon is a later option, not a requirement for a single-user laptop.
- The software backend keeps its private key on disk, so **possession of the file is not
  enough** — a live fingerprint check gates every use. `--no-verify` exists for headless tests
  and clears the UV flag, so an unverified credential is visible to the relying party.
- A fingerprint-gated software authenticator means anyone who can pass the fingerprint on the
  machine can sign in. That is the right trade for a laptop (it is what Windows Hello does) and
  it is a *different* thing from a synced passkey.
- `fmt: "none"` means a relying party cannot distinguish a software authenticator from a
  hardware one. That is what makes this work, and it is worth knowing.

## Usage

    passkey-broker status          # is the daemon running, and which build?
    passkey-broker info            # token + fingerprint capabilities, measured not assumed
    passkey-broker list            # stored credentials (never the private keys)
    passkey-broker register  --rp-id example.com     # create one from the CLI
    passkey-broker authenticate --rp-id example.com  # assert from the CLI

In qutebrowser, run `:greasemonkey-reload` once after installing, then use a site's normal
"add a passkey" flow. The bridge is re-rendered with the live port and token on every daemon
start (`bin/passkey-bridge-build`), so it never points at a dead port.

### The token's PIN

A security key that has a **PIN** set will refuse credential creation with
`CTAP2_ERR_PUAT_REQUIRED` (0x36) until a PIN/UV auth token is supplied — and a key like
"Security Key by Yubico" has no biometric, so the PIN *is* its user verification. The broker's
own fingerprint check is **not** a substitute: the token must be given its PIN, and only then
does it set the UV flag the relying party checks. Supply it through the environment, never
argv (argv is visible in `ps` and in shell history):

    PASSKEY_TOKEN_PIN=123456 passkey-broker register --rp-id example.com --backend token

Two CTAP details are easy to get wrong and are pinned by tests, because both were hit against
real hardware: the option `uv` is for a **built-in sensor** and is rejected with
`CTAP2_ERR_UNSUPPORTED_OPTION` on a PIN-only key (a PIN sets the UV flag via
`pinUvAuthParam`), and `pinUvAuthParam` is the token **authenticating the clientDataHash**
(`protocol.authenticate(token, client_data_hash)`), not the raw token — the raw token is
answered with `CTAP2_ERR_PIN_AUTH_INVALID`.

### It stays out of the way of a page that opted out

QtWebEngine cannot complete a WebAuthn ceremony, so a companion shim (omarchy-qutebrowser's
`google-signin-compat.js`) deletes `PublicKeyCredential` and `navigator.credentials.create/get`
on the Google/Microsoft sign-in hosts, which makes those pages offer a **password** instead of a
passkey that would hang.

The bridge must not undo that. It therefore declines to install when
`window.PublicKeyCredential` is absent, or when `navigator.credentials` has no native
`create`/`get` — i.e. when the page has deliberately opted out — and it only advertises a
platform authenticator (`isUserVerifyingPlatformAuthenticatorAvailable → true`) after a
`/health` probe confirms the daemon is reachable. Claiming a platform authenticator the broker
cannot serve is exactly what turns a working sign-in into *"Couldn't sign you in"*.

## Testing

The full harness is shared with the other Omarchy plugins (`tools/` is vendored byte-for-byte):

    bash tools/run_tests.sh                 # every kind, then mutation
    SKIP_MUTATION=1 bash tools/run_tests.sh # skip the slow mutation pass
    ONLY=unit,js bash tools/run_tests.sh    # a subset

| kind | location |
|------|----------|
| unit | `tests/test_unit_*.py` |
| regression | `tests/test_regression_*.py` |
| integration | `tests/test_integration_*.py` (real HTTP server, real ceremony) |
| e2e | `tests/e2e/test_*.sh` (real bridge JS → real daemon → RP-side verification) |
| js | `tests/js/*.test.js` (`node --test`, bridge in a `node:vm` page) |
| mutation | `tools/mutator.py` against `tests/mutation.json` |
| policy | `tools/policy_check.py` against `policy.json` |

## Phases

- **P1** daemon + CTAP2 behind it, proven against the token
- **P2** the browser bridge: a userscript replacing `navigator.credentials`, over loopback
- **P3** fprintd as the user-verification gate
- **P4** the house rules: unit + regression + integration + e2e + js, mutation ≥ 0.80,
  policy-as-code

## Known limitations

- The **hardware ceremony is proven**: a real "Security Key by Yubico" produced a `packed`
  attestation (AAGUID `149a2021…`), and an assertion whose ES256 signature verifies against the
  registered key with `UP|UV` set and an advancing sign count. It reaches the PIN/UV step, which
  means the key must be present and its PIN supplied; CI still exercises the token path against
  a fake CTAP device.
- `credentials.get()` is answered from the stored credential for the relying party's id; the
  bridge does not yet implement conditional UI (`mediation: "conditional"`).
- The daemon reads the token PIN from its own environment; an interactive PIN prompt for
  browser-driven flows (a pinentry helper) is not implemented yet.
