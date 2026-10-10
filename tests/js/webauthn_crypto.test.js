// Verifies the broker's encoding against node's WebCrypto (the browser's own ECDSA).
//
// This replaces a Python test that SKIPS on this machine: python-cryptography 46.0.7 is
// installed but its backend is missing (`No module named '_cffi_backend'`), so the ES256
// round trip could not run there. A skipped test is an unverified path, not a pass.
//
// It also pins a real implementation detail: WebCrypto and node both return the RAW
// r||s (IEEE P1363) form, while WebAuthn requires ES256 signatures in ASN.1 DER. The
// broker must convert; the last assertion here records that difference.
const { test } = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { execFileSync } = require('node:child_process');

const R = path.join(__dirname, '..', '..');
const FIX = JSON.parse(execFileSync('/usr/bin/python3',
  [path.join(R, 'tests', 'fixtures', 'webauthn_fixture.py')], { encoding: 'utf8' }));
const b = (s) => Buffer.from(s, 'base64url');

async function newKey() {
  return crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
}

test('an ES256 signature over the broker\'s signature base verifies', async () => {
  const authData = b(FIX.authenticator_data_b64u);
  const clientData = b(FIX.client_data_b64u);
  const base = Buffer.concat([authData, crypto.createHash('sha256').update(clientData).digest()]);
  const key = await newKey();
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key.privateKey, base);
  const ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key.publicKey, sig, base);
  assert.ok(ok, 'the signature must verify over authenticatorData || SHA-256(clientDataJSON)');
});

test('a signature over a DIFFERENT rp id does not verify (the test can fail)', async () => {
  const authData = b(FIX.authenticator_data_b64u);
  const clientData = b(FIX.client_data_b64u);
  const base = Buffer.concat([authData, crypto.createHash('sha256').update(clientData).digest()]);
  const other = Buffer.concat([b(FIX.other_rp_authenticator_data_b64u),
                               crypto.createHash('sha256').update(clientData).digest()]);
  const key = await newKey();
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key.privateKey, base);
  const ok = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key.publicKey, sig, other);
  assert.equal(ok, false, 'a wrong rpIdHash must break verification');
});

test('a tampered challenge does not verify', async () => {
  const authData = b(FIX.authenticator_data_b64u);
  const base = Buffer.concat([authData,
    crypto.createHash('sha256').update(b(FIX.client_data_b64u)).digest()]);
  const tampered = Buffer.concat([authData,
    crypto.createHash('sha256').update(Buffer.from('{"type":"webauthn.get","challenge":"nope","origin":"x"}')).digest()]);
  const key = await newKey();
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key.privateKey, base);
  assert.equal(await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key.publicKey, sig, tampered), false);
});

test('WebCrypto emits RAW r||s while WebAuthn requires DER — the broker must convert', async () => {
  const key = await newKey();
  const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key.privateKey,
    Buffer.from('x'));
  assert.equal(sig.byteLength, 64, 'WebCrypto P-256 signatures are 64 bytes of raw r||s');
  // DER adds the SEQUENCE header and two INTEGER headers, so it is always longer than 64
  // and never exactly 64 — this is the conversion the broker has to perform.
  assert.notEqual(sig[0], 0x30, 'a 64-byte signature is not DER (which starts with 0x30)');
});
