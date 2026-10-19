// Unit tests for the browser bridge userscript.
//
// The script runs in a page, so the only honest way to test it in node is to give it a page: a
// fake window/navigator and a fake XMLHttpRequest, injected into a `node:vm` sandbox. That
// exercises the real source — base64url round-trips, the clientDataJSON it builds, the broker
// payloads it sends, and the ArrayBuffer-shaped credentials it returns — without a browser.
//
// Run: node --test tests/js/bridge.test.js
'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const SOURCE = fs.readFileSync(
    path.join(__dirname, '..', '..', 'userscripts', 'qute-passkey.js'), 'utf8');

// A page stand-in plus a request handler the test controls. `config === null` loads the source
// EXACTLY as it ships (with its placeholder CONFIG), which is what the default-config test wants.
// `native: false` simulates a page that has deliberately removed WebAuthn.
function loadBridge(config, handler, opts) {
    opts = opts || {};
    const requests = [];
    // A native navigator.credentials. create/get live on the PROTOTYPE, exactly as
    // CredentialsContainer does in the engine: the bridge patches the prototype, never the
    // navigator instance, because an own property on navigator is the tell a sign-in refuses.
    const CredentialsProto = {
        create: function nativeCreate() { return Promise.reject(new Error('native create')); },
        get: function nativeGet() { return Promise.reject(new Error('native get')); }
    };
    const nativeCreds = opts.native === false ? {} : Object.create(CredentialsProto);
    // navigator.credentials is a PROTOTYPE getter in the engine, so the fake must not put it on
    // the navigator object itself - the tests assert nothing lands there as an own property.
    const navigatorObj = Object.create({ credentials: nativeCreds });

    class FakeXHR {
        constructor() { this.headers = {}; this.responseText = ''; this.status = 0; }
        open(method, url, async) { this.method = method; this.url = url; this.async = async; }
        setRequestHeader(name, value) { this.headers[name] = value; }
        send(body) {
            const req = { method: this.method, url: this.url, async: this.async,
                          headers: this.headers, body: body ? JSON.parse(body) : null };
            requests.push(req);
            // install() now asks /has before touching WebAuthn: only a site the broker holds a
            // credential for may be overridden. `opts.has === false` simulates "nothing to serve
            // here" (which must leave the page's WebAuthn completely alone).
            if (String(this.url).includes('/has')) {
                this.status = 200;
                this.responseText = JSON.stringify({ ok: true,
                                                     has: opts.has !== false,
                                                     install: opts.install !== false });
                return;
            }
            const reply = handler(req);
            this.status = reply.status || 200;
            this.responseText = JSON.stringify(reply.body);
            if (this.onload) { this.onload(); }
            if (this.status !== 200 && this.onerror) { this.onerror(new Error('http ' + this.status)); }
        }
    }

    const windowObj = {
        location: { origin: 'https://example.com', hostname: 'example.com' },
        PublicKeyCredential: opts.noPublicKeyCredential ? undefined
            // The statics are own function properties of the constructor, as the engine has them;
            // the bridge swaps them in place (Proxy-wrapped, so they still look native).
            : Object.assign(function () {}, {
                isUserVerifyingPlatformAuthenticatorAvailable: function () { return Promise.resolve(false); },
                isConditionalMediationAvailable: function () { return Promise.resolve(false); }
            }),
        XMLHttpRequest: FakeXHR
    };
    Object.defineProperty(windowObj, 'navigator', {
        value: navigatorObj, writable: true, configurable: true
    });

    const sandbox = {
        window: windowObj,
        navigator: navigatorObj,
        XMLHttpRequest: FakeXHR,
        btoa, atob, TextEncoder, DOMException, console,
        Promise, Object, JSON, String, Uint8Array, ArrayBuffer, Error
    };
    vm.createContext(sandbox);
    // The source reads CONFIG from its own literal; to inject a config we rewrite that one
    // line, exactly as bin/bridge_build.py does in production. config === null keeps it as-is.
    const source = config === null
        ? SOURCE
        : SOURCE.replace(/var CONFIG = \{.*?\};/, 'var CONFIG = ' + JSON.stringify(config) + ';');
    vm.runInContext(source, sandbox, { filename: 'qute-passkey.js' });
    // install() runs at load and may probe /health; keep those out of the per-test assertions.
    const initial = requests.slice();
    requests.length = 0;
    return { bridge: sandbox.window.__passkeyBridge, requests, initial,
             navigator: sandbox.window.navigator, window: sandbox.window };
}

const CFG = { port: 12345, token: 'tok', build: 'b1' };

// Objects created inside the vm carry that realm's prototypes, so assert.deepStrictEqual
// (which compares prototypes) cannot be used across the boundary. Normalise first.
function plain(value) { return JSON.parse(JSON.stringify(value)); }

function b64uOf(api, text) {
    return api.b64uFromBuf(new TextEncoder().encode(text));
}

test('base64url round-trips and strips padding', () => {
    const { bridge } = loadBridge({ port: 0, token: '' }, () => ({}));
    const raw = new Uint8Array([0, 1, 250, 251, 252, 253, 254, 255]);
    const encoded = bridge.b64uFromBuf(raw);
    assert.ok(!encoded.includes('='), 'no padding');
    assert.ok(!encoded.includes('+') && !encoded.includes('/'), 'url-safe alphabet');
    assert.deepEqual(Array.from(new Uint8Array(bridge.bufFromB64u(encoded))), Array.from(raw));
});

test('clientDataJSON has type, challenge and origin', () => {
    const { bridge } = loadBridge({ port: 0, token: '' }, () => ({}));
    const parsed = JSON.parse(bridge.clientDataJSON('webauthn.create', 'Y2hhbA', 'https://x'));
    assert.deepStrictEqual(parsed,
        { type: 'webauthn.create', challenge: 'Y2hhbA', origin: 'https://x' });
});

test('rpIdOf prefers rp.id then falls back to hostname', () => {
    const { bridge } = loadBridge({ port: 0, token: '' }, () => ({}));
    assert.strictEqual(bridge.rpIdOf({ rp: { id: 'a.example' } }), 'a.example');
    assert.strictEqual(bridge.rpIdOf({}), 'example.com');
});

test('registration credential carries ArrayBuffers, not strings', () => {
    const { bridge } = loadBridge({ port: 0, token: '' }, () => ({}));
    const cred = bridge.toPublicKeyCredential({
        id: 'abc', rawId: 'abc', type: 'public-key',
        response: { clientDataJSON: 'Y2hhbA', attestationObject: 'YXR0', transports: ['usb'] }
    });
    assert.strictEqual(cred.id, 'abc');
    assert.strictEqual(cred.rawId.byteLength, bridge.bufFromB64u('abc').byteLength);
    assert.strictEqual(cred.response.clientDataJSON.byteLength,
                       bridge.bufFromB64u('Y2hhbA').byteLength);
    assert.deepStrictEqual(plain(cred.response.getTransports()), ['usb']);
    assert.deepStrictEqual(plain(cred.getClientExtensionResults()), {});
    assert.strictEqual(cred.authenticatorAttachment, 'platform');
});

test('assertion credential exposes userHandle and nulls it when absent', () => {
    const { bridge } = loadBridge({ port: 0, token: '' }, () => ({}));
    const withHandle = bridge.toAssertionCredential({
        id: 'aWQ', rawId: 'aWQ', type: 'public-key',
        response: { clientDataJSON: 'eA', authenticatorData: 'eQ', signature: 'eg', userHandle: 'dQ' }
    });
    assert.strictEqual(withHandle.response.userHandle.byteLength,
                       bridge.bufFromB64u('dQ').byteLength);
    const withoutHandle = bridge.toAssertionCredential({
        id: 'aWQ', rawId: 'aWQ', type: 'public-key',
        response: { clientDataJSON: 'eA', authenticatorData: 'eQ', signature: 'eg' }
    });
    assert.strictEqual(withoutHandle.response.userHandle, null);
});

test('create() posts the right payload and returns a credential', async () => {
    const { bridge, requests } = loadBridge(CFG, () => ({
        body: { ok: true, credential: {
            id: 'cid', rawId: 'cid', type: 'public-key',
            response: { clientDataJSON: 'Y2Q', attestationObject: 'YXR0' } } }
    }));
    const challenge = new Uint8Array([1, 2, 3, 4]);
    const cred = await bridge.create({ publicKey: {
        challenge, rp: { id: 'example.com' }, user: { id: new Uint8Array([9, 9]) } } });

    assert.strictEqual(requests.length, 1);
    const req = requests[0];
    assert.strictEqual(req.url, 'http://127.0.0.1:' + CFG.port + '/register');
    assert.strictEqual(req.async, true);
    assert.strictEqual(req.headers['X-Broker-Token'], 'tok');
    assert.strictEqual(req.body.rp_id, 'example.com');
    assert.strictEqual(req.body.verify, true);
    // NO `backend` field: the daemon chooses (a security key when attached, else the software
    // key). Sending 'software' here forced every browser ceremony through the fingerprint gate,
    // which a machine whose sensor cannot be used can never satisfy.
    assert.strictEqual('backend' in req.body, false);
    // user_handle is base64url of the raw user id
    assert.strictEqual(req.body.user_handle, bridge.b64uFromBuf(new Uint8Array([9, 9])));
    // client_data decodes to a clientDataJSON of type webauthn.create for this origin
    const cd = JSON.parse(new TextDecoder().decode(bridge.bufFromB64u(req.body.client_data)));
    assert.strictEqual(cd.type, 'webauthn.create');
    assert.strictEqual(cd.origin, 'https://example.com');
    assert.strictEqual(cd.challenge, bridge.b64uFromBuf(challenge));

    assert.strictEqual(cred.id, 'cid');
    assert.strictEqual(cred.rawId.byteLength, bridge.bufFromB64u('cid').byteLength);
});

test('create() throws NotAllowedError when the broker refuses', async () => {
    const { bridge } = loadBridge(CFG, () => ({ body: { ok: false, error: 'declined' } }));
    await assert.rejects(
        () => bridge.create({ publicKey: { challenge: new Uint8Array([1]),
                                           rp: { id: 'example.com' } } }),
        (e) => e.name === 'NotAllowedError');
});

test('create() rejects without publicKey', async () => {
    const { bridge } = loadBridge(CFG, () => ({ body: {} }));
    await assert.rejects(() => bridge.create({}),
                         (e) => e.name === 'NotSupportedError');
});

test('get() maps allowCredentials to allow_ids and falls back to hostname', async () => {
    const { bridge, requests } = loadBridge(CFG, () => ({
        body: { ok: true, credential: {
            id: 'cid', rawId: 'cid', type: 'public-key',
            response: { clientDataJSON: 'Y2Q', authenticatorData: 'YWQ', signature: 'c2ln' } } }
    }));
    const cred = await bridge.get({ publicKey: {
        challenge: new Uint8Array([7]),
        allowCredentials: [{ id: new Uint8Array([1, 1]), type: 'public-key' }] } });
    const req = requests[0];
    assert.match(req.url, /\/authenticate$/);
    assert.strictEqual(req.body.rp_id, 'example.com');            // fallback
    assert.deepStrictEqual(req.body.allow_ids, [bridge.b64uFromBuf(new Uint8Array([1, 1]))]);
    assert.strictEqual(cred.response.authenticatorData.byteLength,
                       bridge.bufFromB64u('YWQ').byteLength);
});

test('get() sends null allow_ids when the page allows any credential', async () => {
    const { bridge, requests } = loadBridge(CFG, () => ({
        body: { ok: true, credential: {
            id: 'eA', rawId: 'eA', type: 'public-key',
            response: { clientDataJSON: 'YQ', authenticatorData: 'Yg', signature: 'Yw' } } }
    }));
    await bridge.get({ publicKey: { challenge: new Uint8Array([1]), rpId: 'rp.example' } });
    assert.strictEqual(requests[0].body.allow_ids, null);
    assert.strictEqual(requests[0].body.rp_id, 'rp.example');
});

test('brokerRequest rejects when no daemon is configured', async () => {
    const { bridge } = loadBridge({ port: 0, token: '' }, () => ({}));
    await assert.rejects(
        () => bridge.create({ publicKey: { challenge: new Uint8Array([1]), rp: { id: 'x' } } }),
        /not running/);
});

test('install() overrides navigator.credentials and the platform-authenticator probe', () => {
    const { navigator } = loadBridge(CFG, () => ({}));
    assert.strictEqual(typeof navigator.credentials.create, 'function');
    assert.strictEqual(typeof navigator.credentials.get, 'function');
    // the statics were installed on the sandbox's PublicKeyCredential
    const { bridge } = loadBridge(CFG, () => ({}));
    assert.strictEqual(typeof bridge.install, 'function');
});

test('install() returns false without a port', () => {
    const { bridge } = loadBridge({ port: 0, token: '' }, () => ({}));
    assert.strictEqual(bridge.install(), false);
});

test('a page calling navigator.credentials.create is intercepted', async () => {
    const { navigator } = loadBridge(CFG, () => ({
        body: { ok: true, credential: {
            id: 'cid', rawId: 'cid', type: 'public-key',
            response: { clientDataJSON: 'Y2Q', attestationObject: 'YXR0' } } }
    }));
    const cred = await navigator.credentials.create({ publicKey: {
        challenge: new Uint8Array([1, 2]), rp: { id: 'example.com' } } });
    assert.strictEqual(cred.id, 'cid');
});

test('a credential without a type falls back to public-key', () => {
    const { bridge } = loadBridge({ port: 0, token: '' }, () => ({}));
    const cred = bridge.toPublicKeyCredential({
        id: 'aWQ', rawId: 'aWQ',
        response: { clientDataJSON: 'eA', attestationObject: 'eg' } });
    assert.strictEqual(cred.type, 'public-key');
    const assertion = bridge.toAssertionCredential({
        id: 'aWQ', rawId: 'aWQ',
        response: { clientDataJSON: 'eA', authenticatorData: 'eQ', signature: 'eg' } });
    assert.strictEqual(assertion.type, 'public-key');
});

test('the shipped default config has port 0 and disables the bridge', () => {
    const { bridge } = loadBridge(null, () => ({}));    // source exactly as shipped
    assert.strictEqual(bridge.CONFIG.port, 0);
    assert.strictEqual(bridge.install(), false);        // no port -> refuses to install
});

test('the platform-authenticator probes are answered', async () => {
    const { window } = loadBridge(CFG, () => ({}));
    assert.strictEqual(await window.PublicKeyCredential
        .isUserVerifyingPlatformAuthenticatorAvailable(), true);
    assert.strictEqual(await window.PublicKeyCredential
        .isConditionalMediationAvailable(), false);
});

// ── fail-safe behaviour: the bridge must not break a page it cannot serve ────────────────

test('install() backs off when PublicKeyCredential was deliberately removed', () => {
    // this is the Google/Microsoft sign-in compat shim: it deletes WebAuthn so the page offers
    // a password. Re-installing it turns a working sign-in into "Couldn't sign you in".
    const { bridge, navigator } = loadBridge(CFG, () => ({}), { noPublicKeyCredential: true });
    assert.strictEqual(bridge.install(), false);
    assert.strictEqual(navigator.credentials.create.name, 'nativeCreate');
    assert.strictEqual(navigator.credentials.get.name, 'nativeGet');
});

test('install() backs off when navigator.credentials cannot do create/get', () => {
    const { bridge, navigator } = loadBridge(CFG, () => ({}), { native: false });
    assert.strictEqual(bridge.install(), false);
    assert.strictEqual(navigator.credentials.create, undefined);
});

test('the platform-authenticator statics are only claimed when the daemon answers', () => {
    const { window } = loadBridge(CFG, (req) => req.url.endsWith('/health')
        ? { status: 500, body: { ok: false } } : { body: {} });
    // The engine does ship these statics (resolving false). With no daemon reachable we must
    // leave them alone rather than claim a platform authenticator we cannot serve.
    return window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
        .then((v) => assert.strictEqual(v, false, 'must stay false when the daemon is unreachable'));
});

test('probeHealthy is false without a configured port', () => {
    const { bridge } = loadBridge({ port: 0, token: '' }, () => ({}));
    assert.strictEqual(bridge.probeHealthy(), false);
});

test('probeHealthy is true when /health answers 200', () => {
    const { bridge } = loadBridge(CFG, () => ({ body: { ok: true } }));
    assert.strictEqual(bridge.probeHealthy(), true);
});

// ── the site gate: the fix for "Couldn't sign you in" ──────────────────────────────────────
// Overriding navigator.credentials makes Google's sign-in treat the browser as tampered and
// refuse the login. So the daemon tells the bridge whether a host may be touched at all, and the
// override itself is installed where the engine's own method lives (CredentialsContainer.prototype)
// behind a Proxy, so a page cannot see it. Passkeys need this: QtWebEngine cannot reach a
// cross-platform key on its own (measured: the ceremony simply hangs with no dialog).
test('install() leaves WebAuthn untouched where the daemon says install:false', () => {
    const { bridge, navigator, window } = loadBridge(CFG, () => ({}), { install: false });
    assert.strictEqual(bridge.install(), false);
    assert.strictEqual(navigator.credentials.create.name, 'nativeCreate',
                       'create must stay native');
    assert.strictEqual(navigator.credentials.get.name, 'nativeGet', 'get must stay native');
    assert.strictEqual(Object.getPrototypeOf(navigator.credentials).create.name, 'nativeCreate',
                       'the prototype must be untouched too');
    return window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable()
        .then((v) => assert.strictEqual(v, false, 'and no platform-authenticator claim either'));
});

test('install() proceeds on a site with NO credential, so registration works', () => {
    const { bridge, navigator } = loadBridge(CFG, () => ({}), { has: false, install: true });
    const before = navigator.credentials.create;
    const nameBefore = before.name;
    const lengthBefore = before.length;
    assert.strictEqual(bridge.install(), true,
                       'a site we hold nothing for is where a new passkey gets registered');
    assert.strictEqual(Object.prototype.hasOwnProperty.call(navigator, 'credentials'), false,
                       'nothing may be added as an own property on navigator');
    // A Proxy preserves name/length, so the replacement is shaped like the method it replaced.
    // (In the engine the target is native, so it also still reports "[native code]".)
    assert.strictEqual(navigator.credentials.create.name, nameBefore);
    assert.strictEqual(navigator.credentials.create.length, lengthBefore);
});

test('install() proceeds when the broker holds a credential for the site', () => {
    const { bridge, navigator } = loadBridge(CFG, () => ({}), { has: true, install: true });
    const nameBefore = navigator.credentials.get.name;
    const lengthBefore = navigator.credentials.get.length;
    assert.strictEqual(bridge.install(), true);
    assert.strictEqual(Object.prototype.hasOwnProperty.call(navigator, 'credentials'), false,
                       'the override lives on the prototype, never on navigator');
    assert.strictEqual(navigator.credentials.get.name, nameBefore);
    assert.strictEqual(navigator.credentials.get.length, lengthBefore);
});

test('siteFlags asks /has for the page host, synchronously', () => {
    const { bridge, requests } = loadBridge(CFG, () => ({}), { has: true, install: true });
    assert.deepStrictEqual(plain(bridge.siteFlags()), { has: true, install: true });
    const asked = requests.filter((r) => r.url.includes('/has'));
    assert.strictEqual(asked.length, 1);
    assert.ok(asked[0].url.includes('host=example.com'), asked[0].url);
    assert.strictEqual(asked[0].async, false, 'install() needs the answer immediately');
});

test('siteFlags is null without a configured port', () => {
    const { bridge } = loadBridge({ port: 0, token: '' }, () => ({}));
    assert.strictEqual(bridge.siteFlags(), null);
});

test('install() reports the native credentials check', () => {
    const native = loadBridge(CFG, () => ({}));
    assert.strictEqual(native.bridge.credentialsLookNative(), true);
    const stripped = loadBridge(CFG, () => ({}), { native: false });
    assert.strictEqual(stripped.bridge.credentialsLookNative(), false);
});

// ── an existing security key must reach the ENGINE, not be swallowed by the broker ─────────
// The broker only serves what IT registered. A key registered elsewhere lives on the token and
// has no broker record, so get() must defer to the native implementation — otherwise every
// existing key (a YubiKey used as 2FA, measured on discord.com) fails with NotAllowedError.

test('get() defers to the native engine when the broker holds no credential for the host', async () => {
    const { navigator, requests } = loadBridge(CFG, () => ({}), { has: false, install: true });
    await assert.rejects(
        () => navigator.credentials.get({ publicKey: { challenge: new Uint8Array([1]) } }),
        /native get/);
    assert.strictEqual(requests.filter((r) => r.url.includes('/authenticate')).length, 0,
                       'the broker must not be asked for a credential it cannot have');
});

test('get() uses the broker when the broker holds a credential for the host', async () => {
    const { navigator, requests } = loadBridge(CFG, () => ({
        body: { ok: true, credential: {
            id: 'cid', rawId: 'cid', type: 'public-key',
            response: { clientDataJSON: 'eA', authenticatorData: 'eQ', signature: 'eg' } } }
    }), { has: true, install: true });
    const cred = await navigator.credentials.get({ publicKey: { challenge: new Uint8Array([1]) } });
    assert.strictEqual(cred.id, 'cid');
    assert.strictEqual(requests.filter((r) => r.url.endsWith('/authenticate')).length, 1);
});

test('create() still registers through the broker on a site with no credential', async () => {
    const { navigator, requests } = loadBridge(CFG, () => ({
        body: { ok: true, credential: {
            id: 'cid', rawId: 'cid', type: 'public-key',
            response: { clientDataJSON: 'eA', attestationObject: 'eg' } } }
    }), { has: false, install: true });
    const cred = await navigator.credentials.create({ publicKey: {
        challenge: new Uint8Array([1]), rp: { id: 'example.com' } } });
    assert.strictEqual(cred.id, 'cid');
    assert.strictEqual(requests.filter((r) => r.url.endsWith('/register')).length, 1,
                       'registration must still go to the broker (that is how a new passkey is made)');
});
