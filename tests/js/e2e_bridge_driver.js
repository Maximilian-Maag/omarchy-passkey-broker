// End-to-end driver: runs the REAL browser bridge against the REAL daemon over HTTP.
//
// This is the cross-language check the unit tests cannot make: the userscript is loaded into a
// `node:vm` page stand-in, its XMLHttpRequest is backed by node's http, so `create()` and
// `get()` travel over a real socket to the Python broker and back. The driver prints the
// ceremony as base64url; tests/e2e/verify_ceremony.py then verifies it as a relying party.
//
// Not a `*.test.js`, so `node --test tests/js/` does not pick it up.
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const http = require('node:http');

const SOURCE = fs.readFileSync(
    path.join(__dirname, '..', '..', 'userscripts', 'qute-passkey.js'), 'utf8');

const PORT = Number(process.env.BROKER_PORT);
const TOKEN = process.env.BROKER_TOKEN || '';

// Minimal XMLHttpRequest over node http, enough for the bridge's single POST shape.
class XHR {
    open(method, url) { this.method = method; this.url = url; }
    setRequestHeader(name, value) { (this.headers = this.headers || {})[name] = value; }
    send(body) {
        const url = new URL(this.url);
        const req = http.request({
            host: url.hostname, port: url.port, path: url.pathname,
            method: this.method || 'POST', headers: this.headers || {}
        }, (res) => {
            let data = '';
            res.on('data', (chunk) => { data += chunk; });
            res.on('end', () => {
                this.status = res.statusCode;
                this.responseText = data;
                if (this.onload) { this.onload(); }
            });
        });
        req.on('error', (err) => { if (this.onerror) { this.onerror(err); } });
        req.end(body);
    }
}

const navigatorObj = {};
const windowObj = {
    location: { origin: 'https://example.com', hostname: 'example.com' },
    PublicKeyCredential: function () {},
    XMLHttpRequest: XHR
};
Object.defineProperty(windowObj, 'navigator',
                      { value: navigatorObj, writable: true, configurable: true });

const sandbox = {
    window: windowObj, navigator: navigatorObj, XMLHttpRequest: XHR,
    btoa, atob, TextEncoder, DOMException, console,
    Promise, Object, JSON, String, Uint8Array, ArrayBuffer, Error, setTimeout
};
vm.createContext(sandbox);
const injected = SOURCE.replace(/var CONFIG = \{.*?\};/,
    'var CONFIG = ' + JSON.stringify({ port: PORT, token: TOKEN, build: 'e2e' }) + ';');
vm.runInContext(injected, sandbox, { filename: 'qute-passkey.js' });
const bridge = sandbox.window.__passkeyBridge;

function b64u(buf) { return bridge.b64uFromBuf(new Uint8Array(buf)); }

(async () => {
    const reg = await bridge.create({ publicKey: {
        challenge: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]),
        rp: { id: 'example.com' },
        user: { id: new Uint8Array([42]) }
    } });
    const assertion = await bridge.get({ publicKey: {
        challenge: new Uint8Array([9, 8, 7]),
        rpId: 'example.com',
        allowCredentials: [{ type: 'public-key', id: bridge.bufFromB64u(reg.id) }]
    } });
    const out = {
        rp_id: 'example.com',
        origin: 'https://example.com',
        registration: {
            id: reg.id,
            clientDataJSON: b64u(reg.response.clientDataJSON),
            attestationObject: b64u(reg.response.attestationObject)
        },
        assertion: {
            id: assertion.id,
            clientDataJSON: b64u(assertion.response.clientDataJSON),
            authenticatorData: b64u(assertion.response.authenticatorData),
            signature: b64u(assertion.response.signature),
            userHandle: assertion.response.userHandle
                ? b64u(assertion.response.userHandle) : null
        }
    };
    process.stdout.write(JSON.stringify(out));
})().catch((err) => {
    console.error('e2e driver error:', err && err.message);
    process.exit(1);
});
