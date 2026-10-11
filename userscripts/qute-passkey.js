// ==UserScript==
// @name         Omarchy passkey bridge
// @namespace    Maximilian-Maag.passkey-broker
// @description  Replaces navigator.credentials so passkeys work in qutebrowser via the local broker
// @match        *://*/*
// @run-at       document-start
// @grant        none
// ==/UserScript==
//
// This is the browser half of omarchy-passkey-broker. QtWebEngine advertises WebAuthn and
// then hangs forever — there is no authenticator behind it — so this script intercepts the
// ceremony the page would run and answers it from the local broker instead.
//
// It runs in the PAGE world on purpose: the override has to be the same `navigator.credentials`
// the page itself calls. (An isolated world would get a different navigator and the override
// would never be seen by the relying party.)
//
// CONFIG is rewritten by `bin/passkey-bridge-build` at daemon start, which is how the script
// learns the live port and the loopback token; the token file is 0600 so the page cannot read
// it any other way. An empty port means "no daemon" and the script disables itself.
(function () {
    'use strict';

    var CONFIG = {"port": 0, "token": "", "build": ""};

    // ── base64url (WebAuthn's transport encoding: no padding) ────────────────

    function b64uFromBuf(buf) {
        var bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
        var s = '';
        for (var i = 0; i < bytes.length; i++) { s += String.fromCharCode(bytes[i]); }
        return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    function bufFromB64u(str) {
        var s = String(str).replace(/-/g, '+').replace(/_/g, '/');
        while (s.length % 4) { s += '='; }
        var bin = atob(s);
        var out = new Uint8Array(bin.length);
        for (var i = 0; i < bin.length; i++) { out[i] = bin.charCodeAt(i); }
        return out.buffer;
    }

    // ── the client's half of the ceremony ────────────────────────────────────
    //
    // The authenticator does NOT build clientDataJSON; the client does, and the authenticator
    // echoes it verbatim. The challenge is carried base64url exactly as the relying party sent
    // it, because the RP compares it against its own bytes.

    function clientDataJSON(type, challengeB64u, origin) {
        return JSON.stringify({type: type, challenge: challengeB64u, origin: origin});
    }

    function rpIdOf(pk) {
        if (pk && pk.rp && pk.rp.id) { return pk.rp.id; }
        return window.location.hostname;
    }

    // ── transport ────────────────────────────────────────────────────────────
    //
    // Plain XMLHttpRequest to the loopback broker. GM_xmlhttpRequest in qutebrowser is a thin
    // XHR wrapper, so using XHR directly is both simpler and what actually runs. 127.0.0.1 is
    // a "potentially trustworthy" origin, so an https page may reach it without a mixed-content
    // block.

    function brokerRequest(path, payload) {
        return new Promise(function (resolve, reject) {
            if (!CONFIG.port) { reject(new Error('passkey-broker not running')); return; }
            var xhr = new XMLHttpRequest();
            xhr.open('POST', 'http://127.0.0.1:' + CONFIG.port + path, true);
            xhr.setRequestHeader('Content-Type', 'application/json');
            xhr.setRequestHeader('X-Broker-Token', CONFIG.token || '');
            xhr.onload = function () {
                var data;
                try { data = JSON.parse(xhr.responseText); }
                catch (e) { reject(new Error('broker: bad response')); return; }
                resolve(data);
            };
            xhr.onerror = function () { reject(new Error('broker unreachable')); };
            xhr.send(JSON.stringify(payload));
        });
    }

    // ── response shaping ─────────────────────────────────────────────────────
    //
    // The page expects real ArrayBuffers, not base64url strings, so every binary field is
    // converted back. A field left as a string makes the relying party's verification fail.

    function toPublicKeyCredential(cred) {
        return {
            id: cred.id,
            rawId: bufFromB64u(cred.rawId),
            type: cred.type || 'public-key',
            authenticatorAttachment: 'platform',
            response: {
                clientDataJSON: bufFromB64u(cred.response.clientDataJSON),
                attestationObject: bufFromB64u(cred.response.attestationObject),
                getTransports: function () { return cred.response.transports || ['internal']; }
            },
            getClientExtensionResults: function () { return {}; }
        };
    }

    function toAssertionCredential(cred) {
        var r = cred.response;
        return {
            id: cred.id,
            rawId: bufFromB64u(cred.rawId),
            type: cred.type || 'public-key',
            authenticatorAttachment: 'platform',
            response: {
                clientDataJSON: bufFromB64u(r.clientDataJSON),
                authenticatorData: bufFromB64u(r.authenticatorData),
                signature: bufFromB64u(r.signature),
                userHandle: r.userHandle ? bufFromB64u(r.userHandle) : null
            },
            getClientExtensionResults: function () { return {}; }
        };
    }

    // ── the intercepted calls ────────────────────────────────────────────────

    function create(options) {
        return Promise.resolve().then(function () {
            var pk = options && options.publicKey;
            if (!pk) { throw new DOMException('publicKey required', 'NotSupportedError'); }
            var cd = clientDataJSON('webauthn.create', b64uFromBuf(pk.challenge),
                                    window.location.origin);
            // NO `backend` field on purpose: the daemon picks the best available one — a
            // security key when attached, else the software key. Pinning 'software' here sent
            // EVERY browser ceremony to the fingerprint-gated backend, which a machine whose
            // sensor the owner cannot use can never satisfy, so passkeys failed with a key
            // plugged in and nothing to do with the key.
            return brokerRequest('/register', {
                rp_id: rpIdOf(pk),
                client_data: b64uFromBuf(new TextEncoder().encode(cd)),
                user_handle: pk.user && pk.user.id ? b64uFromBuf(pk.user.id) : '',
                verify: true
            });
        }).then(function (res) {
            if (!res.ok) { throw new DOMException('passkey-broker: ' + res.error, 'NotAllowedError'); }
            return toPublicKeyCredential(res.credential);
        });
    }

    function get(options) {
        return Promise.resolve().then(function () {
            var pk = options && options.publicKey;
            if (!pk) { throw new DOMException('publicKey required', 'NotSupportedError'); }
            var cd = clientDataJSON('webauthn.get', b64uFromBuf(pk.challenge),
                                    window.location.origin);
            var allow = (pk.allowCredentials || []).map(function (c) { return b64uFromBuf(c.id); });
            return brokerRequest('/authenticate', {
                rp_id: pk.rpId || window.location.hostname,
                client_data: b64uFromBuf(new TextEncoder().encode(cd)),
                allow_ids: allow.length ? allow : null,
                verify: true
            });
        }).then(function (res) {
            if (!res.ok) { throw new DOMException('passkey-broker: ' + res.error, 'NotAllowedError'); }
            return toAssertionCredential(res.credential);
        });
    }

    // ── installation ─────────────────────────────────────────────────────────

    function installPublicKeyCredentialStatics() {
        var PKC = window.PublicKeyCredential;
        if (!PKC) { return; }
        // Without this the page concludes "no platform authenticator" and never offers the
        // passkey path at all. It is only set when the daemon can actually answer (see
        // install): claiming a platform authenticator we cannot serve steers a sign-in page
        // into a passkey ceremony that then fails.
        try { PKC.isUserVerifyingPlatformAuthenticatorAvailable = function () { return Promise.resolve(true); }; }
        catch (e) { /* frozen object: the override below still covers the ceremony */ }
        try { PKC.isConditionalMediationAvailable = function () { return Promise.resolve(false); }; }
        catch (e) { /* optional */ }
    }

    function credentialsLookNative() {
        var creds = window.navigator && window.navigator.credentials;
        return !!(creds && typeof creds.create === "function" && typeof creds.get === "function");
    }

    function probeHealthy() {
        // A synchronous localhost probe, so install() can know whether to advertise. Sync XHR
        // is deprecated but this is a single loopback call at document-start; a failure to
        // probe is treated as "not healthy".
        if (!CONFIG.port) { return false; }
        try {
            var xhr = new XMLHttpRequest();
            xhr.open("GET", "http://127.0.0.1:" + CONFIG.port + "/health", false);
            xhr.send(null);
            return xhr.status === 200;
        } catch (e) { return false; }
    }

    function siteFlags() {
        // {has, install} for THIS page's site, or null when it cannot be determined. A
        // synchronous loopback GET (a simple request, so no preflight — a sync XHR cannot do
        // one, and the token would require a custom header). Answered by the daemon's
        // Origin-scoped /has route:
        //
        //   install - may the bridge touch WebAuthn here AT ALL? False on a host whose sign-in
        //             refuses an overridden API (Google), where the override costs the login.
        //   has     - is there a credential for this site?
        //
        // install is deliberately a property of the HOST and not of the store: a site we hold
        // nothing for is exactly where a NEW passkey gets registered, so "no credential" must
        // never switch the bridge off. (Gating installation on `has` made registration
        // impossible — the bridge was off on precisely the sites that needed it.)
        if (!CONFIG.port) { return null; }
        var host = "";
        try { host = (window.location && window.location.hostname) || ""; } catch (e) { return null; }
        if (!host) { return null; }
        try {
            var xhr = new XMLHttpRequest();
            xhr.open("GET", "http://127.0.0.1:" + CONFIG.port + "/has?host=" +
                            encodeURIComponent(host), false);
            xhr.send(null);
            if (xhr.status !== 200) { return null; }
            var data = JSON.parse(xhr.responseText);
            return {has: data.has === true, install: data.install === true};
        } catch (e) { return null; }
    }

    function install(cfg) {
        if (cfg) { CONFIG = cfg; }
        if (!CONFIG.port || !window.navigator) { return false; }
        // Respect a deliberate opt-out. The Google/Microsoft sign-in compatibility shim removes
        // PublicKeyCredential and navigator.credentials.create/get so those flows offer a
        // password instead of a passkey that cannot complete in QtWebEngine. Re-installing them
        // turns a working sign-in into "Couldn't sign you in", so stay out of the way.
        if (!window.PublicKeyCredential) { return false; }
        if (!credentialsLookNative()) { return false; }
        // Leave the page EXACTLY as found where the daemon says the bridge may not operate.
        // Overriding navigator.credentials on such a host is read as a tampered browser and the
        // sign-in is refused outright ("This browser or app may not be secure").
        var flags = siteFlags();
        if (!flags || !flags.install) { return false; }
        // Only claim a platform authenticator when the daemon is actually reachable; a page
        // that asks first must not be steered into a ceremony we cannot serve.
        if (probeHealthy()) { installPublicKeyCredentialStatics(); }
        var orig = window.navigator.credentials;
        var bridge = Object.create(orig || Object.prototype);
        bridge.create = create;
        bridge.get = get;
        try {
            Object.defineProperty(window.navigator, 'credentials',
                                  {value: bridge, configurable: true, writable: true});
        } catch (e) {
            try { window.navigator.credentials = bridge; } catch (e2) { return false; }
        }
        return true;
    }

    var api = {
        CONFIG: CONFIG,
        b64uFromBuf: b64uFromBuf,
        bufFromB64u: bufFromB64u,
        clientDataJSON: clientDataJSON,
        rpIdOf: rpIdOf,
        toPublicKeyCredential: toPublicKeyCredential,
        toAssertionCredential: toAssertionCredential,
        create: create,
        get: get,
        install: install,
        probeHealthy: probeHealthy,
        siteFlags: siteFlags,
        credentialsLookNative: credentialsLookNative
    };
    if (typeof window !== 'undefined') {
        window.__passkeyBridge = api;
        if (CONFIG.port) { install(CONFIG); }
    }
    if (typeof module !== 'undefined' && module.exports) { module.exports = api; }
})();
