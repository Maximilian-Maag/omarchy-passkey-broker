#!/usr/bin/env python3
"""The loopback transport: a small HTTP server on 127.0.0.1 that any local app can drive.

The bridge in the browser cannot import Python, so the broker exposes a JSON API over
loopback and writes a ``server.json`` describing where it is listening — the same pattern the
omarchy-qutebrowser reader server already uses, so this is proven plumbing rather than a new
invention. Two properties are load-bearing:

  * it binds to 127.0.0.1 only — never 0.0.0.0 — so nothing off the machine can reach it;
  * every request must carry the token from the 0600 ``token`` file, so another local user
    (or a process that is not the owner) cannot register or assert against the store.

Together those make the per-user daemon the security boundary. A system-wide polkit daemon is
a later option; it is not required to be safe for this single-user laptop.
"""
import hmac
import json
import os
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import broker_paths


def build_stamp(directory=None):
    """A short id for the running code, stamped into server.json.

    Same idea as the reader server: a client that finds the port can also confirm WHICH build
    is answering, so a stale daemon (old code, still bound) is visible rather than silently
    mis-answering. Derived from the mtimes of the broker sources, so editing any of them
    changes the stamp.

    `directory` defaults to this file's own directory and is a parameter so a test can point it
    at a throwaway tree instead of the real one.
    """
    here = directory if directory is not None else os.path.dirname(os.path.abspath(__file__))
    newest = 0
    for name in sorted(os.listdir(here)):
        if name.endswith(".py") or name == "passkey-broker":
            try:
                newest = max(newest, int(os.path.getmtime(os.path.join(here, name))))
            except OSError:
                continue
    return "b%x" % (newest,)


class _Handler(BaseHTTPRequestHandler):
    server_version = "passkey-broker"

    # The bridge runs as a page script, so its XHR to this loopback server is CROSS-ORIGIN (the
    # page's origin differs by port) and the browser applies CORS. Without these headers the
    # response is blocked and the bridge reports "broker unreachable" on every site, and the
    # platform-authenticator probe never resolves true. A wildcard origin is safe here because
    # every mutating route is still gated on the token, which only the bridge (a userscript with
    # it baked in) can present — a page that lacks the token gets a 403 and learns nothing.
    CORS_HEADERS = (
        ("Access-Control-Allow-Origin", "*"),
        ("Access-Control-Allow-Methods", "GET, POST, OPTIONS"),
        ("Access-Control-Allow-Headers", "Content-Type, X-Broker-Token"),
        ("Access-Control-Max-Age", "600"),
    )

    # Silence the default stderr logging: the daemon is not a chatty service.
    def log_message(self, *args):
        pass

    # ── plumbing ──────────────────────────────────────────────────────────────

    def _cors(self):
        for name, value in self.CORS_HEADERS:
            self.send_header(name, value)

    def _send(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self._cors()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        # CORS preflight: the bridge sends Content-Type and X-Broker-Token, both of which make
        # the request non-simple, so the browser asks this first.
        self.send_response(204)
        self._cors()
        self.send_header("Content-Length", "0")
        self.end_headers()

    def _token_ok(self):
        supplied = self.headers.get("X-Broker-Token", "")
        expected = self.server.auth_token
        # compare_digest avoids leaking the token length/prefix through timing.
        return bool(expected) and hmac.compare_digest(supplied, expected)

    def _read_json(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if length <= 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None

    # ── routes ────────────────────────────────────────────────────────────────

    def do_GET(self):
        if self.path == "/health":
            # Health is deliberately unauthenticated: it reveals only liveness and the build,
            # which a client needs before it has read the token, and nothing about credentials.
            self._send(200, {"ok": True, "build": self.server.build,
                             "backends": sorted(self.server.broker.backends)})
            return
        if self.path.startswith("/has"):
            self._handle_has()
            return
        self._send(404, {"ok": False, "error": "not_found"})

    def _handle_has(self):
        """Does the broker hold a credential for the ASKING page's site?

        The bridge must be able to ask this BEFORE it has any reason to touch WebAuthn, and a
        page cannot read the 0600 token, so this one route is unauthenticated. It leaks nothing
        because the answer is scoped to the caller: the Origin header must name the very host
        the caller asks about, so a page cannot enumerate which sites the user has passkeys
        for. (A non-browser caller can omit Origin — but a local process can read the 0600
        credential directory directly anyway, so that grants nothing new.)

        Why it matters: overriding navigator.credentials on a site we hold nothing for is not
        merely useless — Google's sign-in treats a tampered WebAuthn API as an insecure browser
        ("This browser or app may not be secure") and refuses the login. With this gate the
        bridge only ever touches WebAuthn where it can actually serve the ceremony.
        """
        host = (parse_qs(urlparse(self.path).query).get("host") or [""])[0].strip().lower()
        origin = self.headers.get("Origin", "")
        if origin:
            origin_host = (urlparse(origin).hostname or "").lower()
            if not host or origin_host != host:
                self._send(403, {"ok": False, "error": "origin_mismatch"})
                return
        if not host:
            self._send(403, {"ok": False, "error": "no_host"})
            return
        has = False
        for record in self.server.broker.list_credentials():
            rp_id = (record.get("rp_id") or "").lower()
            if rp_id and (host == rp_id or host.endswith("." + rp_id)):
                has = True
                break
        self._send(200, {"ok": True, "has": has})

    def do_POST(self):
        if not self._token_ok():
            self._send(403, {"ok": False, "error": "forbidden"})
            return
        body = self._read_json()
        if body is None:
            self._send(400, {"ok": False, "error": "bad_json"})
            return
        handler = self.server.routes.get(self.path)
        if handler is None:
            self._send(404, {"ok": False, "error": "not_found"})
            return
        try:
            result = handler(body)
        except Exception as exc:                        # a backend fault must not kill the daemon
            self._send(500, {"ok": False, "error": "internal", "detail": str(exc)})
            return
        self._send(200, result)


class BrokerServer:
    def __init__(self, broker, token=None, host="127.0.0.1", port=0):
        self.broker = broker
        self.host = host
        self.port = port
        self.build = build_stamp()
        self.auth_token = token if token is not None else self._load_or_create_token()
        self._httpd = None
        self._thread = None

    # ── token ─────────────────────────────────────────────────────────────────

    @staticmethod
    def _load_or_create_token():
        path = broker_paths.token_path()
        broker_paths.ensure_dir(path.parent)
        if path.exists():
            text = path.read_text(encoding="utf-8").strip()
            if text:
                return text
        token = secrets.token_hex(32)
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(token)
        return token

    # ── routes ────────────────────────────────────────────────────────────────

    def routes(self):
        broker = self.broker
        return {
            "/register": lambda b: broker.register(
                b.get("rp_id", ""), b.get("client_data", ""),
                b.get("user_handle", "") or "", b.get("backend", "software"),
                bool(b.get("verify", True))),
            "/authenticate": lambda b: broker.authenticate(
                b.get("rp_id", ""), b.get("client_data", ""),
                b.get("allow_ids"), bool(b.get("verify", True))),
            "/list": lambda b: {"ok": True, "credentials": broker.list_credentials()},
            "/delete": lambda b: broker.delete(b.get("cred_id", "")),
        }

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def start(self):
        httpd = ThreadingHTTPServer((self.host, self.port), _Handler)
        httpd.daemon_threads = True
        httpd.booker = self  # not serialized; just keeps a reference for the handler
        httpd.broker = self.broker
        httpd.auth_token = self.auth_token
        httpd.build = self.build
        httpd.routes = self.routes()
        self._httpd = httpd
        self.port = httpd.server_address[1]
        self._thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        self._thread.start()
        self._write_server_json()
        return self.port

    def _write_server_json(self):
        path = broker_paths.server_json_path()
        broker_paths.ensure_dir(path.parent)
        payload = json.dumps({"port": self.port, "host": self.host, "pid": os.getpid(),
                              "build": self.build}, indent=2)
        tmp = str(path) + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(payload)
        os.replace(tmp, path)

    def stop(self):
        if self._httpd is not None:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None
