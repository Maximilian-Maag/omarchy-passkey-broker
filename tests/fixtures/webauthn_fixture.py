#!/usr/bin/env python3
"""Emit a JSON fixture of the broker's own encoded bytes for the node/WebCrypto test."""
import json
import os
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent.parent / "bin"))
import webauthn_core as w  # noqa: E402

print(json.dumps({
    "authenticator_data_b64u": w.b64u_encode(
        w.authenticator_data("example.com", w.FLAG_UP | w.FLAG_UV, 1)),
    "other_rp_authenticator_data_b64u": w.b64u_encode(
        w.authenticator_data("evil.com", w.FLAG_UP | w.FLAG_UV, 1)),
    "client_data_b64u": w.b64u_encode(
        w.client_data("webauthn.get", w.b64u_encode(os.urandom(32)),
                      "https://example.com")),
}))
