#!/usr/bin/env python3
"""Verify the e2e ceremony the browser bridge produced, as a relying party would.

Reads the JSON emitted by tests/js/e2e_bridge_driver.js (the real userscript, driven through a
real daemon) and checks the things a login actually depends on: the attestation names the right
rp, the assertion signature verifies against the registered public key over the exact
clientDataJSON the page built, and the challenge/origin are the ones sent.
"""
import base64
import json
import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent.parent / "bin"))
import webauthn_core as w  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from fido2 import cbor  # noqa: E402


def b64u(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def check(label, condition):
    print("%s %s" % ("PASS" if condition else "FAIL", label))
    return bool(condition)


def main(path):
    data = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
    ok = True
    rp_id = data["rp_id"]
    origin = data["origin"]

    reg = data["registration"]
    att = cbor.decode(b64u(reg["attestationObject"]))
    ok &= check("attestation fmt is none", att["fmt"] == "none")
    ok &= check("attestation rpIdHash matches rp",
                att["authData"][:32] == w.rp_id_hash(rp_id))

    cd = json.loads(b64u(reg["clientDataJSON"]))
    ok &= check("registration clientData type is webauthn.create",
                cd["type"] == "webauthn.create")
    ok &= check("registration clientData origin matches", cd["origin"] == origin)

    cose = cbor.decode(att["authData"][32 + 1 + 4 + 16 + 2 + 32:])
    pub = ec.EllipticCurvePublicNumbers(int.from_bytes(cose[-2], "big"),
                                        int.from_bytes(cose[-3], "big"),
                                        ec.SECP256R1()).public_key()

    r = data["assertion"]
    ok &= check("assertion uses the registration credential", r["id"] == reg["id"])
    auth_data = b64u(r["authenticatorData"])
    client_data = b64u(r["clientDataJSON"])
    ok &= check("assertion rpIdHash matches rp", auth_data[:32] == w.rp_id_hash(rp_id))
    ok &= check("assertion signature verifies against the registered key",
                w.verify_assertion(pub, auth_data, client_data, b64u(r["signature"])))
    ok &= check("assertion clientData type is webauthn.get",
                json.loads(client_data)["type"] == "webauthn.get")
    ok &= check("user handle round-trips", r["userHandle"] == "Kg")      # b64u of [42]

    print("e2e ceremony: %s" % ("OK" if ok else "FAILED"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
