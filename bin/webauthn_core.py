#!/usr/bin/env python3
"""WebAuthn encoding core for the passkey broker.

Everything in this file is pure transformation — no device, no daemon, no I/O — because it
is the part most likely to be subtly wrong and the cheapest to test exhaustively. A WebAuthn
assertion is only useful if its bytes are exactly what a relying party expects: the
authenticator data is hashed into the signature and the client data hash, so a wrong flag bit
or a mis-encoded CBOR length produces a signature that verifies nowhere.

CBOR is hand-rolled (a deliberately tiny subset) rather than pulled from a library: the
encoding is small, fully specified by what WebAuthn needs, and testable byte-for-byte.
"""
import base64
import hashlib
import os
import json
import struct

# ── base64url ────────────────────────────────────────────────────────────────


def b64u_decode(text):
    """Decode base64url without padding, as WebAuthn transports it.

    Strict on the alphabet: a string carrying characters outside base64url is rejected rather
    than silently having them dropped, so a caller that passes junk (a truncated field, an
    HTML page) gets an error instead of plausible-looking wrong bytes.
    """
    if isinstance(text, bytes):
        text = text.decode()
    pad = "=" * (-len(text) % 4)
    return base64.b64decode(text + pad, altchars=b"-_", validate=True)


def b64u_encode(raw):
    """Encode to base64url with padding stripped, as WebAuthn transports it."""
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


# ── CBOR (the subset WebAuthn needs) ─────────────────────────────────────────


def cbor_uint(major, value):
    if value < 24:
        return bytes([(major << 5) | value])
    if value < 0x100:
        return bytes([(major << 5) | 24, value])
    if value < 0x10000:
        return bytes([(major << 5) | 25]) + struct.pack(">H", value)
    if value < 0x100000000:
        return bytes([(major << 5) | 26]) + struct.pack(">I", value)
    return bytes([(major << 5) | 27]) + struct.pack(">Q", value)


def cbor_encode(value):
    """Encode a subset of CBOR: int, bytes, str, bool, None, list, dict.

    Order is preserved rather than canonicalised. WebAuthn does not require canonical
    ordering, and the attestation object's fields are built in the order the spec lists.
    """
    if value is True:
        return b"\xf5"
    if value is False:
        return b"\xf4"
    if value is None:
        return b"\xf6"
    if isinstance(value, int):
        if value >= 0:
            return cbor_uint(0, value)
        return cbor_uint(1, -1 - value)
    if isinstance(value, bytes):
        return cbor_uint(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode()
        return cbor_uint(3, len(raw)) + raw
    if isinstance(value, (list, tuple)):
        return cbor_uint(4, len(value)) + b"".join(cbor_encode(v) for v in value)
    if isinstance(value, dict):
        out = cbor_uint(5, len(value))
        for k, v in value.items():
            out += cbor_encode(k) + cbor_encode(v)
        return out
    raise TypeError("cannot CBOR-encode %r" % (type(value).__name__,))


def cbor_map_length(encoded):
    """Read back the map-header length of an encoded dict (used by the tests)."""
    if not encoded or (encoded[0] >> 5) != 5:
        raise ValueError("not a CBOR map")
    add = encoded[0] & 0x1F
    if add < 24:
        return add, 1
    if add == 24:
        return encoded[1], 2
    raise ValueError("map length too large for this subset")


# ── authenticator data ───────────────────────────────────────────────────────

FLAG_UP = 0x01        # user present
FLAG_UV = 0x04        # user verified
FLAG_BE = 0x08        # backup eligible
FLAG_BS = 0x10        # backup state
FLAG_AT = 0x40        # attested credential data included
FLAG_ED = 0x80        # extension data included


def rp_id_hash(rp_id):
    """The RP ID is SHA-256'd into the authenticator data; a mismatch fails verification."""
    return hashlib.sha256(rp_id.encode()).digest()


def authenticator_data(rp_id, flags, sign_count, attested=None, extensions=None):
    """Build authenticatorData: rpIdHash | flags | signCount | [attestedCredentialData]
    | [extensions] (CTAP2/WebAuthn §6.1)."""
    out = rp_id_hash(rp_id) + bytes([flags]) + struct.pack(">I", sign_count)
    if attested is not None:
        aaguid, cred_id, cose_key = attested
        if len(aaguid) != 16:
            raise ValueError("aaguid must be 16 bytes")
        if len(cred_id) > 1023:
            raise ValueError("credential id too long")
        out += aaguid + struct.pack(">H", len(cred_id)) + cred_id + cbor_encode(cose_key)
    if extensions is not None:
        out += cbor_encode(extensions)
    return out


def cose_es256(x, y):
    """COSE key for ES256 (alg -7): a P-256 public key as x/y coordinates."""
    return {1: 2, 3: -7, -1: 1, -2: x, -3: y}


def attestation_object(auth_data, fmt="none", att_stmt=None):
    """The ``none`` attestation object (WebAuthn §6.5.4). ``none`` is what makes a software
    authenticator indistinguishable from hardware to the relying party — which is what lets
    this broker work at all, and is also the reason it is a deliberate choice."""
    return cbor_encode({"fmt": fmt,
                        "attStmt": {} if att_stmt is None else att_stmt,
                        "authData": auth_data})


def client_data(request_type, challenge, origin, token_binding=None):
    """clientDataJSON. The challenge must be echoed exactly as received — it is hashed into
    the signature, so a single byte of difference invalidates the whole assertion."""
    data = {"type": request_type, "challenge": challenge, "origin": origin}
    if token_binding is not None:
        data["tokenBinding"] = token_binding
    return json.dumps(data, separators=(",", ":")).encode()


def assertion_signature_base(auth_data, client_data_bytes):
    """The bytes an assertion signs: authenticatorData || SHA-256(clientDataJSON)."""
    return auth_data + hashlib.sha256(client_data_bytes).digest()


def make_credential_id():
    """A credential id is opaque; 32 random bytes is the conventional choice."""
    return os.urandom(32)


def public_key_credential(cred_id, att_obj, client_data_bytes, transports=None):
    """The JSON-ish structure a page expects from navigator.credentials.create()."""
    out = {"id": b64u_encode(cred_id), "rawId": b64u_encode(cred_id),
           "type": "public-key", "response": {
               "clientDataJSON": b64u_encode(client_data_bytes),
               "attestationObject": b64u_encode(att_obj)}}
    if transports:
        out["response"]["transports"] = list(transports)
    return out


def assertion_response(cred_id, auth_data, client_data_bytes, signature, user_handle=None):
    """The structure a page expects from navigator.credentials.get()."""
    out = {"id": b64u_encode(cred_id), "rawId": b64u_encode(cred_id), "type": "public-key",
           "response": {"clientDataJSON": b64u_encode(client_data_bytes),
                        "authenticatorData": b64u_encode(auth_data),
                        "signature": b64u_encode(signature)}}
    if user_handle is not None:
        out["response"]["userHandle"] = b64u_encode(user_handle)
    return out


def verify_assertion(public_key, auth_data, client_data_bytes, signature):
    """Verify an assertion the way a relying party would. Used by the tests to prove the
    encoding is spec-correct rather than merely well-shaped."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.exceptions import InvalidSignature
    try:
        public_key.verify(signature, assertion_signature_base(auth_data, client_data_bytes),
                          ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


# ── helpers the broker builds on ─────────────────────────────────────────────

# AAGUID for the software (fingerprint-gated) platform authenticator. 16 bytes, as the spec
# requires. It is a fixed value so a relying party sees a stable authenticator identity across
# registrations; it is NOT the all-zero "no attestation" AAGUID, which would mean the broker
# refused to identify itself.
AAGUID_SOFTWARE = bytes.fromhex("6f6d61726368792d706173736b6579")[:16].ljust(16, b"\x00")


def cose_es256_from_coords(x, y):
    """COSE ES256 key from the P-256 public key's x/y integers, left-padded to 32 bytes each.

    WebAuthn carries the coordinates big-endian, fixed width — a coordinate whose high byte is
    zero must still be 32 bytes, so the padding is part of the encoding rather than cosmetic.
    """
    return cose_es256(x.to_bytes(32, "big"), y.to_bytes(32, "big"))
