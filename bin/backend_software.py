#!/usr/bin/env python3
"""The software (platform) authenticator backend.

This is the fingerprint-gated one: an ES256 key generated here, its private half kept in the
credential store (0600), and every use gated by a fingerprint check that the broker runs before
it will sign. It exists because most laptops have no security key attached, and a fingerprint
is the thing the person actually has with them.

The signature is produced with ``cryptography``, which returns ASN.1 DER for ES256 — exactly
what WebAuthn requires. (WebCrypto, by contrast, returns raw r||s, which a relying party will
reject; that difference is pinned by the node test.)
"""
import webauthn_core as w
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

# WebAuthn COSE algorithm identifier for ECDSA-with-SHA256 (P-256).
ALG_ES256 = -7


class SoftwareBackend:
    name = "software"

    @property
    def aaguid(self):
        return w.AAGUID_SOFTWARE

    def register(self, rp_id, client_data_bytes, user_handle=b"", uv=True):
        """Create a credential. Returns (record_fields, response_dict)."""
        key = ec.generate_private_key(ec.SECP256R1())
        nums = key.public_key().public_numbers()
        cose_key = w.cose_es256_from_coords(nums.x, nums.y)
        cred_id = w.make_credential_id()
        flags = w.FLAG_UP | (w.FLAG_UV if uv else 0)
        auth_data = w.authenticator_data(rp_id, flags, 0,
                                         attested=(self.aaguid, cred_id, cose_key))
        att_obj = w.attestation_object(auth_data)
        private_pem = key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()).decode()
        record = {
            "cred_id": w.b64u_encode(cred_id),
            "rp_id": rp_id,
            "backend": self.name,
            "alg": ALG_ES256,
            "aaguid": self.aaguid.hex(),
            "sign_count": 0,
            "user_handle": w.b64u_encode(user_handle) if user_handle else None,
            "private_pem": private_pem,          # SECRET — the store writes this 0600
        }
        response = w.public_key_credential(cred_id, att_obj, client_data_bytes,
                                           transports=["internal"])
        return record, response

    def authenticate(self, record, client_data_bytes, uv=True):
        """Sign an assertion. Returns (updates_dict, response_dict)."""
        key = serialization.load_pem_private_key(record["private_pem"].encode(), password=None)
        cred_id = w.b64u_decode(record["cred_id"])
        sign_count = int(record.get("sign_count", 0)) + 1
        flags = w.FLAG_UP | (w.FLAG_UV if uv else 0)
        auth_data = w.authenticator_data(record["rp_id"], flags, sign_count)
        signature = key.sign(w.assertion_signature_base(auth_data, client_data_bytes),
                             ec.ECDSA(hashes.SHA256()))
        handle = record.get("user_handle")
        response = w.assertion_response(cred_id, auth_data, client_data_bytes, signature,
                                        user_handle=w.b64u_decode(handle) if handle else None)
        return {"sign_count": sign_count}, response
