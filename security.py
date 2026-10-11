"""Encryption and integrity helpers. Secrets are supplied outside SQLite."""
import base64
import hashlib
import hmac
import json
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _secret(name: str) -> bytes:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"{name} must be configured before this operation.")
    return value.encode("utf-8")


def encrypt_note(text: str):
    encoded = _secret("MEDICAL_STRONGROOM_ENCRYPTION_KEY")
    key = base64.urlsafe_b64decode(encoded + b"=" * (-len(encoded) % 4))
    if len(key) != 32:
        raise RuntimeError("Encryption key must decode to exactly 32 bytes.")
    nonce = os.urandom(12)
    return AESGCM(key).encrypt(nonce, text.encode("utf-8"), None), base64.urlsafe_b64encode(nonce).decode("ascii")


def decrypt_note(ciphertext: bytes, iv: str) -> str:
    encoded = _secret("MEDICAL_STRONGROOM_ENCRYPTION_KEY")
    key = base64.urlsafe_b64decode(encoded + b"=" * (-len(encoded) % 4))
    if len(key) != 32:
        raise RuntimeError("Encryption key must decode to exactly 32 bytes.")
    encoded_iv = iv.encode("ascii")
    nonce = base64.urlsafe_b64decode(encoded_iv + b"=" * (-len(encoded_iv) % 4))
    return AESGCM(key).decrypt(nonce, bytes(ciphertext), None).decode("utf-8")


def sign_audit_record(record: dict) -> str:
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(_secret("MEDICAL_STRONGROOM_AUDIT_KEY"), canonical, hashlib.sha256).hexdigest()


def verify_audit_record(record: dict, signature: str) -> bool:
    return hmac.compare_digest(sign_audit_record(record), signature)
