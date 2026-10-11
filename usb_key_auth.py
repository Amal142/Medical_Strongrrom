"""Challenge-response authentication using a private-key file on a USB drive.

The browser reads the key file locally and signs only the one-time challenge.
The private key is never uploaded; SQLite stores only the public key.
"""
import base64
import secrets
from datetime import datetime, timedelta, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from db import get_db


def _b64url(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _save_challenge(user_id, purpose, challenge, ip_address=None):
    challenge_id = secrets.token_urlsafe(32)
    expires = (datetime.now(timezone.utc) + timedelta(minutes=3)).isoformat()
    conn = get_db()
    try:
        conn.execute("DELETE FROM webauthn_challenges WHERE expires_at < ?", (datetime.now(timezone.utc).isoformat(),))
        conn.execute(
            """INSERT INTO webauthn_challenges
               (challenge_id, user_id, challenge, purpose, ip_address, expires_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (challenge_id, user_id, challenge, purpose, ip_address, expires),
        )
        conn.commit()
    finally:
        conn.close()
    return challenge_id


def _consume_challenge(challenge_id, purpose):
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT * FROM webauthn_challenges WHERE challenge_id = ? AND purpose = ?",
            (challenge_id, purpose),
        ).fetchone()
        conn.execute("DELETE FROM webauthn_challenges WHERE challenge_id = ?", (challenge_id,))
        conn.commit()
        if row is None or datetime.now(timezone.utc) > datetime.fromisoformat(row["expires_at"]):
            return None
        return row
    finally:
        conn.close()


def list_credentials(user_id):
    conn = get_db()
    try:
        return conn.execute("SELECT * FROM staff_security_keys WHERE user_id = ?", (user_id,)).fetchall()
    finally:
        conn.close()


def begin_login(user, ip_address=None):
    credentials = list_credentials(user["id"])
    purpose = "login" if credentials else "enroll"
    challenge = secrets.token_bytes(32)
    challenge_id = _save_challenge(user["id"], purpose, challenge, ip_address)
    opts = {"challenge": _b64url(challenge)}
    if credentials:
        opts["credential_ids"] = [_b64url(bytes(c["credential_id"])) for c in credentials]
        return "login_key_usb.html", opts, challenge_id
    return "login_key_usb_enroll.html", opts, challenge_id


def begin_password_recovery(username, ip_address=None):
    """Return same-shaped recovery options regardless of whether a key exists."""
    conn = get_db()
    try:
        user = conn.execute("SELECT id FROM staff WHERE username = ?", (username,)).fetchone()
        user_id = user["id"] if user else None
        has_key = bool(user_id and conn.execute(
            "SELECT 1 FROM staff_security_keys WHERE user_id = ? LIMIT 1", (user_id,)
        ).fetchone())
    finally:
        conn.close()
    challenge = secrets.token_bytes(32)
    if has_key:
        challenge_id = _save_challenge(user_id, "password_reset", challenge, ip_address)
    else:
        challenge_id = secrets.token_urlsafe(32)
    return {
        "challenge_id": challenge_id,
        "options": {"challenge": _b64url(challenge)},
    }


def verify_password_recovery(challenge_id, credential_id, signature):
    challenge_row = _consume_challenge(challenge_id, "password_reset")
    if challenge_row is None:
        raise ValueError("Recovery check failed or expired.")
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT * FROM staff_security_keys WHERE user_id = ? AND credential_id = ?",
            (challenge_row["user_id"], credential_id),
        ).fetchone()
        if row is None:
            raise ValueError("Recovery check failed.")
        _verify_signature(bytes(row["public_key"]), bytes(challenge_row["challenge"]), signature)
        conn.execute("UPDATE staff_security_keys SET sign_count = sign_count + 1 WHERE id = ?", (row["id"],))
        conn.commit()
        return challenge_row["user_id"]
    except InvalidSignature as exc:
        raise ValueError("Recovery check failed.") from exc
    finally:
        conn.close()


def _verify_signature(public_key_der, challenge, signature_raw):
    public_key = serialization.load_der_public_key(public_key_der)
    if not isinstance(public_key, ec.EllipticCurvePublicKey) or not isinstance(public_key.curve, ec.SECP256R1):
        raise ValueError("Only ECDSA P-256 USB key files are supported.")
    if len(signature_raw) != 64:
        raise ValueError("Malformed signature.")
    signature_der = encode_dss_signature(
        int.from_bytes(signature_raw[:32], "big"), int.from_bytes(signature_raw[32:], "big")
    )
    public_key.verify(signature_der, challenge, ec.ECDSA(hashes.SHA256()))


def verify_login(challenge_id, credential_id, signature):
    challenge_row = _consume_challenge(challenge_id, "login")
    if challenge_row is None:
        raise ValueError("This key challenge expired. Sign in again.")
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT * FROM staff_security_keys WHERE user_id = ? AND credential_id = ?",
            (challenge_row["user_id"], credential_id),
        ).fetchone()
        if row is None:
            raise ValueError("This USB key is not registered to the account.")
        _verify_signature(bytes(row["public_key"]), bytes(challenge_row["challenge"]), signature)
        conn.execute("UPDATE staff_security_keys SET sign_count = sign_count + 1 WHERE id = ?", (row["id"],))
        conn.commit()
        return challenge_row["user_id"]
    except InvalidSignature as exc:
        raise ValueError("USB key signature was invalid.") from exc
    finally:
        conn.close()


def verify_initial_enrollment(challenge_id, credential_id, public_key_der, signature):
    challenge_row = _consume_challenge(challenge_id, "enroll")
    if challenge_row is None:
        raise ValueError("This enrollment challenge expired. Sign in again.")
    _verify_signature(public_key_der, bytes(challenge_row["challenge"]), signature)
    _store_key(challenge_row["user_id"], credential_id, public_key_der)
    return challenge_row["user_id"]


def begin_enrollment(user_id, ip_address=None):
    challenge = secrets.token_bytes(32)
    challenge_id = _save_challenge(user_id, "enroll", challenge, ip_address)
    return {"challenge": _b64url(challenge)}, challenge_id


def verify_enrollment(challenge_id, credential_id, public_key_der, signature, user_id):
    challenge_row = _consume_challenge(challenge_id, "enroll")
    if challenge_row is None or challenge_row["user_id"] != user_id:
        raise ValueError("This enrollment challenge expired. Try again.")
    _verify_signature(public_key_der, bytes(challenge_row["challenge"]), signature)
    _store_key(user_id, credential_id, public_key_der)


def _store_key(user_id, credential_id, public_key_der):
    # Validate the key type before persisting it.
    key = serialization.load_der_public_key(public_key_der)
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValueError("Only ECDSA P-256 USB key files are supported.")
    conn = get_db()
    try:
        conn.execute(
            """INSERT INTO staff_security_keys
               (user_id, credential_id, public_key, sign_count, transports)
               VALUES (?, ?, ?, 0, '[]')""",
            (user_id, credential_id, public_key_der),
        )
        conn.commit()
    finally:
        conn.close()
