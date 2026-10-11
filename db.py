"""Thin SQLite connection helper. One file, one purpose: give the rest of
the app a connection with foreign keys enforced and rows returned as dicts.
"""
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "medical_strongroom.db"
SCHEMA_PATH = Path(__file__).parent / "schema.sql"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    """Create tables if they don't exist yet. Safe to call on every startup."""
    conn = get_db()
    with open(SCHEMA_PATH) as f:
        conn.executescript(f.read())
    recovery_migration = "password-reset-challenge-v1"
    if not conn.execute("SELECT 1 FROM schema_migrations WHERE migration_key = ?", (recovery_migration,)).fetchone():
        conn.execute("ALTER TABLE webauthn_challenges RENAME TO webauthn_challenges_old")
        conn.execute("""CREATE TABLE webauthn_challenges (
            challenge_id TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES staff(id) ON DELETE CASCADE,
            challenge BLOB NOT NULL,
            purpose TEXT NOT NULL CHECK (purpose IN ('login', 'enroll', 'password_reset')),
            ip_address TEXT,
            expires_at TEXT NOT NULL
        )""")
        conn.execute("""INSERT INTO webauthn_challenges
            (challenge_id, user_id, challenge, purpose, ip_address, expires_at)
            SELECT challenge_id, user_id, challenge, purpose, ip_address, expires_at
            FROM webauthn_challenges_old""")
        conn.execute("DROP TABLE webauthn_challenges_old")
        conn.execute("INSERT INTO schema_migrations (migration_key) VALUES (?)", (recovery_migration,))
    migration = "usb-key-file-auth-v1"
    applied = conn.execute("SELECT 1 FROM schema_migrations WHERE migration_key = ?", (migration,)).fetchone()
    if not applied:
        # Revoke older sessions and discard credentials from the earlier FIDO/WebAuthn implementation.
        conn.execute("DELETE FROM sessions")
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        for row in conn.execute("SELECT id, public_key FROM staff_security_keys").fetchall():
            try:
                key = serialization.load_der_public_key(bytes(row["public_key"]))
                if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
                    raise ValueError("Unexpected public-key type")
            except (ValueError, TypeError):
                conn.execute("DELETE FROM staff_security_keys WHERE id = ?", (row["id"],))
        conn.execute("INSERT INTO schema_migrations (migration_key) VALUES (?)", (migration,))
    columns = {row["name"] for row in conn.execute("PRAGMA table_info(audit_log)")}
    if "previous_signature" not in columns:
        conn.execute("ALTER TABLE audit_log ADD COLUMN previous_signature TEXT NOT NULL DEFAULT ''")
    staff_columns = {row["name"] for row in conn.execute("PRAGMA table_info(staff)")}
    if "can_assign_patients" not in staff_columns:
        conn.execute("ALTER TABLE staff ADD COLUMN can_assign_patients INTEGER NOT NULL DEFAULT 0 CHECK (can_assign_patients IN (0, 1))")
    if "approval_status" not in staff_columns:
        conn.execute("ALTER TABLE staff ADD COLUMN approval_status TEXT NOT NULL DEFAULT 'approved' CHECK (approval_status IN ('pending', 'approved', 'rejected'))")
    legacy_notes = conn.execute(
        "SELECT id, encrypted_note FROM clinical_notes WHERE iv = 'PLACEHOLDER-NO-IV-YET'"
    ).fetchall()
    if legacy_notes:
        from security import encrypt_note
        for note in legacy_notes:
            ciphertext, iv = encrypt_note(bytes(note["encrypted_note"]).decode("utf-8"))
            conn.execute("UPDATE clinical_notes SET encrypted_note = ?, iv = ? WHERE id = ?",
                         (ciphertext, iv, note["id"]))
    conn.commit()
    conn.close()
