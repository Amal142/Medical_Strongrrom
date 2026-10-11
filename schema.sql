-- Medical Strongroom database schema
-- Week 2 scope: staff + sessions (auth). Other tables included now so
-- later weeks (documents/notes, audit log) don't require a migration.

CREATE TABLE IF NOT EXISTS staff (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    username            TEXT NOT NULL UNIQUE,
    email               TEXT NOT NULL UNIQUE,
    password_hash       TEXT NOT NULL,          -- bcrypt hash, never plaintext
    role                TEXT NOT NULL CHECK (role IN ('admin', 'clinician', 'frontdesk')),
    approval_status     TEXT NOT NULL DEFAULT 'approved' CHECK (approval_status IN ('pending', 'approved', 'rejected')),
    can_assign_patients INTEGER NOT NULL DEFAULT 0 CHECK (can_assign_patients IN (0, 1)),
    full_name           TEXT NOT NULL,
    failed_login_count  INTEGER NOT NULL DEFAULT 0,
    locked_until         TEXT,                   -- ISO timestamp, NULL if not locked
    created_at          TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS sessions (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id             INTEGER NOT NULL REFERENCES staff(id) ON DELETE CASCADE,
    session_token_hash  TEXT NOT NULL UNIQUE,   -- SHA-256 of the token; raw token only ever lives in the cookie
    ip_address          TEXT,
    created_at          TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS staff_security_keys (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER NOT NULL REFERENCES staff(id) ON DELETE CASCADE,
    credential_id   BLOB NOT NULL UNIQUE,
    public_key      BLOB NOT NULL,
    sign_count      INTEGER NOT NULL DEFAULT 0,
    transports      TEXT NOT NULL DEFAULT '[]',
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS webauthn_challenges (
    challenge_id    TEXT PRIMARY KEY,
    user_id         INTEGER NOT NULL REFERENCES staff(id) ON DELETE CASCADE,
    challenge       BLOB NOT NULL,
    purpose         TEXT NOT NULL CHECK (purpose IN ('login', 'enroll', 'password_reset')),
    ip_address      TEXT,
    expires_at      TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS schema_migrations (
    migration_key TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS patients (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    mrn           TEXT NOT NULL UNIQUE,
    full_name     TEXT NOT NULL,
    dob           TEXT NOT NULL,
    contact_info  TEXT,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS patient_assignments (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id    INTEGER NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
    clinician_id  INTEGER NOT NULL REFERENCES staff(id) ON DELETE CASCADE,
    UNIQUE(patient_id, clinician_id)
);

CREATE TABLE IF NOT EXISTS clinical_notes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    patient_id      INTEGER NOT NULL REFERENCES patients(id) ON DELETE CASCADE,
    author_id       INTEGER NOT NULL REFERENCES staff(id),
    encrypted_note  BLOB NOT NULL,
    iv              TEXT NOT NULL,
    created_at      TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_id        INTEGER REFERENCES staff(id),
    action          TEXT NOT NULL,
    target_type     TEXT,
    target_id       INTEGER,
    timestamp       TEXT NOT NULL DEFAULT (datetime('now')),
    previous_signature TEXT NOT NULL DEFAULT '',
    hmac_signature  TEXT NOT NULL
);
