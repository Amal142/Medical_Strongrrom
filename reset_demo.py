
"""Back up the demo database, then clear all demo records for a fresh start.

Run this only after stopping the Flask development server. The SQLite schema
and migration history are preserved; application data is cleared.
"""

from datetime import datetime
from pathlib import Path
import sqlite3


DB_PATH = Path(__file__).parent / "medical_strongroom.db"

# Fixed allowlist: only these application tables may be cleared.
TABLES_TO_CLEAR = (
    "webauthn_challenges",
    "sessions",
    "staff_security_keys",
    "clinical_notes",
    "audit_log",
    "patient_assignments",
    "patients",
    "staff",
)


def main():
    if not DB_PATH.exists():
        raise SystemExit(f"Database not found: {DB_PATH}")

    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    backup_path = DB_PATH.with_name(
        f"medical_strongroom.backup-{stamp}.db"
    )

    # Back up the database before modifying it.
    with sqlite3.connect(DB_PATH) as source:
        with sqlite3.connect(backup_path) as backup:
            source.backup(backup)

    # Clear demo data in a single transaction.
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("PRAGMA foreign_keys = ON")

        existing_tables = {
            row[0]
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }

        try:
            for table in TABLES_TO_CLEAR:
                if table in existing_tables:
                    # Safe identifier: table comes only from the fixed
                    # TABLES_TO_CLEAR allowlist, never from user input.
                    conn.execute(f'DELETE FROM "{table}"')  # nosec B608

            if "sqlite_sequence" in existing_tables:
                placeholders = ", ".join("?" for _ in TABLES_TO_CLEAR)
                conn.execute(
                    f"DELETE FROM sqlite_sequence WHERE name IN ({placeholders})",
                    TABLES_TO_CLEAR,
                )

            conn.commit()

        except Exception:
            conn.rollback()
            raise

    print(f"Demo data cleared. Backup saved at: {backup_path}")


if __name__ == "__main__":
    main()
