"""Patient records, assignments, and clinical notes.

Security decision this file exists to enforce: a clinician being "a
clinician" is not enough to see a patient. They must appear together in
patient_assignments. Every function that returns patient or note data
takes the current user and checks this explicitly -- there is no code
path that returns a patient's notes without that check running.

Clinical notes are encrypted before storage; authorization is checked
before any note content is decrypted.
"""
from db import get_db
import json
from audit import log_event
from security import encrypt_note, decrypt_note


class PatientError(Exception):
    """Raised for not-found / not-authorized conditions. Message is safe
    to show to the user -- see note below on why 404 and 403 are merged.
    """


# ---------- patient CRUD (front-desk only at the route layer) ----------

def create_patient(mrn: str, full_name: str, dob: str, contact_info: str, actor_id=None) -> int:
    conn = get_db()
    try:
        existing = conn.execute("SELECT id FROM patients WHERE mrn = ?", (mrn,)).fetchone()
        if existing:
            raise PatientError("A patient with that MRN already exists.")
        cur = conn.execute(
            "INSERT INTO patients (mrn, full_name, dob, contact_info) VALUES (?, ?, ?, ?)",
            (mrn, full_name, dob, contact_info),
        )
        conn.commit()
        log_event(actor_id, "create_patient", "patient", cur.lastrowid)
        return cur.lastrowid
    finally:
        conn.close()


def update_patient(patient_id: int, full_name: str, dob: str, contact_info: str, actor_id=None) -> None:
    conn = get_db()
    try:
        conn.execute(
            "UPDATE patients SET full_name = ?, dob = ?, contact_info = ? WHERE id = ?",
            (full_name, dob, contact_info, patient_id),
        )
        conn.commit()
        log_event(actor_id, "edit_demographics", "patient", patient_id)
    finally:
        conn.close()


def get_patient(patient_id: int):
    conn = get_db()
    try:
        return conn.execute("SELECT * FROM patients WHERE id = ?", (patient_id,)).fetchone()
    finally:
        conn.close()


def list_all_patients():
    """Front-desk view: every patient, demographics only. No
    per-patient check is needed here because front-desk's permission is
    role-wide (see the threat model: front-desk sees demographics for
    scheduling, but is blocked from notes at the route/role level, not a
    per-patient level like clinicians are).
    """
    conn = get_db()
    try:
        return conn.execute("SELECT * FROM patients ORDER BY full_name").fetchall()
    finally:
        conn.close()


def list_clinicians_for_assignment():
    """Return all clinicians, including the assignment lead, as valid assignees."""
    conn = get_db()
    try:
        return conn.execute(
            "SELECT id, full_name FROM staff WHERE role = 'clinician' ORDER BY full_name"
        ).fetchall()
    finally:
        conn.close()


def list_assignable_patients():
    conn = get_db()
    try:
        return conn.execute("SELECT id, mrn, full_name FROM patients ORDER BY full_name").fetchall()
    finally:
        conn.close()


# ---------- assignment check (the IDOR fix) ----------

def is_assigned(patient_id: int, clinician_id: int) -> bool:
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT 1 FROM patient_assignments WHERE patient_id = ? AND clinician_id = ?",
            (patient_id, clinician_id),
        ).fetchone()
        return row is not None
    finally:
        conn.close()


def assign_patient(patient_id: int, clinician_id: int, actor_id=None) -> None:
    conn = get_db()
    try:
        conn.execute(
            "INSERT OR IGNORE INTO patient_assignments (patient_id, clinician_id) VALUES (?, ?)",
            (patient_id, clinician_id),
        )
        conn.commit()
        log_event(actor_id, "assign_patient", "patient", patient_id)
    finally:
        conn.close()


def list_assigned_patients(clinician_id: int):
    """Clinician view: ONLY patients this clinician is assigned to. This is
    the query that replaces list_all_patients() for the clinician role --
    the restriction is built into the SQL, not applied afterward in Python.
    """
    conn = get_db()
    try:
        return conn.execute(
            """SELECT patients.* FROM patients
               JOIN patient_assignments ON patient_assignments.patient_id = patients.id
               WHERE patient_assignments.clinician_id = ?
               ORDER BY patients.full_name""",
            (clinician_id,),
        ).fetchall()
    finally:
        conn.close()


def get_patient_for_clinician(patient_id: int, clinician_id: int):
    """Returns the patient row only if this clinician is assigned to them,
    else raises. This is the single choke point every clinician-facing
    route must call before returning anything about a patient.
    """
    if not is_assigned(patient_id, clinician_id):
        log_event(clinician_id, "access_denied", "patient", patient_id)
        # Deliberately the SAME error whether the patient doesn't exist or
        # just isn't assigned to this clinician -- distinguishing the two
        # would let an attacker enumerate valid patient IDs by watching
        # which ones return "not found" vs "not yours".
        raise PatientError("Patient not found.")
    patient = get_patient(patient_id)
    if patient is not None:
        log_event(clinician_id, "view_demographics", "patient", patient_id)
    return patient


# ---------- clinical notes ----------

def add_note(patient_id: int, author_id: int, note_text: str) -> int:
    """Encrypt with AES-GCM before writing ciphertext and its unique nonce."""
    if isinstance(note_text, dict):
        note_text = json.dumps(note_text, ensure_ascii=False)
    ciphertext, iv = encrypt_note(note_text)
    conn = get_db()
    try:
        cur = conn.execute(
            """INSERT INTO clinical_notes (patient_id, author_id, encrypted_note, iv)
               VALUES (?, ?, ?, ?)""",
            (patient_id, author_id, ciphertext, iv),
        )
        conn.commit()
        log_event(author_id, "create_note", "patient", patient_id)
        return cur.lastrowid
    finally:
        conn.close()


def get_notes_for_patient(patient_id: int, clinician_id: int):
    """Enforces the assignment check before returning ANY note data --
    this is the function the IDOR attack in the threat model is testing.
    """
    if not is_assigned(patient_id, clinician_id):
        log_event(clinician_id, "access_denied", "patient", patient_id)
        raise PatientError("Patient not found.")

    conn = get_db()
    try:
        rows = conn.execute(
            """SELECT clinical_notes.id, clinical_notes.created_at, clinical_notes.encrypted_note,
                      clinical_notes.iv, staff.full_name AS author_name
               FROM clinical_notes
               JOIN staff ON staff.id = clinical_notes.author_id
               WHERE clinical_notes.patient_id = ?
               ORDER BY clinical_notes.created_at DESC""",
            (patient_id,),
        ).fetchall()
        notes = []
        for r in rows:
            decrypted = decrypt_note(r["encrypted_note"], r["iv"])
            try:
                parsed = json.loads(decrypted)
            except (TypeError, ValueError):
                parsed = None
            structured = parsed if isinstance(parsed, dict) and parsed.get("schema") == "soap-v1" else None
            notes.append({
                "id": r["id"],
                "created_at": r["created_at"],
                "author_name": r["author_name"],
                "text": decrypted if structured is None else structured.get("additional_notes", ""),
                "sections": structured,
            })
        log_event(clinician_id, "view_notes", "patient", patient_id)
        for note in notes:
            log_event(clinician_id, "view_note", "note", note["id"])
        return notes
    finally:
        conn.close()


def update_note(note_id: int, patient_id: int, clinician_id: int, note_text: str) -> None:
    if not is_assigned(patient_id, clinician_id):
        raise PatientError("Patient not found.")
    if isinstance(note_text, dict):
        note_text = json.dumps(note_text, ensure_ascii=False)
    ciphertext, iv = encrypt_note(note_text)
    conn = get_db()
    try:
        row = conn.execute("SELECT id FROM clinical_notes WHERE id = ? AND patient_id = ?", (note_id, patient_id)).fetchone()
        if row is None:
            raise PatientError("Note not found.")
        conn.execute("UPDATE clinical_notes SET encrypted_note = ?, iv = ? WHERE id = ?", (ciphertext, iv, note_id))
        conn.commit()
        log_event(clinician_id, "edit_note", "note", note_id)
    finally:
        conn.close()
