r"""Focused security regression tests using an isolated synthetic SQLite database.

Run with: .\.venv\Scripts\python.exe -m unittest discover -s tests -v
"""
import base64
import os
import tempfile
import unittest
from pathlib import Path

import bcrypt
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

# Set test-only secrets before importing modules that read configuration.
os.environ["MEDICAL_STRONGROOM_ENCRYPTION_KEY"] = base64.urlsafe_b64encode(b"E" * 32).decode().rstrip("=")
os.environ["MEDICAL_STRONGROOM_AUDIT_KEY"] = "test-only-audit-key-not-for-real-data"
os.environ["MEDICAL_STRONGROOM_COOKIE_SECURE"] = "0"
os.environ["MEDICAL_STRONGROOM_DEBUG"] = "0"

import admin
import app as application
import auth
import db
import patients
import security
import usb_key_auth
from audit import list_events, log_event


class SecurityControlsTests(unittest.TestCase):
    password = "SyntheticPass9!"

    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.original_db_path = db.DB_PATH
        db.DB_PATH = Path(self.temporary_directory.name) / "synthetic-test.db"
        application.app.config["TESTING"] = True
        application.app.config["DEBUG"] = False
        application.app.config["_database_initialized"] = False
        db.init_db()
        application.app.config["_database_initialized"] = True

        password_hash = bcrypt.hashpw(self.password.encode(), bcrypt.gensalt(rounds=4)).decode()
        conn = db.get_db()
        try:
            self.user_ids = {}
            for username, role in (
                ("test-admin", "admin"),
                ("test-clinician", "clinician"),
                ("other-clinician", "clinician"),
                ("test-frontdesk", "frontdesk"),
            ):
                cursor = conn.execute(
                    "INSERT INTO staff (username, email, password_hash, role, full_name) VALUES (?, ?, ?, ?, ?)",
                    (username, f"{username}@example.test", password_hash, role, username),
                )
                self.user_ids[username] = cursor.lastrowid
            self.patient_ids = []
            for mrn, name in (("SYN-001", "Synthetic Patient One"), ("SYN-002", "Synthetic Patient Two")):
                cursor = conn.execute(
                    "INSERT INTO patients (mrn, full_name, dob, contact_info) VALUES (?, ?, ?, ?)",
                    (mrn, name, "1980-01-01", "synthetic@example.test"),
                )
                self.patient_ids.append(cursor.lastrowid)
            conn.execute(
                "INSERT INTO patient_assignments (patient_id, clinician_id) VALUES (?, ?)",
                (self.patient_ids[0], self.user_ids["test-clinician"]),
            )
            conn.commit()
        finally:
            conn.close()
        self.client = application.app.test_client()

    def tearDown(self):
        db.DB_PATH = self.original_db_path
        application.app.config["_database_initialized"] = False
        self.temporary_directory.cleanup()

    def login_as(self, username):
        token = auth.create_session_for_user(self.user_ids[username], "127.0.0.1")
        self.client.set_cookie(application.SESSION_COOKIE_NAME, token)
        return token

    def csrf_token(self):
        cookie = self.client.get_cookie(application.CSRF_COOKIE_NAME)
        return cookie.value if cookie else ""

    def test_password_hashing_and_generic_login_failures(self):
        hashed = auth.hash_password(self.password)
        self.assertNotEqual(hashed, self.password)
        self.assertTrue(hashed.startswith(("$2a$", "$2b$", "$2y$")))
        self.assertTrue(auth.verify_password(self.password, hashed))

        errors = []
        for username, password in (("test-clinician", "WrongPassword9!"), ("missing-user", "WrongPassword9!")):
            with self.assertRaises(auth.AuthError) as raised:
                auth.verify_login_password(username, password)
            errors.append(str(raised.exception))
        self.assertEqual(errors[0], errors[1])
        self.assertEqual(errors[0], "Invalid username or password.")

        with self.assertRaisesRegex(auth.AuthError, "Invalid username or password"):
            auth.verify_login_password("test-clinician' OR 1=1 --", self.password)
        self.assertEqual(auth.validate_session("' OR 1=1 --"), None)

    def test_repeated_bad_passwords_trigger_temporary_lockout(self):
        for _ in range(auth.MAX_FAILED_ATTEMPTS):
            with self.assertRaises(auth.AuthError):
                auth.verify_login_password("test-clinician", "WrongPassword9!")
        with self.assertRaisesRegex(auth.AuthError, "temporarily locked"):
            auth.verify_login_password("test-clinician", self.password)

    def test_usb_challenge_success_issues_a_hardened_session_cookie(self):
        user_id = self.user_ids["test-clinician"]
        user = auth.verify_login_password("test-clinician", self.password)
        private_key = ec.generate_private_key(ec.SECP256R1())
        public_der = private_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )
        credential_id = b"synthetic-usb-credential-id"
        conn = db.get_db()
        try:
            conn.execute(
                "INSERT INTO staff_security_keys (user_id, credential_id, public_key) VALUES (?, ?, ?)",
                (user_id, credential_id, public_der),
            )
            conn.commit()
        finally:
            conn.close()

        response = self.client.get("/login")
        self.assertEqual(response.status_code, 200)
        _template_name, options, challenge_id = usb_key_auth.begin_login(user)
        challenge = base64.urlsafe_b64decode(options["challenge"] + "=" * (-len(options["challenge"]) % 4))
        signature_der = private_key.sign(challenge, ec.ECDSA(hashes.SHA256()))
        r_value, s_value = decode_dss_signature(signature_der)
        signature_raw = r_value.to_bytes(32, "big") + s_value.to_bytes(32, "big")
        encode = lambda value: base64.urlsafe_b64encode(value).rstrip(b"=").decode()
        verified = self.client.post(
            "/login/key/verify",
            json={"challenge_id": challenge_id, "credential_id": encode(credential_id), "signature": encode(signature_raw)},
            headers={"X-CSRF-Token": self.csrf_token()},
        )
        self.assertEqual(verified.status_code, 200)
        self.assertEqual(verified.get_json()["redirect"], "/dashboard")
        raw_session = self.client.get_cookie(application.SESSION_COOKIE_NAME).value
        self.assertEqual(auth.validate_session(raw_session)["id"], user_id)

        original_cookie_setting = application.COOKIE_SECURE
        application.COOKIE_SECURE = True
        try:
            with application.app.test_request_context("/"):
                secure_response = application._authenticated_response(user_id, "127.0.0.1")
            session_cookie = next(value for value in secure_response.headers.getlist("Set-Cookie") if value.startswith("strongroom_session="))
            self.assertIn("HttpOnly", session_cookie)
            self.assertIn("Secure", session_cookie)
            self.assertIn("SameSite=Strict", session_cookie)
        finally:
            application.COOKIE_SECURE = original_cookie_setting

    def test_protected_route_requires_login_and_security_headers_are_present(self):
        response = self.client.get("/dashboard")
        self.assertEqual(response.status_code, 302)
        response = self.client.get("/login")
        self.assertEqual(response.status_code, 200)
        self.assertIn("nonce-", response.headers["Content-Security-Policy"])
        self.assertEqual(response.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertEqual(response.headers["Referrer-Policy"], "strict-origin-when-cross-origin")

    def test_csrf_rejects_missing_token_and_cross_origin_post(self):
        self.login_as("test-admin")
        missing_token = self.client.post("/logout")
        self.assertEqual(missing_token.status_code, 400)

        self.client.get("/dashboard")
        token = self.csrf_token()
        cross_origin = self.client.post(
            "/logout", headers={"X-CSRF-Token": token, "Origin": "https://attacker.example"}
        )
        self.assertEqual(cross_origin.status_code, 403)

    def test_logout_and_deactivation_invalidate_existing_sessions(self):
        token = self.login_as("test-clinician")
        self.client.get("/dashboard")
        response = self.client.post("/logout", data={"csrf_token": self.csrf_token()})
        self.assertEqual(response.status_code, 302)
        self.assertIsNone(auth.validate_session(token))

        deactivated_token = auth.create_session_for_user(self.user_ids["other-clinician"], "127.0.0.1")
        admin.deactivate_staff(self.user_ids["other-clinician"])
        self.assertIsNone(auth.validate_session(deactivated_token))

    def test_expired_session_is_rejected_server_side(self):
        token = auth.create_session_for_user(self.user_ids["test-clinician"], "127.0.0.1")
        token_hash = auth.hashlib.sha256(token.encode()).hexdigest()
        conn = db.get_db()
        try:
            conn.execute("UPDATE sessions SET expires_at = '2000-01-01T00:00:00+00:00' WHERE session_token_hash = ?", (token_hash,))
            conn.commit()
        finally:
            conn.close()
        self.assertIsNone(auth.validate_session(token))

    def test_role_checks_block_admin_and_frontdesk_from_notes(self):
        for username in ("test-admin", "test-frontdesk"):
            token = auth.create_session_for_user(self.user_ids[username], "127.0.0.1")
            self.client.set_cookie(application.SESSION_COOKIE_NAME, token)
            response = self.client.get(f"/patients/{self.patient_ids[0]}/notes")
            self.assertEqual(response.status_code, 403, username)
            self.client.delete_cookie(application.SESSION_COOKIE_NAME)

    def test_clinician_patient_assignment_blocks_idor(self):
        self.login_as("test-clinician")
        allowed = self.client.get(f"/patients/{self.patient_ids[0]}/notes")
        denied = self.client.get(f"/patients/{self.patient_ids[1]}/notes")
        self.assertEqual(allowed.status_code, 200)
        self.assertEqual(denied.status_code, 404)
        self.assertIn(b"Patient not found", denied.data)

    def test_note_ciphertext_is_authenticated_and_tampering_is_rejected(self):
        patient_id = self.patient_ids[0]
        clinician_id = self.user_ids["test-clinician"]
        note_text = "SYNTHETIC-ONLY confidential note"
        note_id = patients.add_note(patient_id, clinician_id, note_text)
        second_note_id = patients.add_note(patient_id, clinician_id, note_text)
        conn = db.get_db()
        try:
            row = conn.execute("SELECT encrypted_note, iv FROM clinical_notes WHERE id = ?", (note_id,)).fetchone()
            second_iv = conn.execute("SELECT iv FROM clinical_notes WHERE id = ?", (second_note_id,)).fetchone()["iv"]
            ciphertext, iv = bytes(row["encrypted_note"]), row["iv"]
        finally:
            conn.close()
        self.assertNotIn(note_text.encode(), ciphertext)
        self.assertNotEqual(iv, second_iv)
        self.assertEqual(security.decrypt_note(ciphertext, iv), note_text)
        with self.assertRaises(InvalidTag):
            security.decrypt_note(ciphertext[:-1] + bytes([ciphertext[-1] ^ 1]), iv)
        changed_nonce = base64.urlsafe_b64encode(b"N" * 12).decode().rstrip("=")
        with self.assertRaises(InvalidTag):
            security.decrypt_note(ciphertext, changed_nonce)

    def test_audit_hmac_detects_record_tampering(self):
        log_event(self.user_ids["test-admin"], "synthetic_security_test", "test", 1)
        self.assertTrue(list_events()[-1]["valid"])
        conn = db.get_db()
        try:
            conn.execute("UPDATE audit_log SET action = 'tampered' WHERE id = (SELECT MAX(id) FROM audit_log)")
            conn.commit()
        finally:
            conn.close()
        self.assertFalse(list_events()[-1]["valid"])

    def test_deleting_a_middle_audit_record_breaks_the_following_chain(self):
        for number in range(3):
            log_event(self.user_ids["test-admin"], f"synthetic_chain_event_{number}", "test", number)
        conn = db.get_db()
        try:
            event_ids = [row[0] for row in conn.execute("SELECT id FROM audit_log ORDER BY id")]
            conn.execute("DELETE FROM audit_log WHERE id = ?", (event_ids[1],))
            conn.commit()
        finally:
            conn.close()
        events = list_events()
        self.assertTrue(events[0]["valid"])
        self.assertFalse(events[1]["valid"])


if __name__ == "__main__":
    unittest.main()
