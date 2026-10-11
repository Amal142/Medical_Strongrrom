# Medical Strongroom

A small Flask clinic-records demo focused on access control, confidentiality of clinical notes, and auditability.

## Set up on Windows

Open the project folder in VS Code, then open **Terminal → New Terminal**. Run these commands from the folder containing `app.py`. Python 3.12 must be installed and available through the Windows `py` launcher. Create a virtual environment and install the pinned dependencies:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Create two independent secrets in the same VS Code terminal. This uses the .NET API available in Windows PowerShell and PowerShell 7; the earlier `[RandomNumberGenerator]::GetBytes(32)` static call is not available in some Windows PowerShell versions.

```powershell
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$encryptionBytes = New-Object byte[] 32
$auditBytes = New-Object byte[] 32
$rng.GetBytes($encryptionBytes)
$rng.GetBytes($auditBytes)
$rng.Dispose()
$env:MEDICAL_STRONGROOM_ENCRYPTION_KEY = [Convert]::ToBase64String($encryptionBytes).TrimEnd('=').Replace('+','-').Replace('/','_')
$env:MEDICAL_STRONGROOM_AUDIT_KEY = [Convert]::ToBase64String($auditBytes)
```

To copy the generated values into a password manager, display them in the terminal:

```powershell
Write-Output $env:MEDICAL_STRONGROOM_ENCRYPTION_KEY
Write-Output $env:MEDICAL_STRONGROOM_AUDIT_KEY
```

**Keep these exact secret values safe and reuse them.** The commands above generate new secrets; run them only for a new database setup. If you generate a different encryption key later, existing encrypted notes cannot be decrypted. If you close this terminal, set the original values again in the new terminal (retrieve them from your password manager); do not generate replacements for a database that already contains notes. Keep the secrets out of the project folder and back them up separately from the SQLite database.

Then create the predetermined administrator and start the local development server. The bootstrap asks for the administrator's name and uses that name as the login username; the admin role cannot be created from the staff form. If an administrator already exists, rerunning this command changes that account's login/display name without changing its password.

```powershell
.\.venv\Scripts\python.exe .\bootstrap_admin.py
.\.venv\Scripts\python.exe .\bootstrap_frontdesk.py
.\.venv\Scripts\python.exe .\bootstrap_assignment_doctor.py
$env:MEDICAL_STRONGROOM_COOKIE_SECURE = '0' # local HTTP only
.\.venv\Scripts\python.exe .\app.py
```

Run `bootstrap_admin.py` once to create the administrator; if you run it again, it renames the existing administrator. Run the front-desk and assignment-doctor bootstrap commands once each; they report an error if those accounts already exist. Do not reset the database just to restart the server. Keep the VS Code terminal open while using the app at `http://127.0.0.1:5000`. Stop the server with **Ctrl+C**. For the next run, open a new terminal and restore the original values (retrieve them from your password manager):

```powershell
$env:MEDICAL_STRONGROOM_ENCRYPTION_KEY = '<your saved encryption key>'
$env:MEDICAL_STRONGROOM_AUDIT_KEY = '<your saved audit key>'
$env:MEDICAL_STRONGROOM_COOKIE_SECURE = '0' # local HTTP only
.\.venv\Scripts\python.exe .\app.py
```

`MEDICAL_STRONGROOM_COOKIE_SECURE` is set to `0` only because the local development server uses HTTP. Keep secure cookies enabled behind HTTPS. Debug mode is off by default; do not set `MEDICAL_STRONGROOM_DEBUG=1` in production. The app issues CSRF tokens for browser forms and JSON requests, sends a restrictive Content Security Policy with nonces for inline scripts, and adds browser security headers. HSTS is sent when secure cookies are enabled. The Flask development server is for local demonstration only, not production. The audit HMAC key and AES key are read from the process environment and are never stored in SQLite. Never commit either key.

## Security regression tests

Run the focused security suite from the project folder:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

The suite creates an isolated temporary SQLite database and uses synthetic accounts and patient records; it does not read or modify `medical_strongroom.db`. It covers bcrypt hashing and generic login failures, temporary lockout, successful USB challenge verification and session-cookie flags, protected routes and response headers, CSRF rejection, session expiry/logout/deactivation, role and patient-assignment checks, AES-GCM ciphertext/nonce tampering, SQL-injection-shaped login input, and audit-record tampering and chain deletion. Last recorded run: **12 tests passed (2026-10-10)**. This is focused regression evidence, not a complete security assessment.

## Database backup and restore

The SQLite database contains staff and patient demographics, account data, assignments, audit events, and encrypted clinical-note ciphertext. Patient demographics are not encrypted by the application. Use synthetic records only. Store database backups on a BitLocker-protected volume or another encrypted, access-controlled backup destination; do not save backups in the project folder, on an unprotected USB drive, or in Git. Back up the encryption and audit keys separately in a password manager or protected offline location.

To make a consistent SQLite backup, stop the app first and choose a destination on an encrypted drive. Replace `E:` with that drive's letter:

```powershell
$backupDir = 'E:\EncryptedBackups\MedicalStrongroom'
New-Item -ItemType Directory -Force -Path $backupDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$backupPath = Join-Path $backupDir "medical_strongroom-$stamp.db"
.\.venv\Scripts\python.exe -c "import sqlite3,sys; src=sqlite3.connect('medical_strongroom.db'); dst=sqlite3.connect(sys.argv[1]); src.backup(dst); dst.close(); src.close()" $backupPath
```

For restore, stop the app, preserve the current database as a separate rollback copy, then copy the chosen backup to `medical_strongroom.db`. Restore the exact `MEDICAL_STRONGROOM_ENCRYPTION_KEY` and `MEDICAL_STRONGROOM_AUDIT_KEY` values that were active when the backup was made before starting the app. The encryption key is required to read notes; the audit key is required for old audit signatures to validate. Test restores with synthetic data before relying on any backup.

## Key recovery and rotation

The encrypted USB key file and its separate passphrase are both needed for login. While signed in, open **Manage security keys** and register a second key file; save a protected copy on a separate USB drive and keep its passphrase in a password manager. Password recovery verifies a registered USB key and its passphrase. If all copies of a registered key file or its passphrase are lost, the current app has no administrator key-recovery or key-replacement workflow; an administrator password reset does not bypass the USB-key requirement.

The note-encryption and audit-signing keys are independent. Keep each original value stable and restore it together with its database backup. The app does not currently implement a safe key-rotation migration. Do not replace either environment value on a database with existing records: changing the encryption key makes saved notes unreadable, while changing the audit key makes existing audit signatures fail verification. A future rotation must be a planned maintenance migration that backs up the database and both old keys, re-encrypts every note with the new encryption key, verifies the restored data, and retains protected rollback materials. Audit-key rotation also needs explicit key-version handling and a controlled re-signing or verification plan; it is not automated here.

## Production deployment limits

This project is an educational Flask demo and is not ready to store real patient information. It currently starts with Flask's development server; it has no production WSGI deployment configuration, trusted-host allowlist, managed secret-store integration, database-file encryption, or automated encryption-key rotation. Do not expose `app.py` directly to the internet.

A production deployment would first need a supported production WSGI server behind TLS, strict host validation, secure proxy configuration, `MEDICAL_STRONGROOM_COOKIE_SECURE=1`, debug mode left off, process secrets supplied by a managed secret store, least-privilege service and file permissions, encrypted and access-controlled database backups, tested recovery procedures, and a reviewed key-rotation design. Those deployment controls are requirements for future work, not features supplied by this demo.

## Reset the demo data

Stop the Flask server, then run `python .\reset_demo.py` from this folder. The script saves a timestamped, unencrypted SQLite backup beside the database before clearing accounts, patients, notes, assignments, security keys, sessions, and audit entries. Use it only with synthetic demo records, then move the backup to encrypted, access-controlled storage; it preserves the schema and migration history. Recreate the admin, Paris Anderson, and the assignment doctor with the bootstrap commands above before restarting the app.

## Access model

- The predetermined administrator account is created by `bootstrap_admin.py`; its login username is the administrator's chosen name, and rerunning the script can rename it without resetting the password. The predetermined front-desk account for Paris Anderson (`paris`) is created by `bootstrap_frontdesk.py`; each bootstrap prompts for a password and stores only its bcrypt hash. Create the designated assignment doctor with `bootstrap_assignment_doctor.py`; this clinician has the additional ability to assign patients to treating clinicians. Admins can create/deactivate other clinician and front-desk accounts, reset staff passwords, and review audit metadata. Admin pages do not expose patient demographics or note contents.
- Staff sign in with bcrypt-verified passwords plus a private-key file kept on a regular USB drive. On first sign-in, an account with no registered key creates one before a session is issued. Later sign-ins require a signature from the matching private-key file.
- Passwords must be at least 10 characters and include at least one number and one special character. This is enforced when staff register, administrators create or reset passwords, bootstrap accounts are provisioned, and a password is recovered with a USB key.
- Public staff sign-ups are saved as pending requests. An administrator reviews them in **Manage staff** and approves or rejects each request. Pending and rejected accounts cannot sign in; after approval, a clinician or front-desk user completes USB-key enrollment at first sign-in. Accounts created directly by an administrator are approved immediately.
- **Forgot password** recovery requires the account's registered USB key file and its passphrase. The key signs a one-time, three-minute challenge; after verification, the user can choose a new password. Accounts without an enrolled key need an administrator to reset their password.
- Clinicians see assigned patients and can create, read, and edit their notes. Authorization is checked against `patient_assignments` on each patient/note operation.
- Front-desk staff create/edit demographics and cannot reach clinical-note routes.
- Each note is encrypted with AES-256-GCM using a fresh 96-bit nonce before storage. The nonce is stored beside the ciphertext; the key stays outside the database.
- Audit events are HMAC-SHA-256 signed and linked to the previous event. The admin audit page checks both each signature and the chain. This detects changed or removed middle rows; a standalone local database cannot independently detect truncation of its final rows.

## Regular USB key file

This version supports an ordinary USB flash drive. During first sign-in, the browser creates an ECDSA P-256 key pair and saves an encrypted key file named after the account username (for example, `amal.strongroom-key`). You choose a separate passphrase; PBKDF2 derives an AES-256-GCM key in the browser to encrypt the private key. The app stores only the public key and random credential ID in SQLite. At each later login, choose the key file from the USB and enter its passphrase; the browser decrypts locally, signs a fresh random challenge, and sends only the signature. The server verifies it with the stored public key before issuing a session. The private key is never sent to the server. Losing the key-file passphrase means that file cannot be used; register a backup key and store its passphrase securely. Older v1 key files remain accepted for compatibility, but newly created files use encrypted v2 format.

The USB drive is storage, not a hardware cryptographic device. Anyone who copies an encrypted key file still needs its passphrase to use it. Keep both the USB and passphrase secure. The browser needs a secure context for cryptographic operations; `http://localhost` is permitted for local development, and a real deployment must use HTTPS. Save at least one backup key file to a separate secure USB before relying on the feature; the app supports registering additional key files from **Manage security keys**.

The assignment doctor opens **Assign patients to clinicians** from the dashboard. Assignments are audited, and the doctor’s note access remains limited to patients assigned to that doctor. Admins still have no patient-record access.

Existing demo notes marked with the old placeholder IV are encrypted automatically on first database initialization. Set and safely retain the encryption key before upgrading; do not delete the key afterward.
