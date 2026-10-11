"""Medical Strongroom -- Flask entry point.

Cookie security decisions (Week 3 material, set up correctly from the start):
- HttpOnly: JavaScript can never read the session cookie (blocks XSS token theft)
- Secure: cookie is only ever sent over HTTPS (disable only for local HTTP development)
- SameSite=Strict: cookie isn't sent on cross-site requests (blocks a large class of CSRF)
"""
from functools import wraps
import os
import base64
import json
import hmac
import secrets
from urllib.parse import urlsplit
from flask import Flask, request, redirect, url_for, render_template, g, make_response

from db import init_db
from auth import register_staff, request_staff_account, verify_login_password, create_session_for_user, logout as auth_logout, validate_session, validate_password, AuthError
import patients as patients_module
import admin as admin_module
from patients import PatientError
from audit import log_event, list_events
import usb_key_auth

app = Flask(__name__)
app.config["_database_initialized"] = False
app.config["DEBUG"] = False
app.config["TEMPLATES_AUTO_RELOAD"] = True


@app.before_request
def ensure_database():
    if not app.config["_database_initialized"]:
        init_db()
        app.config["_database_initialized"] = True

SESSION_COOKIE_NAME = "strongroom_session"
# Secure cookies default on; set to 0 only when using local HTTP.
COOKIE_SECURE = os.environ.get("MEDICAL_STRONGROOM_COOKIE_SECURE", "1") == "1"
CSRF_COOKIE_NAME = "strongroom_csrf"
STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


@app.before_request
def protect_state_changes():
    """Require a same-origin double-submit token on every state-changing request."""
    g.csp_nonce = secrets.token_urlsafe(18)
    cookie_token = request.cookies.get(CSRF_COOKIE_NAME, "")
    g.csrf_token = cookie_token if len(cookie_token) >= 32 else secrets.token_urlsafe(32)
    if request.method not in STATE_CHANGING_METHODS:
        return None

    submitted_token = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")
    if not cookie_token or not hmac.compare_digest(cookie_token, submitted_token):
        return ("CSRF validation failed. Reload the page and try again.", 400)

    origin = request.headers.get("Origin")
    if origin:
        parsed_origin = urlsplit(origin)
        if parsed_origin.scheme not in {"http", "https"} or parsed_origin.netloc.lower() != request.host.lower():
            return ("Cross-origin request rejected.", 403)


@app.after_request
def set_security_headers(response):
    """Set browser protections consistently on HTML, JSON, and error responses."""
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; script-src 'self' 'nonce-{}'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; "
        "form-action 'self'; frame-ancestors 'none'".format(getattr(g, "csp_nonce", "")),
    )
    if COOKIE_SECURE:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")

    if hasattr(g, "csrf_token"):
        response.set_cookie(
            CSRF_COOKIE_NAME, g.csrf_token, httponly=False, secure=COOKIE_SECURE,
            samesite="Strict", max_age=8 * 60 * 60, path="/",
        )
    return response


@app.context_processor
def inject_csrf_token():
    return {
        "csrf_token": lambda: getattr(g, "csrf_token", ""),
        "csp_nonce": lambda: getattr(g, "csp_nonce", ""),
    }


def current_user():
    if not hasattr(g, "_user"):
        token = request.cookies.get(SESSION_COOKIE_NAME)
        g._user = validate_session(token)
    return g._user


def _decode_b64url(value):
    if not isinstance(value, str):
        raise ValueError("Expected a base64url string.")
    encoded = value.encode("ascii")
    return base64.urlsafe_b64decode(encoded + b"=" * (-len(encoded) % 4))


def login_required(role=None):
    """Decorator: require a valid session, optionally restricted to one role
    or a list/tuple of allowed roles (e.g. role=("clinician", "frontdesk")
    for a route both can reach, each seeing different data inside the view).
    Role is re-checked here on the SERVER on every request -- never trust
    a client-supplied role field, and never rely on hiding a UI button.
    """
    allowed = None
    if role is not None:
        allowed = {role} if isinstance(role, str) else set(role)

    def decorator(view_fn):
        @wraps(view_fn)
        def wrapped(*args, **kwargs):
            user = current_user()
            if user is None:
                return redirect(url_for("login_page"))
            if allowed is not None and user["role"] not in allowed:
                log_event(user["id"], "access_denied", request.endpoint, None)
                return ("Forbidden: insufficient privileges.", 403)
            return view_fn(*args, **kwargs)
        return wrapped
    return decorator


@app.route("/register", methods=["GET", "POST"])
def register_page():
    if request.method == "GET":
        return render_template("register.html", error=None)

    try:
        staff_id = request_staff_account(
            username=request.form["username"].strip(),
            email=request.form["email"].strip(),
            password=request.form["password"],
            full_name=request.form["full_name"].strip(),
            role=request.form["role"],
        )
    except AuthError as e:
        return render_template("register.html", error=str(e))

    log_event(None, "staff_registration_requested", "staff", staff_id)
    return render_template("register_pending.html", full_name=request.form["full_name"].strip())


@app.route("/admin/staff/new", methods=["GET", "POST"])
@login_required(role="admin")
def admin_staff_new():
    if request.method == "GET":
        return render_template("register.html", error=None, admin_creation=True)
    try:
        staff_id = register_staff(
            username=request.form["username"].strip(), email=request.form["email"].strip(),
            password=request.form["password"], full_name=request.form["full_name"].strip(),
            role=request.form["role"],
        )
    except AuthError as e:
        return render_template("register.html", error=str(e), admin_creation=True)
    log_event(current_user()["id"], "create_staff", "staff", staff_id)
    return redirect(url_for("admin_staff_list"))


def _authenticated_response(user_id, ip_address):
    token = create_session_for_user(user_id, ip_address)
    # Rotate the readable request token when authentication state changes.
    g.csrf_token = secrets.token_urlsafe(32)
    resp = make_response({"redirect": url_for("dashboard")})
    resp.set_cookie(
        SESSION_COOKIE_NAME, token, httponly=True, secure=COOKIE_SECURE,
        samesite="Strict", max_age=8 * 60 * 60,
    )
    return resp


@app.route("/login", methods=["GET", "POST"])
def login_page():
    if request.method == "GET":
        return render_template("login.html", error=None)

    try:
        user = verify_login_password(
            username=request.form["username"].strip(),
            password=request.form["password"],
        )
    except AuthError as e:
        log_event(None, "login_failed", "account", None)
        return render_template("login.html", error=str(e))
    template, options, challenge_id = usb_key_auth.begin_login(user, request.remote_addr)
    return render_template(template, options_json=json.dumps(options), challenge_id=challenge_id, username=user["username"],
                           verify_url=url_for("login_key_verify"),
                           register_url=url_for("login_key_register"))


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "GET":
        return render_template("forgot_password.html", error=None)
    username = request.form.get("username", "").strip()
    recovery = usb_key_auth.begin_password_recovery(username, request.remote_addr)
    options = recovery["options"]
    challenge_id = recovery["challenge_id"]
    return render_template(
        "password_recovery_key.html", username=username, options_json=json.dumps(options),
        challenge_id=challenge_id, recover_url=url_for("forgot_password_complete"),
    )


@app.route("/forgot-password/complete", methods=["POST"])
def forgot_password_complete():
    body = request.get_json(silent=True) or {}
    new_password = body.get("new_password", "")
    if not isinstance(new_password, str):
        return ({"error": "Choose a valid password."}, 400)
    try:
        validate_password(new_password)
    except ValueError as e:
        return ({"error": str(e)}, 400)
    try:
        user_id = usb_key_auth.verify_password_recovery(
            body.get("challenge_id", ""),
            _decode_b64url(body.get("credential_id", "")),
            _decode_b64url(body.get("signature", "")),
        )
        admin_module.reset_staff_password(user_id, new_password)
        log_event(user_id, "password_reset_with_usb", "staff", user_id)
    except Exception:
        return ({"error": "Password recovery failed. Check the USB key and try again."}, 400)
    return {"redirect": url_for("login_page")}


@app.route("/login/key/verify", methods=["POST"])
def login_key_verify():
    body = request.get_json(silent=True) or {}
    try:
        user_id = usb_key_auth.verify_login(
            body.get("challenge_id", ""),
            _decode_b64url(body.get("credential_id", "")),
            _decode_b64url(body.get("signature", "")),
        )
    except Exception:
        log_event(None, "security_key_failed", "login", None)
        return ({"error": "Security-key check failed or expired. Sign in again."}, 400)
    log_event(user_id, "security_key_verified", "login", None)
    return _authenticated_response(user_id, request.remote_addr)


@app.route("/login/key/register", methods=["POST"])
def login_key_register():
    body = request.get_json(silent=True) or {}
    try:
        user_id = usb_key_auth.verify_initial_enrollment(
            body.get("challenge_id", ""),
            _decode_b64url(body.get("credential_id", "")),
            _decode_b64url(body.get("public_key", "")),
            _decode_b64url(body.get("signature", "")),
        )
    except Exception:
        log_event(None, "security_key_enrollment_failed", "login", None)
        return ({"error": "Security-key enrollment failed or expired. Sign in again."}, 400)
    log_event(user_id, "security_key_enrolled", "staff", user_id)
    log_event(user_id, "security_key_verified", "login", None)
    return _authenticated_response(user_id, request.remote_addr)


@app.route("/logout", methods=["POST"])
def logout_page():
    user = current_user()
    if user is not None:
        log_event(user["id"], "logout", "session", None)
    auth_logout(request.cookies.get(SESSION_COOKIE_NAME))
    g.csrf_token = secrets.token_urlsafe(32)
    resp = redirect(url_for("login_page"))
    resp.delete_cookie(SESSION_COOKIE_NAME)
    return resp


@app.route("/dashboard")
@login_required()
def dashboard():
    return render_template("dashboard.html", user=current_user())


@app.route("/admin/audit")
@login_required(role="admin")
def admin_audit():
    return render_template("audit_log.html", events=list_events())


@app.route("/security-keys")
@login_required()
def security_keys_page():
    user = current_user()
    return render_template("security_keys.html", credentials=usb_key_auth.list_credentials(user["id"]), username=user["username"])


@app.route("/security-keys/options", methods=["POST"])
@login_required()
def security_keys_options():
    user = current_user()
    body = request.get_json(silent=True) or {}
    try:
        verified = verify_login_password(user["username"], body.get("password", ""))
        if verified["id"] != user["id"]:
            raise AuthError("Password verification failed.")
    except AuthError as e:
        return ({"error": str(e)}, 403)
    options, challenge_id = usb_key_auth.begin_enrollment(user["id"], request.remote_addr)
    return {"options": options, "challenge_id": challenge_id}


@app.route("/security-keys/verify", methods=["POST"])
@login_required()
def security_keys_verify():
    user = current_user()
    body = request.get_json(silent=True) or {}
    try:
        usb_key_auth.verify_enrollment(
            body.get("challenge_id", ""),
            _decode_b64url(body.get("credential_id", "")),
            _decode_b64url(body.get("public_key", "")),
            _decode_b64url(body.get("signature", "")),
            user["id"],
        )
    except Exception:
        log_event(user["id"], "security_key_enrollment_failed", "staff", user["id"])
        return ({"error": "Security-key enrollment failed or expired."}, 400)
    log_event(user["id"], "security_key_enrolled", "staff", user["id"])
    return {"ok": True}


@app.route("/")
def index():
    return redirect(url_for("dashboard") if current_user() else url_for("login_page"))


# ---------- patients: shared URL, role-dependent data ----------
# Both clinician and frontdesk can request /patients, but the handler
# returns a different, role-appropriate query for each -- the restriction
# is decided server-side inside the view, never by which link the UI shows.

@app.route("/patients")
@login_required(role=("clinician", "frontdesk"))
def patients_list():
    user = current_user()
    if user["role"] == "clinician":
        rows = patients_module.list_assigned_patients(user["id"])
        for patient in rows:
            log_event(user["id"], "view_demographics", "patient", patient["id"])
    else:  # frontdesk
        rows = patients_module.list_all_patients()
        log_event(user["id"], "list_demographics", "patient", None)
    return render_template("patients_list.html", patients=rows, user=user)


@app.route("/assignments", methods=["GET", "POST"])
@login_required()
def assignments_page():
    user = current_user()
    if user["role"] != "clinician" or not user["can_assign_patients"]:
        log_event(user["id"], "access_denied", request.endpoint, None)
        return ("Forbidden: patient assignment permission required.", 403)
    error = None
    if request.method == "POST":
        try:
            patient_id = int(request.form.get("patient_id", ""))
            clinician_id = int(request.form.get("clinician_id", ""))
            patient = patients_module.get_patient(patient_id)
            if patient is None or clinician_id not in {c["id"] for c in patients_module.list_clinicians_for_assignment()}:
                raise ValueError
            patients_module.assign_patient(patient_id, clinician_id, actor_id=user["id"])
            return redirect(url_for("assignments_page"))
        except (TypeError, ValueError):
            error = "Choose a valid patient and clinician."
    return render_template(
        "admin_assign.html", patients=patients_module.list_assignable_patients(),
        clinicians=patients_module.list_clinicians_for_assignment(), error=error,
    )


@app.route("/patients/new", methods=["GET", "POST"])
@login_required(role="frontdesk")
def patient_new():
    if request.method == "GET":
        return render_template("patient_form.html", error=None, patient=None)
    try:
        patients_module.create_patient(
            mrn=request.form["mrn"].strip(),
            full_name=request.form["full_name"].strip(),
            dob=request.form["dob"].strip(),
            contact_info=request.form["contact_info"].strip(), actor_id=current_user()["id"],
        )
    except PatientError as e:
        return render_template("patient_form.html", error=str(e), patient=None)
    return redirect(url_for("patients_list"))


@app.route("/patients/<int:patient_id>/edit", methods=["GET", "POST"])
@login_required(role="frontdesk")
def patient_edit(patient_id):
    patient = patients_module.get_patient(patient_id)
    if patient is None:
        return ("Patient not found.", 404)
    if request.method == "GET":
        log_event(current_user()["id"], "view_demographics", "patient", patient_id)
        return render_template("patient_form.html", error=None, patient=patient)
    patients_module.update_patient(
        patient_id,
        full_name=request.form["full_name"].strip(),
        dob=request.form["dob"].strip(),
        contact_info=request.form["contact_info"].strip(),
        actor_id=current_user()["id"],
    )
    return redirect(url_for("patients_list"))


# ---------- clinician: notes (this is the IDOR-sensitive route) ----------

@app.route("/patients/<int:patient_id>/notes")
@login_required(role="clinician")
def patient_notes(patient_id):
    user = current_user()
    try:
        # get_patient_for_clinician raises PatientError if this clinician
        # is not in patient_assignments for this patient -- that's the fix
        # for "change the patient ID in the URL" from the threat model.
        patient = patients_module.get_patient_for_clinician(patient_id, user["id"])
        notes = patients_module.get_notes_for_patient(patient_id, user["id"])
    except PatientError as e:
        return (str(e), 404)
    return render_template("patient_detail.html", patient=patient, notes=notes, user=user)


@app.route("/patients/<int:patient_id>/notes/new", methods=["GET", "POST"])
@login_required(role="clinician")
def note_new(patient_id):
    user = current_user()
    try:
        patient = patients_module.get_patient_for_clinician(patient_id, user["id"])
    except PatientError as e:
        return (str(e), 404)

    if request.method == "GET":
        return render_template("note_form.html", patient=patient, error=None, note_data={})

    note_data = _clinical_note_from_form()
    if not note_data["chief_concern"] or not note_data["assessment"] or not note_data["plan"]:
        return render_template("note_form.html", patient=patient, error="Complete the chief concern, assessment, and plan before saving.", note_data=note_data)
    patients_module.add_note(patient_id, author_id=user["id"], note_text=note_data)
    return redirect(url_for("patient_notes", patient_id=patient_id))


@app.route("/patients/<int:patient_id>/notes/<int:note_id>/edit", methods=["GET", "POST"])
@login_required(role="clinician")
def note_edit(patient_id, note_id):
    user = current_user()
    try:
        patient = patients_module.get_patient_for_clinician(patient_id, user["id"])
        notes = patients_module.get_notes_for_patient(patient_id, user["id"])
        note = next((n for n in notes if n["id"] == note_id), None)
        if note is None:
            return ("Note not found.", 404)
        if request.method == "POST":
            note_data = _clinical_note_from_form()
            legacy_edit = not note.get("sections")
            if not legacy_edit and (not note_data["chief_concern"] or not note_data["assessment"] or not note_data["plan"]):
                return render_template("note_form.html", patient=patient, note=note, error="Complete the chief concern, assessment, and plan before saving.", note_data=note_data)
            saved_content = note_data.get("additional_notes", "") if legacy_edit and not any(note_data.get(k) for k in ("chief_concern", "assessment", "plan")) else note_data
            if legacy_edit and isinstance(saved_content, str) and not saved_content.strip():
                return render_template("note_form.html", patient=patient, note=note, error="Enter note content before saving.", note_data=note_data)
            patients_module.update_note(note_id, patient_id, user["id"], saved_content)
            return redirect(url_for("patient_notes", patient_id=patient_id))
        note_data = dict(note.get("sections") or {})
        if not note_data:
            note_data["additional_notes"] = note.get("text", "")
        return render_template("note_form.html", patient=patient, note=note, error=None, note_data=note_data)
    except PatientError as e:
        return (str(e), 404)


def _clinical_note_from_form():
    """Collect structured visit fields for encrypted SOAP-note storage."""
    fields = (
        "chief_concern", "history", "medical_history", "medications_allergies",
        "review_of_systems", "vitals", "exam_findings", "assessment", "plan",
        "follow_up", "additional_notes",
    )
    data = {key: request.form.get(key, "").strip() for key in fields}
    data["schema"] = "soap-v1"
    return data


# ---------- admin: staff management ----------

@app.route("/admin/staff")
@login_required(role="admin")
def admin_staff_list():
    return render_template("admin_staff_list.html", staff=admin_module.list_staff())


@app.route("/admin/staff/<int:staff_id>", methods=["GET", "POST"])
@login_required(role="admin")
def admin_staff_detail(staff_id):
    member = admin_module.get_staff_member(staff_id)
    if member is None:
        return ("Staff member not found.", 404)

    error = None
    if request.method == "POST":
        action = request.form.get("action")
        if action == "deactivate":
            admin_module.deactivate_staff(staff_id)
            log_event(current_user()["id"], "deactivate_staff", "staff", staff_id)
        elif action == "approve_request":
            if admin_module.approve_staff_request(staff_id):
                log_event(current_user()["id"], "approve_staff_registration", "staff", staff_id)
        elif action == "reject_request":
            if admin_module.reject_staff_request(staff_id):
                log_event(current_user()["id"], "reject_staff_registration", "staff", staff_id)
        elif action == "reset_password":
            try:
                admin_module.reset_staff_password(staff_id, request.form.get("new_password", ""))
                log_event(current_user()["id"], "reset_staff_password", "staff", staff_id)
            except ValueError as e:
                error = str(e)
        member = admin_module.get_staff_member(staff_id)

    return render_template("admin_staff_detail.html", member=member, error=error)


if __name__ == "__main__":
    app.run(debug=os.environ.get("MEDICAL_STRONGROOM_DEBUG", "0") == "1")
