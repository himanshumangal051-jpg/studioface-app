import os
import json
import secrets
import sqlite3
import datetime as dt
import uuid
import re
import hmac
import time
from io import BytesIO
import urllib.parse
from functools import wraps

from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
import requests

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as GoogleRequest
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    POSTGRES_AVAILABLE = True
except ImportError:
    POSTGRES_AVAILABLE = False

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "face_engine.db")

SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    # Safe for local development; production should always set SECRET_KEY.
    SECRET_KEY = secrets.token_hex(32)

app.config.update(
    SECRET_KEY=SECRET_KEY,
    MAX_CONTENT_LENGTH=int(os.environ.get("MAX_CONTENT_LENGTH", str(250 * 1024 * 1024))),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "1") == "1",
    PERMANENT_SESSION_LIFETIME=dt.timedelta(hours=12),
)

BREVO_API_KEY = os.environ.get("BREVO_API_KEY", "")
BREVO_SENDER_EMAIL = os.environ.get("BREVO_SENDER_EMAIL", "")
BREVO_SENDER_NAME = os.environ.get("BREVO_SENDER_NAME", "StudioFace AI")
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
DATABASE_URL = os.environ.get("DATABASE_URL", "")
ADMIN_SECRET_PIN = os.environ.get("ADMIN_SECRET_PIN", "")
APP_BASE_URL = os.environ.get("APP_BASE_URL", "").rstrip("/")

# Keep OAuth secure; never enable insecure transport automatically in production.
if os.environ.get("ALLOW_INSECURE_OAUTH", "0") == "1":
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
os.environ["OAUTHLIB_RELAX_TOKEN_SCOPE"] = "1"

OTP_TTL_SECONDS = int(os.environ.get("OTP_TTL_SECONDS", "600"))
OTP_MAX_ATTEMPTS = int(os.environ.get("OTP_MAX_ATTEMPTS", "5"))
OTP_RESEND_COOLDOWN = int(os.environ.get("OTP_RESEND_COOLDOWN", "60"))
RATE_LIMIT_WINDOW = int(os.environ.get("RATE_LIMIT_WINDOW", "60"))
RATE_LIMIT_MAX = int(os.environ.get("RATE_LIMIT_MAX", "8"))
MAX_FILES_PER_EVENT = int(os.environ.get("MAX_FILES_PER_EVENT", "200"))

# Safer allowlist for media uploads.
ALLOWED_EXTENSIONS = {
    "jpg", "jpeg", "png", "webp", "gif",
    "mp4", "mov", "avi", "mkv", "webm",
    "mp3", "wav", "m4a", "aac"
}

OTP_STORE = {}
RATE_LIMIT_STORE = {}
SCOPES = ["https://www.googleapis.com/auth/drive.file"]

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def now_utc():
    return dt.datetime.now(dt.timezone.utc)


def client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def configured_redirect_uri():
    if APP_BASE_URL:
        return f"{APP_BASE_URL}/oauth2callback"
    return url_for("oauth2callback", _external=True, _scheme="https")


def require_config(*names):
    missing = [name for name, value in names if not value]
    if missing:
        raise RuntimeError(f"Missing required configuration: {', '.join(missing)}")


def allowed_file(filename):
    return bool(filename and "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS)


def constant_time_equal(a, b):
    return hmac.compare_digest(str(a or ""), str(b or ""))


def cleanup_ephemeral_stores():
    cutoff = time.time() - max(OTP_TTL_SECONDS, RATE_LIMIT_WINDOW) * 2
    for key in list(OTP_STORE):
        created = OTP_STORE[key].get("created_at", 0)
        if created < cutoff:
            OTP_STORE.pop(key, None)
    for key in list(RATE_LIMIT_STORE):
        items = [ts for ts in RATE_LIMIT_STORE[key] if ts >= time.time() - RATE_LIMIT_WINDOW]
        if items:
            RATE_LIMIT_STORE[key] = items
        else:
            RATE_LIMIT_STORE.pop(key, None)


def rate_limited(key, limit=RATE_LIMIT_MAX, window=RATE_LIMIT_WINDOW):
    cleanup_ephemeral_stores()
    now = time.time()
    recent = [ts for ts in RATE_LIMIT_STORE.get(key, []) if ts >= now - window]
    if len(recent) >= limit:
        RATE_LIMIT_STORE[key] = recent
        return True
    recent.append(now)
    RATE_LIMIT_STORE[key] = recent
    return False


def csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


@app.context_processor
def inject_security_helpers():
    return {"csrf_token": csrf_token()}


def validate_csrf():
    if request.method in {"GET", "HEAD", "OPTIONS"}:
        return True
    supplied = request.headers.get("X-CSRF-Token")
    if not supplied:
        supplied = request.form.get("csrf_token")
    expected = session.get("csrf_token")
    return bool(expected and supplied and constant_time_equal(expected, supplied))


@app.before_request
def csrf_guard():
    if request.endpoint in {"static", "health_check"}:
        return None
    if not validate_csrf():
        if request.path.startswith("/api/"):
            return jsonify({"success": False, "message": "Security token expired. Refresh the page and try again."}), 403
        return "Security token expired. Refresh the page and try again.", 403
    return None


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get("client_id"):
            if request.path.startswith("/api/"):
                return jsonify({"success": False, "message": "Authentication required."}), 401
            return redirect(url_for("client_login"))
        return view(*args, **kwargs)
    return wrapper


def admin_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get("is_admin"):
            return render_template("admin_activity.html", authenticated=False), 403
        return view(*args, **kwargs)
    return wrapper

# -----------------------------------------------------------------------------
# Security headers
# -----------------------------------------------------------------------------
@app.after_request
def add_security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if request.is_secure:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response

# -----------------------------------------------------------------------------
# Health check
# -----------------------------------------------------------------------------
@app.route("/healthz")
def health_check():
    try:
        conn, _db_type = get_db_connection()
        conn.execute("SELECT 1")
        conn.close()
        return jsonify({"status": "ok", "service": "StudioFace AI", "database": "ok"}), 200
    except Exception:
        app.logger.exception("Health check database failure")
        return jsonify({"status": "degraded", "service": "StudioFace AI", "database": "error"}), 503


@app.route("/privacy")
def privacy():
    return render_template("privacy.html")


@app.route("/terms")
def terms():
    return render_template("terms.html")

# -----------------------------------------------------------------------------
# Database
# -----------------------------------------------------------------------------
def get_db_connection():
    if DATABASE_URL and POSTGRES_AVAILABLE:
        db_url = DATABASE_URL
        if db_url.startswith("postgres://"):
            db_url = db_url.replace("postgres://", "postgresql://", 1)
        conn = psycopg2.connect(db_url, connect_timeout=10)
        return conn, "POSTGRES"

    conn = sqlite3.connect(DB_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA journal_mode = WAL")
    return conn, "SQLITE"


def _sqlite_columns(cursor, table):
    return {row[1] for row in cursor.execute(f"PRAGMA table_info({table})").fetchall()}


def _add_sqlite_column(cursor, table, column, definition):
    columns = _sqlite_columns(cursor, table)
    if column not in columns:
        cursor.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def migrate_sqlite_legacy_schema(conn):
    """Add the columns expected by the current app without deleting legacy data."""
    cursor = conn.cursor()
    tables = {r[0] for r in cursor.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}

    if "clients" not in tables:
        cursor.execute("""
            CREATE TABLE clients (
                id TEXT PRIMARY KEY,
                studio_name TEXT NOT NULL,
                owner_name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                phone TEXT NOT NULL,
                password TEXT NOT NULL,
                google_tokens TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
    else:
        _add_sqlite_column(cursor, "clients", "owner_name", "TEXT")
        _add_sqlite_column(cursor, "clients", "phone", "TEXT")
        _add_sqlite_column(cursor, "clients", "password", "TEXT")
        _add_sqlite_column(cursor, "clients", "google_tokens", "TEXT")
        cursor.execute("UPDATE clients SET owner_name = COALESCE(owner_name, studio_name) WHERE owner_name IS NULL OR owner_name = ''")
        cursor.execute("UPDATE clients SET phone = COALESCE(phone, '') WHERE phone IS NULL")
        cursor.execute("UPDATE clients SET password = password_hash WHERE (password IS NULL OR password = '') AND password_hash IS NOT NULL")

    if "events" not in tables:
        cursor.execute("""
            CREATE TABLE events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id TEXT NOT NULL,
                event_id TEXT UNIQUE NOT NULL,
                event_name TEXT NOT NULL,
                event_date TEXT NOT NULL,
                drive_folder_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
    else:
        _add_sqlite_column(cursor, "events", "event_id", "TEXT")
        _add_sqlite_column(cursor, "events", "event_name", "TEXT")
        _add_sqlite_column(cursor, "events", "event_date", "TEXT")
        _add_sqlite_column(cursor, "events", "drive_folder_id", "TEXT")
        cursor.execute("UPDATE events SET event_id = COALESCE(event_id, id) WHERE event_id IS NULL OR event_id = ''")
        cursor.execute("UPDATE events SET event_name = COALESCE(event_name, name, 'Untitled Event') WHERE event_name IS NULL OR event_name = ''")
        cursor.execute("UPDATE events SET event_date = COALESCE(event_date, substr(created_at, 1, 10), date('now')) WHERE event_date IS NULL OR event_date = ''")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT,
            action TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Helpful indexes, all additive.
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_clients_email ON clients(email)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_client_id ON events(client_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_activity_timestamp ON activity_logs(timestamp)")
    conn.commit()
    cursor.close()


def init_db():
    conn, db_type = get_db_connection()
    cursor = conn.cursor()
    try:
        if db_type == "POSTGRES":
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS clients (
                    id TEXT PRIMARY KEY,
                    studio_name TEXT NOT NULL,
                    owner_name TEXT NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    phone TEXT NOT NULL,
                    password TEXT NOT NULL,
                    google_tokens TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY,
                    client_id TEXT NOT NULL,
                    event_id TEXT UNIQUE NOT NULL,
                    event_name TEXT NOT NULL,
                    event_date TEXT NOT NULL,
                    drive_folder_id TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS activity_logs (
                    id BIGSERIAL PRIMARY KEY,
                    email TEXT,
                    action TEXT NOT NULL,
                    details TEXT,
                    ip_address TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_pg_clients_email ON clients(email)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_pg_events_client_id ON events(client_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_pg_activity_timestamp ON activity_logs(timestamp)")
            conn.commit()
        else:
            migrate_sqlite_legacy_schema(conn)
    finally:
        cursor.close()
        conn.close()


init_db()


def log_activity(email, action, details=""):
    try:
        conn, db_type = get_db_connection()
        cursor = conn.cursor()
        placeholder = "%s" if db_type == "POSTGRES" else "?"
        cursor.execute(
            f"INSERT INTO activity_logs (email, action, details, ip_address) VALUES ({placeholder}, {placeholder}, {placeholder}, {placeholder})",
            (email, action, details[:2000], client_ip()),
        )
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as exc:
        app.logger.warning("Activity log error: %s", exc)

# -----------------------------------------------------------------------------
# Google Drive
# -----------------------------------------------------------------------------
def get_drive_service(client_id):
    conn, db_type = get_db_connection()
    cursor = conn.cursor()
    ph = "%s" if db_type == "POSTGRES" else "?"
    cursor.execute(f"SELECT google_tokens FROM clients WHERE id = {ph}", (client_id,))
    row = cursor.fetchone()
    cursor.close()
    conn.close()

    if not row or not row[0]:
        return None

    try:
        token_info = json.loads(row[0])
        if not token_info.get("token"):
            return None
        creds = Credentials(
            token=token_info.get("token"),
            refresh_token=token_info.get("refresh_token"),
            token_uri=token_info.get("token_uri", "https://oauth2.googleapis.com/token"),
            client_id=GOOGLE_CLIENT_ID,
            client_secret=GOOGLE_CLIENT_SECRET,
            scopes=SCOPES,
            expiry=dt.datetime.fromisoformat(token_info["expiry"]) if token_info.get("expiry") else None,
        )
        if creds.expired and creds.refresh_token:
            creds.refresh(GoogleRequest())
            refreshed = {
                "token": creds.token,
                "refresh_token": creds.refresh_token,
                "token_uri": "https://oauth2.googleapis.com/token",
                "scopes": SCOPES,
                "expiry": creds.expiry.isoformat() if creds.expiry else None,
            }
            conn2, db2 = get_db_connection()
            cur2 = conn2.cursor()
            ph2 = "%s" if db2 == "POSTGRES" else "?"
            try:
                cur2.execute(f"UPDATE clients SET google_tokens = {ph2} WHERE id = {ph2}", (json.dumps(refreshed), client_id))
                conn2.commit()
            finally:
                cur2.close(); conn2.close()
        return build("drive", "v3", credentials=creds, cache_discovery=False)
    except Exception as exc:
        app.logger.warning("Invalid/expired stored Google token: %s", exc)
        return None


def get_or_create_root_folder(service):
    query = "name = 'StudioFace Events' and mimeType = 'application/vnd.google-apps.folder' and trashed = false"
    result = service.files().list(q=query, spaces="drive", fields="files(id,name)", pageSize=10).execute()
    files = result.get("files", [])
    if files:
        return files[0]["id"]
    folder = service.files().create(
        body={"name": "StudioFace Events", "mimeType": "application/vnd.google-apps.folder"},
        fields="id",
    ).execute()
    return folder["id"]

# -----------------------------------------------------------------------------
# OTP / Email
# -----------------------------------------------------------------------------
def send_email_otp(recipient_email, otp):
    require_config(("BREVO_API_KEY", BREVO_API_KEY), ("BREVO_SENDER_EMAIL", BREVO_SENDER_EMAIL))
    response = requests.post(
        "https://api.brevo.com/v3/smtp/email",
        headers={
            "api-key": BREVO_API_KEY,
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
        json={
            "sender": {"name": BREVO_SENDER_NAME, "email": BREVO_SENDER_EMAIL},
            "to": [{"email": recipient_email}],
            "subject": "Your StudioFace verification code",
            "htmlContent": f"""
            <div style=\"font-family:Arial,sans-serif;max-width:440px;margin:auto;padding:24px;background:#0F172A;border-radius:16px;color:#F8FAFC;text-align:center\">
              <h2 style=\"color:#6366F1\">StudioFace AI</h2>
              <p style=\"color:#94A3B8\">Your verification code is:</p>
              <div style=\"background:#1E293B;border-radius:12px;padding:18px;margin:20px 0;border:1px dashed #6366F1\">
                <span style=\"font-size:32px;font-weight:800;letter-spacing:6px;color:#818CF8;font-family:monospace\">{otp}</span>
              </div>
              <p style=\"color:#64748B;font-size:12px\">This code expires in {OTP_TTL_SECONDS // 60} minutes.</p>
            </div>
            """,
        },
        timeout=10,
    )
    return response.status_code in (200, 201, 202), response.text

# -----------------------------------------------------------------------------
# Routes: public / client auth
# -----------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")


@app.route("/client/signup", methods=["GET", "POST"])
def client_signup():
    if request.method == "GET":
        return render_template("client_signup.html")

    data = request.form
    studio_name = data.get("studio_name", "").strip()
    owner_name = data.get("owner_name", "").strip() or studio_name
    email = data.get("email", "").strip().lower()
    phone = data.get("phone", "").strip()
    password = data.get("password", "")
    otp = data.get("otp", "").strip()

    if not studio_name or not email or not password:
        return render_template("client_signup.html", error="Studio name, email and password are required."), 400
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        return render_template("client_signup.html", error="Please enter a valid email address."), 400
    if len(password) < 8:
        return render_template("client_signup.html", error="Password must be at least 8 characters."), 400

    otp_entry = OTP_STORE.get(email)
    verified_email = session.get("verified_email") == email
    otp_valid = verified_email
    if not otp_valid and otp_entry:
        age = time.time() - otp_entry.get("created_at", 0)
        if age <= OTP_TTL_SECONDS and otp_entry.get("attempts", 0) < OTP_MAX_ATTEMPTS:
            otp_valid = constant_time_equal(otp_entry.get("otp"), otp)
    if not otp_valid:
        return render_template("client_signup.html", error="Invalid or expired OTP. Please verify again."), 400

    hashed_pw = generate_password_hash(password, method="scrypt")
    client_id = str(uuid.uuid4())
    conn, db_type = get_db_connection()
    cursor = conn.cursor()
    ph = "%s" if db_type == "POSTGRES" else "?"
    try:
        cursor.execute(
            f"INSERT INTO clients (id, studio_name, owner_name, email, phone, password) VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph})",
            (client_id, studio_name, owner_name, email, phone, hashed_pw),
        )
        conn.commit()
        session.clear()
        session.permanent = True
        session.update({"client_id": client_id, "studio_name": studio_name, "client_email": email})
        OTP_STORE.pop(email, None)
        log_activity(email, "SIGNUP_SUCCESS", f"Studio: {studio_name}")
        return redirect(url_for("client_dashboard"))
    except Exception as exc:
        conn.rollback()
        log_activity(email, "SIGNUP_FAILED", str(exc))
        return render_template("client_signup.html", error="An account with this email may already exist."), 400
    finally:
        cursor.close()
        conn.close()


@app.route("/client/login", methods=["GET", "POST"])
def client_login():
    if request.method == "GET":
        return render_template("client_login.html")

    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    if rate_limited(f"login:{client_ip()}:{email}", limit=8, window=60):
        return render_template("client_login.html", error="Too many attempts. Please try again later."), 429

    conn, db_type = get_db_connection()
    cursor = conn.cursor()
    ph = "%s" if db_type == "POSTGRES" else "?"
    cursor.execute(f"SELECT id, studio_name, password FROM clients WHERE email = {ph}", (email,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if user and user[2] and check_password_hash(user[2], password):
        session.clear()
        session.permanent = True
        session.update({"client_id": user[0], "studio_name": user[1], "client_email": email})
        log_activity(email, "LOGIN_SUCCESS")
        return redirect(url_for("client_dashboard"))

    log_activity(email, "LOGIN_FAILED")
    return render_template("client_login.html", error="Invalid email or password."), 401


@app.route("/client/logout")
def client_logout():
    email = session.get("client_email", "unknown")
    log_activity(email, "LOGOUT")
    session.clear()
    return redirect(url_for("client_login"))

# -----------------------------------------------------------------------------
# OTP API
# -----------------------------------------------------------------------------
@app.route("/api/auth/send-otp", methods=["POST"])
def api_send_otp():
    data = request.get_json(silent=True) or {}
    target = str(data.get("target", "")).strip().lower()
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", target):
        return jsonify({"success": False, "message": "Valid email address is required."}), 400
    if rate_limited(f"otp:{client_ip()}:{target}", limit=5, window=300):
        return jsonify({"success": False, "message": "Too many OTP requests. Please try again later."}), 429

    existing = OTP_STORE.get(target)
    if existing and time.time() - existing.get("created_at", 0) < OTP_RESEND_COOLDOWN:
        return jsonify({"success": False, "message": "Please wait before requesting another OTP."}), 429

    otp = f"{secrets.randbelow(1_000_000):06d}"
    OTP_STORE[target] = {"otp": otp, "created_at": time.time(), "attempts": 0}
    log_activity(target, "OTP_REQUESTED")

    try:
        success, _msg = send_email_otp(target, otp)
    except RuntimeError as exc:
        OTP_STORE.pop(target, None)
        return jsonify({"success": False, "message": str(exc)}), 500
    except requests.RequestException:
        OTP_STORE.pop(target, None)
        return jsonify({"success": False, "message": "Unable to send OTP right now."}), 502

    if success:
        return jsonify({"success": True, "message": "OTP has been sent to your email inbox."})
    OTP_STORE.pop(target, None)
    return jsonify({"success": False, "message": "Email service rejected the request."}), 502


@app.route("/api/auth/verify-otp", methods=["POST"])
def api_verify_otp():
    data = request.get_json(silent=True) or {}
    target = str(data.get("target", "")).strip().lower()
    otp = str(data.get("otp", "")).strip()
    entry = OTP_STORE.get(target)

    if not entry or time.time() - entry.get("created_at", 0) > OTP_TTL_SECONDS:
        OTP_STORE.pop(target, None)
        return jsonify({"success": False, "message": "Invalid or expired OTP."}), 400

    entry["attempts"] += 1
    valid = entry["attempts"] <= OTP_MAX_ATTEMPTS and constant_time_equal(entry.get("otp"), otp)
    if valid:
        session["verified_email"] = target
        session.permanent = True
        OTP_STORE.pop(target, None)
        log_activity(target, "OTP_VERIFIED_SUCCESS")
        return jsonify({"success": True, "message": "Email verified successfully."})

    if entry["attempts"] >= OTP_MAX_ATTEMPTS:
        OTP_STORE.pop(target, None)
    log_activity(target, "OTP_VERIFY_FAILED")
    return jsonify({"success": False, "message": "Invalid or expired OTP."}), 400

# -----------------------------------------------------------------------------
# Google OAuth
# -----------------------------------------------------------------------------
@app.route("/connect-google")
@app.route("/auth/google/connect")
@login_required
def google_connect():
    require_config(("GOOGLE_CLIENT_ID", GOOGLE_CLIENT_ID), ("GOOGLE_CLIENT_SECRET", GOOGLE_CLIENT_SECRET))
    redirect_uri = configured_redirect_uri()
    state = secrets.token_urlsafe(32)
    session["oauth_state"] = state
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": " ".join(SCOPES),
        "access_type": "offline",
        "prompt": "consent",
        "state": state,
    }
    auth_url = "https://accounts.google.com/o/oauth2/v2/auth?" + urllib.parse.urlencode(params)
    return redirect(auth_url)


@app.route("/oauth2callback")
def oauth2callback():
    error = request.args.get("error")
    if error:
        return render_template("client_dashboard.html", error=f"Google authorization denied: {error}"), 400

    code = request.args.get("code")
    returned_state = request.args.get("state")
    expected_state = session.pop("oauth_state", None)
    if not code or not expected_state or not constant_time_equal(returned_state, expected_state):
        return render_template("client_dashboard.html", error="Invalid Google OAuth callback."), 400

    client_id_session = session.get("client_id")
    client_email_session = session.get("client_email")
    if not client_id_session or not client_email_session:
        return redirect(url_for("client_login"))

    require_config(("GOOGLE_CLIENT_ID", GOOGLE_CLIENT_ID), ("GOOGLE_CLIENT_SECRET", GOOGLE_CLIENT_SECRET))
    redirect_uri = configured_redirect_uri()

    token_response = requests.post(
        "https://oauth2.googleapis.com/token",
        data={
            "code": code,
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
        },
        timeout=15,
    )
    token_data = token_response.json()
    if token_response.status_code != 200 or "access_token" not in token_data:
        app.logger.warning("Google OAuth token exchange failed: %s", token_response.text[:500])
        return render_template("client_dashboard.html", error="Unable to connect Google Drive."), 502

    expiry = None
    if token_data.get("expires_in"):
        expiry = (now_utc() + dt.timedelta(seconds=int(token_data["expires_in"]))).isoformat()
    stored_token = {
        "token": token_data.get("access_token"),
        "refresh_token": token_data.get("refresh_token"),
        "token_uri": "https://oauth2.googleapis.com/token",
        "scopes": SCOPES,
        "expiry": expiry,
    }

    conn, db_type = get_db_connection()
    cursor = conn.cursor()
    ph = "%s" if db_type == "POSTGRES" else "?"
    try:
        cursor.execute(
            f"UPDATE clients SET google_tokens = {ph} WHERE id = {ph} AND email = {ph}",
            (json.dumps(stored_token), client_id_session, client_email_session),
        )
        conn.commit()
        log_activity(client_email_session, "GOOGLE_DRIVE_CONNECTED")
    finally:
        cursor.close()
        conn.close()

    return redirect(url_for("client_dashboard"))

# -----------------------------------------------------------------------------
# Dashboard / Event upload
# -----------------------------------------------------------------------------
@app.route("/client/dashboard")
@login_required
def client_dashboard():
    conn, db_type = get_db_connection()
    cursor = conn.cursor()
    ph = "%s" if db_type == "POSTGRES" else "?"
    client_id = session.get("client_id")
    try:
        cursor.execute(f"SELECT id, google_tokens, studio_name FROM clients WHERE id = {ph}", (client_id,))
        client_row = cursor.fetchone()
        if not client_row:
            session.clear()
            return redirect(url_for("client_login"))
        session["studio_name"] = client_row[2]
        has_drive = bool(client_row[1])
        cursor.execute(
            f"SELECT id, event_id, event_name, event_date, created_at, drive_folder_id FROM events WHERE client_id = {ph} ORDER BY created_at DESC, id DESC",
            (client_id,),
        )
        events = cursor.fetchall()
        return render_template("client_dashboard.html", studio_name=session.get("studio_name"), has_drive=has_drive, events=events)
    finally:
        cursor.close()
        conn.close()


@app.route("/api/events/create", methods=["POST"])
@app.route("/client/create-event", methods=["POST"])
@login_required
def api_create_event():
    if rate_limited(f"event-create:{client_ip()}:{session.get('client_id')}", limit=10, window=60):
        return jsonify({"success": False, "message": "Too many upload requests. Please try again later."}), 429

    event_name = (request.form.get("event_name") or request.form.get("event_title") or "").strip()
    if not event_name:
        return jsonify({"success": False, "message": "Event title is required."}), 400
    if len(event_name) > 200:
        return jsonify({"success": False, "message": "Event title is too long."}), 400

    service = get_drive_service(session["client_id"])
    if not service:
        return jsonify({"success": False, "message": "Please connect your Google Drive first."}), 400

    uploaded_files = [
        f for f in (request.files.getlist("media_files") or request.files.getlist("files") or request.files.getlist("file"))
        if f and f.filename
    ]
    if not uploaded_files:
        return jsonify({"success": False, "message": "No media files selected for upload."}), 400
    if len(uploaded_files) > MAX_FILES_PER_EVENT:
        return jsonify({"success": False, "message": f"Maximum {MAX_FILES_PER_EVENT} files allowed per event."}), 400

    invalid = [f.filename for f in uploaded_files if not allowed_file(f.filename)]
    if invalid:
        return jsonify({"success": False, "message": "One or more file types are not allowed."}), 400

    # Prevent path-like names while keeping user-friendly filenames.
    safe_event_name = re.sub(r"[^\w\- .()&]+", "_", event_name).strip()[:120] or "Untitled Event"

    try:
        root_folder_id = get_or_create_root_folder(service)
        folder_res = service.files().create(
            body={
                "name": safe_event_name,
                "mimeType": "application/vnd.google-apps.folder",
                "parents": [root_folder_id],
            },
            fields="id",
        ).execute()
        event_folder_id = folder_res["id"]

        uploaded_count = 0
        for upload in uploaded_files:
            file_name = secure_filename(upload.filename)
            if not file_name:
                continue
            upload.stream.seek(0)
            media = MediaIoBaseUpload(
                upload.stream,
                mimetype=upload.content_type or "application/octet-stream",
                chunksize=1024 * 1024,
                resumable=True,
            )
            service.files().create(
                body={"name": file_name, "parents": [event_folder_id]},
                media_body=media,
                fields="id,name,size",
            ).execute()
            uploaded_count += 1

        event_uuid = str(uuid.uuid4())
        event_date = now_utc().date().isoformat()
        conn, db_type = get_db_connection()
        cursor = conn.cursor()
        try:
            if db_type == "POSTGRES":
                cursor.execute(
                    "INSERT INTO events (id, client_id, event_id, event_name, event_date, drive_folder_id) VALUES (%s,%s,%s,%s,%s,%s)",
                    (str(uuid.uuid4()), session["client_id"], event_uuid, event_name, event_date, event_folder_id),
                )
            else:
                # Works with both the legacy TEXT id schema and AUTOINCREMENT schemas.
                cursor.execute(
                    "INSERT INTO events (client_id, event_id, event_name, event_date, drive_folder_id) VALUES (?,?,?,?,?)",
                    (session["client_id"], event_uuid, event_name, event_date, event_folder_id),
                )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cursor.close()
            conn.close()

        log_activity(session.get("client_email", "client"), "EVENT_CREATED", f"Event: {event_name}, Files: {uploaded_count}")
        return jsonify({"success": True, "message": "Event created & synced to Google Drive!", "event_id": event_uuid, "files": uploaded_count})

    except Exception as exc:
        app.logger.exception("Drive upload error")
        return jsonify({"success": False, "message": "Upload failed. Please try again."}), 500

# -----------------------------------------------------------------------------
# Admin portal
# -----------------------------------------------------------------------------
@app.route("/admin/activity", methods=["GET", "POST"])
def admin_activity():
    if request.method == "POST":
        if rate_limited(f"admin:{client_ip()}", limit=5, window=300):
            return render_template("admin_activity.html", error="Too many attempts. Please try later."), 429
        pin = request.form.get("pin", "")
        if ADMIN_SECRET_PIN and constant_time_equal(pin, ADMIN_SECRET_PIN):
            session.clear()
            session.permanent = True
            session["is_admin"] = True
            log_activity("admin", "ADMIN_LOGIN")
        else:
            log_activity("admin", "ADMIN_LOGIN_FAILED")
            return render_template("admin_activity.html", error="Invalid Master PIN", authenticated=False), 401

    if not session.get("is_admin"):
        return render_template("admin_activity.html", authenticated=False)

    conn, db_type = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT id, studio_name, owner_name, email, phone, created_at FROM clients ORDER BY created_at DESC")
        clients = cursor.fetchall()
        cursor.execute("SELECT id, email, action, details, ip_address, timestamp FROM activity_logs ORDER BY id DESC LIMIT 100")
        logs = cursor.fetchall()
        return render_template("admin_activity.html", authenticated=True, clients=clients, logs=logs)
    finally:
        cursor.close()
        conn.close()

@app.route("/admin/logout")
def admin_logout():
    session.clear()
    return redirect(url_for("admin_activity"))

# -----------------------------------------------------------------------------
# Error handling
# -----------------------------------------------------------------------------
@app.errorhandler(413)
def request_too_large(_error):
    if request.path.startswith("/api/"):
        return jsonify({"success": False, "message": "Uploaded files are too large."}), 413
    return "Uploaded files are too large.", 413

@app.errorhandler(404)
def not_found(_error):
    if request.path.startswith("/api/"):
        return jsonify({"success": False, "message": "Endpoint not found."}), 404
    return "Page not found.", 404

@app.errorhandler(Exception)
def unhandled_exception(error):
    app.logger.exception("Unhandled application error: %s", error)
    if request.path.startswith("/api/"):
        return jsonify({"success": False, "message": "An unexpected server error occurred."}), 500
    return "An unexpected server error occurred.", 500

# -----------------------------------------------------------------------------
# Server entry point
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    debug = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(host="0.0.0.0", port=port, debug=debug)
