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

from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_file
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
import requests
import cv2
import numpy as np

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as GoogleRequest
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload, MediaIoBaseDownload

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

SECRET_KEY = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

app.config.update(
    SECRET_KEY=SECRET_KEY,
    MAX_CONTENT_LENGTH=int(os.environ.get("MAX_CONTENT_LENGTH", str(500 * 1024 * 1024))),
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

if os.environ.get("ALLOW_INSECURE_OAUTH", "0") == "1":
    os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
os.environ["OAUTHLIB_RELAX_TOKEN_SCOPE"] = "1"

OTP_TTL_SECONDS = int(os.environ.get("OTP_TTL_SECONDS", "600"))
OTP_MAX_ATTEMPTS = int(os.environ.get("OTP_MAX_ATTEMPTS", "5"))
OTP_RESEND_COOLDOWN = int(os.environ.get("OTP_RESEND_COOLDOWN", "60"))
RATE_LIMIT_WINDOW = int(os.environ.get("RATE_LIMIT_WINDOW", "60"))
RATE_LIMIT_MAX = int(os.environ.get("RATE_LIMIT_MAX", "10"))
MAX_FILES_PER_EVENT = int(os.environ.get("MAX_FILES_PER_EVENT", "300"))

ALLOWED_IMG = {"jpg", "jpeg", "png", "webp"}
ALLOWED_VID = {"mp4", "mov", "webm", "mkv"}
ALLOWED_EXTENSIONS = ALLOWED_IMG | ALLOWED_VID

OTP_STORE = {}
RATE_LIMIT_STORE = {}
SCOPES = ["https://www.googleapis.com/auth/drive"]

CASCADE_CACHE = None

def get_face_cascade():
    global CASCADE_CACHE
    if CASCADE_CACHE is None:
        xml_path = cv2.data.haarcascades + 'haarcascade_frontalface_default.xml'
        CASCADE_CACHE = cv2.CascadeClassifier(xml_path)
    return CASCADE_CACHE

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def now_utc():
    return dt.datetime.now(dt.timezone.utc)

def client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    return forwarded.split(",")[0].strip() if forwarded else request.remote_addr or "unknown"

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

def is_video(filename):
    return bool(filename and "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_VID)

def constant_time_equal(a, b):
    return hmac.compare_digest(str(a or ""), str(b or ""))

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
    supplied = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token")
    expected = session.get("csrf_token")
    return bool(expected and supplied and constant_time_equal(expected, supplied))

@app.before_request
def csrf_guard():
    if request.endpoint in {"static", "health_check", "guest_event_portal", "api_guest_face_access", "download_media_stream"}:
        return None
    if not validate_csrf():
        if request.path.startswith("/api/"):
            return jsonify({"success": False, "message": "Security token expired."}), 403
        return "Security token expired.", 403
    return None

def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not session.get("client_id"):
            return redirect(url_for("client_login"))
        return view(*args, **kwargs)
    return wrapper

# -----------------------------------------------------------------------------
# Database Setup & Safe Migration
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
                );
                CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY,
                    client_id TEXT NOT NULL,
                    event_id TEXT UNIQUE NOT NULL,
                    event_name TEXT NOT NULL,
                    event_pin TEXT DEFAULT '1234',
                    event_date TEXT NOT NULL,
                    drive_folder_id TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS event_media (
                    id TEXT PRIMARY KEY,
                    event_id TEXT NOT NULL,
                    client_id TEXT NOT NULL,
                    drive_file_id TEXT NOT NULL,
                    file_name TEXT NOT NULL,
                    mime_type TEXT NOT NULL,
                    face_encodings TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS guest_leads (
                    id TEXT PRIMARY KEY,
                    event_id TEXT NOT NULL,
                    guest_name TEXT NOT NULL,
                    guest_phone TEXT NOT NULL,
                    guest_email TEXT,
                    selfie_encoding TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS activity_logs (
                    id BIGSERIAL PRIMARY KEY,
                    email TEXT,
                    action TEXT NOT NULL,
                    details TEXT,
                    ip_address TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
            cursor.execute("ALTER TABLE events ADD COLUMN IF NOT EXISTS event_pin TEXT DEFAULT '1234';")
        else:
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
                );
                CREATE TABLE IF NOT EXISTS events (
                    id TEXT PRIMARY KEY,
                    client_id TEXT NOT NULL,
                    event_id TEXT UNIQUE NOT NULL,
                    event_name TEXT NOT NULL,
                    event_pin TEXT DEFAULT '1234',
                    event_date TEXT NOT NULL,
                    drive_folder_id TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS event_media (
                    id TEXT PRIMARY KEY,
                    event_id TEXT NOT NULL,
                    client_id TEXT NOT NULL,
                    drive_file_id TEXT NOT NULL,
                    file_name TEXT NOT NULL,
                    mime_type TEXT NOT NULL,
                    face_encodings TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS guest_leads (
                    id TEXT PRIMARY KEY,
                    event_id TEXT NOT NULL,
                    guest_name TEXT NOT NULL,
                    guest_phone TEXT NOT NULL,
                    guest_email TEXT,
                    selfie_encoding TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                CREATE TABLE IF NOT EXISTS activity_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT,
                    action TEXT NOT NULL,
                    details TEXT,
                    ip_address TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
            """)
        conn.commit()
    finally:
        cursor.close()
        conn.close()

init_db()

# -----------------------------------------------------------------------------
# Face Extraction & Similarity Logic
# -----------------------------------------------------------------------------
def extract_face_histograms(image_bytes):
    try:
        cascade = get_face_cascade()
        np_arr = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
        if img is None:
            return []
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        faces = cascade.detectMultiScale(gray, scaleFactor=1.2, minNeighbors=5, minSize=(60, 60))
        encodings = []
        for (x, y, w, h) in faces:
            face_roi = gray[y:y+h, x:x+w]
            face_resized = cv2.resize(face_roi, (32, 32))
            hist = cv2.equalizeHist(face_resized).flatten().astype("float32")
            norm = np.linalg.norm(hist)
            if norm > 0:
                hist /= norm
            encodings.append(hist.tolist())
        return encodings
    except Exception as err:
        app.logger.warning("Face processing failed: %s", err)
        return []

def match_face(guest_vec, media_vecs_json, threshold=0.60):
    if not media_vecs_json or not guest_vec:
        return False
    try:
        target = np.array(guest_vec, dtype="float32")
        media_vecs = json.loads(media_vecs_json)
        for vec in media_vecs:
            v = np.array(vec, dtype="float32")
            sim = np.dot(target, v)
            if sim >= threshold:
                return True
    except Exception:
        return False
    return False

# -----------------------------------------------------------------------------
# Google Drive Connection
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

        expiry_dt = None
        if token_info.get("expiry"):
            raw = dt.datetime.fromisoformat(token_info["expiry"])
            expiry_dt = raw.astimezone(dt.timezone.utc).replace(tzinfo=None) if raw.tzinfo else raw

        creds = Credentials(
            token=token_info.get("token"),
            refresh_token=token_info.get("refresh_token"),
            token_uri=token_info.get("token_uri", "https://oauth2.googleapis.com/token"),
            client_id=GOOGLE_CLIENT_ID,
            client_secret=GOOGLE_CLIENT_SECRET,
            scopes=SCOPES,
            expiry=expiry_dt,
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
                cur2.close()
                conn2.close()
        return build("drive", "v3", credentials=creds, cache_discovery=False)
    except Exception as exc:
        app.logger.warning("Google Drive token error: %s", exc)
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
# Routes
# -----------------------------------------------------------------------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/privacy")
def privacy():
    return render_template("privacy.html")

@app.route("/terms")
def terms():
    return render_template("terms.html")

@app.route("/healthz")
def health_check():
    return jsonify({"status": "ok", "service": "StudioFace AI"}), 200

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

    if not studio_name or not email or not password or len(password) < 8:
        return render_template("client_signup.html", error="Please fill all fields properly."), 400

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
        return redirect(url_for("client_dashboard"))
    except Exception:
        return render_template("client_signup.html", error="Email already registered."), 400
    finally:
        cursor.close()
        conn.close()

@app.route("/client/login", methods=["GET", "POST"])
def client_login():
    if request.method == "GET":
        return render_template("client_login.html")
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")

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
        return redirect(url_for("client_dashboard"))
    return render_template("client_login.html", error="Invalid email or password."), 401

@app.route("/client/logout")
def client_logout():
    session.clear()
    return redirect(url_for("client_login"))

@app.route("/connect-google")
@login_required
def google_connect():
    state = secrets.token_urlsafe(32)
    session["oauth_state"] = state
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": configured_redirect_uri(),
        "response_type": "code",
        "scope": " ".join(SCOPES),
        "access_type": "offline",
        "prompt": "consent",
        "state": state,
    }
    return redirect("https://accounts.google.com/o/oauth2/v2/auth?" + urllib.parse.urlencode(params))

@app.route("/oauth2callback")
def oauth2callback():
    code = request.args.get("code")
    client_id = session.get("client_id")
    if not code or not client_id:
        return redirect(url_for("client_login"))

    token_response = requests.post(
        "https://oauth2.googleapis.com/token",
        data={
            "code": code,
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "redirect_uri": configured_redirect_uri(),
            "grant_type": "authorization_code",
        },
        timeout=15,
    )
    token_data = token_response.json()
    if token_response.status_code != 200 or "access_token" not in token_data:
        return render_template("client_dashboard.html", error="Google Auth failed."), 502

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
        cursor.execute(f"UPDATE clients SET google_tokens = {ph} WHERE id = {ph}", (json.dumps(stored_token), client_id))
        conn.commit()
    finally:
        cursor.close()
        conn.close()
    return redirect(url_for("client_dashboard"))

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
        has_drive = bool(client_row and client_row[1])

        cursor.execute(f"SELECT id, event_id, event_name, event_pin, event_date, created_at, drive_folder_id FROM events WHERE client_id = {ph} ORDER BY created_at DESC", (client_id,))
        events = cursor.fetchall()
        return render_template("client_dashboard.html", studio_name=client_row[2], has_drive=has_drive, events=events)
    finally:
        cursor.close()
        conn.close()

@app.route("/api/events/create", methods=["POST"])
@login_required
def api_create_event():
    event_name = (request.form.get("event_name") or request.form.get("event_title") or "").strip()
    if not event_name:
        return jsonify({"success": False, "message": "Event title is required."}), 400

    service = get_drive_service(session["client_id"])
    if not service:
        return jsonify({"success": False, "message": "Please connect your Google Drive first."}), 400

    files = request.files.getlist("media_files") or request.files.getlist("files")
    uploaded_files = [f for f in files if f and f.filename and allowed_file(f.filename)]
    if not uploaded_files:
        return jsonify({"success": False, "message": "No valid media selected."}), 400

    root_id = get_or_create_root_folder(service)
    safe_name = re.sub(r"[^\w\- .()&]+", "_", event_name).strip()[:100]
    folder = service.files().create(
        body={"name": safe_name, "mimeType": "application/vnd.google-apps.folder", "parents": [root_id]},
        fields="id",
    ).execute()
    event_folder_id = folder["id"]

    event_uuid = str(uuid.uuid4())
    event_pin = f"{secrets.randbelow(9000) + 1000}"
    event_date = now_utc().date().isoformat()

    conn, db_type = get_db_connection()
    cursor = conn.cursor()
    ph = "%s" if db_type == "POSTGRES" else "?"

    try:
        cursor.execute(
            f"INSERT INTO events (id, client_id, event_id, event_name, event_pin, event_date, drive_folder_id) VALUES ({ph},{ph},{ph},{ph},{ph},{ph},{ph})",
            (str(uuid.uuid4()), session["client_id"], event_uuid, event_name, event_pin, event_date, event_folder_id)
        )

        for up in uploaded_files:
            fn = secure_filename(up.filename)
            file_bytes = up.read()
            up.stream.seek(0)
            media = MediaIoBaseUpload(BytesIO(file_bytes), mimetype=up.content_type or "application/octet-stream", resumable=True)
            f_drive = service.files().create(body={"name": fn, "parents": [event_folder_id]}, media_body=media, fields="id").execute()

            encodings_json = "[]"
            if not is_video(fn):
                faces = extract_face_histograms(file_bytes)
                encodings_json = json.dumps(faces)

            cursor.execute(
                f"INSERT INTO event_media (id, event_id, client_id, drive_file_id, file_name, mime_type, face_encodings) VALUES ({ph},{ph},{ph},{ph},{ph},{ph},{ph})",
                (str(uuid.uuid4()), event_uuid, session["client_id"], f_drive["id"], fn, up.content_type or "image/jpeg", encodings_json)
            )

        conn.commit()
        return jsonify({
            "success": True,
            "message": "Event created successfully!",
            "event_id": event_uuid,
            "event_pin": event_pin,
            "share_url": f"/event/{event_uuid}"
        })
    finally:
        cursor.close()
        conn.close()

# -----------------------------------------------------------------------------
# Guest Face Search & Download Portal
# -----------------------------------------------------------------------------
@app.route("/event/<event_id>")
def guest_event_portal(event_id):
    conn, db_type = get_db_connection()
    cursor = conn.cursor()
    ph = "%s" if db_type == "POSTGRES" else "?"
    try:
        cursor.execute(f"SELECT e.event_name, e.event_date, c.studio_name FROM events e JOIN clients c ON e.client_id = c.id WHERE e.event_id = {ph}", (event_id,))
        row = cursor.fetchone()
        if not row:
            return "Event not found.", 404
        return render_template("guest_portal.html", event_id=event_id, event_name=row[0], event_date=row[1], studio_name=row[2])
    finally:
        cursor.close()
        conn.close()

@app.route("/api/event/<event_id>/guest-access", methods=["POST"])
def api_guest_face_access(event_id):
    name = request.form.get("guest_name", "").strip()
    phone = request.form.get("guest_phone", "").strip()
    email = request.form.get("guest_email", "").strip()
    pin = request.form.get("event_pin", "").strip()
    selfie = request.files.get("selfie")

    if not name or not phone or not pin:
        return jsonify({"success": False, "message": "Name, phone and PIN are required."}), 400

    conn, db_type = get_db_connection()
    cursor = conn.cursor()
    ph = "%s" if db_type == "POSTGRES" else "?"
    try:
        cursor.execute(f"SELECT event_pin, client_id FROM events WHERE event_id = {ph}", (event_id,))
        ev = cursor.fetchone()
        if not ev or not constant_time_equal(ev[0], pin):
            return jsonify({"success": False, "message": "Invalid Event PIN."}), 403

        client_id = ev[1]
        guest_enc = None
        if selfie and selfie.filename:
            selfie_bytes = selfie.read()
            selfie_faces = extract_face_histograms(selfie_bytes)
            if selfie_faces:
                guest_enc = selfie_faces[0]

        cursor.execute(f"SELECT id, file_name, mime_type, drive_file_id, face_encodings FROM event_media WHERE event_id = {ph}", (event_id,))
        rows = cursor.fetchall()

        matched_media = []
        for r in rows:
            mid, fn, mime, df_id, f_enc_json = r[0], r[1], r[2], r[3], r[4]
            if is_video(fn):
                matched_media.append({"id": mid, "file_name": fn, "type": "video", "download_url": f"/media/download/{client_id}/{df_id}/{fn}"})
            elif guest_enc and match_face(guest_enc, f_enc_json):
                matched_media.append({"id": mid, "file_name": fn, "type": "photo", "download_url": f"/media/download/{client_id}/{df_id}/{fn}"})

        return jsonify({
            "success": True,
            "guest_name": name,
            "matched_count": len(matched_media),
            "media": matched_media
        })
    finally:
        cursor.close()
        conn.close()

@app.route("/media/download/<client_id>/<drive_file_id>/<filename>")
def download_media_stream(client_id, drive_file_id, filename):
    service = get_drive_service(client_id)
    if not service:
        return "Authentication error.", 403

    request_file = service.files().get_media(fileId=drive_file_id)
    fh = BytesIO()
    downloader = MediaIoBaseDownload(fh, request_file)
    done = False
    while not done:
        _, done = downloader.next_chunk()
    fh.seek(0)
    return send_file(fh, as_attachment=True, download_name=secure_filename(filename))

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)
