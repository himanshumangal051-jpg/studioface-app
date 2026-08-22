import os
import sys
import json
import random
import sqlite3
import datetime
from io import BytesIO
import urllib.parse

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, jsonify, send_file
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
import requests

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload

try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    POSTGRES_AVAILABLE = True
except ImportError:
    POSTGRES_AVAILABLE = False

# -------------------------------------------------------------
# Configuration & Environment
# -------------------------------------------------------------
app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.secret_key = os.environ.get("SECRET_KEY", "studioface_prod_secret_key_2026_x99")

BREVO_API_KEY = os.environ.get("BREVO_API_KEY", "")
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
DATABASE_URL = os.environ.get("DATABASE_URL", "")
ADMIN_SECRET_PIN = os.environ.get("ADMIN_SECRET_PIN", "admin@studioface2026")

# OAuth Environment Overrides for Secure Proxy Handling
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, 'face_engine.db')

OTP_STORE = {}
SCOPES = ['https://www.googleapis.com/auth/drive.file']

# -------------------------------------------------------------
# Keep-Alive Route (Render Health Check)
# -------------------------------------------------------------
@app.route('/healthz')
def health_check():
    return "OK", 200

# -------------------------------------------------------------
# Database Abstraction (PostgreSQL / SQLite Auto-Switch)
# -------------------------------------------------------------
def get_db_connection():
    if DATABASE_URL and POSTGRES_AVAILABLE:
        db_url = DATABASE_URL
        if db_url.startswith("postgres://"):
            db_url = db_url.replace("postgres://", "postgresql://", 1)
        conn = psycopg2.connect(db_url)
        return conn, "POSTGRES"
    else:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn, "SQLITE"

def init_db():
    conn, db_type = get_db_connection()
    cursor = conn.cursor()

    if db_type == "POSTGRES":
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS clients (
                id SERIAL PRIMARY KEY,
                studio_name TEXT NOT NULL,
                owner_name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                phone TEXT NOT NULL,
                password TEXT NOT NULL,
                google_tokens TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS events (
                id SERIAL PRIMARY KEY,
                client_id INTEGER NOT NULL,
                event_id TEXT UNIQUE NOT NULL,
                event_name TEXT NOT NULL,
                event_date TEXT NOT NULL,
                drive_folder_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS activity_logs (
                id SERIAL PRIMARY KEY,
                email TEXT,
                action TEXT NOT NULL,
                details TEXT,
                ip_address TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        ''')
    else:
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS clients (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                studio_name TEXT NOT NULL,
                owner_name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                phone TEXT NOT NULL,
                password TEXT NOT NULL,
                google_tokens TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id INTEGER NOT NULL,
                event_id TEXT UNIQUE NOT NULL,
                event_name TEXT NOT NULL,
                event_date TEXT NOT NULL,
                drive_folder_id TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS activity_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT,
                action TEXT NOT NULL,
                details TEXT,
                ip_address TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

    conn.commit()
    cursor.close()
    conn.close()

init_db()

def log_activity(email, action, details=""):
    try:
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        conn, db_type = get_db_connection()
        cursor = conn.cursor()
        placeholder = "%s" if db_type == "POSTGRES" else "?"
        cursor.execute(f'''
            INSERT INTO activity_logs (email, action, details, ip_address)
            VALUES ({placeholder}, {placeholder}, {placeholder}, {placeholder})
        ''', (email, action, details, ip))
        conn.commit()
        cursor.close()
        conn.close()
    except Exception as e:
        print(f"[Activity Log Error]: {e}")

# -------------------------------------------------------------
# Brevo Email OTP Sender
# -------------------------------------------------------------
def send_email_otp(recipient_email, otp):
    try:
        url = "https://api.brevo.com/v3/smtp/email"
        headers = {
            "api-key": BREVO_API_KEY,
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        payload = {
            "sender": {"name": "StudioFace AI", "email": "himanshumangal051@gmail.com"},
            "to": [{"email": recipient_email}],
            "subject": f"Verification Code: {otp} - StudioFace",
            "htmlContent": f"""
            <div style="font-family: Arial, sans-serif; max-width: 440px; margin: auto; padding: 24px; background: #0F172A; border-radius: 16px; color: #F8FAFC; text-align: center;">
                <h2 style="color: #6366F1; margin-bottom: 10px;">StudioFace AI</h2>
                <p style="color: #94A3B8;">Aapka verification OTP code hai:</p>
                <div style="background: #1E293B; border-radius: 12px; padding: 18px; margin: 20px 0; border: 1px dashed #6366F1;">
                    <span style="font-size: 32px; font-weight: 800; letter-spacing: 6px; color: #818CF8; font-family: monospace;">{otp}</span>
                </div>
                <p style="color: #64748B; font-size: 12px;">Yeh code 10 minute ke liye valid hai.</p>
            </div>
            """
        }
        response = requests.post(url, headers=headers, json=payload, timeout=10)
        return response.status_code in [200, 201, 202], response.text
    except Exception as e:
        return False, str(e)

# -------------------------------------------------------------
# Authentication & Public Routes
# -------------------------------------------------------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/client/signup', methods=['GET', 'POST'])
def client_signup():
    if request.method == 'GET':
        return render_template('client_signup.html')
    
    data = request.form
    studio_name = data.get('studio_name', '').strip()
    owner_name = data.get('owner_name', '').strip() or studio_name
    email = data.get('email', '').strip().lower()
    phone = data.get('phone', '').strip()
    password = data.get('password', '')
    otp = data.get('otp', '').strip()

    is_valid_otp = (session.get('verified_email') == email) or (email in OTP_STORE and OTP_STORE[email].get('otp') == otp)
    if not is_valid_otp:
        return render_template('client_signup.html', error="Invalid or expired OTP. Please verify again.")

    hashed_pw = generate_password_hash(password)
    conn, db_type = get_db_connection()
    cursor = conn.cursor()
    ph = "%s" if db_type == "POSTGRES" else "?"

    try:
        cursor.execute(f'''
            INSERT INTO clients (studio_name, owner_name, email, phone, password)
            VALUES ({ph}, {ph}, {ph}, {ph}, {ph})
            RETURNING id
        ''' if db_type == "POSTGRES" else f'''
            INSERT INTO clients (studio_name, owner_name, email, phone, password)
            VALUES ({ph}, {ph}, {ph}, {ph}, {ph})
        ''', (studio_name, owner_name, email, phone, hashed_pw))
        
        if db_type == "POSTGRES":
            new_id = cursor.fetchone()[0]
        else:
            new_id = cursor.lastrowid

        conn.commit()

        log_activity(email, "SIGNUP_SUCCESS", f"Studio: {studio_name}, Phone: {phone}")
        session['client_id'] = new_id
        session['studio_name'] = studio_name
        session['client_email'] = email
        OTP_STORE.pop(email, None)
        session.pop('verified_email', None)
        return redirect(url_for('client_dashboard'))
    except Exception as e:
        log_activity(email, "SIGNUP_FAILED", str(e))
        return render_template('client_signup.html', error="An account with this email already exists.")
    finally:
        cursor.close()
        conn.close()

@app.route('/client/login', methods=['GET', 'POST'])
def client_login():
    if request.method == 'GET':
        return render_template('client_login.html')

    email = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')

    conn, db_type = get_db_connection()
    cursor = conn.cursor()
    ph = "%s" if db_type == "POSTGRES" else "?"
    cursor.execute(f"SELECT id, studio_name, password FROM clients WHERE email = {ph}", (email,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if user and check_password_hash(user[2], password):
        session['client_id'] = user[0]
        session['studio_name'] = user[1]
        session['client_email'] = email
        log_activity(email, "LOGIN_SUCCESS")
        return redirect(url_for('client_dashboard'))
    
    log_activity(email, "LOGIN_FAILED")
    return render_template('client_login.html', error="Invalid email or password.")

@app.route('/client/logout')
def client_logout():
    email = session.get('client_email', 'unknown')
    log_activity(email, "LOGOUT")
    session.clear()
    return redirect(url_for('client_login'))

# -------------------------------------------------------------
# OTP API Endpoints
# -------------------------------------------------------------
@app.route('/api/auth/send-otp', methods=['POST'])
def api_send_otp():
    target = request.json.get('target', '').strip().lower()
    if not target or '@' not in target:
        return jsonify({"success": False, "message": "Valid email address is required."}), 400

    otp = str(random.randint(100000, 999999))
    OTP_STORE[target] = {"otp": otp, "time": datetime.datetime.now()}
    log_activity(target, "OTP_REQUESTED")

    success, msg = send_email_otp(target, otp)
    if success:
        return jsonify({"success": True, "message": "OTP has been sent to your email inbox."})
    return jsonify({"success": False, "message": msg}), 400

@app.route('/api/auth/verify-otp', methods=['POST'])
def api_verify_otp():
    data = request.get_json() or {}
    target = data.get('target', '').strip().lower()
    otp = data.get('otp', '').strip()

    if target in OTP_STORE and OTP_STORE[target]['otp'] == otp:
        session['verified_email'] = target
        log_activity(target, "OTP_VERIFIED_SUCCESS")
        return jsonify({"success": True, "message": "Email verified successfully."})
    
    log_activity(target, "OTP_VERIFY_FAILED", f"Attempted OTP: {otp}")
    return jsonify({"success": False, "message": "Invalid or expired OTP."}), 400

# -------------------------------------------------------------
# Google OAuth Flow & Drive Connection
# -------------------------------------------------------------
@app.route('/connect-google')
@app.route('/auth/google/connect')
def google_connect():
    if 'client_id' not in session and 'client_email' not in session:
        return redirect(url_for('client_login'))

    redirect_uri = url_for('oauth2callback', _external=True, _scheme='https')
    client_config = {
        "web": {
            "client_id": GOOGLE_CLIENT_ID or os.environ.get("GOOGLE_CLIENT_ID", ""),
            "client_secret": GOOGLE_CLIENT_SECRET or os.environ.get("GOOGLE_CLIENT_SECRET", ""),
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token"
        }
    }

    try:
        flow = Flow.from_client_config(client_config, scopes=SCOPES, redirect_uri=redirect_uri)
        auth_url, state = flow.authorization_url(access_type='offline', include_granted_scopes='true', prompt='consent')
        session['oauth_state'] = state
        return redirect(auth_url)
    except Exception as e:
        return f"Google OAuth Config Error: {e}", 500

@app.route('/oauth2callback')
def oauth2callback():
    redirect_uri = url_for('oauth2callback', _external=True, _scheme='https')
    client_config = {
        "web": {
            "client_id": GOOGLE_CLIENT_ID or os.environ.get("GOOGLE_CLIENT_ID", ""),
            "client_secret": GOOGLE_CLIENT_SECRET or os.environ.get("GOOGLE_CLIENT_SECRET", ""),
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token"
        }
    }

    try:
        flow = Flow.from_client_config(
            client_config,
            scopes=SCOPES,
            state=session.get('oauth_state'),
            redirect_uri=redirect_uri
        )

        auth_response_url = request.url
        if auth_response_url.startswith("http://"):
            auth_response_url = auth_response_url.replace("http://", "https://", 1)

        flow.fetch_token(authorization_response=auth_response_url)
        creds = flow.credentials

        token_data = {
            'token': creds.token,
            'refresh_token': creds.refresh_token,
            'client_id': creds.client_id,
            'client_secret': creds.client_secret,
            'scopes': creds.scopes
        }

        client_id = session.get('client_id')
        client_email = session.get('client_email')

        conn, db_type = get_db_connection()
        cursor = conn.cursor()
        ph = "%s" if db_type == "POSTGRES" else "?"

        if client_id:
            cursor.execute(f"UPDATE clients SET google_tokens = {ph} WHERE id = {ph}", (json.dumps(token_data), client_id))
        elif client_email:
            cursor.execute(f"UPDATE clients SET google_tokens = {ph} WHERE email = {ph}", (json.dumps(token_data), client_email))

        conn.commit()
        cursor.close()
        conn.close()

        log_activity(client_email or "client", "GOOGLE_DRIVE_CONNECTED", "Drive tokens stored successfully")
        return redirect(url_for('client_dashboard'))

    except Exception as e:
        print(f"[OAuth Callback Exception]: {e}")
        log_activity(session.get('client_email', 'unknown'), "GOOGLE_AUTH_ERROR", str(e))
        return f"<div style='font-family:sans-serif;padding:30px;background:#0F172A;color:#FFF;'><h2>Google Connection Error</h2><p>{str(e)}</p><a href='/client/dashboard' style='color:#818CF8;'>Back to Dashboard</a></div>", 500

@app.route('/client/dashboard')
def client_dashboard():
    if 'client_id' not in session and 'client_email' not in session:
        return redirect(url_for('client_login'))

    conn, db_type = get_db_connection()
    cursor = conn.cursor()
    ph = "%s" if db_type == "POSTGRES" else "?"

    client_id = session.get('client_id')
    client_email = session.get('client_email')

    if client_id:
        cursor.execute(f"SELECT id, google_tokens, studio_name FROM clients WHERE id = {ph}", (client_id,))
    else:
        cursor.execute(f"SELECT id, google_tokens, studio_name FROM clients WHERE email = {ph}", (client_email,))

    client_row = cursor.fetchone()
    has_drive = bool(client_row and client_row[1])
    
    events = []
    if client_row:
        session['client_id'] = client_row[0]
        session['studio_name'] = client_row[2]
        cursor.execute(f"SELECT id, event_id, event_name, event_date, created_at FROM events WHERE client_id = {ph} ORDER BY id DESC", (client_row[0],))
        events = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('client_dashboard.html', studio_name=session.get('studio_name'), has_drive=has_drive, events=events)

# -------------------------------------------------------------
# Master Activity & Admin Portal
# -------------------------------------------------------------
@app.route('/admin/activity', methods=['GET', 'POST'])
def admin_activity():
    if request.method == 'POST':
        pin = request.form.get('pin', '')
        if pin == ADMIN_SECRET_PIN:
            session['is_admin'] = True
        else:
            return render_template('admin_activity.html', error="Invalid Master PIN", authenticated=False)

    if not session.get('is_admin'):
        return render_template('admin_activity.html', authenticated=False)

    conn, db_type = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT id, studio_name, owner_name, email, phone, created_at FROM clients ORDER BY id DESC")
    clients = cursor.fetchall()

    cursor.execute("SELECT id, email, action, details, ip_address, timestamp FROM activity_logs ORDER BY id DESC LIMIT 100")
    logs = cursor.fetchall()

    cursor.close()
    conn.close()

    return render_template('admin_activity.html', authenticated=True, clients=clients, logs=logs)

# -------------------------------------------------------------
# Server Entry Point
# -------------------------------------------------------------
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)