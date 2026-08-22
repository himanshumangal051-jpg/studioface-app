import os
import sys
import json
import random
import sqlite3
import datetime
from io import BytesIO

from flask import (
    Flask, render_template, request, redirect,
    url_for, session, jsonify, send_file
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import requests

import cv2
import numpy as np
from PIL import Image

from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload

# -------------------------------------------------------------
# Configuration
# -------------------------------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "studioface_prod_secret_key_2026_x99")

BREVO_API_KEY = os.environ.get(
    "BREVO_API_KEY",
    "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"
)

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, 'face_engine.db')

OTP_STORE = {}
SCOPES = ['https://www.googleapis.com/auth/drive.file']

# -------------------------------------------------------------
# Database Setup
# -------------------------------------------------------------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

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
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (client_id) REFERENCES clients (id)
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS event_media (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_id TEXT NOT NULL,
            drive_file_id TEXT NOT NULL,
            file_name TEXT NOT NULL,
            file_type TEXT NOT NULL,
            thumbnail_url TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (event_id) REFERENCES events (event_id)
        )
    ''')

    conn.commit()
    conn.close()

init_db()

# -------------------------------------------------------------
# Brevo HTTP Email Dispatcher
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
            "sender": {
                "name": "StudioFace AI",
                "email": "himanshumangal051@gmail.com"
            },
            "to": [
                {"email": recipient_email}
            ],
            "subject": f"Verification Code: {otp} - StudioFace",
            "htmlContent": f"""
            <div style="font-family: Arial, sans-serif; max-width: 440px; margin: auto; padding: 24px; background: #0F172A; border-radius: 16px; color: #F8FAFC; text-align: center;">
                <h2 style="color: #6366F1; margin: 0 0 10px;">StudioFace AI</h2>
                <p style="color: #94A3B8; font-size: 14px;">Your verification OTP code is:</p>
                <div style="background: #1E293B; border-radius: 12px; padding: 18px; margin: 20px 0; border: 1px dashed #6366F1;">
                    <span style="font-size: 32px; font-weight: 800; letter-spacing: 6px; color: #818CF8; font-family: monospace;">{otp}</span>
                </div>
                <p style="color: #64748B; font-size: 12px;">Valid for 10 minutes. Please do not share this code.</p>
            </div>
            """
        }

        response = requests.post(url, headers=headers, json=payload, timeout=10)
        if response.status_code in [200, 201, 202]:
            return True, "OTP sent successfully."
        else:
            print(f"[Brevo Error] {response.status_code}: {response.text}")
            return False, f"Email error: {response.text}"
    except Exception as e:
        print(f"[Brevo Exception]: {str(e)}")
        return False, str(e)

# -------------------------------------------------------------
# Face Recognition & Detection Helper
# -------------------------------------------------------------
face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')

def detect_faces(image_bytes):
    try:
        np_arr = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
        if img is None:
            return []
        gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
        faces = face_cascade.detectMultiScale(gray, scaleFactor=1.1, minNeighbors=5, minSize=(40, 40))
        return faces
    except Exception as e:
        print(f"[Face Detection Error]: {e}")
        return []

# -------------------------------------------------------------
# Google Drive Integration Helpers
# -------------------------------------------------------------
def get_drive_service(client_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT google_tokens FROM clients WHERE id = ?", (client_id,))
    row = cursor.fetchone()
    conn.close()

    if not row or not row[0]:
        return None

    token_info = json.loads(row[0])
    creds = Credentials(
        token=token_info.get('token'),
        refresh_token=token_info.get('refresh_token'),
        token_uri="https://oauth2.googleapis.com/token",
        client_id=token_info.get('client_id'),
        client_secret=token_info.get('client_secret'),
        scopes=SCOPES
    )
    return build('drive', 'v3', credentials=creds)

def get_or_create_root_folder(service):
    query = "name = 'StudioFace Events' and mimeType = 'application/vnd.google-apps.folder' and trashed = false"
    results = service.files().list(q=query, spaces='drive', fields='files(id, name)').execute()
    files = results.get('files', [])
    if files:
        return files[0]['id']
    
    folder_metadata = {
        'name': 'StudioFace Events',
        'mimeType': 'application/vnd.google-apps.folder'
    }
    folder = service.files().create(body=folder_metadata, fields='id').execute()
    return folder.get('id')

# -------------------------------------------------------------
# Public & Authentication Routes
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

    is_valid_otp = False
    if session.get('verified_email') == email:
        is_valid_otp = True
    elif email in OTP_STORE and OTP_STORE[email].get('otp') == otp:
        is_valid_otp = True

    if not is_valid_otp:
        return render_template('client_signup.html', error="Invalid or expired OTP. Please verify your email again.")

    hashed_pw = generate_password_hash(password)

    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO clients (studio_name, owner_name, email, phone, password)
            VALUES (?, ?, ?, ?, ?)
        ''', (studio_name, owner_name, email, phone, hashed_pw))
        conn.commit()
        client_id = cursor.lastrowid
        conn.close()

        session['client_id'] = client_id
        session['studio_name'] = studio_name
        OTP_STORE.pop(email, None)
        session.pop('verified_email', None)
        return redirect(url_for('client_dashboard'))
    except sqlite3.IntegrityError:
        return render_template('client_signup.html', error="An account with this email already exists.")

@app.route('/client/login', methods=['GET', 'POST'])
def client_login():
    if request.method == 'GET':
        return render_template('client_login.html')

    email = request.form.get('email', '').strip().lower()
    password = request.form.get('password', '')

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, studio_name, password FROM clients WHERE email = ?", (email,))
    user = cursor.fetchone()
    conn.close()

    if user and check_password_hash(user[2], password):
        session['client_id'] = user[0]
        session['studio_name'] = user[1]
        return redirect(url_for('client_dashboard'))
    
    return render_template('client_login.html', error="Invalid email or password.")

@app.route('/client/logout')
def client_logout():
    session.clear()
    return redirect(url_for('client_login'))

@app.route('/client/forgot-password', methods=['GET', 'POST'])
def client_forgot_password():
    if request.method == 'GET':
        return render_template('client_forgot_password.html')
    
    email = request.form.get('email', '').strip().lower()
    otp = request.form.get('otp', '').strip()
    new_password = request.form.get('new_password', '')

    if session.get('verified_email') != email and (email not in OTP_STORE or OTP_STORE[email]['otp'] != otp):
        return render_template('client_forgot_password.html', error="Invalid or expired OTP.")

    hashed_pw = generate_password_hash(new_password)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE clients SET password = ? WHERE email = ?", (hashed_pw, email))
    conn.commit()
    conn.close()

    OTP_STORE.pop(email, None)
    session.pop('verified_email', None)
    return redirect(url_for('client_login'))

# -------------------------------------------------------------
# Verification API Routes
# -------------------------------------------------------------
@app.route('/api/auth/send-otp', methods=['POST'])
def api_send_otp():
    target = request.json.get('target', '').strip().lower()
    if not target or '@' not in target:
        return jsonify({"success": False, "message": "Valid email address is required."}), 400

    generated_otp = str(random.randint(100000, 999999))
    OTP_STORE[target] = {"otp": generated_otp, "time": datetime.datetime.now()}

    success, msg = send_email_otp(target, generated_otp)
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
        return jsonify({"success": True, "message": "Email verified successfully."})
    return jsonify({"success": False, "message": "Invalid or expired OTP."}), 400

# -------------------------------------------------------------
# Studio Client Dashboard & Events
# -------------------------------------------------------------
@app.route('/client/dashboard')
def client_dashboard():
    if 'client_id' not in session:
        return redirect(url_for('client_login'))

    client_id = session['client_id']
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("SELECT google_tokens, studio_name FROM clients WHERE id = ?", (client_id,))
    client_row = cursor.fetchone()
    has_drive = bool(client_row and client_row[0])

    cursor.execute("SELECT id, event_id, event_name, event_date, created_at FROM events WHERE client_id = ? ORDER BY id DESC", (client_id,))
    events = cursor.fetchall()
    conn.close()

    return render_template('client_dashboard.html', studio_name=session.get('studio_name'), has_drive=has_drive, events=events)

@app.route('/client/events/create', methods=['POST'])
def create_event():
    if 'client_id' not in session:
        return redirect(url_for('client_login'))

    client_id = session['client_id']
    event_name = request.form.get('event_name', '').strip()
    event_date = request.form.get('event_date', '').strip()
    event_id = "EVT-" + str(random.randint(100000, 999999))

    drive_service = get_drive_service(client_id)
    folder_id = None

    if drive_service:
        try:
            root_id = get_or_create_root_folder(drive_service)
            folder_metadata = {
                'name': f"{event_name} ({event_id})",
                'mimeType': 'application/vnd.google-apps.folder',
                'parents': [root_id]
            }
            folder = drive_service.files().create(body=folder_metadata, fields='id').execute()
            folder_id = folder.get('id')
        except Exception as e:
            print(f"[Drive Folder Error]: {e}")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO events (client_id, event_id, event_name, event_date, drive_folder_id)
        VALUES (?, ?, ?, ?, ?)
    ''', (client_id, event_id, event_name, event_date, folder_id))
    conn.commit()
    conn.close()

    return redirect(url_for('client_dashboard'))

# -------------------------------------------------------------
# Google OAuth Integration Routes
# -------------------------------------------------------------
@app.route('/auth/google/connect')
def google_connect():
    if 'client_id' not in session:
        return redirect(url_for('client_login'))

    redirect_uri = url_for('oauth2callback', _external=True)
    
    client_config = {
        "web": {
            "client_id": os.environ.get("GOOGLE_CLIENT_ID", ""),
            "client_secret": os.environ.get("GOOGLE_CLIENT_SECRET", ""),
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token"
        }
    }

    flow = Flow.from_client_config(
        client_config,
        scopes=SCOPES,
        redirect_uri=redirect_uri
    )
    authorization_url, state = flow.authorization_url(
        access_type='offline',
        include_granted_scopes='true',
        prompt='consent'
    )
    session['oauth_state'] = state
    return redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
    if 'client_id' not in session:
        return redirect(url_for('client_login'))

    redirect_uri = url_for('oauth2callback', _external=True)
    client_config = {
        "web": {
            "client_id": os.environ.get("GOOGLE_CLIENT_ID", ""),
            "client_secret": os.environ.get("GOOGLE_CLIENT_SECRET", ""),
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token"
        }
    }

    flow = Flow.from_client_config(
        client_config,
        scopes=SCOPES,
        state=session.get('oauth_state'),
        redirect_uri=redirect_uri
    )
    flow.fetch_token(authorization_response=request.url)
    creds = flow.credentials

    token_data = {
        'token': creds.token,
        'refresh_token': creds.refresh_token,
        'client_id': creds.client_id,
        'client_secret': creds.client_secret,
        'scopes': creds.scopes
    }

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("UPDATE clients SET google_tokens = ? WHERE id = ?", (json.dumps(token_data), session['client_id']))
    conn.commit()
    conn.close()

    return redirect(url_for('client_dashboard'))

# -------------------------------------------------------------
# Guest Portal Route
# -------------------------------------------------------------
@app.route('/guest/<event_id>')
def guest_portal(event_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT event_name, event_date FROM events WHERE event_id = ?", (event_id,))
    event = cursor.fetchone()
    conn.close()

    if not event:
        return "Event not found", 404

    return render_template('guest_portal.html', event_id=event_id, event_name=event[0], event_date=event[1])

# -------------------------------------------------------------
# Server Entry Point
# -------------------------------------------------------------
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)