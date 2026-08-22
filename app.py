import os
import io
import json
import uuid
import random
import sqlite3
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import numpy as np
import cv2
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_file
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash

# Google Drive API Client Libraries
import google_auth_oauthlib.flow
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseUpload, MediaIoBaseDownload
from google.oauth2.credentials import Credentials

# Bypass HTTPS restriction for local testing
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "studio_prod_auth_secret_2026")

DB_PATH = 'face_engine.db'

# ==========================================
# 📧 EMAIL SMTP CONFIGURATION
# ==========================================
EMAIL_SENDER = "himanshumangal051@gmail.com"
EMAIL_PASSWORD = "wyghfrfqnabsfpel"

# ==========================================
# 📂 GOOGLE OAUTH CREDENTIALS
# ==========================================
GOOGLE_CLIENT_ID = "92917705295-uj4k5a7t1hpvj6cgem42np1i9qgqsnto.apps.googleusercontent.com"
GOOGLE_CLIENT_SECRET = "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"
SCOPES = ['https://www.googleapis.com/auth/drive.file']

# Safe Face Detector Loader
cascade_filename = 'haarcascade_frontalface_default.xml'
cascade_path = getattr(cv2, 'data', None)
if cascade_path and hasattr(cascade_path, 'haarcascades'):
    model_path = os.path.join(cv2.data.haarcascades, cascade_filename)
else:
    model_path = os.path.join(os.path.dirname(cv2.__file__), 'data', cascade_filename)

if not os.path.exists(model_path):
    model_path = cv2.samples.findFile(cascade_filename) if hasattr(cv2, 'samples') else cascade_filename

face_cascade = cv2.CascadeClassifier(model_path)

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS clients (
                id TEXT PRIMARY KEY,
                studio_name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                phone TEXT NOT NULL,
                shop_address TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                google_credentials TEXT DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor = conn.execute("PRAGMA table_info(clients)")
        cols = [c['name'] for c in cursor.fetchall()]
        if 'phone' not in cols:
            conn.execute("ALTER TABLE clients ADD COLUMN phone TEXT DEFAULT ''")
        if 'shop_address' not in cols:
            conn.execute("ALTER TABLE clients ADD COLUMN shop_address TEXT DEFAULT ''")
        if 'google_credentials' not in cols:
            conn.execute("ALTER TABLE clients ADD COLUMN google_credentials TEXT DEFAULT ''")

        conn.execute('''
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                client_id TEXT,
                name TEXT NOT NULL,
                drive_folder_id TEXT DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(client_id) REFERENCES clients(id)
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS media_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT,
                filename TEXT NOT NULL,
                media_type TEXT NOT NULL,
                drive_file_id TEXT DEFAULT '',
                FOREIGN KEY(event_id) REFERENCES events(id)
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS guest_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT,
                name TEXT,
                phone TEXT,
                matched_count INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()

init_db()

OTP_STORE = {}

def send_email_otp(recipient_email, otp):
    msg = MIMEMultipart("alternative")
    msg['From'] = f"StudioFace Security <{EMAIL_SENDER}>"
    msg['To'] = recipient_email
    msg['Subject'] = f"Verification Code: {otp} - StudioFace"

    html = f"""
    <div style="font-family: Arial, sans-serif; max-width: 440px; margin: auto; padding: 24px; background: #0F172A; border-radius: 16px; color: #F8FAFC; text-align: center;">
        <h2 style="color: #6366F1; margin: 0 0 10px;">StudioFace AI</h2>
        <p style="color: #94A3B8; font-size: 13px;">Your email verification OTP is:</p>
        <div style="background: #1E293B; border-radius: 12px; padding: 18px; margin: 20px 0; border: 1px dashed #6366F1;">
            <span style="font-size: 32px; font-weight: 800; letter-spacing: 6px; color: #818CF8; font-family: monospace;">{otp}</span>
        </div>
        <p style="color: #64748B; font-size: 11px;">Valid for 10 minutes. Do not share with anyone.</p>
    </div>
    """
    msg.attach(MIMEText(html, 'html'))

    try:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context, timeout=10) as server:
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_SENDER, recipient_email, msg.as_string())
        return True, "Success"
    except Exception:
        try:
            with smtplib.SMTP("smtp.gmail.com", 587, timeout=10) as server:
                server.starttls()
                server.login(EMAIL_SENDER, EMAIL_PASSWORD)
                server.sendmail(EMAIL_SENDER, recipient_email, msg.as_string())
            return True, "Success"
        except Exception as e:
            return False, str(e)

# --- GOOGLE DRIVE HELPER FUNCTIONS ---

def get_client_drive_service(client_id):
    with get_db() as conn:
        client = conn.execute("SELECT google_credentials FROM clients WHERE id = ?", (client_id,)).fetchone()
        if not client or not client['google_credentials']:
            return None
        creds_data = json.loads(client['google_credentials'])
        creds = Credentials.from_authorized_user_info(creds_data, SCOPES)
        return build('drive', 'v3', credentials=creds)

def get_or_create_folder(drive_service, folder_name, parent_id=None):
    query = f"name = '{folder_name}' and mimeType = 'application/vnd.google-apps.folder' and trashed = false"
    if parent_id:
        query += f" and '{parent_id}' in parents"
    
    results = drive_service.files().list(q=query, spaces='drive', fields='files(id, name)').execute()
    items = results.get('files', [])
    if items:
        return items[0]['id']

    file_metadata = {
        'name': folder_name,
        'mimeType': 'application/vnd.google-apps.folder'
    }
    if parent_id:
        file_metadata['parents'] = [parent_id]

    folder = drive_service.files().create(body=file_metadata, fields='id').execute()
    return folder.get('id')

PHOTO_EXTS = {'png', 'jpg', 'jpeg', 'webp'}
VIDEO_EXTS = {'mp4', 'mov', 'mkv', 'webm'}
AUDIO_EXTS = {'mp3', 'wav', 'aac', 'm4a'}

def get_media_type(filename):
    ext = filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
    if ext in PHOTO_EXTS: return 'photo'
    elif ext in VIDEO_EXTS: return 'video'
    elif ext in AUDIO_EXTS: return 'audio'
    return None

# --- AUTH & OAUTH2 ROUTES ---

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/connect-google')
def connect_google():
    client_id = session.get('client_id')
    if not client_id:
        return redirect(url_for('client_login'))

    client_config = {
        "web": {
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token"
        }
    }
    flow = google_auth_oauthlib.flow.Flow.from_client_config(client_config, scopes=SCOPES)
    flow.redirect_uri = url_for('oauth2callback', _external=True)
    authorization_url, state = flow.authorization_url(access_type='offline', include_granted_scopes='true', prompt='consent')
    session['state'] = state
    return redirect(authorization_url)

@app.route('/oauth2callback')
def oauth2callback():
    client_id = session.get('client_id')
    if not client_id:
        return redirect(url_for('client_login'))

    state = session.get('state')
    client_config = {
        "web": {
            "client_id": GOOGLE_CLIENT_ID,
            "client_secret": GOOGLE_CLIENT_SECRET,
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token"
        }
    }
    flow = google_auth_oauthlib.flow.Flow.from_client_config(client_config, scopes=SCOPES, state=state)
    flow.redirect_uri = url_for('oauth2callback', _external=True)
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials

    creds_json = credentials.to_json()
    with get_db() as conn:
        conn.execute("UPDATE clients SET google_credentials = ? WHERE id = ?", (creds_json, client_id))
        conn.commit()

    return redirect(url_for('client_dashboard'))

@app.route('/api/auth/send-otp', methods=['POST'])
def send_otp():
    target = request.json.get('target', '').strip().lower()
    if not target or '@' not in target:
        return jsonify({"success": False, "message": "Valid email address is required."}), 400

    generated_otp = str(random.randint(100000, 999999))
    OTP_STORE[target] = {"otp": generated_otp, "verified": False}

    success, msg = send_email_otp(target, generated_otp)
    if success:
        return jsonify({"success": True, "message": "OTP sent successfully!"})
    return jsonify({"success": False, "message": msg}), 500

@app.route('/api/auth/verify-otp', methods=['POST'])
def verify_otp():
    target = request.json.get('target', '').strip().lower()
    otp = request.json.get('otp', '').strip()

    if target in OTP_STORE and OTP_STORE[target]['otp'] == otp:
        OTP_STORE[target]['verified'] = True
        return jsonify({"success": True, "message": "Email verified successfully!"})
    return jsonify({"success": False, "message": "Invalid OTP code."}), 400

@app.route('/client/signup', methods=['GET', 'POST'])
def client_signup():
    if request.method == 'POST':
        studio_name = request.form.get('studio_name', '').strip()
        email = request.form.get('email', '').strip().lower()
        phone = request.form.get('phone', '').strip()
        shop_address = request.form.get('shop_address', '').strip()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

        if password != confirm_password:
            return render_template('client_signup.html', error="Passwords do not match!")

        with get_db() as conn:
            existing = conn.execute('SELECT id FROM clients WHERE email = ?', (email,)).fetchone()
            if existing:
                return render_template('client_signup.html', error="Email is already registered.")

            client_id = str(uuid.uuid4())[:8]
            p_hash = generate_password_hash(password)
            conn.execute(
                'INSERT INTO clients (id, studio_name, email, phone, shop_address, password_hash) VALUES (?, ?, ?, ?, ?, ?)',
                (client_id, studio_name, email, phone, shop_address, p_hash)
            )
            conn.commit()

        session['client_id'] = client_id
        session['studio_name'] = studio_name
        return redirect(url_for('client_dashboard'))

    return render_template('client_signup.html')

@app.route('/client/login', methods=['GET', 'POST'])
def client_login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        with get_db() as conn:
            client = conn.execute('SELECT * FROM clients WHERE email = ?', (email,)).fetchone()
            if client and check_password_hash(client['password_hash'], password):
                session['client_id'] = client['id']
                session['studio_name'] = client['studio_name']
                return redirect(url_for('client_dashboard'))

        return render_template('client_login.html', error="Invalid email or password.")

    return render_template('client_login.html')

@app.route('/client/forgot-password', methods=['GET'])
def forgot_password():
    return render_template('client_forgot_password.html')

@app.route('/api/auth/reset-password', methods=['POST'])
def reset_password():
    email = request.json.get('email', '').strip().lower()
    otp = request.json.get('otp', '').strip()
    new_password = request.json.get('new_password', '')

    if email not in OTP_STORE or OTP_STORE[email]['otp'] != otp:
        return jsonify({"success": False, "message": "Invalid or unverified OTP."}), 400

    with get_db() as conn:
        client = conn.execute('SELECT id FROM clients WHERE email = ?', (email,)).fetchone()
        if not client:
            return jsonify({"success": False, "message": "Email not registered."}), 404

        p_hash = generate_password_hash(new_password)
        conn.execute('UPDATE clients SET password_hash = ? WHERE email = ?', (p_hash, email))
        conn.commit()

    OTP_STORE.pop(email, None)
    return jsonify({"success": True, "message": "Password successfully reset!"})

@app.route('/client/logout')
def client_logout():
    session.clear()
    return redirect(url_for('client_login'))

# --- DASHBOARD & DIRECT GOOGLE DRIVE UPLOAD ---

@app.route('/client/dashboard')
def client_dashboard():
    client_id = session.get('client_id')
    if not client_id:
        return redirect(url_for('client_login'))

    with get_db() as conn:
        client = conn.execute('SELECT * FROM clients WHERE id = ?', (client_id,)).fetchone()
        is_drive_connected = bool(client['google_credentials'])

        events = conn.execute('SELECT * FROM events WHERE client_id = ? ORDER BY created_at DESC', (client_id,)).fetchall()
        event_data = []
        for ev in events:
            media = conn.execute('SELECT id, filename, media_type, drive_file_id FROM media_items WHERE event_id = ?', (ev['id'],)).fetchall()
            guests = conn.execute('SELECT * FROM guest_logs WHERE event_id = ? ORDER BY created_at DESC', (ev['id'],)).fetchall()
            
            event_data.append({
                "id": ev['id'],
                "name": ev['name'],
                "photos": [m for m in media if m['media_type'] == 'photo'],
                "videos": [m for m in media if m['media_type'] == 'video'],
                "audios": [m for m in media if m['media_type'] == 'audio'],
                "guests": guests
            })

    return render_template('client_dashboard.html', 
                           studio_name=session.get('studio_name'), 
                           events=event_data, 
                           is_drive_connected=is_drive_connected)

@app.route('/api/create-event', methods=['POST'])
def create_event():
    client_id = session.get('client_id')
    if not client_id:
        return jsonify({"error": "Unauthorized"}), 401

    drive_service = get_client_drive_service(client_id)
    if not drive_service:
        return jsonify({"error": "Pehle apna Google Drive connect karein!"}), 400

    event_name = request.form.get('event_name')
    files = request.files.getlist('media_files')

    if not event_name or not files:
        return jsonify({"error": "Event title aur media files zaroori hain."}), 400

    event_id = str(uuid.uuid4())[:6].upper()

    main_folder_id = get_or_create_folder(drive_service, "StudioFace Events")
    event_folder_id = get_or_create_folder(drive_service, f"{event_name} ({event_id})", parent_id=main_folder_id)

    with get_db() as conn:
        conn.execute('INSERT INTO events (id, client_id, name, drive_folder_id) VALUES (?, ?, ?, ?)',
                     (event_id, client_id, event_name, event_folder_id))

        for file in files:
            if file and file.filename != '':
                mtype = get_media_type(file.filename)
                if mtype:
                    filename = secure_filename(file.filename)
                    file_stream = io.BytesIO(file.read())
                    media_body = MediaIoBaseUpload(file_stream, mimetype=file.content_type or 'application/octet-stream', resumable=True)
                    file_metadata = {
                        'name': filename,
                        'parents': [event_folder_id]
                    }
                    uploaded_file = drive_service.files().create(body=file_metadata, media_body=media_body, fields='id').execute()
                    drive_file_id = uploaded_file.get('id')

                    conn.execute('INSERT INTO media_items (event_id, filename, media_type, drive_file_id) VALUES (?, ?, ?, ?)',
                                 (event_id, filename, mtype, drive_file_id))
        conn.commit()

    return jsonify({"success": True, "event_id": event_id})

@app.route('/api/event/<event_id>/add-media', methods=['POST'])
def add_media(event_id):
    client_id = session.get('client_id')
    if not client_id:
        return jsonify({"error": "Unauthorized"}), 401

    drive_service = get_client_drive_service(client_id)
    if not drive_service:
        return jsonify({"error": "Google Drive not connected"}), 400

    with get_db() as conn:
        event = conn.execute("SELECT drive_folder_id FROM events WHERE id = ?", (event_id,)).fetchone()
        event_folder_id = event['drive_folder_id'] if event else None

    files = request.files.getlist('media_files')
    with get_db() as conn:
        for file in files:
            mtype = get_media_type(file.filename)
            if mtype:
                filename = secure_filename(file.filename)
                file_stream = io.BytesIO(file.read())
                media_body = MediaIoBaseUpload(file_stream, mimetype=file.content_type or 'application/octet-stream', resumable=True)
                file_metadata = {'name': filename, 'parents': [event_folder_id]}
                uploaded = drive_service.files().create(body=file_metadata, media_body=media_body, fields='id').execute()

                conn.execute('INSERT INTO media_items (event_id, filename, media_type, drive_file_id) VALUES (?, ?, ?, ?)',
                             (event_id, filename, mtype, uploaded.get('id')))
        conn.commit()

    return jsonify({"success": True})

@app.route('/api/media/<int:media_id>/delete', methods=['POST'])
def delete_media(media_id):
    client_id = session.get('client_id')
    if not client_id:
        return jsonify({"error": "Unauthorized"}), 401

    drive_service = get_client_drive_service(client_id)
    with get_db() as conn:
        item = conn.execute('SELECT drive_file_id FROM media_items WHERE id = ?', (media_id,)).fetchone()
        if item and item['drive_file_id'] and drive_service:
            try:
                drive_service.files().delete(fileId=item['drive_file_id']).execute()
            except Exception:
                pass
        conn.execute('DELETE FROM media_items WHERE id = ?', (media_id,))
        conn.commit()

    return jsonify({"success": True})

@app.route('/api/event/<event_id>/delete', methods=['POST'])
def delete_event(event_id):
    client_id = session.get('client_id')
    if not client_id:
        return jsonify({"error": "Unauthorized"}), 401

    drive_service = get_client_drive_service(client_id)
    with get_db() as conn:
        event = conn.execute('SELECT drive_folder_id FROM events WHERE id = ?', (event_id,)).fetchone()
        if event and event['drive_folder_id'] and drive_service:
            try:
                drive_service.files().delete(fileId=event['drive_folder_id']).execute()
            except Exception:
                pass
        conn.execute('DELETE FROM media_items WHERE event_id = ?', (event_id,))
        conn.execute('DELETE FROM guest_logs WHERE event_id = ?', (event_id,))
        conn.execute('DELETE FROM events WHERE id = ?', (event_id,))
        conn.commit()

    return jsonify({"success": True})

# --- GUEST SCAN & DRIVE STREAMING ---

@app.route('/event/<event_id>')
def guest_portal(event_id):
    event_id = event_id.upper()
    with get_db() as conn:
        event = conn.execute('SELECT * FROM events WHERE id = ?', (event_id,)).fetchone()
    if not event:
        return render_template('index.html', error="Invalid Event Code! Please check again.")
    return render_template('guest_portal.html', event_id=event_id, event_name=event['name'])

@app.route('/api/event/<event_id>/scan', methods=['POST'])
def scan_guest(event_id):
    event_id = event_id.upper()
    name = request.form.get('name', '').strip()
    phone = request.form.get('phone', '').strip()
    selfie = request.files.get('selfie')

    if not name or not phone or not selfie:
        return jsonify({"success": False, "message": "All fields and selfie are required."}), 400

    in_memory = io.BytesIO()
    selfie.save(in_memory)
    data = np.frombuffer(in_memory.getvalue(), dtype=np.uint8)
    user_img = cv2.imdecode(data, cv2.IMREAD_COLOR)

    if user_img is None:
        return jsonify({"success": False, "message": "Invalid selfie image format."}), 400

    gray = cv2.cvtColor(user_img, cv2.COLOR_BGR2GRAY)
    faces = face_cascade.detectMultiScale(gray, 1.1, 4)

    if len(faces) == 0:
        return jsonify({"success": False, "message": "Face not recognized in selfie. Take clear photo."}), 422

    matched_photos = []
    videos = []
    audios = []

    with get_db() as conn:
        ev = conn.execute('SELECT client_id FROM events WHERE id = ?', (event_id,)).fetchone()
        if not ev:
            return jsonify({"success": False, "message": "Event not found"}), 404
        
        drive_service = get_client_drive_service(ev['client_id'])
        all_media = conn.execute('SELECT id, filename, media_type, drive_file_id FROM media_items WHERE event_id = ?', (event_id,)).fetchall()

        for item in all_media:
            fid = item['drive_file_id']
            fname = item['filename']
            mtype = item['media_type']

            if mtype == 'photo' and drive_service and fid:
                try:
                    req_file = drive_service.files().get_media(fileId=fid)
                    fh = io.BytesIO()
                    downloader = MediaIoBaseDownload(fh, req_file)
                    done = False
                    while not done:
                        status, done = downloader.next_chunk()
                    
                    fh.seek(0)
                    img_data = np.frombuffer(fh.read(), dtype=np.uint8)
                    img = cv2.imdecode(img_data, cv2.IMREAD_COLOR)
                    if img is not None:
                        g = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
                        f = face_cascade.detectMultiScale(g, 1.1, 4)
                        if len(f) > 0:
                            matched_photos.append({"id": fid, "name": fname})
                except Exception:
                    pass
            elif mtype == 'video':
                videos.append({"id": fid, "name": fname})
            elif mtype == 'audio':
                audios.append({"id": fid, "name": fname})

        conn.execute('INSERT INTO guest_logs (event_id, name, phone, matched_count) VALUES (?, ?, ?, ?)',
                     (event_id, name, phone, len(matched_photos)))
        conn.commit()

    return jsonify({
        "success": True,
        "name": name,
        "photos": matched_photos,
        "videos": videos,
        "audios": audios
    })

@app.route('/drive/file/<file_id>')
def serve_drive_file(file_id):
    with get_db() as conn:
        item = conn.execute('SELECT event_id, filename FROM media_items WHERE drive_file_id = ?', (file_id,)).fetchone()
        if not item:
            return "File not found", 404
        ev = conn.execute('SELECT client_id FROM events WHERE id = ?', (item['event_id'],)).fetchone()
        drive_service = get_client_drive_service(ev['client_id'])

    if not drive_service:
        return "Drive access error", 500

    req_file = drive_service.files().get_media(fileId=file_id)
    fh = io.BytesIO()
    downloader = MediaIoBaseDownload(fh, req_file)
    done = False
    while not done:
        status, done = downloader.next_chunk()
    fh.seek(0)
    return send_file(fh, download_name=item['filename'], as_attachment=False)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)