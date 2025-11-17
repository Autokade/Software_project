# app.py - Full app with login, upload, duplicate detection, RSA certs, plagiarism, backup/restore

from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file, abort, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from hashlib import sha256
from simhash import Simhash
import PyPDF2
import os
from datetime import datetime, timezone
import json
import base64
import uuid
import shutil
import hashlib as hashlib_std

# cryptography for RSA signing/verification
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend

# -------- Flask app setup --------
app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024  # 32MB max file size
app.config['KEYS_FOLDER'] = 'keys'
app.config['CERTS_FOLDER'] = 'certs'
app.config['BACKUP_FOLDER'] = 'backups'

for d in (app.config['UPLOAD_FOLDER'], app.config['KEYS_FOLDER'], app.config['CERTS_FOLDER'], app.config['BACKUP_FOLDER']):
    os.makedirs(d, exist_ok=True)

# Simple JSON "DB" files
USERS_FILE = 'users.json'
WORKS_FILE = 'works.json'
CERTS_FILE = 'certificates.json'
REPORTS_FILE = 'reports.json'

# ---------- JSON helpers ----------
def load_json(filename):
    if os.path.exists(filename):
        with open(filename, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

def save_json(filename, data):
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

def get_users():
    return load_json(USERS_FILE)

def save_user(email, name, password):
    users = get_users()
    users[email] = {
        'name': name,
        'password': generate_password_hash(password),
        'created_at': datetime.now(timezone.utc).isoformat()
    }
    save_json(USERS_FILE, users)

def get_works():
    return load_json(WORKS_FILE)

def save_work(work_data):
    works = get_works()
    work_id = str(datetime.now(timezone.utc).timestamp()) + "-" + uuid.uuid4().hex[:6]
    works[work_id] = work_data
    save_json(WORKS_FILE, works)
    return work_id

def get_certificates():
    return load_json(CERTS_FILE)

def save_certificate_record(cert_id, cert_record):
    certs = get_certificates()
    certs[cert_id] = cert_record
    save_json(CERTS_FILE, certs)

def get_reports():
    return load_json(REPORTS_FILE)

def save_report(report_id, report):
    reports = get_reports()
    reports[report_id] = report
    save_json(REPORTS_FILE, reports)

# ---------- Duplicate detection helpers ----------
def extract_pdf_text(filepath):
    """Extract text from PDF for similarity checking"""
    try:
        reader = PyPDF2.PdfReader(filepath)
        text = ""
        for page in reader.pages:
            text += page.extract_text() or ""
        return text
    except Exception:
        return ""

def compute_fingerprint(filepath):
    """Compute SHA-256 fingerprint of file bytes"""
    with open(filepath, "rb") as f:
        return sha256(f.read()).hexdigest()

def compute_simhash(text):
    """Compute simhash as integer string"""
    return str(Simhash(text).value)

def is_duplicate(new_fp, new_simhash, works):
    """Check DB for exact or near duplicate"""
    for work_id, w in works.items():
        if w.get('fingerprint') == new_fp:
            return True, "Exact duplicate file detected."
        if 'simhash' in w:
            try:
                old_sim = int(w['simhash'])
                new_sim = int(new_simhash)
                hamming_distance = bin(old_sim ^ new_sim).count("1")
                # threshold: < 8 bits different => near-duplicate (tweakable)
                if hamming_distance < 8:
                    similarity_pct = 100 - round((hamming_distance / 64) * 100, 2)
                    return True, f"Near duplicate detected ({similarity_pct}% similarity)."
            except Exception:
                continue
    return False, None

# ---------- RSA key generation / load ----------
PRIVATE_KEY_PATH = os.path.join(app.config['KEYS_FOLDER'], 'private_key.pem')
PUBLIC_KEY_PATH = os.path.join(app.config['KEYS_FOLDER'], 'public_key.pem')

def generate_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    # write private
    with open(PRIVATE_KEY_PATH, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    # write public
    public_key = private_key.public_key()
    with open(PUBLIC_KEY_PATH, 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    return private_key, public_key

def load_or_create_keys():
    if os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH):
        with open(PRIVATE_KEY_PATH, 'rb') as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
        with open(PUBLIC_KEY_PATH, 'rb') as f:
            public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
        return private_key, public_key
    else:
        return generate_rsa_keypair()

PRIVATE_KEY, PUBLIC_KEY = load_or_create_keys()

def sign_bytes(data: bytes) -> str:
    signature = PRIVATE_KEY.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode('utf-8')

def verify_signature(public_key_pem: bytes, data: bytes, signature_b64: str) -> bool:
    try:
        public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())
        signature = base64.b64decode(signature_b64)
        public_key.verify(
            signature,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

# ---------- Utility ----------
def admin_required():
    """Simple admin guard: change to proper check in production."""
    user = session.get('user')
    if not user:
        return False
    # treat the first registered user as admin for demo OR check specific email
    admin_email = list(get_users().keys())[0] if get_users() else None
    return user.get('email') == admin_email

# ---------- Routes: auth, index, register, login, logout ----------
@app.route('/')
def index():
    if 'user' not in session:
        return redirect(url_for('login'))
    works = get_works()
    works_list = [{'id': k, **v} for k, v in works.items()]
    works_list.sort(key=lambda x: x.get('uploaded_at', ''), reverse=True)
    total_works = len(works_list)
    work_types = len(set(w.get('work_type', 'other') for w in works_list))
    return render_template('index.html', works=works_list, total_works=total_works, work_types=work_types, user=session['user'])

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        users = get_users()
        if email in users and check_password_hash(users[email]['password'], password):
            session['user'] = {'email': email, 'name': users[email]['name']}
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        users = get_users()
        if email in users:
            flash('Email already registered', 'error')
        else:
            save_user(email, name, password)
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

# ---------- Upload with duplicate detection ----------
@app.route('/upload', methods=['POST'])
def upload():
    if 'user' not in session:
        return redirect(url_for('login'))
    title = request.form.get('title')
    description = request.form.get('description')
    work_type = request.form.get('work_type')
    file = request.files.get('file')
    if file and title:
        filename = secure_filename(file.filename)
        # avoid overwriting: include uuid prefix
        filename = f"{uuid.uuid4().hex[:8]}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        works = get_works()
        fingerprint = compute_fingerprint(filepath)
        pdf_text = extract_pdf_text(filepath)
        simhash_value = compute_simhash(pdf_text)
        duplicate, reason = is_duplicate(fingerprint, simhash_value, works)
        if duplicate:
            flash(reason, "error")
            try:
                os.remove(filepath)
            except Exception:
                pass
            return redirect(url_for('index'))
        work_data = {
            'title': title,
            'description': description,
            'work_type': work_type,
            'filename': filename,
            'uploaded_by': session['user']['name'],
            'uploaded_at': datetime.now(timezone.utc).isoformat(),
            'fingerprint': fingerprint,
            'simhash': simhash_value,
            'file_size': os.path.getsize(filepath)
        }
        work_id = save_work(work_data)
        flash('Work uploaded successfully!', 'success')
        return redirect(url_for('work_detail', work_id=work_id))
    else:
        flash('Please provide title and file', 'error')
    return redirect(url_for('index'))

# ---------- Work detail ----------
@app.route('/work/<work_id>')
def work_detail(work_id):
    if 'user' not in session:
        return redirect(url_for('login'))
    works = get_works()
    if work_id in works:
        work = works[work_id]
        work['id'] = work_id
        return render_template('work_detail.html', work=work)
    else:
        flash('Work not found', 'error')
        return redirect(url_for('index'))

# ---------- Issue certificate for a work (signed) ----------
@app.route('/issue_certificate', methods=['GET', 'POST'])
def issue_certificate():
    if 'user' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        work_id = request.form.get('work_id')
        works = get_works()
        if work_id not in works:
            flash('Work not found', 'error')
            return redirect(url_for('index'))
        work = works[work_id]
        cert_id = uuid.uuid4().hex
        ts = datetime.now(timezone.utc).isoformat()
        payload = {
            "certificate_id": cert_id,
            "work_id": work_id,
            "fingerprint": work.get('fingerprint'),
            "simhash": work.get('simhash'),
            "issued_at": ts,
            "issued_by": session['user']['email']
        }
        # sign the canonical bytes (fingerprint + issued_at)
        to_sign = (payload['fingerprint'] + "|" + payload['issued_at']).encode('utf-8')
        signature_b64 = sign_bytes(to_sign)
        payload['signature'] = signature_b64
        # save certificate file (JSON)
        cert_path = os.path.join(app.config['CERTS_FOLDER'], f"{cert_id}.json")
        with open(cert_path, 'w', encoding='utf-8') as f:
            json.dump(payload, f, indent=2)
        # save record
        save_certificate_record(cert_id, {
            "certificate_id": cert_id,
            "work_id": work_id,
            "cert_path": cert_path,
            "issued_at": ts,
            "issued_by": session['user']['email']
        })
        flash('Certificate issued and saved.', 'success')
        return send_file(cert_path, as_attachment=True)
    # GET: show issue form with user's works
    works = get_works()
    user_works = {k: v for k,v in works.items() if v.get('uploaded_by') == session['user']['name']}
    return render_template('issue_certificate.html', works=user_works)

# ---------- Verify certificate ----------
@app.route('/verify_certificate', methods=['GET', 'POST'])
def verify_certificate():
    if request.method == 'POST':
        # Accept uploaded cert JSON file or certificate id
        cert_file = request.files.get('cert_file')
        cert_id = request.form.get('cert_id')
        input_fingerprint = request.form.get('fingerprint', '').strip()
        cert_data = None
        if cert_file:
            try:
                cert_data = json.load(cert_file)
            except Exception:
                flash('Invalid certificate file', 'error')
                return redirect(url_for('verify_certificate'))
        elif cert_id:
            certs = get_certificates()
            cert_data = certs.get(cert_id)
            if cert_data and 'cert_path' in cert_data:
                with open(cert_data['cert_path'], 'r', encoding='utf-8') as f:
                    cert_data = json.load(f)
        else:
            flash('Provide certificate file or id', 'error')
            return redirect(url_for('verify_certificate'))
        if not cert_data:
            flash('Certificate not found or invalid', 'error')
            return redirect(url_for('verify_certificate'))
        # verify signature
        sig = cert_data.get('signature')
        fp = cert_data.get('fingerprint')
        issued_at = cert_data.get('issued_at')
        if not sig or not fp or not issued_at:
            flash('Certificate missing required fields', 'error')
            return redirect(url_for('verify_certificate'))
        # load public key bytes
        with open(PUBLIC_KEY_PATH, 'rb') as f:
            pub_pem = f.read()
        # verify signature over fingerprint|issued_at
        to_verify = (fp + "|" + issued_at).encode('utf-8')
        sig_ok = verify_signature(pub_pem, to_verify, sig)
        # check fingerprint match if provided by user
        fingerprint_match = None
        if input_fingerprint:
            fingerprint_match = (input_fingerprint == fp)
        # check timestamp valid (not in future)
        try:
            cert_ts = datetime.fromisoformat(issued_at)
            now_ts = datetime.now(timezone.utc)
            timestamp_ok = cert_ts <= now_ts
        except Exception:
            timestamp_ok = False
        result = {
            'signature_valid': sig_ok,
            'fingerprint_match': fingerprint_match,
            'timestamp_valid': timestamp_ok,
            'certificate': cert_data
        }
        # log verification (append to reports)
        report_id = uuid.uuid4().hex
        save_report(report_id, {
            'type': 'verification',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'user': session.get('user', {}).get('email'),
            'result': result
        })
        return render_template('verify_result.html', result=result)
    return render_template('verify_certificate.html')

# ---------- Plagiarism (SimHash) check ----------
@app.route('/plagiarism', methods=['GET', 'POST'])
def plagiarism():
    if 'user' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        file = request.files.get('file')
        if not file:
            flash('Please upload a file', 'error')
            return redirect(url_for('plagiarism'))
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], f"tmp_{uuid.uuid4().hex[:8]}_{filename}")
        file.save(filepath)
        text = extract_pdf_text(filepath)
        new_sim = int(compute_simhash(text))
        works = get_works()
        matches = []
        for wid, w in works.items():
            if 'simhash' in w:
                try:
                    old_sim = int(w['simhash'])
                    hd = bin(old_sim ^ new_sim).count("1")
                    similarity_pct = max(0.0, 100 - round((hd / 64) * 100, 2))
                    matches.append({
                        'work_id': wid,
                        'title': w.get('title'),
                        'uploaded_by': w.get('uploaded_by'),
                        'similarity_pct': similarity_pct,
                        'hamming_distance': hd
                    })
                except Exception:
                    continue
        matches.sort(key=lambda x: x['similarity_pct'], reverse=True)
        report = {
            'report_id': uuid.uuid4().hex,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'checked_by': session['user']['email'],
            'filename': filename,
            'matches': matches[:20]
        }
        save_report(report['report_id'], report)
        try:
            os.remove(filepath)
        except Exception:
            pass
        return render_template('plagiarism_result.html', report=report)
    return render_template('plagiarism.html')

# ---------- Admin backup & restore ----------
@app.route('/admin/backup', methods=['GET', 'POST'])
def admin_backup():
    if not admin_required():
        abort(403)
    if request.method == 'POST':
        # make a timestamped backup folder (zip)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        backup_name = f"backup_{ts}"
        backup_path = os.path.join(app.config['BACKUP_FOLDER'], f"{backup_name}.zip")
        # files to backup: users.json, works.json, certificates.json, reports.json, uploads (optionally)
        to_include = []
        for f in (USERS_FILE, WORKS_FILE, CERTS_FILE, REPORTS_FILE):
            if os.path.exists(f):
                to_include.append(f)
        # create zip
        shutil.make_archive(os.path.join(app.config['BACKUP_FOLDER'], backup_name), 'zip', root_dir='.', base_dir='.')
        # compute checksum of zip
        checksum = compute_file_checksum(backup_path)
        # save metadata
        meta = {
            'backup_name': os.path.basename(backup_path),
            'created_at': datetime.now(timezone.utc).isoformat(),
            'checksum': checksum
        }
        # return file for download
        return send_file(backup_path, as_attachment=True)
    return render_template('admin_backup.html')

@app.route('/admin/restore', methods=['POST'])
def admin_restore():
    if not admin_required():
        abort(403)
    uploaded = request.files.get('backup_file')
    if not uploaded:
        flash('Upload backup zip', 'error')
        return redirect(url_for('admin_backup'))
    fn = secure_filename(uploaded.filename)
    tmp_path = os.path.join(app.config['BACKUP_FOLDER'], f"tmp_restore_{uuid.uuid4().hex[:6]}_{fn}")
    uploaded.save(tmp_path)
    # For simplicity: extract and overwrite JSON files if present
    try:
        shutil.unpack_archive(tmp_path, extract_dir=app.config['BACKUP_FOLDER'])
        # check for our files in extracted dir and copy them to root
        # (Note: do careful checks in production)
        extracted_dir = app.config['BACKUP_FOLDER']
        for fname in (USERS_FILE, WORKS_FILE, CERTS_FILE, REPORTS_FILE):
            extracted_path = os.path.join(extracted_dir, fname)
            if os.path.exists(extracted_path):
                shutil.copy(extracted_path, fname)
        flash('Restore completed (files overwritten).', 'success')
    except Exception as e:
        flash(f'Restore failed: {e}', 'error')
    finally:
        try:
            os.remove(tmp_path)
        except Exception:
            pass
    return redirect(url_for('index'))

def compute_file_checksum(path):
    h = hashlib_std.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            h.update(chunk)
    return h.hexdigest()

# ---------- Serve certificate file (download) ----------
@app.route('/cert/<cert_id>')
def serve_certificate(cert_id):
    certs = get_certificates()
    rec = certs.get(cert_id)
    if not rec:
        abort(404)
    cert_path = rec.get('cert_path')
    if not cert_path or not os.path.exists(cert_path):
        abort(404)
    return send_file(cert_path, as_attachment=True)

# ---------- Simple API endpoints ----------
@app.route('/api/works')
def api_works():
    return jsonify(get_works())

@app.route('/api/reports')
def api_reports():
    return jsonify(get_reports())

# ---------- Run app ----------
if __name__ == '__main__':
    # ensure keys exist at startup
    global PRIVATE_KEY, PUBLIC_KEY
    PRIVATE_KEY, PUBLIC_KEY = load_or_create_keys()
    app.run(debug=True)
