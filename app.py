# app.py - Full app with login, upload, duplicate detection, RSA certs, plagiarism, backup/restore

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, send_file, abort, jsonify
)
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

# ---------------- App & config ----------------
app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024  # 32MB
app.config['KEYS_FOLDER'] = 'keys'
app.config['CERTS_FOLDER'] = 'certs'
app.config['BACKUP_FOLDER'] = 'backups'

# ensure directories exist
for d in (app.config['UPLOAD_FOLDER'], app.config['KEYS_FOLDER'],
          app.config['CERTS_FOLDER'], app.config['BACKUP_FOLDER']):
    os.makedirs(d, exist_ok=True)

# JSON "DB" paths
USERS_FILE = 'users.json'
WORKS_FILE = 'works.json'
CERTS_FILE = 'certificates.json'
REPORTS_FILE = 'reports.json'

# ---------------- Globals for RSA keys ----------------
PRIVATE_KEY_PATH = os.path.join(app.config['KEYS_FOLDER'], 'private_key.pem')
PUBLIC_KEY_PATH = os.path.join(app.config['KEYS_FOLDER'], 'public_key.pem')

PRIVATE_KEY = None
PUBLIC_KEY = None

# ---------------- JSON helpers ----------------
def load_json(filename):
    if os.path.exists(filename):
        with open(filename, 'r', encoding='utf-8') as f:
            try:
                return json.load(f)
            except Exception:
                return {}
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

# ---------------- Duplicate detection helpers ----------------
def extract_pdf_text(filepath):
    """Extract text from PDF for similarity checking (best-effort)."""
    try:
        reader = PyPDF2.PdfReader(filepath)
        text = ""
        for page in reader.pages:
            text += page.extract_text() or ""
        return text
    except Exception:
        # fallback: empty string if parsing fails
        return ""

def compute_fingerprint(filepath):
    """SHA-256 fingerprint of file bytes (exact match)."""
    h = sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

def compute_simhash(text):
    """Compute Simhash integer as string (for storage)."""
    return str(Simhash(text).value)

def is_duplicate(new_fp, new_simhash, works, hamming_threshold=8):
    """
    Check DB for exact or near duplicate.
    Returns (True, message, existing_work_id) or (False, None, None)
    """
    for wid, w in works.items():
        if w.get('fingerprint') == new_fp:
            return True, "Exact duplicate file detected.", wid
        if 'simhash' in w and w['simhash']:
            try:
                old_sim = int(w['simhash'])
                new_sim = int(new_simhash)
                hd = bin(old_sim ^ new_sim).count("1")
                if hd < hamming_threshold:
                    similarity_pct = 100 - round((hd / 64) * 100, 2)
                    return True, f"Near duplicate detected ({similarity_pct}% similarity).", wid
            except Exception:
                continue
    return False, None, None

# ---------------- RSA helpers ----------------
def generate_rsa_keypair(key_size=2048):
    """Generate RSA keypair and write to disk (PEM)."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size, backend=default_backend())
    public_key = private_key.public_key()

    # private
    priv_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(PRIVATE_KEY_PATH, 'wb') as f:
        f.write(priv_pem)

    # public
    pub_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(PUBLIC_KEY_PATH, 'wb') as f:
        f.write(pub_pem)

    return private_key, public_key

def load_or_create_keys():
    """Load keys if present, otherwise generate and return them."""
    global PRIVATE_KEY, PUBLIC_KEY
    try:
        if os.path.exists(PRIVATE_KEY_PATH) and os.path.exists(PUBLIC_KEY_PATH):
            with open(PRIVATE_KEY_PATH, 'rb') as f:
                PRIVATE_KEY = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
            with open(PUBLIC_KEY_PATH, 'rb') as f:
                PUBLIC_KEY = serialization.load_pem_public_key(f.read(), backend=default_backend())
        else:
            PRIVATE_KEY, PUBLIC_KEY = generate_rsa_keypair()
    except Exception:
        # if anything fails, generate fresh keys
        PRIVATE_KEY, PUBLIC_KEY = generate_rsa_keypair()
    return PRIVATE_KEY, PUBLIC_KEY

def sign_bytes(data: bytes) -> str:
    """Sign bytes with server private key, return base64 signature."""
    global PRIVATE_KEY
    if PRIVATE_KEY is None:
        raise RuntimeError("Private key not available")
    signature = PRIVATE_KEY.sign(
        data,
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode('utf-8')

def verify_signature(public_key_pem: bytes, data: bytes, signature_b64: str) -> bool:
    """Verify a base64 signature using a public key (PEM bytes)."""
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

# ---------------- Utility functions ----------------
def compute_file_checksum(path):
    h = hashlib_std.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            h.update(chunk)
    return h.hexdigest()

def admin_required():
    """Treat first registered user as admin (demo). Replace for real auth."""
    user = session.get('user')
    if not user:
        return False
    users = get_users()
    if not users:
        return False
    admin_email = list(users.keys())[0]  # first registered user
    return user.get('email') == admin_email

# ---------------- Routes: auth ----------------
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

@app.route('/api')
def api_page():
    return render_template('api.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash('Logged out successfully', 'success')
    return redirect(url_for('login'))

# ---------------- Home / index ----------------
@app.route('/')
def index():
    if 'user' not in session:
        return redirect(url_for('login'))
    works = get_works()
    works_list = [{'id': k, **v} for k, v in works.items()]
    works_list.sort(key=lambda x: x.get('uploaded_at', ''), reverse=True)
    total_works = len(works_list)
    work_types = len(set(w.get('work_type', 'other') for w in works_list))
    return render_template('index.html', works=works_list, total_works=total_works,
                           work_types=work_types, user=session['user'])

# ---------------- Upload route (duplicate detection) ----------------
@app.route('/upload', methods=['POST'])
def upload():
    if 'user' not in session:
        return redirect(url_for('login'))
    title = request.form.get('title')
    description = request.form.get('description')
    work_type = request.form.get('work_type')
    file = request.files.get('file')
    if file and title:
        filename_raw = secure_filename(file.filename)
        # prefix with uuid to avoid collisions
        filename = f"{uuid.uuid4().hex[:8]}_{filename_raw}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        works = get_works()
        fingerprint = compute_fingerprint(filepath)
        pdf_text = extract_pdf_text(filepath)
        simhash_value = compute_simhash(pdf_text)

        duplicate, reason, existing_wid = is_duplicate(fingerprint, simhash_value, works)
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

# ---------------- Work detail ----------------
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

# ---------------- Issue certificate (signed) ----------------
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
        # canonical bytes to sign: fingerprint + '|' + issued_at
        to_sign = (payload['fingerprint'] + "|" + payload['issued_at']).encode('utf-8')
        signature_b64 = sign_bytes(to_sign)
        payload['signature'] = signature_b64

        # save certificate JSON file
        cert_path = os.path.join(app.config['CERTS_FOLDER'], f"{cert_id}.json")
        with open(cert_path, 'w', encoding='utf-8') as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)

        save_certificate_record(cert_id, {
            "certificate_id": cert_id,
            "work_id": work_id,
            "cert_path": cert_path,
            "issued_at": ts,
            "issued_by": session['user']['email']
        })
        flash('Certificate issued and saved.', 'success')
        return send_file(cert_path, as_attachment=True)
    # GET: render form of user's works
    works = get_works()
    user_works = {k: v for k, v in works.items() if v.get('uploaded_by') == session['user']['name']}
    return render_template('issue_certificate.html', works=user_works)

# ---------------- Verify certificate ----------------
@app.route('/verify_certificate', methods=['GET', 'POST'])
def verify_certificate():
    if request.method == 'POST':
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
            rec = certs.get(cert_id)
            if rec and 'cert_path' in rec and os.path.exists(rec['cert_path']):
                with open(rec['cert_path'], 'r', encoding='utf-8') as f:
                    cert_data = json.load(f)
            else:
                flash('Certificate id not found', 'error')
                return redirect(url_for('verify_certificate'))
        else:
            flash('Provide certificate file or id', 'error')
            return redirect(url_for('verify_certificate'))

        if not cert_data:
            flash('Certificate not found or invalid', 'error')
            return redirect(url_for('verify_certificate'))

        sig = cert_data.get('signature')
        fp = cert_data.get('fingerprint')
        issued_at = cert_data.get('issued_at')
        if not sig or not fp or not issued_at:
            flash('Certificate missing required fields', 'error')
            return redirect(url_for('verify_certificate'))

        # load server public key bytes (we used server key to sign)
        if not os.path.exists(PUBLIC_KEY_PATH):
            flash('Public key not found on server', 'error')
            return redirect(url_for('verify_certificate'))
        with open(PUBLIC_KEY_PATH, 'rb') as f:
            pub_pem = f.read()

        to_verify = (fp + "|" + issued_at).encode('utf-8')
        sig_ok = verify_signature(pub_pem, to_verify, sig)

        fingerprint_match = None
        if input_fingerprint:
            fingerprint_match = (input_fingerprint == fp)

        # timestamp check: issued_at <= now
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

        # log verification
        report_id = uuid.uuid4().hex
        save_report(report_id, {
            'type': 'verification',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'user': session.get('user', {}).get('email'),
            'result': result
        })

        return render_template('verify_result.html', result=result)
    return render_template('verify_certificate.html')

# ---------------- Plagiarism (SimHash) ----------------
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
        tmpname = f"tmp_{uuid.uuid4().hex[:8]}_{filename}"
        tmp_path = os.path.join(app.config['UPLOAD_FOLDER'], tmpname)
        file.save(tmp_path)
        text = extract_pdf_text(tmp_path)
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
            os.remove(tmp_path)
        except Exception:
            pass
        return render_template('plagiarism_result.html', report=report)
    return render_template('plagiarism.html')

# ---------------- Admin: generate keys endpoint ----------------
@app.route('/admin/generate_keys', methods=['POST', 'GET'])
def admin_generate_keys():
    if not admin_required():
        abort(403)
    if request.method == 'POST':
        # generate fresh keys and overwrite existing
        private_key, public_key = generate_rsa_keypair()
        # reload into memory
        load_or_create_keys()
        flash('RSA keypair generated/overwritten.', 'success')
        return redirect(url_for('index'))
    return render_template('admin_generate_keys.html')

# ---------------- Admin: backup & restore ----------------
@app.route('/admin/backup', methods=['GET', 'POST'])
def admin_backup():
    if not admin_required():
        abort(403)
    if request.method == 'POST':
        ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        backup_name = f"backup_{ts}"
        backup_zip = os.path.join(app.config['BACKUP_FOLDER'], f"{backup_name}.zip")
        # create zip of whole repo root (can be tuned)
        shutil.make_archive(os.path.join(app.config['BACKUP_FOLDER'], backup_name), 'zip', root_dir='.', base_dir='.')
        checksum = compute_file_checksum(backup_zip)
        meta = {
            'backup_name': os.path.basename(backup_zip),
            'created_at': datetime.now(timezone.utc).isoformat(),
            'checksum': checksum
        }
        # optionally save metadata somewhere
        return send_file(backup_zip, as_attachment=True)
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
    try:
        shutil.unpack_archive(tmp_path, extract_dir=app.config['BACKUP_FOLDER'])
        extracted_dir = app.config['BACKUP_FOLDER']
        for fname in (USERS_FILE, WORKS_FILE, CERTS_FILE, REPORTS_FILE):
            src = os.path.join(extracted_dir, fname)
            if os.path.exists(src):
                shutil.copy(src, fname)
        flash('Restore completed (files overwritten).', 'success')
    except Exception as e:
        flash(f'Restore failed: {e}', 'error')
    finally:
        try:
            os.remove(tmp_path)
        except Exception:
            pass
    return redirect(url_for('index'))

# ---------------- Serve certificate file ----------------
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

# ---------------- Simple API endpoints ----------------
@app.route('/api/works')
def api_works():
    return jsonify(get_works())

@app.route('/api/reports')
def api_reports():
    return jsonify(get_reports())

# ---------------- Startup ----------------
# Load or create keys when module loads
load_or_create_keys()

if __name__ == '__main__':
    # reload/generate keys at startup too
    load_or_create_keys()
    app.run(debug=True)
