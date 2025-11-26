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

# ================= JSON helpers =================
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

# USERS
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

# WORKS
def get_works():
    return load_json(WORKS_FILE)

def save_work(work_data):
    works = get_works()
    work_id = str(datetime.now(timezone.utc).timestamp()) + "-" + uuid.uuid4().hex[:6]
    works[work_id] = work_data
    save_json(WORKS_FILE, works)
    return work_id

# CERTIFICATES
def get_certificates():
    return load_json(CERTS_FILE)

def save_certificate_record(cert_id, cert_record):
    certs = get_certificates()
    certs[cert_id] = cert_record
    save_json(CERTS_FILE, certs)

# REPORTS (plagiarism + verification logs)
def get_reports():
    return load_json(REPORTS_FILE)

def save_report(report_id, report):
    reports = get_reports()
    reports[report_id] = report
    save_json(REPORTS_FILE, reports)

# ================= Duplicate Checking =================
def extract_pdf_text(filepath):
    try:
        reader = PyPDF2.PdfReader(filepath)
        text = ""
        for page in reader.pages:
            text += page.extract_text() or ""
        return text
    except Exception:
        return ""

def compute_fingerprint(filepath):
    h = sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            h.update(chunk)
    return h.hexdigest()

def compute_simhash(text):
    return str(Simhash(text).value)

def is_duplicate(new_fp, new_simhash, works, hamming_threshold=8):
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

# ================ RSA Key Helpers =================
def generate_rsa_keypair(key_size=2048):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size, backend=default_backend())
    public_key = private_key.public_key()

    with open(PRIVATE_KEY_PATH, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(PUBLIC_KEY_PATH, 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    return private_key, public_key

def load_or_create_keys():
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
        PRIVATE_KEY, PUBLIC_KEY = generate_rsa_keypair()
    return PRIVATE_KEY, PUBLIC_KEY

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

# ================= AUTH Routes =================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        users = get_users()
        if email in users and check_password_hash(users[email]['password'], password):
            session['user'] = {'email': email, 'name': users[email]['name']}
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
    flash('Logged out!', 'success')
    return redirect(url_for('login'))

# ================= INDEX =================
@app.route('/')
def index():
    if 'user' not in session:
        return redirect(url_for('login'))

    works = get_works()
    works_list = [{'id': k, **v} for k, v in works.items()]
    works_list.sort(key=lambda x: x.get('uploaded_at', ''), reverse=True)

    reports = get_reports()
    plagiarism_reports = sorted(
        reports.values(),
        key=lambda x: x.get('timestamp', ''),
        reverse=True
    )

    return render_template('index.html',
        works=works_list,
        plagiarism_reports=plagiarism_reports,
        user=session['user']
    )

# ================= UPLOAD WORK =================
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
            os.remove(filepath)
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

    flash('Title and file required', 'error')
    return redirect(url_for('index'))

# ================= WORK DETAILS =================
@app.route('/work/<work_id>')
def work_detail(work_id):
    if 'user' not in session:
        return redirect(url_for('login'))

    works = get_works()
    if work_id in works:
        work = works[work_id]
        work['id'] = work_id
        return render_template('work_detail.html', work=work)
    flash('Work not found', 'error')
    return redirect(url_for('index'))

# ================= DOWNLOAD WORK =================
@app.route('/download/<work_id>')
def download_work(work_id):
    works = get_works()
    rec = works.get(work_id)
    if not rec:
        abort(404)
    path = os.path.join(app.config['UPLOAD_FOLDER'], rec.get('filename'))
    if not os.path.exists(path):
        abort(404)
    return send_file(path, as_attachment=True)

# ================= ISSUE CERT =================
@app.route('/issue_certificate', methods=['GET', 'POST'])
def issue_certificate():
    if 'user' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        work_id = request.form.get('work_id')
        works = get_works()

        if work_id not in works:
            flash('Work missing!', 'error')
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
        to_sign = (payload['fingerprint'] + "|" + payload['issued_at']).encode('utf-8')
        payload['signature'] = sign_bytes(to_sign)

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

        flash('Certificate Issued!', 'success')
        return send_file(cert_path, as_attachment=True)

    works = get_works()
    user_works = {k: v for k, v in works.items()
                  if v.get('uploaded_by') == session['user']['name']}

    return render_template('issue_certificate.html', works=user_works)

# ================= VERIFY CERT =================
@app.route('/verify_certificate', methods=['GET', 'POST'])
def verify_certificate():
    if request.method == 'POST':
        cert_file = request.files.get('cert_file')

        if not cert_file:
            flash('Upload certificate JSON', 'error')
            return redirect(url_for('verify_certificate'))

        try:
            cert_data = json.load(cert_file)
        except:
            flash('Invalid certificate JSON', 'error')
            return redirect(url_for('verify_certificate'))

        sig = cert_data.get('signature')
        fp = cert_data.get('fingerprint')
        issued_at = cert_data.get('issued_at')

        with open(PUBLIC_KEY_PATH, 'rb') as f:
            pub_pem = f.read()

        to_verify = (fp + "|" + issued_at).encode('utf-8')
        signature_ok = verify_signature(pub_pem, to_verify, sig)

        result = {
            'signature_valid': signature_ok,
            'certificate': cert_data
        }
        return render_template('verify_result.html', result=result)

    return render_template('verify_certificate.html')

# ================= PLAGIARISM =================
@app.route('/plagiarism', methods=['POST'])
def plagiarism():
    if 'user' not in session:
        return redirect(url_for('login'))

    file = request.files.get('file')
    if not file:
        flash("Upload a PDF", "error")
        return redirect(url_for('index'))

    filename = secure_filename(file.filename)
    tmp_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
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
            except:
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

    flash("Plagiarism scan complete!", "success")
    return redirect(url_for('index'))

# ================= API DOCS =================
@app.route('/api')
def api_page():
    return render_template('api.html')

@app.route('/api/works')
def api_works():
    return jsonify(get_works())

@app.route('/api/reports')
def api_reports():
    return jsonify(get_reports())

# ================= STARTUP =================
load_or_create_keys()

if __name__ == '__main__':
    load_or_create_keys()
    app.run(debug=True)
