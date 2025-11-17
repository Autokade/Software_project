# app.py - Updated version with login, upload, and duplicate detection

from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from hashlib import sha256
from simhash import Simhash
import PyPDF2
import os
from datetime import datetime
import json

app = Flask(__name__)
app.secret_key = 'your-secret-key-change-this-in-production'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Create uploads folder if it doesn't exist
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Simple database simulation using JSON files
USERS_FILE = 'users.json'
WORKS_FILE = 'works.json'


# ------------------ JSON DATABASE HELPERS ------------------

def load_json(filename):
    if os.path.exists(filename):
        with open(filename, 'r') as f:
            return json.load(f)
    return {}

def save_json(filename, data):
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)

def get_users():
    return load_json(USERS_FILE)

def save_user(email, name, password):
    users = get_users()
    users[email] = {
        'name': name,
        'password': generate_password_hash(password),
        'created_at': datetime.now().isoformat()
    }
    save_json(USERS_FILE, users)

def get_works():
    return load_json(WORKS_FILE)

def save_work(work_data):
    works = get_works()
    work_id = str(datetime.now().timestamp())
    works[work_id] = work_data
    save_json(WORKS_FILE, works)
    return work_id


# ------------------ DUPLICATE DETECTION HELPERS ------------------

def extract_pdf_text(filepath):
    """Extract text from PDF for similarity checking"""
    try:
        reader = PyPDF2.PdfReader(filepath)
        text = ""
        for page in reader.pages:
            text += page.extract_text() or ""
        return text
    except:
        return ""


def compute_fingerprint(filepath):
    """Compute SHA-256 fingerprint of file bytes"""
    with open(filepath, "rb") as f:
        return sha256(f.read()).hexdigest()


def compute_simhash(text):
    """Compute simhash of extracted text"""
    return str(Simhash(text).value)


def is_duplicate(new_fp, new_simhash, works):
    """Check database for exact or near duplicate"""
    for work_id, w in works.items():

        # Exact duplicate (same file bytes)
        if w.get('fingerprint') == new_fp:
            return True, "Exact duplicate file detected."

        # Near duplicate (similar content)
        if 'simhash' in w:
            old_sim = int(w['simhash'])
            new_sim = int(new_simhash)
            hamming_distance = bin(old_sim ^ new_sim).count("1")

            if hamming_distance < 5:  # very similar files
                return True, "Near duplicate file detected (similar content)."

    return False, None


# ------------------ ROUTES ------------------

@app.route('/')
def index():
    if 'user' not in session:
        return redirect(url_for('login'))
    
    works = get_works()
    works_list = [{'id': k, **v} for k, v in works.items()]
    works_list.sort(key=lambda x: x.get('uploaded_at', ''), reverse=True)

    total_works = len(works_list)
    work_types = len(set(w.get('work_type', 'other') for w in works_list))
    
    return render_template('index.html', 
        works=works_list, 
        total_works=total_works,
        work_types=work_types,
        user=session['user']
    )


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


# ------------------ UPDATED UPLOAD ROUTE (with duplicate detection) ------------------

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
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        # === DUPLICATE DETECTION ===
        works = get_works()
        fingerprint = compute_fingerprint(filepath)
        pdf_text = extract_pdf_text(filepath)
        simhash_value = compute_simhash(pdf_text)

        duplicate, reason = is_duplicate(fingerprint, simhash_value, works)
        if duplicate:
            flash(reason, "error")
            os.remove(filepath)
            return redirect(url_for('index'))

        # === SAVE FILE IF NOT DUPLICATE ===
        work_data = {
            'title': title,
            'description': description,
            'work_type': work_type,
            'filename': filename,
            'uploaded_by': session['user']['name'],
            'uploaded_at': datetime.now().isoformat(),
            'fingerprint': fingerprint,
            'simhash': simhash_value,
            'file_size': os.path.getsize(filepath)
        }

        save_work(work_data)
        flash('Work uploaded successfully!', 'success')

    else:
        flash('Please provide title and file', 'error')
    
    return redirect(url_for('index'))


@app.route('/search')
def search():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('search.html')


@app.route('/stats')
def stats():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('stats.html')


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


# ------------------ RUN APP ------------------

if __name__ == '__main__':
    app.run(debug=True)
