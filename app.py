from flask import Flask, render_template, jsonify, request
import sqlite3
import json
from datetime import datetime

app = Flask(__name__)
DB_NAME = "creative_registry.db"

def init_database():
    """Initialize database tables if they don't exist"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS registry (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            creator TEXT NOT NULL,
            title TEXT NOT NULL,
            work_type TEXT NOT NULL,
            fingerprint TEXT UNIQUE NOT NULL,
            simhash TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            signature TEXT NOT NULL,
            license TEXT NOT NULL,
            file_size INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS certificates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            certificate_id TEXT UNIQUE NOT NULL,
            registry_id INTEGER,
            certificate_data TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (registry_id) REFERENCES registry (id)
        )
    ''')
    
    conn.commit()
    conn.close()

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

# ✅ CALL DB INIT HERE — AFTER THE FUNCTION EXISTS
init_database()


# ---------------- ROUTES BELOW ----------------

@app.route('/')
def index():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM registry ORDER BY created_at DESC')
    works = cursor.fetchall()

    cursor.execute('SELECT COUNT(*) as total FROM registry')
    total_works = cursor.fetchone()['total']

    cursor.execute('SELECT work_type, COUNT(*) as count FROM registry GROUP BY work_type')
    type_stats = cursor.fetchall()

    conn.close()
    return render_template('index.html', works=works, total_works=total_works, type_stats=type_stats)


@app.route('/work/<int:work_id>')
def work_detail(work_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM registry WHERE id = ?', (work_id,))
    work = cursor.fetchone()
    conn.close()

    if work:
        return render_template('work_detail.html', work=work)
    else:
        return "Work not found", 404


@app.route('/search')
def search():
    query = request.args.get('q', '')
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute('''
        SELECT * FROM registry 
        WHERE title LIKE ? OR creator LIKE ? OR work_type LIKE ?
        ORDER BY created_at DESC
    ''', (f'%{query}%', f'%{query}%', f'%{query}%'))

    works = cursor.fetchall()
    conn.close()

    return render_template('search.html', works=works, query=query)


@app.route('/api/works')
def api_works():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM registry ORDER BY created_at DESC')
    works = cursor.fetchall()
    conn.close()
    return jsonify([dict(work) for work in works])


@app.route('/api/work/<int:work_id>')
def api_work(work_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM registry WHERE id = ?', (work_id,))
    work = cursor.fetchone()
    conn.close()

    if work:
        return jsonify(dict(work))
    else:
        return jsonify({"error": "Work not found"}), 404


@app.route('/stats')
def stats():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) as total FROM registry')
    total_works = cursor.fetchone()['total']

    cursor.execute('SELECT work_type, COUNT(*) as count FROM registry GROUP BY work_type')
    type_stats = cursor.fetchall()

    cursor.execute('SELECT creator, COUNT(*) as count FROM registry GROUP BY creator ORDER BY count DESC LIMIT 10')
    top_creators = cursor.fetchall()

    cursor.execute('SELECT license, COUNT(*) as count FROM registry GROUP BY license')
    license_stats = cursor.fetchall()

    conn.close()

    return render_template('stats.html', total_works=total_works, type_stats=type_stats, top_creators=top_creators, license_stats=license_stats)


if __name__ == "__main__":
    print("Running locally...")
    print("chal ja")
    init_database()
    # app.run(debug=True)
