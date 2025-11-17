import streamlit as st
import base64
import json
import os
import hashlib
import sqlite3
from datetime import datetime
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import simhash

# --- DATABASE SETUP ---
DB_NAME = "creative_registry.db"

def init_database():
    """Initialize SQLite database with required tables"""
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

def save_to_registry(entry):
    """Save work entry to database"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    try:
        cursor.execute('''
            INSERT INTO registry (creator, title, work_type, fingerprint, simhash, 
                                timestamp, signature, license, file_size)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            entry['creator'],
            entry['title'],
            entry['work_type'],
            entry['fingerprint'],
            str(entry['simhash']),
            entry['timestamp'],
            entry['signature'],
            entry['license'],
            entry['file_size']
        ))
        
        registry_id = cursor.lastrowid
        conn.commit()
        return registry_id
    except sqlite3.IntegrityError:
        return None
    finally:
        conn.close()

def save_certificate(cert_id, registry_id, cert_data):
    """Save certificate to database"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT INTO certificates (certificate_id, registry_id, certificate_data)
        VALUES (?, ?, ?)
    ''', (cert_id, registry_id, json.dumps(cert_data)))
    
    conn.commit()
    conn.close()

def load_all_registry():
    """Load all registry entries from database"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM registry ORDER BY created_at DESC')
    rows = cursor.fetchall()
    conn.close()
    
    registry = []
    for row in rows:
        registry.append({
            'id': row[0],
            'creator': row[1],
            'title': row[2],
            'work_type': row[3],
            'fingerprint': row[4],
            'simhash': int(row[5]),
            'timestamp': row[6],
            'signature': row[7],
            'license': row[8],
            'file_size': row[9],
            'created_at': row[10]
        })
    
    return registry

def search_similar_works(simhash_value, threshold=10):
    """Search for similar works in database"""
    registry = load_all_registry()
    similar_works = []
    
    for entry in registry:
        distance = simhash.Simhash(simhash_value).distance(simhash.Simhash(entry['simhash']))
        if distance < threshold:
            similar_works.append({
                'title': entry['title'],
                'creator': entry['creator'],
                'timestamp': entry['timestamp'],
                'distance': distance,
                'similarity': round((1 - distance/64) * 100, 2)
            })
    
    return similar_works

def get_registry_stats():
    """Get statistics about the registry"""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    cursor.execute('SELECT COUNT(*) FROM registry')
    total_works = cursor.fetchone()[0]
    
    cursor.execute('SELECT work_type, COUNT(*) FROM registry GROUP BY work_type')
    type_counts = cursor.fetchall()
    
    conn.close()
    
    return {
        'total_works': total_works,
        'type_counts': dict(type_counts)
    }

# --- AES ENCRYPTION/DECRYPTION ---
def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data.encode())
    return base64.b64encode(cipher.nonce + tag + ciphertext).decode()

def aes_decrypt(ciphertext_b64, key):
    raw = base64.b64decode(ciphertext_b64)
    nonce, tag, ciphertext = raw[:16], raw[16:32], raw[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

# --- SimHash + Fingerprinting ---
def generate_simhash(content):
    return simhash.Simhash(content).value

def generate_content_fingerprint(content):
    simhash_value = generate_simhash(content)
    fingerprint = hashlib.sha256(str(simhash_value).encode()).hexdigest()
    return fingerprint, simhash_value

# --- Digital Signature ---
def sign_fingerprint(fingerprint, private_key_path="private.pem"):
    try:
        key = RSA.import_key(open(private_key_path).read())
        h = SHA256.new(fingerprint.encode())
        return pkcs1_15.new(key).sign(h)
    except FileNotFoundError:
        st.error("⚠️ Private key not found. Generate keys first!")
        return None

def verify_signature(fingerprint, signature, public_key_path="public.pem"):
    try:
        key = RSA.import_key(open(public_key_path).read())
        h = SHA256.new(fingerprint.encode())
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError, FileNotFoundError):
        return False

# --- Key Generation ---
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    
    with open("private.pem", "wb") as f:
        f.write(private_key)
    with open("public.pem", "wb") as f:
        f.write(public_key)
    
    return private_key, public_key

# --- Certificate Generation ---
def generate_certificate(metadata):
    cert = {
        "certificate_id": hashlib.sha256(str(metadata).encode()).hexdigest()[:16],
        "creator": metadata['creator'],
        "title": metadata['title'],
        "work_type": metadata['work_type'],
        "fingerprint": metadata['fingerprint'],
        "timestamp": metadata['timestamp'],
        "signature": metadata['signature'],
        "license": metadata['license']
    }
    return cert

# --- File Processing ---
def process_content(uploaded_file):
    if uploaded_file.type == "text/plain":
        return uploaded_file.read().decode()
    else:
        return uploaded_file.read().decode(errors='ignore')

# --- Initialize Database on Startup ---
init_database()

# --- Streamlit App UI ---
st.set_page_config(page_title="Creative Work Registry", layout="wide", page_icon="🎨")

# Sidebar
with st.sidebar:
    st.title("🎨 Creator Tools")
    st.markdown("---")
    
    # Key Management
    st.subheader("🔑 Key Management")
    if st.button("Generate New RSA Keys"):
        with st.spinner("Generating keys..."):
            priv, pub = generate_rsa_keys()
            st.success("✅ Keys generated!")
            st.download_button("Download Private Key", priv, "private.pem")
            st.download_button("Download Public Key", pub, "public.pem")
    
    st.markdown("---")
    
    # Statistics
    stats = get_registry_stats()
    st.info(f"📊 **Registry Stats**\n\n**Total Works:** {stats['total_works']}")
    
    if stats['type_counts']:
        st.write("**By Type:**")
        for work_type, count in stats['type_counts'].items():
            st.write(f"- {work_type}: {count}")
    
    st.markdown("---")
    
    # Database Management
    st.subheader("💾 Database")
    st.write(f"Database: `{DB_NAME}`")
    
    if st.button("🗑️ Clear All Data"):
        if st.checkbox("⚠️ Confirm deletion"):
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            cursor.execute('DELETE FROM certificates')
            cursor.execute('DELETE FROM registry')
            conn.commit()
            conn.close()
            st.success("Database cleared!")
            st.rerun()

# Main Header
st.title("🎨 Creative Work Timestamp & Ownership Registry")
st.markdown("**Prove your creative ownership with cryptographic timestamping - All data stored permanently!**")

# Website Link Banner
st.info("🌐 **View Public Registry:** Visit our public website to browse all registered works → [http://localhost:5000](http://localhost:5000)")
st.markdown("---")

# Tabs
tab1, tab2, tab3, tab4, tab5 = st.tabs(["📝 Register Work", "🔍 Verify Ownership", "🕵️ Plagiarism Check", "📚 Registry", "💾 Backup"])

# TAB 1: Register New Work
with tab1:
    st.header("Register Your Creative Work")
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        creator_name = st.text_input("👤 Creator Name", placeholder="Your full name")
        work_title = st.text_input("📄 Work Title", placeholder="My Amazing Novel")
        work_type = st.selectbox("🎭 Work Type", 
            ["Written Work", "Source Code", "Music Lyrics", "Poetry", "Script", "Research Paper", "Other"])
        
        license_type = st.selectbox("⚖️ License Type",
            ["All Rights Reserved", "Creative Commons BY", "Creative Commons BY-SA", 
             "Creative Commons BY-NC", "MIT License", "GPL", "Public Domain"])
    
    with col2:
        st.info("**Why Register?**\n\n✅ Prove creation date\n✅ Detect plagiarism\n✅ Generate certificates\n✅ Protect IP rights\n\n**🔒 Stored Permanently**")
    
    uploaded_file = st.file_uploader("📤 Upload Your Creative Work", type=["txt", "md", "py", "js", "html", "css"])
    
    if uploaded_file and creator_name and work_title:
        if st.button("🔒 Register & Timestamp Work", type="primary"):
            with st.spinner("Processing and registering..."):
                content = process_content(uploaded_file)
                
                # Generate fingerprint
                fingerprint, simhash_value = generate_content_fingerprint(content)
                timestamp = datetime.now().isoformat()
                
                # Check for similar works
                similar = search_similar_works(simhash_value)
                
                if similar:
                    st.warning("⚠️ Similar works found in registry!")
                    for work in similar:
                        st.write(f"- **{work['title']}** by {work['creator']} ({work['similarity']}% similar)")
                    
                    proceed = st.checkbox("I confirm this is my original work and want to proceed")
                    if not proceed:
                        st.stop()
                
                # Sign fingerprint
                signature = sign_fingerprint(fingerprint)
                
                if signature:
                    # Create registry entry
                    entry = {
                        'creator': creator_name,
                        'title': work_title,
                        'work_type': work_type,
                        'fingerprint': fingerprint,
                        'simhash': simhash_value,
                        'timestamp': timestamp,
                        'signature': signature.hex(),
                        'license': license_type,
                        'file_size': len(content)
                    }
                    
                    # Save to database
                    registry_id = save_to_registry(entry)
                    
                    if registry_id:
                        # Generate certificate
                        certificate = generate_certificate(entry)
                        save_certificate(certificate['certificate_id'], registry_id, certificate)
                        
                        st.success("🎉 Work Successfully Registered & Saved to Database!")
                        st.balloons()
                        
                        # Display certificate
                        st.subheader("📜 Ownership Certificate")
                        col1, col2 = st.columns(2)
                        with col1:
                            st.code(f"Certificate ID: {certificate['certificate_id']}")
                            st.code(f"Creator: {certificate['creator']}")
                            st.code(f"Title: {certificate['title']}")
                            st.code(f"Type: {certificate['work_type']}")
                        with col2:
                            st.code(f"Timestamp: {certificate['timestamp']}")
                            st.code(f"License: {certificate['license']}")
                            st.code(f"Fingerprint: {certificate['fingerprint'][:32]}...")
                        
                        # Download certificate
                        cert_json = json.dumps(certificate, indent=4)
                        st.download_button(
                            "📥 Download Certificate",
                            cert_json,
                            f"certificate_{certificate['certificate_id']}.json",
                            "application/json"
                        )
                    else:
                        st.error("❌ This work already exists in the registry!")

# TAB 2: Verify Ownership
with tab2:
    st.header("🔍 Verify Ownership Certificate")
    
    cert_file = st.file_uploader("Upload Certificate JSON", type=["json"], key="verify")
    
    if cert_file:
        cert_data = json.load(cert_file)
        
        st.subheader("Certificate Details")
        col1, col2 = st.columns(2)
        
        with col1:
            st.write(f"**Creator:** {cert_data.get('creator')}")
            st.write(f"**Title:** {cert_data.get('title')}")
            st.write(f"**Type:** {cert_data.get('work_type')}")
        
        with col2:
            st.write(f"**Timestamp:** {cert_data.get('timestamp')}")
            st.write(f"**License:** {cert_data.get('license')}")
        
        # Verify signature
        fingerprint = cert_data.get('fingerprint')
        signature_hex = cert_data.get('signature')
        
        if fingerprint and signature_hex:
            is_valid = verify_signature(fingerprint, bytes.fromhex(signature_hex))
            
            if is_valid:
                st.success("✅ **VALID** - Signature verified! This certificate is authentic.")
                
                # Check if exists in database
                conn = sqlite3.connect(DB_NAME)
                cursor = conn.cursor()
                cursor.execute('SELECT * FROM registry WHERE fingerprint = ?', (fingerprint,))
                result = cursor.fetchone()
                conn.close()
                
                if result:
                    st.info("📋 **Found in Registry** - This work is registered in the database.")
                else:
                    st.warning("⚠️ Not found in local registry database.")
            else:
                st.error("❌ **INVALID** - Signature verification failed! Certificate may be tampered.")
        else:
            st.error("Invalid certificate format")

# TAB 3: Plagiarism Check
with tab3:
    st.header("🕵️ Check for Plagiarism")
    st.write("Upload a work to check if similar content exists in the registry")
    
    check_file = st.file_uploader("Upload Work to Check", type=["txt", "md", "py", "js"], key="plagiarism")
    
    similarity_threshold = st.slider("Similarity Threshold", 0, 64, 10, 
        help="Lower values = stricter matching")
    
    if check_file:
        content = process_content(check_file)
        fingerprint, simhash_value = generate_content_fingerprint(content)
        
        similar_works = search_similar_works(simhash_value, similarity_threshold)
        
        if similar_works:
            st.warning(f"⚠️ Found {len(similar_works)} similar work(s) in database")
            
            for work in similar_works:
                with st.expander(f"📄 {work['title']} ({work['similarity']}% similar)"):
                    st.write(f"**Creator:** {work['creator']}")
                    st.write(f"**Registered:** {work['timestamp']}")
                    st.write(f"**SimHash Distance:** {work['distance']}")
                    
                    if work['similarity'] > 90:
                        st.error("⚠️ Very high similarity - possible plagiarism!")
                    elif work['similarity'] > 70:
                        st.warning("⚠️ High similarity detected")
                    else:
                        st.info("ℹ️ Some similarity found")
        else:
            st.success("✅ No similar works found in registry!")

# TAB 4: Registry Browser
with tab4:
    st.header("📚 Registry of Creative Works")
    
    registry = load_all_registry()
    
    if registry:
        # Filters
        col1, col2 = st.columns(2)
        with col1:
            available_types = list(set([w['work_type'] for w in registry]))
            filter_type = st.multiselect("Filter by Type", options=available_types)
        with col2:
            search = st.text_input("🔍 Search by title or creator")
        
        # Apply filters
        filtered = registry
        
        if filter_type:
            filtered = [w for w in filtered if w['work_type'] in filter_type]
        
        if search:
            filtered = [w for w in filtered if search.lower() in w['title'].lower() or search.lower() in w['creator'].lower()]
        
        st.write(f"Showing {len(filtered)} of {len(registry)} works")
        
        for idx, work in enumerate(filtered):
            with st.expander(f"📄 {work['title']} by {work['creator']}"):
                col1, col2 = st.columns(2)
                with col1:
                    st.write(f"**Type:** {work['work_type']}")
                    st.write(f"**License:** {work['license']}")
                    st.write(f"**File Size:** {work['file_size']} bytes")
                with col2:
                    st.write(f"**Registered:** {work['timestamp']}")
                    st.write(f"**Created At:** {work['created_at']}")
                    st.write(f"**Fingerprint:** {work['fingerprint'][:32]}...")
                
                # Download certificate
                cert = generate_certificate(work)
                cert_json = json.dumps(cert, indent=4)
                st.download_button(
                    "📥 Download Certificate",
                    cert_json,
                    f"certificate_{cert['certificate_id']}.json",
                    key=f"download_{idx}"
                )
    else:
        st.info("📭 No works registered yet. Go to 'Register Work' tab to add your first creative work!")

# TAB 5: Backup & Export
with tab5:
    st.header("💾 Backup & Data Management")
    
    st.subheader("📤 Export Data")
    
    registry = load_all_registry()
    
    if registry:
        col1, col2 = st.columns(2)
        
        with col1:
            st.write("**Export Registry as JSON**")
            registry_json = json.dumps(registry, indent=4)
            st.download_button(
                "📥 Download Full Registry (JSON)",
                registry_json,
                f"registry_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                "application/json"
            )
        
        with col2:
            st.write("**Export Database File**")
            with open(DB_NAME, 'rb') as f:
                st.download_button(
                    "📥 Download Database File",
                    f,
                    f"registry_database_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db",
                    "application/octet-stream"
                )
        
        st.markdown("---")
        
        st.subheader("📊 Database Statistics")
        stats = get_registry_stats()
        
        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("Total Works", stats['total_works'])
        with col2:
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM certificates')
            cert_count = cursor.fetchone()[0]
            conn.close()
            st.metric("Certificates", cert_count)
        with col3:
            db_size = os.path.getsize(DB_NAME) if os.path.exists(DB_NAME) else 0
            st.metric("Database Size", f"{db_size / 1024:.2f} KB")
        
        st.write("**Works by Type:**")
        for work_type, count in stats['type_counts'].items():
            st.write(f"- {work_type}: {count}")
    else:
        st.info("No data to export yet!")