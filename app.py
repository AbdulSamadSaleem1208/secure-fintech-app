import streamlit as st
import sqlite3
import bcrypt
from cryptography.fernet import Fernet
import re
import time
import os

# -------------------- INITIAL SETUP --------------------
DB_FILE = "fintech_secure.db"
KEY_FILE = "secret.key"
LOCKOUT_LIMIT = 5
LOCKOUT_TIME = 300  # 5 minutes
SESSION_TIMEOUT = 600  # 10 minutes

st.set_page_config(page_title="Secure FinTech App", page_icon="💳", layout="centered")

# -------------------- ENCRYPTION KEY --------------------
def load_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    return open(KEY_FILE, "rb").read()

fernet = Fernet(load_key())

# -------------------- DATABASE SETUP --------------------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE,
                    email TEXT,
                    password BLOB,
                    failed_attempts INTEGER DEFAULT 0,
                    lockout_until REAL DEFAULT 0
                )""")
    c.execute("""CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT,
                    action TEXT,
                    timestamp TEXT
                )""")
    conn.commit()
    conn.close()

init_db()

# -------------------- HELPERS --------------------
def log_action(username, action):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO audit_log (username, action, timestamp) VALUES (?, ?, ?)",
              (username, action, time.strftime("%Y-%m-%d %H:%M:%S")))
    conn.commit()
    conn.close()

def valid_input(text, max_len=100):
    if not text or len(text) > max_len or re.search(r"[<>{}'\";]|--|\bOR\b|\bAND\b", text, re.IGNORECASE):
        return False
    return True

def is_logged_in():
    return "logged_in" in st.session_state and st.session_state.logged_in

def check_session_timeout():
    if "last_activity" in st.session_state:
        if time.time() - st.session_state.last_activity > SESSION_TIMEOUT:
            logout()
            st.warning("⏰ Session expired due to inactivity. Please log in again.")
            st.rerun()
    st.session_state.last_activity = time.time()

def logout():
    for key in list(st.session_state.keys()):
        del st.session_state[key]

# -------------------- REGISTRATION --------------------
def register():
    st.subheader("🔐 Register New Account")
    username = st.text_input("Username (max 50 chars)", max_chars=50)
    email = st.text_input("Email (max 100 chars)", max_chars=100)
    password = st.text_input("Password", type="password")
    confirm = st.text_input("Confirm Password", type="password")

    if st.button("Register"):
        if not valid_input(username, 50):
            st.warning("Invalid characters or too long username.")
            return
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            st.warning("Invalid email address.")
            return
        if password != confirm:
            st.warning("Passwords do not match.")
            return
        # ✅ FIXED regex for strong password check
        if len(password) < 8 or not re.search(r"(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*\W)", password):
            st.warning("Password must include upper, lower, digit, and special character.")
            return

        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        try:
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute("INSERT INTO users (username, email, password) VALUES (?, ?, ?)",
                      (username, email, hashed_pw))
            conn.commit()
            conn.close()
            log_action(username, "User Registered")
            st.success("✅ Registration successful! Please go to Login page.")
        except sqlite3.IntegrityError:
            st.error("Username or Email already exists.")

# -------------------- LOGIN --------------------
def login():
    st.subheader("🔑 Login to Your Account")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("SELECT password, failed_attempts, lockout_until FROM users WHERE username = ?", (username,))
        user = c.fetchone()

        if not user:
            st.error("Invalid credentials.")
            return

        hashed_pw, failed_attempts, lockout_until = user
        now = time.time()

        if lockout_until > now:
            st.error("Account locked. Try again later.")
            conn.close()
            return

        if bcrypt.checkpw(password.encode('utf-8'), hashed_pw):
            c.execute("UPDATE users SET failed_attempts = 0, lockout_until = 0 WHERE username = ?", (username,))
            conn.commit()
            conn.close()

            st.session_state.logged_in = True
            st.session_state.username = username
            st.session_state.last_activity = time.time()

            log_action(username, "User Logged In")
            st.success("✅ Login successful!")
            st.rerun()
        else:
            failed_attempts += 1
            if failed_attempts >= LOCKOUT_LIMIT:
                lockout_until = now + LOCKOUT_TIME
                c.execute("UPDATE users SET failed_attempts=?, lockout_until=? WHERE username=?",
                          (failed_attempts, lockout_until, username))
                conn.commit()
                conn.close()
                log_action(username, "Account Locked After Failed Attempts")
                st.error("🚫 Too many failed attempts. Account temporarily locked.")
            else:
                c.execute("UPDATE users SET failed_attempts=? WHERE username=?", (failed_attempts, username))
                conn.commit()
                conn.close()
                st.error(f"Invalid password. {LOCKOUT_LIMIT - failed_attempts} attempts left.")

# -------------------- DASHBOARD --------------------
def dashboard():
    check_session_timeout()
    st.subheader(f"💼 Welcome, {st.session_state.username}")
    st.write("This is your secure FinTech dashboard.")
    choice = st.selectbox(
        "Choose an action:",
        ["View Profile", "Encrypt/Decrypt Data", "Upload File", "View Audit Log", "Logout"]
    )

    if choice == "View Profile":
        update_profile()
    elif choice == "Encrypt/Decrypt Data":
        encryption_demo()
    elif choice == "Upload File":
        upload_file()
    elif choice == "View Audit Log":
        show_logs()
    elif choice == "Logout":
        log_action(st.session_state.username, "User Logged Out")
        logout()
        st.info("You have been logged out.")
        st.rerun()

# -------------------- PROFILE --------------------
def update_profile():
    st.write("### 🧾 Update Profile Info")
    new_email = st.text_input("New Email")
    if st.button("Update Email"):
        if not re.match(r"[^@]+@[^@]+\.[^@]+", new_email):
            st.warning("Invalid email format.")
        else:
            conn = sqlite3.connect(DB_FILE)
            c = conn.cursor()
            c.execute("UPDATE users SET email = ? WHERE username = ?", (new_email, st.session_state.username))
            conn.commit()
            conn.close()
            log_action(st.session_state.username, "Email Updated")
            st.success("✅ Email updated successfully!")

# -------------------- ENCRYPTION DEMO --------------------
def encryption_demo():
    st.write("### 🔐 Data Encryption / Decryption")
    data = st.text_input("Enter data to encrypt:")
    if st.button("Encrypt"):
        if data:
            encrypted = fernet.encrypt(data.encode()).decode()
            st.code(encrypted)
            st.session_state["last_encrypted"] = encrypted
        else:
            st.warning("Please enter data first.")
    if st.button("Decrypt"):
        if "last_encrypted" in st.session_state:
            decrypted = fernet.decrypt(st.session_state["last_encrypted"].encode()).decode()
            st.code(decrypted)
        else:
            st.warning("Nothing to decrypt yet.")

# -------------------- FILE UPLOAD VALIDATION --------------------
def upload_file():
    st.write("### 📂 Secure File Upload")
    file = st.file_uploader("Upload file (only .csv, .txt, .pdf allowed)", type=["csv", "txt", "pdf"])
    if file:
        st.success(f"✅ File '{file.name}' uploaded successfully and validated.")
        log_action(st.session_state.username, f"Uploaded file: {file.name}")

# -------------------- AUDIT LOG --------------------
def show_logs():
    st.write("### 📜 User Activity Logs")
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT username, action, timestamp FROM audit_log ORDER BY id DESC")
    logs = c.fetchall()
    conn.close()
    for l in logs:
        st.text(f"{l[2]} | {l[0]} | {l[1]}")

# -------------------- MAIN --------------------
def main():
    st.title("💳 Secure FinTech Application")
    st.markdown("Demonstrating secure authentication, encryption, validation, and cybersecurity test compliance.")

    menu = ["Login", "Register", "About"]
    choice = st.sidebar.selectbox("Menu", menu)

    try:
        if choice == "Login":
            if is_logged_in():
                dashboard()
            else:
                login()
        elif choice == "Register":
            register()
        elif choice == "About":
            st.info("""
            **Secure FinTech Application (Full Test Compliance)**  
            - SQL Injection protection ✅  
            - Password & email validation ✅  
            - Session timeout (10 min) ✅  
            - Login lockout (5 fails) ✅  
            - File upload validation ✅  
            - Encryption (Fernet) ✅  
            - Audit logs ✅  
            """)
    except Exception as e:
        st.error("⚠️ A controlled error occurred. Sensitive details are hidden for security.")
        log_action("SYSTEM", f"Error: {str(e)}")

if __name__ == "__main__":
    main()
