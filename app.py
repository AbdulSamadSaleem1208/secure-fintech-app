# app.py
import streamlit as st
import sqlite3
from passlib.hash import bcrypt
from cryptography.fernet import Fernet
import base64
import os
import re
from datetime import datetime, timedelta
import pandas as pd
import io
import magic  # optional, file type detection

# ---------------------------
# Configuration / Constants
# ---------------------------
DB_PATH = "hbl_fintech.db"
KEY_PATH = "fernet.key"
SESSION_TIMEOUT_MINUTES = 10  # idle timeout for demo (adjustable)
MAX_UPLOAD_SIZE_MB = 2
ALLOWED_FILE_EXTS = [".png", ".jpg", ".jpeg", ".pdf", ".txt", ".csv"]

# ---------------------------
# Utilities
# ---------------------------
def get_key():
    """Load or generate a fernet key"""
    if os.path.exists(KEY_PATH):
        with open(KEY_PATH, "rb") as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_PATH, "wb") as f:
            f.write(key)
        return key

FERNET = Fernet(get_key())

def encrypt_text(plaintext: str) -> bytes:
    if plaintext is None:
        return None
    return FERNET.encrypt(plaintext.encode())

def decrypt_text(token: bytes) -> str:
    if token is None:
        return None
    return FERNET.decrypt(token).decode()

def init_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    cur = conn.cursor()
    
    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash TEXT,
        email BLOB,
        created_at TEXT
    )
    """)
  
    cur.execute("""
    CREATE TABLE IF NOT EXISTS profiles (
        user_id INTEGER PRIMARY KEY,
        full_name BLOB,
        phone BLOB,
        balance_encrypted BLOB,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)
    # Audit logs
    cur.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        action TEXT,
        details TEXT,
        timestamp TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)
    # Optional files table
    cur.execute("""
    CREATE TABLE IF NOT EXISTS uploads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        filename TEXT,
        content BLOB,
        content_type TEXT,
        uploaded_at TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )
    """)
    conn.commit()
    return conn

conn = init_db()

def log_action(user_id, action, details=""):
    cur = conn.cursor()
    cur.execute("INSERT INTO audit_logs (user_id, action, details, timestamp) VALUES (?, ?, ?, ?)",
                (user_id, action, details, datetime.utcnow().isoformat()))
    conn.commit()

def get_user_by_username(username):
    cur = conn.cursor()
    cur.execute("SELECT id, username, password_hash, email, created_at FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    return row

def create_user(username, password_plain, email_plain):
    pw_hash = bcrypt.hash(password_plain)
    email_enc = encrypt_text(email_plain)
    cur = conn.cursor()
    try:
        cur.execute("INSERT INTO users (username, password_hash, email, created_at) VALUES (?, ?, ?, ?)",
                    (username, pw_hash, email_enc, datetime.utcnow().isoformat()))
        conn.commit()
        user_id = cur.lastrowid
        # create empty profile
        cur.execute("INSERT OR REPLACE INTO profiles (user_id, full_name, phone, balance_encrypted) VALUES (?, ?, ?, ?)",
                    (user_id, None, None, encrypt_text("0.00")))
        conn.commit()
        log_action(user_id, "register", "User registered")
        return user_id
    except sqlite3.IntegrityError:
        return None

# ---------------------------
# Password policy
# ---------------------------
def validate_password_policy(pw: str) -> (bool, str):
    if len(pw) < 8:
        return False, "Password must be at least 8 characters."
    if not re.search(r"[A-Z]", pw):
        return False, "Include at least one uppercase letter."
    if not re.search(r"[a-z]", pw):
        return False, "Include at least one lowercase letter."
    if not re.search(r"[0-9]", pw):
        return False, "Include at least one digit."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", pw):
        return False, "Include at least one special character (!@#$...)."
    return True, "OK"

# ---------------------------
# Session helpers
# ---------------------------
def initialize_session_state():
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
        st.session_state.user_id = None
        st.session_state.username = None
        st.session_state.last_active = datetime.utcnow()

def touch_session():
    st.session_state.last_active = datetime.utcnow()

def is_session_expired():
    if not st.session_state.logged_in:
        return False
    idle = datetime.utcnow() - st.session_state.last_active
    return idle > timedelta(minutes=SESSION_TIMEOUT_MINUTES)

def logout():
    if st.session_state.logged_in:
        log_action(st.session_state.user_id, "logout", "User logged out")
    st.session_state.logged_in = False
    st.session_state.user_id = None
    st.session_state.username = None
    st.session_state.last_active = datetime.utcnow()

# ---------------------------
# Inputs validation helpers
# ---------------------------
def safe_numeric_input(value, min_val=None, max_val=None):
    try:
        f = float(value)
    except Exception:
        return None, "Not a valid number"
    if (min_val is not None and f < min_val) or (max_val is not None and f > max_val):
        return None, f"Value must be between {min_val} and {max_val}"
    return f, None

def validate_filename(filename):
    ext = os.path.splitext(filename)[1].lower()
    if ext not in ALLOWED_FILE_EXTS:
        return False, f"Extension {ext} not allowed"
    return True, None

def detect_mime(file_bytes):
    try:
        m = magic.from_buffer(file_bytes, mime=True)
        return m
    except Exception:
        return None

# ---------------------------
# App UI Pages
# ---------------------------
def registration_page():
    st.header("Register")
    try:
        with st.form("register_form"):
            username = st.text_input("Username").strip()
            email = st.text_input("Email")
            pw = st.text_input("Password", type="password")
            pw2 = st.text_input("Confirm Password", type="password")
            submitted = st.form_submit_button("Register")
            if submitted:
                if not username or not email or not pw or not pw2:
                    st.warning("All fields are required.")
                elif pw != pw2:
                    st.error("Passwords do not match.")
                else:
                    ok, msg = validate_password_policy(pw)
                    if not ok:
                        st.error(f"Password policy error: {msg}")
                    else:
                        user_id = create_user(username, pw, email)
                        if user_id is None:
                            st.error("Username already exists. Choose another.")
                        else:
                            st.success("Registration successful. Please log in.")
    except Exception as e:
        st.error("An error occurred while registering. Please try again.")
        # Do not reveal exception details to the user

def login_page():
    st.header("Login")
    try:
        with st.form("login_form"):
            username = st.text_input("Username").strip()
            pw = st.text_input("Password", type="password")
            submitted = st.form_submit_button("Login")
            if submitted:
                if not username or not pw:
                    st.warning("Enter username and password.")
                else:
                    row = get_user_by_username(username)
                    if row is None:
                        st.error("Invalid username or password.")
                    else:
                        user_id, uname, pw_hash, email_enc, created_at = row
                        if bcrypt.verify(pw, pw_hash):
                            st.session_state.logged_in = True
                            st.session_state.user_id = user_id
                            st.session_state.username = uname
                            touch_session()
                            log_action(user_id, "login", "User logged in")
                            st.experimental_rerun()
                        else:
                            # log failed attempt
                            log_action(None, "failed_login", f"username={username}")
                            st.error("Invalid username or password.")
    except Exception:
        st.error("Login service currently unavailable.")

def dashboard_page():
    touch_session()
    st.header("Dashboard")
    st.write(f"Welcome, **{st.session_state.username}**")
    # Show profile summary
    cur = conn.cursor()
    cur.execute("SELECT u.id, u.username, u.email, p.full_name, p.phone, p.balance_encrypted FROM users u LEFT JOIN profiles p ON u.id = p.user_id WHERE u.id = ?", (st.session_state.user_id,))
    row = cur.fetchone()
    if row:
        uid, uname, email_enc, name_enc, phone_enc, balance_enc = row
        email = decrypt_text(email_enc) if email_enc else ""
        full_name = decrypt_text(name_enc) if name_enc else ""
        phone = decrypt_text(phone_enc) if phone_enc else ""
        balance = decrypt_text(balance_enc) if balance_enc else "0.00"
        st.subheader("Profile Summary")
        st.write(f"**Full name:** {full_name or 'Not set'}")
        st.write(f"**Email:** {email or 'Not set'}")
        st.write(f"**Phone:** {phone or 'Not set'}")
        st.write(f"**Account Balance (encrypted):** {balance}")
    else:
        st.info("Profile not found.")

    # Quick actions
    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("New Transaction"):
            st.session_state.page = "transaction"
            st.experimental_rerun()
    with col2:
        if st.button("Upload File"):
            st.session_state.page = "upload"
            st.experimental_rerun()
    with col3:
        if st.button("View Logs"):
            st.session_state.page = "logs"
            st.experimental_rerun()

def transaction_page():
    touch_session()
    st.header("Create Transaction (Demo)")
    st.write("Input a numeric amount and description. This demonstrates input validation and audit logging.")
    try:
        with st.form("txn"):
            amount_raw = st.text_input("Amount (PKR)")
            description = st.text_area("Description", max_chars=300)
            submit = st.form_submit_button("Submit Transaction")
            if submit:
                amount, err = safe_numeric_input(amount_raw, min_val=0.01)
                if err:
                    st.error(f"Amount error: {err}")
                elif not description.strip():
                    st.error("Description required.")
                else:
                    # For demo, we will store a "transaction" in audit logs
                    details = f"Txn amount={amount:.2f}; desc={description[:100]}"
                    log_action(st.session_state.user_id, "transaction", details)
                    st.success("Transaction recorded (audit logged).")
    except Exception:
        st.error("Could not process transaction. Please try again.")

def profile_page():
    touch_session()
    st.header("Update Profile")
    cur = conn.cursor()
    cur.execute("SELECT full_name, phone, balance_encrypted FROM profiles WHERE user_id = ?", (st.session_state.user_id,))
    row = cur.fetchone()
    name = ""
    phone = ""
    balance = "0.00"
    if row:
        name_enc, phone_enc, bal_enc = row
        name = decrypt_text(name_enc) if name_enc else ""
        phone = decrypt_text(phone_enc) if phone_enc else ""
        balance = decrypt_text(bal_enc) if bal_enc else "0.00"
    try:
        with st.form("profile_form"):
            full_name = st.text_input("Full Name", value=name)
            phone_in = st.text_input("Phone", value=phone)
            balance_in = st.text_input("Balance (for demo only)", value=balance)
            submitted = st.form_submit_button("Save Profile")
            if submitted:
                # Basic validation
                if len(full_name) > 100:
                    st.error("Full name too long.")
                else:
                    # Validate numeric balance
                    bal_float, err = safe_numeric_input(balance_in, min_val=0)
                    if err:
                        st.error("Balance must be numeric and non-negative.")
                    else:
                        cur.execute("UPDATE profiles SET full_name = ?, phone = ?, balance_encrypted = ? WHERE user_id = ?",
                                    (encrypt_text(full_name), encrypt_text(phone_in), encrypt_text(f"{bal_float:.2f}"), st.session_state.user_id))
                        conn.commit()
                        log_action(st.session_state.user_id, "profile_update", "Updated profile fields")
                        st.success("Profile updated securely.")
    except Exception:
        st.error("Failed to update profile. Try again.")

def upload_page():
    touch_session()
    st.header("Upload File (validation demo)")
    try:
        uploaded = st.file_uploader("Choose a file", type=[ext.strip(".") for ext in ALLOWED_FILE_EXTS])
        if uploaded is not None:
            filename = uploaded.name
            contents = uploaded.read()
            # size check
            if len(contents) > MAX_UPLOAD_SIZE_MB * 1024 * 1024:
                st.error(f"File too large. Max {MAX_UPLOAD_SIZE_MB} MB.")
                return
            ok, msg = validate_filename(filename)
            if not ok:
                st.error(msg)
                return
            mime = detect_mime(contents)
            # Basic sanity: if magic is available, ensure mime roughly matches ext
            if mime:
                st.write(f"Detected MIME: {mime}")
            # store in DB
            cur = conn.cursor()
            cur.execute("INSERT INTO uploads (user_id, filename, content, content_type, uploaded_at) VALUES (?, ?, ?, ?, ?)",
                        (st.session_state.user_id, filename, contents, mime or "unknown", datetime.utcnow().isoformat()))
            conn.commit()
            log_action(st.session_state.user_id, "file_upload", f"uploaded {filename}")
            st.success("File uploaded and logged.")
    except Exception:
        st.error("Failed to upload file. Please try a different file.")

def logs_page():
    touch_session()
    st.header("Audit / Activity Logs")
    cur = conn.cursor()
    cur.execute("SELECT id, action, details, timestamp FROM audit_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT 200", (st.session_state.user_id,))
    rows = cur.fetchall()
    if not rows:
        st.info("No logs yet.")
    else:
        df = pd.DataFrame(rows, columns=["ID", "Action", "Details", "Timestamp"])
        st.dataframe(df)

def logout_button():
    if st.button("Logout"):
        logout()
        st.experimental_rerun()

# ---------------------------
# Test case template download feature
# ---------------------------
def test_case_template_download():
    st.subheader("Manual Test Case Template (Download)")
    template = [
        ["No.", "Test Case", "Action Performed", "Expected Outcome", "Observed Result", "Pass/Fail", "Screenshot Path/Note"]
    ]
    # Add sample starter rows
    for i in range(1, 6):
        template.append([i, "", "", "", "", "", ""])
    df = pd.DataFrame(template[1:], columns=template[0])
    csv = df.to_csv(index=False).encode("utf-8")
    st.download_button("Download Test Case Template (CSV)", data=csv, file_name="manual_test_cases_template.csv", mime="text/csv")
    st.info("Make at least 20 manual tests. Save screenshots and complete the CSV with results.")

# ---------------------------
# Navigation / Main
# ---------------------------
def main():
    st.set_page_config(page_title="Secure FinTech Demo - HBL", layout="wide")
    initialize_session_state()

    # Top bar
    st.title("Flow of Funds – HBL (Secure FinTech Demo)")
    # Left navigation
    menu = ["Home", "Register", "Login"]
    if st.session_state.logged_in:
        menu += ["Dashboard", "Profile", "Transaction", "Upload", "Logs", "Download Test Template", "Logout"]
    choice = st.sidebar.selectbox("Menu", menu)

    # Session expiry enforcement
    if st.session_state.logged_in and is_session_expired():
        st.warning("Session expired due to inactivity.")
        logout()
        st.experimental_rerun()

    # Map selection to pages
    try:
        if choice == "Home":
            st.header("About this Demo")
            st.write("""
            This application is a small, secure FinTech demo built for educational purposes.
            It demonstrates user registration & login with hashed passwords, encrypted data storage,
            input validation, session management, audit logging, and file upload validation.
            Use the sidebar to navigate. For assignment, perform at least 20 manual tests and document them.
            """)
            st.markdown("**Note:** This demo is for learning & manual testing only. Do not use in production without further security review.")
            test_case_template_download()
        elif choice == "Register":
            registration_page()
        elif choice == "Login":
            if st.session_state.logged_in:
                st.info("Already logged in.")
            else:
                login_page()
        elif choice == "Dashboard":
            if not st.session_state.logged_in:
                st.warning("Please login first.")
            else:
                dashboard_page()
                logout_button()
        elif choice == "Transaction":
            if not st.session_state.logged_in:
                st.warning("Please login first.")
            else:
                transaction_page()
                logout_button()
        elif choice == "Profile":
            if not st.session_state.logged_in:
                st.warning("Please login first.")
            else:
                profile_page()
                logout_button()
        elif choice == "Upload":
            if not st.session_state.logged_in:
                st.warning("Please login first.")
            else:
                upload_page()
                logout_button()
        elif choice == "Logs":
            if not st.session_state.logged_in:
                st.warning("Please login first.")
            else:
                logs_page()
                logout_button()
        elif choice == "Download Test Template":
            if not st.session_state.logged_in:
                st.warning("Please login first.")
            else:
                test_case_template_download()
                logout_button()
        elif choice == "Logout":
            logout()
            st.success("Logged out.")
            st.experimental_rerun()
    except Exception:
        st.error("An unexpected error occurred. Please try again later.")
        # Do not reveal internal error

if __name__ == "__main__":
    main()
