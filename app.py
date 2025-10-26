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
                    password BLOB
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

def valid_input(text):
    if re.search(r"[<>{}'\";]", text):
        return False
    return True

def is_logged_in():
    return "logged_in" in st.session_state and st.session_state.logged_in

def logout():
    for key in list(st.session_state.keys()):
        del st.session_state[key]

# -------------------- REGISTRATION --------------------
def register():
    st.subheader("🔐 Register New Account")
    username = st.text_input("Username")
    email = st.text_input("Email")
    password = st.text_input("Password", type="password")
    confirm = st.text_input("Confirm Password", type="password")

    if st.button("Register"):
        if not valid_input(username):
            st.warning("Invalid characters in username.")
            return
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            st.warning("Invalid email address.")
            return
        if password != confirm:
            st.warning("Passwords do not match.")
            return
        if len(password) < 8 or not re.search(r"(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*\\W)", password):
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
        c.execute("SELECT password FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()

        if user and bcrypt.checkpw(password.encode('utf-8'), user[0]):
            st.session_state.logged_in = True
            st.session_state.username = username
            log_action(username, "User Logged In")
            st.success("✅ Login successful!")
            st.rerun()
        else:
            st.error("Invalid credentials.")

# -------------------- DASHBOARD --------------------
def dashboard():
    st.subheader(f"💼 Welcome, {st.session_state.username}")
    st.write("This is your secure FinTech dashboard.")
    st.write("Perform safe operations and test cybersecurity manually.")

    choice = st.selectbox("Choose an action:", ["View Profile", "Encrypt/Decrypt Data", "View Audit Log", "Logout"])

    if choice == "View Profile":
        update_profile()
    elif choice == "Encrypt/Decrypt Data":
        encryption_demo()
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
    st.markdown("This app demonstrates **secure authentication, encryption, and manual cybersecurity testing**.")

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
            **Secure FinTech Application**  
            - Encrypted passwords (bcrypt)  
            - Input validation & sanitization  
            - Secure session management  
            - Audit logs  
            - Encryption/decryption demo  
            - Manual cybersecurity test ready (20 test cases)
            """)
    except Exception as e:
        st.error("⚠️ A controlled error occurred. Sensitive details are hidden for security.")
        log_action("SYSTEM", f"Error: {str(e)}")

if __name__ == "__main__":
    main()
