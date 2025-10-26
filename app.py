import streamlit as st
from pymongo import MongoClient
import bcrypt
from cryptography.fernet import Fernet
import re
import time
import os

# -------------------- INITIAL SETUP --------------------
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

# -------------------- MONGODB CONNECTION --------------------
def get_db():
    client = MongoClient("mongodb://localhost:27017/")  # local MongoDB
    db = client["fintech_app"]
    return db

db = get_db()
users_col = db["users"]
audit_col = db["audit_log"]

# -------------------- HELPERS --------------------
def log_action(username, action):
    try:
        audit_col.insert_one({
            "username": username,
            "action": action,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        })
    except Exception:
        pass

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
            st.warning("⏰ Session expired. Please log in again.")
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
            st.warning("Invalid or too long username.")
            return
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            st.warning("Invalid email address.")
            return
        if password != confirm:
            st.warning("Passwords do not match.")
            return
        if len(password) < 8 or not re.search(r"(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*\W)", password):
            st.warning("Password must include upper, lower, digit, and special character.")
            return

        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        try:
            if users_col.find_one({"$or": [{"username": username}, {"email": email}]}):
                st.error("Username or Email already exists.")
                return
            users_col.insert_one({
                "username": username,
                "email": email,
                "password": hashed_pw,
                "failed_attempts": 0,
                "lockout_until": 0
            })
            log_action(username, "User Registered")
            st.success("✅ Registration successful! Please go to Login page.")
        except Exception as e:
            st.error("⚠️ Registration failed. Try again later.")
            log_action("SYSTEM", f"Registration error: {str(e)}")

# -------------------- LOGIN --------------------
def login():
    st.subheader("🔑 Login to Your Account")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        try:
            user = users_col.find_one({"username": username})
        except Exception as e:
            st.error("⚠️ Unable to access authentication backend. Try again later.")
            log_action("SYSTEM", f"DB access error: {str(e)}")
            return

        if not user:
            st.error("Invalid credentials.")
            return

        hashed_pw = user["password"]
        failed_attempts = user.get("failed_attempts", 0)
        lockout_until = user.get("lockout_until", 0)
        now = time.time()

        if lockout_until and lockout_until > now:
            st.error("Account locked. Try again later.")
            return

        try:
            if bcrypt.checkpw(password.encode('utf-8'), hashed_pw):
                users_col.update_one({"username": username}, {"$set": {"failed_attempts": 0, "lockout_until": 0}})
                st.session_state.logged_in = True
                st.session_state.username = username
                st.session_state.last_activity = time.time()
                log_action(username, "User Logged In")
                st.success("✅ Login successful!")
                st.rerun()
            else:
                fa = failed_attempts + 1
                if fa >= LOCKOUT_LIMIT:
                    lockout_until = now + LOCKOUT_TIME
                    users_col.update_one({"username": username}, {"$set": {"failed_attempts": fa, "lockout_until": lockout_until}})
                    log_action(username, "Account Locked After Failed Attempts")
                    st.error("🚫 Too many failed attempts. Account temporarily locked.")
                else:
                    users_col.update_one({"username": username}, {"$set": {"failed_attempts": fa}})
                    st.error(f"Invalid password. {LOCKOUT_LIMIT - fa} attempts left.")
        except Exception as e:
            st.error("⚠️ Authentication failed. Try again later.")
            log_action("SYSTEM", f"Auth error: {str(e)}")

# -------------------- DASHBOARD --------------------
def dashboard():
    check_session_timeout()
    st.subheader(f"💼 Welcome, {st.session_state.username}")
    st.write("This is your secure FinTech dashboard.")

    choice = st.selectbox("Choose an action:",
                          ["View Profile", "Encrypt/Decrypt Data", "Upload File", "View Audit Log", "Logout"])

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
            try:
                users_col.update_one({"username": st.session_state.username}, {"$set": {"email": new_email}})
                log_action(st.session_state.username, "Email Updated")
                st.success("✅ Email updated successfully!")
            except Exception:
                st.error("⚠️ Could not update email. Try again later.")

# -------------------- ENCRYPTION DEMO --------------------
def encryption_demo():
    st.write("### 🔐 Data Encryption / Decryption")
    data = st.text_input("Enter data to encrypt:")
    if st.button("Encrypt"):
        if data:
            try:
                encrypted = fernet.encrypt(data.encode()).decode()
                st.code(encrypted)
                st.session_state["last_encrypted"] = encrypted
            except Exception:
                st.error("⚠️ Encryption failed.")
        else:
            st.warning("Please enter data first.")
    if st.button("Decrypt"):
        if "last_encrypted" in st.session_state:
            try:
                decrypted = fernet.decrypt(st.session_state["last_encrypted"].encode()).decode()
                st.code(decrypted)
            except Exception:
                st.error("⚠️ Decryption failed or data corrupted.")
        else:
            st.warning("Nothing to decrypt yet.")

# -------------------- FILE UPLOAD --------------------
def upload_file():
    st.write("### 📂 Secure File Upload")
    file = st.file_uploader("Upload file (.csv, .txt, .pdf only)", type=["csv", "txt", "pdf"])
    if file:
        st.success(f"✅ File '{file.name}' uploaded successfully.")
        log_action(st.session_state.username, f"Uploaded file: {file.name}")

# -------------------- AUDIT LOG --------------------
def show_logs():
    st.write("### 📜 User Activity Logs")
    try:
        logs = audit_col.find().sort("_id", -1)
        for l in logs:
            st.text(f"{l['timestamp']} | {l['username']} | {l['action']}")
    except Exception:
        st.error("⚠️ Could not load logs.")

# -------------------- MAIN --------------------
def main():
    st.title("💳 Secure FinTech Application")
    st.markdown("Demonstrating secure authentication, encryption, and MongoDB integration.")

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
            **Secure FinTech Application (MongoDB Version)**  
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
