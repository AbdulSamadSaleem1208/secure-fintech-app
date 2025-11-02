# app.py
import os
import time
import re
import streamlit as st
import bcrypt
from cryptography.fernet import Fernet
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure

# -------------------- CONFIG --------------------
KEY_FILE = "secret.key"
LOCKOUT_LIMIT = 5
LOCKOUT_TIME = 300   # seconds (5 minutes)
SESSION_TIMEOUT = 600  # seconds (10 minutes)

st.set_page_config(page_title="Secure FinTech App", page_icon="💳", layout="centered")

# -------------------- ENCRYPTION KEY --------------------
def load_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    return open(KEY_FILE, "rb").read()

fernet = Fernet(load_key())

# -------------------- MONGO / SECRETS --------------------
# Replace USER and CLUSTER with your values (these are non-secret)
MONGO_USER = "abdulsamadsaleem1208_db_user"
MONGO_CLUSTER = "cluster0.qkvquvb.mongodb.net"
MONGO_DBNAME = "fintech_db"   # as you confirmed

def get_mongo_password():
    # Prefer Streamlit secrets
    try:
        if "MONGODB_PASSWORD" in st.secrets:
            return st.secrets["MONGODB_PASSWORD"]
    except Exception:
        pass
    # Fallback to environment variable for local dev
    return os.getenv("MONGODB_PASSWORD")

MONGO_PWD = get_mongo_password()
if not MONGO_PWD:
    st.error("🔒 MongoDB password not found. Set MONGODB_PASSWORD in Streamlit secrets (recommended) or as an environment variable for local testing.")
    st.stop()

# Build connection string including DB name
MONGO_URI = f"mongodb+srv://{MONGO_USER}:{MONGO_PWD}@{MONGO_CLUSTER}/{MONGO_DBNAME}?retryWrites=true&w=majority"

# Attempt connection
try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=8000)
    client.admin.command("ping")
    st.sidebar.success("✅ Connected to MongoDB Atlas")
except ConnectionFailure as e:
    st.sidebar.error("⚠️ Cannot connect to MongoDB Atlas. Check your secrets and IP Access List.")
    st.write("Connection error:", str(e))
    st.stop()

# Collections
db = client[MONGO_DBNAME]
users_col = db["users"]
audit_col = db["audit_log"]
pred_col = db["predictions"]  # optional predictions collection

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
    return st.session_state.get("logged_in", False)

def check_session_timeout():
    if "last_activity" in st.session_state:
        if time.time() - st.session_state["last_activity"] > SESSION_TIMEOUT:
            logout()
            st.warning("⏰ Session expired. Please log in again.")
            st.rerun()
    st.session_state["last_activity"] = time.time()

def logout():
    for k in list(st.session_state.keys()):
        del st.session_state[k]

# -------------------- REGISTRATION --------------------
def register():
    st.subheader("🔐 Register New Account")
    username = st.text_input("Username (max 50 chars)", max_chars=50, key="reg_username")
    email = st.text_input("Email (max 100 chars)", max_chars=100, key="reg_email")
    password = st.text_input("Password", type="password", key="reg_password")
    confirm = st.text_input("Confirm Password", type="password", key="reg_confirm")

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

        hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

        try:
            if users_col.find_one({"username": username}) or users_col.find_one({"email": email}):
                st.error("Username or Email already exists.")
                return

            users_col.insert_one({
                "username": username,
                "email": email,
                "password": hashed_pw,
                "failed_attempts": 0,
                "lockout_until": 0,
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
            })
            log_action(username, "User Registered")
            st.success("✅ Registration successful! Please go to Login page.")
        except Exception as e:
            st.error("⚠️ Registration failed. Try again later.")
            log_action("SYSTEM", f"Registration error: {str(e)}")

# -------------------- LOGIN --------------------
def login():
    st.subheader("🔑 Login to Your Account")
    username = st.text_input("Username", key="login_username")
    password = st.text_input("Password", type="password", key="login_password")

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

        hashed_pw = user.get("password")
        failed_attempts = user.get("failed_attempts", 0)
        lockout_until = user.get("lockout_until", 0)
        now = time.time()

        if lockout_until and lockout_until > now:
            st.error("Account locked. Try again later.")
            return

        try:
            if isinstance(hashed_pw, str):
                hashed_pw = hashed_pw.encode("utf-8")

            if bcrypt.checkpw(password.encode("utf-8"), hashed_pw):
                users_col.update_one({"username": username}, {"$set": {"failed_attempts": 0, "lockout_until": 0}})
                st.session_state["logged_in"] = True
                st.session_state["username"] = username
                st.session_state["last_activity"] = time.time()
                log_action(username, "User Logged In")
                st.success("✅ Login successful!")
                st.rerun()
            else:
                fa = failed_attempts + 1
                update_data = {"failed_attempts": fa}
                if fa >= LOCKOUT_LIMIT:
                    update_data["lockout_until"] = now + LOCKOUT_TIME
                    st.error("🚫 Too many failed attempts. Account temporarily locked.")
                    log_action(username, "Account Locked After Failed Attempts")
                else:
                    st.error(f"Invalid password. {LOCKOUT_LIMIT - fa} attempts left.")
                users_col.update_one({"username": username}, {"$set": update_data})
        except Exception as e:
            st.error("⚠️ Authentication failed. Try again later.")
            log_action("SYSTEM", f"Auth error: {str(e)}")

# -------------------- DASHBOARD --------------------
def dashboard():
    check_session_timeout()
    st.subheader(f"💼 Welcome, {st.session_state.get('username')}")
    st.write("This is your secure FinTech dashboard.")

    choice = st.selectbox("Choose an action:", ["View Profile", "Add Prediction", "Encrypt/Decrypt Data", "Upload File", "View Audit Log", "Logout"], key="dashboard_choice")

    if choice == "View Profile":
        update_profile()
    elif choice == "Add Prediction":
        add_prediction()
    elif choice == "Encrypt/Decrypt Data":
        encryption_demo()
    elif choice == "Upload File":
        upload_file()
    elif choice == "View Audit Log":
        show_logs()
    elif choice == "Logout":
        log_action(st.session_state.get("username"), "User Logged Out")
        logout()
        st.info("You have been logged out.")
        st.rerun()

# -------------------- PROFILE --------------------
def update_profile():
    st.write("### 🧾 Update Profile Info")
    new_email = st.text_input("New Email", key="new_email")
    if st.button("Update Email"):
        if not re.match(r"[^@]+@[^@]+\.[^@]+", new_email):
            st.warning("Invalid email format.")
        else:
            try:
                users_col.update_one({"username": st.session_state.get("username")}, {"$set": {"email": new_email}})
                log_action(st.session_state.get("username"), "Email Updated")
                st.success("✅ Email updated successfully!")
            except Exception:
                st.error("⚠️ Could not update email. Try again later.")

# -------------------- PREDICTIONS --------------------
def add_prediction():
    st.write("### 🧠 Save a Prediction (example)")
    pred_text = st.text_input("Prediction/result", key="pred_text")
    pred_value = st.number_input("Score", value=0.0, step=0.1, key="pred_score")
    if st.button("Save Prediction"):
        if not is_logged_in():
            st.warning("Please login first.")
            return
        try:
            pred_doc = {
                "username": st.session_state.get("username"),
                "text": pred_text,
                "score": float(pred_value),
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
            }
            pred_col.insert_one(pred_doc)
            log_action(st.session_state.get("username"), "Saved Prediction")
            st.success("✅ Prediction saved.")
        except Exception as e:
            st.error("⚠️ Could not save prediction.")
            log_action("SYSTEM", f"Prediction save error: {str(e)}")

# -------------------- ENCRYPTION DEMO --------------------
def encryption_demo():
    st.write("### 🔐 Data Encryption / Decryption")
    data = st.text_input("Enter data to encrypt:", key="enc_input")
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
    uploaded_file = st.file_uploader("Upload file (.csv, .txt, .pdf only)", type=["csv", "txt", "pdf"], key="upload")
    if uploaded_file:
        st.success(f"✅ File '{uploaded_file.name}' uploaded successfully.")
        log_action(st.session_state.get("username"), f"Uploaded file: {uploaded_file.name}")

# -------------------- AUDIT LOG --------------------
def show_logs():
    st.write("### 📜 User Activity Logs")
    try:
        logs = audit_col.find().sort("_id", -1).limit(200)
        for l in logs:
            st.text(f"{l.get('timestamp')} | {l.get('username')} | {l.get('action')}")
    except Exception:
        st.error("⚠️ Could not load logs.")

# -------------------- MAIN --------------------
def main():
    st.title("💳 Secure FinTech Application")
    st.markdown("Demonstrating secure authentication, encryption, and example predictions storage.")

    menu = ["Login", "Register", "About"]
    choice = st.sidebar.selectbox("Menu", menu, key="main_menu")

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
            **Secure FinTech Application (MongoDB Atlas version)**  
            - MongoDB Cloud database ✅  
            - SQL Injection protection ✅  
            - Password & email validation ✅  
            - Session timeout (10 min) ✅  
            - Login lockout (5 fails) ✅  
            - File upload validation ✅  
            - Encryption (Fernet) ✅  
            - Audit logs & predictions ✅  
            """)
    except Exception as e:
        st.error("⚠️ A controlled error occurred. Sensitive details are hidden for security.")
        log_action("SYSTEM", f"Error: {str(e)}")

if __name__ == "__main__":
    main()
