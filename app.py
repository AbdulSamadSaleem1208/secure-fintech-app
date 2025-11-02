# app.py - Pink Luxe FinTech (all logic same; improved connection handling + UI)
import os
import time
import re
import streamlit as st
import bcrypt
from cryptography.fernet import Fernet
from pymongo import MongoClient
from pymongo.errors import ConnectionFailure

# ---------------- page ----------------
st.set_page_config(page_title="FinTech Luxe 💖", page_icon="💖", layout="wide")

# ---------------- style (pink glass) ----------------
st.markdown(
    """
    <style>
    body { background: linear-gradient(120deg, #fff1f6 0%, #ffeef8 100%); font-family: 'Poppins', sans-serif; }
    .block-container { background: rgba(255,255,255,0.85); border-radius: 20px; padding: 2rem 2.5rem; box-shadow: 0 10px 30px rgba(255,105,180,0.12); }
    section[data-testid="stSidebar"] { background: linear-gradient(180deg,#ffd6e8 0%,#ffc9e3 100%); border-right: 1px solid rgba(255,105,180,0.2); }
    h1,h2,h3 { color:#c2185b; text-align:center; font-weight:700; }
    .stButton>button { background: linear-gradient(90deg,#ff66a3,#ff85c1); color:#fff; border-radius:12px; padding: 0.6rem 1.2rem; font-weight:700; }
    .stButton>button:hover { transform: scale(1.03); box-shadow: 0 6px 18px rgba(255, 105, 180, 0.25); }
    input, textarea { border-radius:10px !important; border:2px solid #ffc0d9 !important; background:#fff7fb !important; padding:8px !important; }
    .action-card { background: rgba(255,255,255,0.75); border-radius:16px; padding:1.25rem; box-shadow: 0 6px 20px rgba(255,192,203,0.18); transition:0.22s; text-align:center; }
    .action-card:hover { transform: translateY(-6px); }
    footer { visibility:hidden; }
    </style>
    """,
    unsafe_allow_html=True,
)

# ---------------- config ----------------
KEY_FILE = "secret.key"
LOCKOUT_LIMIT = 5
LOCKOUT_TIME = 300
SESSION_TIMEOUT = 600

# ---------------- encryption key ----------------
def load_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
    return open(KEY_FILE, "rb").read()

fernet = Fernet(load_key())

# ---------------- Mongo connection (robust) ----------------
# Preferred: put full URI in st.secrets as MONGODB_URI, or set env var MONGODB_URI
# Fallback: set MONGODB_PASSWORD in st.secrets or env and the USER/CLUSTER below will be used.
# OPTIONAL: If you want to hardcode a URI for quick testing, paste it in HARD_CODED_URI below (not recommended).
HARD_CODED_URI = None
MONGO_USER_PART = "izzaasifbaloch101_db_user"   # update if you want different DB user
MONGO_CLUSTER_PART = "cluster0.wer7rjt.mongodb.net"
MONGO_DBNAME = "fintech_db"

def get_mongo_uri():
    # 1) full uri from st.secrets
    try:
        if "MONGODB_URI" in st.secrets:
            return st.secrets["MONGODB_URI"]
    except Exception:
        pass
    # 2) full uri from env
    if os.getenv("MONGODB_URI"):
        return os.getenv("MONGODB_URI")
    # 3) password present -> build uri
    try:
        if "MONGODB_PASSWORD" in st.secrets:
            pwd = st.secrets["MONGODB_PASSWORD"]
        else:
            pwd = os.getenv("MONGODB_PASSWORD")
    except Exception:
        pwd = os.getenv("MONGODB_PASSWORD")
    if pwd:
        return f"mongodb+srv://{MONGO_USER_PART}:{pwd}@{MONGO_CLUSTER_PART}/{MONGO_DBNAME}?retryWrites=true&w=majority"
    # 4) final fallback: hard-coded (if you intentionally set it in code)
    if HARD_CODED_URI:
        return HARD_CODED_URI
    return None

MONGO_URI = get_mongo_uri()
if not MONGO_URI:
    st.sidebar.error("🔒 MongoDB URI not configured. Put MONGODB_URI (recommended) or MONGODB_PASSWORD in Streamlit secrets or env.")
    st.stop()

# Attempt connection - show helpful (non-secret) debug info if fail
try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=10000)
    client.admin.command("ping")
    st.sidebar.success("💗 Connected to MongoDB Atlas")
except Exception as e:
    # Provide safe debug hints without exposing credentials
    st.sidebar.error("⚠️ Cannot connect to MongoDB Atlas.")
    st.write("Connection error (safe message):", str(e).splitlines()[0])
    st.write("Debug hints:")
    st.write("- Ensure the URI is correct and placed in Streamlit secrets or environment variable.")
    st.write("- Make sure your IP is whitelisted in Atlas (you can add 0.0.0.0/0 temporarily for testing).")
    st.write("- If you see SSL/TLS errors, update certifi / pymongo / cryptography packages and retry.")
    st.stop()

db = client[MONGO_DBNAME]
users_col = db["users"]
audit_col = db["audit_log"]
pred_col = db["predictions"]

# ---------------- helpers & security ----------------
def log_action(username, action):
    try:
        audit_col.insert_one({"username": username, "action": action, "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")})
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

# ---------------- registration ----------------
def register():
    st.header("🌸 Create Account")
    col1, col2 = st.columns([1,1])
    with col1:
        username = st.text_input("Username", max_chars=50, key="reg_user")
        email = st.text_input("Email", max_chars=100, key="reg_email")
    with col2:
        password = st.text_input("Password", type="password", key="reg_pw")
        confirm = st.text_input("Confirm Password", type="password", key="reg_confirm")
    if st.button("Register ✨"):
        if not valid_input(username, 50):
            st.warning("Invalid username.")
            return
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            st.warning("Invalid email.")
            return
        if password != confirm:
            st.warning("Passwords do not match.")
            return
        if len(password) < 8 or not re.search(r"(?=.*[A-Z])(?=.*[a-z])(?=.*[0-9])(?=.*\W)", password):
            st.warning("Password must include upper, lower, digit, special char.")
            return
        hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
        try:
            if users_col.find_one({"username": username}) or users_col.find_one({"email": email}):
                st.error("Username or email already exists.")
                return
            users_col.insert_one({
                "username": username, "email": email, "password": hashed_pw,
                "failed_attempts": 0, "lockout_until": 0,
                "created_at": time.strftime("%Y-%m-%d %H:%M:%S")
            })
            log_action(username, "User Registered")
            st.success("Registration successful! Please login.")
        except Exception as e:
            st.error("Registration failed. Try again later.")
            log_action("SYSTEM", "Registration error")

# ---------------- login ----------------
def login():
    st.header("💞 Login")
    username = st.text_input("Username", key="login_user")
    password = st.text_input("Password", type="password", key="login_pw")
    if st.button("Login 💫"):
        try:
            user = users_col.find_one({"username": username})
        except Exception:
            st.error("Auth backend error.")
            return
        if not user:
            st.error("Invalid credentials.")
            return
        hashed_pw = user.get("password")
        failed_attempts = user.get("failed_attempts", 0)
        lockout_until = user.get("lockout_until", 0)
        now = time.time()
        if lockout_until and lockout_until > now:
            st.error("Account temporarily locked.")
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
                st.success("Login successful!")
                st.rerun()
            else:
                fa = failed_attempts + 1
                update_data = {"failed_attempts": fa}
                if fa >= LOCKOUT_LIMIT:
                    update_data["lockout_until"] = now + LOCKOUT_TIME
                    st.error("Too many failed attempts. Account locked temporarily.")
                    log_action(username, "Account Locked")
                else:
                    st.error(f"Invalid password. {LOCKOUT_LIMIT - fa} attempts left.")
                users_col.update_one({"username": username}, {"$set": update_data})
        except Exception:
            st.error("Authentication error. Try again later.")
            log_action("SYSTEM", "Auth error")

# ---------------- dashboard & features ----------------
def dashboard():
    check_session_timeout()
    st.header(f"💼 Welcome, {st.session_state.get('username')}")
    st.caption("Pink Luxe - Secure FinTech Dashboard")
    c1, c2, c3 = st.columns(3)
    if c1.button("🧾 View Profile"):
        update_profile()
    if c2.button("🔮 Add Prediction"):
        add_prediction()
    if c3.button("🔐 Encrypt/Decrypt"):
        encryption_demo()
    if c1.button("📂 Upload File", key="u1"):
        upload_file()
    if c2.button("📜 View Logs", key="u2"):
        show_logs()
    if c3.button("🚪 Logout", key="u3"):
        log_action(st.session_state.get("username"), "User Logged Out")
        logout()
        st.info("You have been logged out.")
        st.rerun()

def update_profile():
    st.subheader("Update Email")
    new_email = st.text_input("New Email", key="upd_email")
    if st.button("Update"):
        if not re.match(r"[^@]+@[^@]+\.[^@]+", new_email):
            st.warning("Invalid email format.")
        else:
            users_col.update_one({"username": st.session_state.get("username")}, {"$set": {"email": new_email}})
            log_action(st.session_state.get("username"), "Email Updated")
            st.success("Email updated.")

def add_prediction():
    st.subheader("Save Prediction")
    text = st.text_input("Prediction text", key="pred_text")
    score = st.number_input("Score", value=0.0, step=0.1, key="pred_score")
    if st.button("Save Prediction", key="save_pred"):
        if not is_logged_in():
            st.warning("Please login.")
            return
        pred_col.insert_one({"username": st.session_state.get("username"), "text": text, "score": float(score), "created_at": time.strftime("%Y-%m-%d %H:%M:%S")})
        log_action(st.session_state.get("username"), "Saved Prediction")
        st.success("Prediction saved.")

def encryption_demo():
    st.subheader("Encrypt / Decrypt")
    data = st.text_input("Data to encrypt", key="enc_input")
    if st.button("Encrypt"):
        if data:
            enc = fernet.encrypt(data.encode()).decode()
            st.session_state["last_enc"] = enc
            st.code(enc)
    if st.button("Decrypt"):
        if "last_enc" in st.session_state:
            try:
                dec = fernet.decrypt(st.session_state["last_enc"].encode()).decode()
                st.code(dec)
            except Exception:
                st.error("Decryption failed.")

def upload_file():
    st.subheader("Upload file (.csv .txt .pdf)")
    file = st.file_uploader("", type=["csv", "txt", "pdf"])
    if file:
        st.success(f"Uploaded {file.name}")
        log_action(st.session_state.get("username"), f"Uploaded file: {file.name}")

def show_logs():
    st.subheader("Activity Logs")
    try:
        logs = audit_col.find().sort("_id", -1).limit(100)
        for l in logs:
            st.write(f"{l.get('timestamp')} | {l.get('username')} | {l.get('action')}")
    except Exception:
        st.error("Could not load logs.")

# ---------------- main ----------------
def main():
    st.title("💖 FinTech Luxe")
    menu = ["Login", "Register", "About"]
    choice = st.sidebar.selectbox("Menu", menu)
    # connection hint
    st.sidebar.caption("Connection: using MONGODB_URI (preferred). Edit in Streamlit Secrets or env.")
    if choice == "Login":
        if is_logged_in(): dashboard()
        else: login()
    elif choice == "Register":
        register()
    elif choice == "About":
        st.info("FinTech Luxe — stylish pink UI with the same secure backend logic.")

if __name__ == "__main__":
    main()
