# -------------------- Libraries --------------------
import streamlit as st
import hashlib
import json
import os
from cryptography.fernet import Fernet
from datetime import datetime, timedelta

# -------------------- File Constants --------------------
USER_DB = "users.json"
DATA_DB = "data.json"

# -------------------- Helpers --------------------
def hash_password(pwd):
    return hashlib.sha256(pwd.encode()).hexdigest()

def load_json(path):
    if os.path.exists(path):
        with open(path, "r") as f:
            return json.load(f)
    return {}

def save_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=4)

def get_cipher(key):
    return Fernet(key.encode())

def generate_key():
    return Fernet.generate_key().decode()

# -------------------- Load Data --------------------
users = load_json(USER_DB)
data = load_json(DATA_DB)

# -------------------- Session Setup --------------------
st.session_state.setdefault("logged_in", False)
st.session_state.setdefault("username", "")
st.session_state.setdefault("failed_attempts", 0)
st.session_state.setdefault("lockout_until", None)

# -------------------- Decrypt Function --------------------
def decrypt_text(enc_text, passkey):
    user = st.session_state.username
    hashed = hash_password(passkey)

    if enc_text in data[user] and data[user][enc_text]["passkey"] == hashed:
        key = users[user]["key"]
        cipher = get_cipher(key)
        st.session_state.failed_attempts = 0
        return cipher.decrypt(enc_text.encode()).decode()
    
    st.session_state.failed_attempts += 1
    if st.session_state.failed_attempts >= 3:
        st.session_state.lockout_until = datetime.now() + timedelta(seconds=30)
    return None

# -------------------- Auth Pages --------------------
if not st.session_state.logged_in:
    st.title("🔐 Login System")
    tabs = st.tabs(["Login", "Sign Up"])

    # Sign Up
    with tabs[1]:
        st.subheader("🧾 Create Account")
        new_user = st.text_input("New Username")
        new_pass = st.text_input("New Password", type="password")
        if st.button("Register"):
            if new_user in users:
                st.error("Username already exists.")
            elif len(new_pass) < 8:
                st.error("Password must be at least 8 characters.")
            else:
                key = generate_key()
                users[new_user] = {"password": hash_password(new_pass), "key": key}
                data[new_user] = {}
                save_json(USER_DB, users)
                save_json(DATA_DB, data)
                st.success("Account created! Please log in.")

    # Login
    with tabs[0]:
        st.subheader("🔐 Login")
        user = st.text_input("Username")
        pwd = st.text_input("Password", type="password")
        if st.button("Login"):
            if user in users and users[user]["password"] == hash_password(pwd):
                st.session_state.logged_in = True
                st.session_state.username = user
                st.success("Logged in successfully!")
                st.rerun()
            else:
                st.error("Invalid credentials.")

# -------------------- Main App --------------------
else:
    st.title(f"🛡️ Welcome, {st.session_state.username}")
    menu = st.sidebar.selectbox("Menu", ["Home", "Store Data", "Retrieve Data", "Download", "Logout"])

    if menu == "Logout":
        st.session_state.logged_in = False
        st.session_state.username = ""
        st.rerun()

    elif menu == "Home":
        st.info("Use the sidebar to encrypt/decrypt your data.")

    elif menu == "Store Data":
        st.subheader("🔐 Store Encrypted Data")
        text = st.text_area("Enter data")
        passkey = st.text_input("Create passkey", type="password")
        if st.button("Encrypt & Save"):
            if text and passkey:
                user = st.session_state.username
                key = users[user]["key"]
                cipher = get_cipher(key)
                encrypted = cipher.encrypt(text.encode()).decode()
                data[user][encrypted] = {
                    "passkey": hash_password(passkey),
                    "timestamp": datetime.now().isoformat()
                }
                save_json(DATA_DB, data)
                st.success("Data saved!")
                st.code(encrypted)
            else:
                st.error("All fields are required.")

    elif menu == "Retrieve Data":
        st.subheader("🔍 Decrypt Data")
        user_data = data.get(st.session_state.username, {})
        if user_data:
            options = list(user_data.keys())
            selected = st.selectbox("Select entry", options)
            passkey = st.text_input("Enter passkey", type="password")
            if st.button("Decrypt"):
                if st.session_state.lockout_until and datetime.now() < st.session_state.lockout_until:
                    wait = (st.session_state.lockout_until - datetime.now()).seconds
                    st.error(f"Too many attempts. Try again in {wait} seconds.")
                else:
                    result = decrypt_text(selected, passkey)
                    if result:
                        st.success("Success!")
                        st.text_area("Decrypted Text", result)
                    else:
                        st.error("Incorrect passkey.")
        else:
            st.info("No data found.")

    elif menu == "Download":
        st.subheader("📥 Download Data")
        user_data = data.get(st.session_state.username, {})
        if user_data:
            json_text = json.dumps(user_data, indent=4)
            st.download_button("Download JSON", data=json_text, file_name=f"{st.session_state.username}_data.json", mime="application/json")
        else:
            st.info("No data to download.")
