import streamlit as st
import hashlib
import json
import os
from cryptography.fernet import Fernet

# Constants
DATA_FILE = "secure_data.json"
KEY = Fernet.generate_key()
cipher = Fernet(KEY)

# Initialize or load stored data
if os.path.exists(DATA_FILE):
    with open(DATA_FILE, "r") as f:
        stored_data = json.load(f)
else:
    stored_data = {}

# Session state for failed attempts
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0


def hash_passkey(passkey):
    return hashlib.sha256(passkey.encode()).hexdigest()


def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()


def decrypt_data(encrypted_text, passkey):
    hashed_passkey = hash_passkey(passkey)
    for data in stored_data.values():
        if data["encrypted_text"] == encrypted_text and data["passkey"] == hashed_passkey:
            st.session_state.failed_attempts = 0
            return cipher.decrypt(encrypted_text.encode()).decode()
    st.session_state.failed_attempts += 1
    return None


def save_data():
    with open(DATA_FILE, "w") as f:
        json.dump(stored_data, f)


# Streamlit UI
st.title("🔐 Secure Data Encryption System")

menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Menu", menu)

if choice == "Home":
    st.subheader("Welcome!")
    st.write("Securely store and retrieve your text using encryption and a secret passkey.")

elif choice == "Store Data":
    st.subheader("📥 Store Encrypted Data")
    text = st.text_area("Enter text:")
    passkey = st.text_input("Enter passkey:", type="password")

    if st.button("Encrypt & Save"):
        if text and passkey:
            encrypted = encrypt_data(text)
            hashed = hash_passkey(passkey)
            stored_data[encrypted] = {
                "encrypted_text": encrypted,
                "passkey": hashed
            }
            save_data()
            st.success("Data encrypted and saved!")
        else:
            st.warning("Please enter both text and passkey.")

elif choice == "Retrieve Data":
    st.subheader("🔎 Retrieve Your Data")

    if st.session_state.failed_attempts >= 3:
        st.warning("Too many failed attempts. Please login again.")
        st.switch_page("Login")  # Optional: you can use rerun instead
    else:
        encrypted_input = st.text_area("Enter Encrypted Text:")
        passkey = st.text_input("Enter Passkey:", type="password")

        if st.button("Decrypt"):
            if encrypted_input and passkey:
                result = decrypt_data(encrypted_input, passkey)
                if result:
                    st.success(f"Decrypted Text: {result}")
                else:
                    st.error(f"Incorrect passkey! Attempts left: {3 - st.session_state.failed_attempts}")
            else:
                st.warning("Please provide all fields.")

elif choice == "Login":
    st.subheader("🔐 Reauthorize Access")
    login_pass = st.text_input("Enter Master Password:", type="password")

    if st.button("Login"):
        if login_pass == "admin123":
            st.session_state.failed_attempts = 0
            st.success("Logged in successfully. Try retrieving data again.")
        else:
            st.error("Incorrect master password.")

