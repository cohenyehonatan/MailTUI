# secure_store.py

import os
import base64
import json
import hashlib
import getpass

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken

# === CONFIG ===
SALT_FILE = "credentials/.salt"
ITERATIONS = 100_000
ENC_EXT = ".enc"

def _get_password(confirm_if_new=True):
    salt_exists = os.path.exists(SALT_FILE)
    pw = getpass.getpass("🔑 Enter encryption password: ").encode()

    if confirm_if_new and not salt_exists:
        confirm = getpass.getpass("🔁 Confirm password: ").encode()
        if pw != confirm:
            raise ValueError("❌ Passwords do not match. Aborting.")
    return pw

def _generate_salt():
    return os.urandom(16)

def _get_or_create_salt():
    if not os.path.exists(SALT_FILE):
        with open(SALT_FILE, "wb") as f:
            salt = _generate_salt()
            f.write(salt)
            return salt
    with open(SALT_FILE, "rb") as f:
        return f.read()

def _derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(password))

def encrypt_file(input_path, output_path=None):
    password = _get_password()
    salt = _get_or_create_salt()
    key = _derive_key(password, salt)
    fernet = Fernet(key)

    with open(input_path, "rb") as f:
        plaintext = f.read()

    ciphertext = fernet.encrypt(plaintext)

    if not output_path:
        output_path = input_path + ENC_EXT

    with open(output_path, "wb") as f:
        f.write(ciphertext)

    print(f"✅ Encrypted {input_path} → {output_path}")

def decrypt_file(input_path, output_path=None):
    password = _get_password()
    salt = _get_or_create_salt()
    key = _derive_key(password, salt)
    fernet = Fernet(key)

    with open(input_path, "rb") as f:
        ciphertext = f.read()

    try:
        plaintext = fernet.decrypt(ciphertext)
    except InvalidToken:
        raise Exception("❌ Invalid password or file integrity check failed.")

    if not output_path:
        output_path = input_path.replace(ENC_EXT, "")

    with open(output_path, "wb") as f:
        f.write(plaintext)

    print(f"✅ Decrypted {input_path} → {output_path}")
    return plaintext

def decrypt_to_memory(input_path):
    password = _get_password()
    salt = _get_or_create_salt()
    key = _derive_key(password, salt)
    fernet = Fernet(key)

    with open(input_path, "rb") as f:
        ciphertext = f.read()

    try:
        return fernet.decrypt(ciphertext)
    except InvalidToken:
        raise Exception("❌ Invalid password or file integrity check failed.")
