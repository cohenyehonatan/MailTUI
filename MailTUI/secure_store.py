# secure_store.py

import os
import re
import base64
import json
import hashlib
import getpass
import traceback
import urwid
import tempfile
import struct
import unicodedata
import termios

from typing import Union
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken

# === CONFIG ===
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CREDENTIALS_DIR = os.path.join(BASE_DIR, "..", "credentials")

if not os.path.exists(CREDENTIALS_DIR):
    os.makedirs(CREDENTIALS_DIR, mode=0o700)

SALT_FILE = os.path.join(CREDENTIALS_DIR, ".salt")
ITERATIONS = 100_000
ENC_EXT = ".enc"

__all__ = ["encrypt_file", "decrypt_file", "decrypt_to_memory", "CLIENT_SECRET_FILE"]

MAGIC = b"MTUI"      # 4
VER_V1 = 1           # 1
HDR_FMT = "!4sBHI"   # MAGIC(4), ver(1), salt_len(2), iter_count(4)  -> total 11 bytes

LEGACY_PBKDF2_ITERS = (
    100_000,   # common old default
    130_000,   # random projects use this
    200_000,   # you might have bumped to this
    300_000,   # and/or this
)

class DeferPassword(Exception):
    pass

def find_client_secret_file():
    from setup_wizard import update_body
    pattern = re.compile(r"client_secret_([\w\-]+)\.apps\.googleusercontent\.com\.json")
    found_files = []

    for fname in os.listdir(CREDENTIALS_DIR):
        print(f"🔍 Checking file: {fname}")
        match = pattern.fullmatch(fname)
        if not match:
            update_body(urwid.Pile([
                urwid.Text("❌ Client secret file could not be found."),
                urwid.Text(f"⛔ Filename '{fname}' doesn't match expected pattern."),
                urwid.Divider(),
                urwid.Text("Traceback:"),
                urwid.Text(traceback.format_exc()),
                urwid.Divider(),
                urwid.AttrMap(urwid.Button("Retry", on_press=lambda btn: find_client_secret_file()), None, focus_map='reversed'),
            ]))
            continue

        client_id_from_filename = match.group(1)
        full_path = os.path.join(CREDENTIALS_DIR, fname)
        found_files.append(full_path)

        try:
            with open(full_path) as f:
                data = json.load(f)

                container = data.get("installed") or data.get("web")
                if not container:
                    print(f"⛔ Missing 'installed' or 'web' container.")
                    continue

                client_id_in_file = container.get("client_id", "")
                if client_id_from_filename in client_id_in_file:
                    print(f"✅ Valid client secret found: {fname}")
                    return full_path
                else:
                    update_body(urwid.Pile([
                        urwid.Text("❌ Client secret file could not be found."),
                        urwid.Text(f"⛔ Client ID {client_id_in_file} in file {full_path} doesn't match filename."),
                        urwid.Divider(),
                        urwid.Text("Traceback:"),
                        urwid.Text(traceback.format_exc()),
                        urwid.Divider(),
                        urwid.AttrMap(urwid.Button("Retry", on_press=lambda btn: find_client_secret_file()), None, focus_map='reversed'),
                    ]))

        except Exception as e:
            update_body(urwid.Pile([
                urwid.Text("❌ Client secret file could not be found."),
                urwid.Text(f"⚠️ Skipping {fname} due to error: {e}"),
                urwid.Divider(),
                urwid.Text("Traceback:"),
                urwid.Text(traceback.format_exc()),
                urwid.Divider(),
                urwid.AttrMap(urwid.Button("Retry", on_press=lambda btn: find_client_secret_file()), None, focus_map='reversed'),
            ]))
            continue

    update_body(urwid.Pile([
        urwid.Text("❌ Client secret file could not be found."),
        urwid.Text(f"❌ No valid client secret file found in {CREDENTIALS_DIR}. Candidates checked: {found_files}"),
        urwid.Divider(),
        urwid.Text("Traceback:"),
        urwid.Text(traceback.format_exc()),
        urwid.Divider(),
        urwid.AttrMap(urwid.Button("Retry", on_press=lambda btn: find_client_secret_file()), None, focus_map='reversed'),
    ]))
    return [os.path.join(CREDENTIALS_DIR, fname) for fname in os.listdir(CREDENTIALS_DIR)]

CLIENT_SECRET_FILE = find_client_secret_file()

def get_token_path():
    from secure_store import CLIENT_SECRET_FILE, CREDENTIALS_DIR
    if CLIENT_SECRET_FILE:
        # # Use filename stem as token ID
        # basename = os.path.splitext(os.path.basename(CLIENT_SECRET_FILE))[0]
        # return os.path.join(CREDENTIALS_DIR, f"{basename}.token.pickle")
        if isinstance(CLIENT_SECRET_FILE, str):
            name = os.path.splitext(os.path.basename(CLIENT_SECRET_FILE))[0]
        else:
            raise TypeError("CLIENT_SECRET_FILE must be a string.")
        return os.path.join(CREDENTIALS_DIR, f"{name}.token.pickle")
    else:
        # Fallback default
        return os.path.join(CREDENTIALS_DIR, "token.pickle")

def _normalize_pw(s: str) -> str:
    s = s.replace("\r", "").replace("\n", "")
    return unicodedata.normalize("NFC", s)

def _prompt_tty(prompt: str) -> str:
    # Always use the real terminal. Also flush any junk bytes first.
    with open("/dev/tty", "r+") as tty:
        try:
            termios.tcflush(tty.fileno(), termios.TCIFLUSH)  # drop pending input
        except Exception:
            pass
        return getpass.getpass(prompt, stream=tty)

def _get_password(confirm_if_new=True, always_confirm=False):
    salt_exists = os.path.exists(SALT_FILE)

    # Try to pause urwid cleanly if a loop exists.
    loop = None
    try:
        from setup_wizard import STATE
        loop = STATE.get("loop")
    except Exception:
        pass

    if loop:
        try: loop.screen.stop()
        except Exception: pass

    try:
        pw_str = _normalize_pw(_prompt_tty("🔑 Enter encryption password: "))
        need_confirm = always_confirm or (confirm_if_new and not salt_exists)
        if need_confirm:
            confirm_str = _normalize_pw(_prompt_tty("🔁 Confirm password: "))
            if pw_str != confirm_str:
                raise ValueError("❌ Passwords do not match. Aborting.")
    finally:
        if loop:
            try: loop.screen.start()  # put urwid back
            except Exception: pass

    return pw_str.encode("utf-8")

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

def _derive_key(password: bytes, salt: bytes, iterations: int = 300_000) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    return base64.urlsafe_b64encode(kdf.derive(password))

def encrypt_file(input_path, output_path=None):
    password = _get_password().decode('utf-8')
    salt = _get_or_create_salt()
    key = _derive_key(password.encode('utf-8'), salt)
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
    password = _get_password().decode('utf-8')
    salt = _get_or_create_salt()
    key = _derive_key(password.encode('utf-8'), salt)
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

def _current_pbkdf2_iters() -> int:
    # whatever your current default is inside _derive_key
    return 300_000  # <-- set this to YOUR real current value

def decrypt_to_memory(input_path, *, prompt_password=True, password: Union[str, None] = None):
    if not os.path.exists(input_path):
        raise FileNotFoundError(input_path)

    if password is None:
        if not prompt_password:
            raise DeferPassword("Password prompt deferred.")
        password = _get_password().decode('utf-8')

    with open(input_path, "rb") as f:
        head = f.read(11)
        magic, ver, salt_len, iterations = None, None, None, None
        try:
            magic, ver, salt_len, iterations = struct.unpack(HDR_FMT, head)
        except struct.error:
            magic = None

        if magic == MAGIC and ver == VER_V1:
            salt = f.read(salt_len)
            ciphertext = f.read()
            key = _derive_key(password.encode('utf-8'), salt, iterations=iterations or _current_pbkdf2_iters())
            try:
                return Fernet(key).decrypt(ciphertext)
            except InvalidToken:
                raise Exception("❌ Invalid password or file integrity check failed.")

        # v0 fallback (external salt; unknown iters)
        blob = head + f.read()
        salt = _get_or_create_salt()
        candidates = (_current_pbkdf2_iters(),) + LEGACY_PBKDF2_ITERS
        tried = set()
        for iters in candidates:
            if iters in tried: continue
            tried.add(iters)
            try:
                key = _derive_key(password.encode('utf-8'), salt, iterations=iters)
                return Fernet(key).decrypt(blob)
            except InvalidToken:
                continue
        raise Exception("❌ Invalid password, wrong salt, or KDF mismatch.")

    

def _write_atomic(path, data: bytes):
    d = os.path.dirname(os.path.abspath(path)) or "."
    fd, tmp = tempfile.mkstemp(prefix=".mtui.", suffix=".tmp", dir=d)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass

def encrypt_bytes_to_file(plaintext: bytes, output_path: str, *, password: str, iterations: int = 200_000, embed_salt=True) -> None:
    if not isinstance(plaintext, (bytes, bytearray)):
        raise TypeError("plaintext must be bytes")

    # Always use a fresh random salt for v1
    if embed_salt:
        salt = os.urandom(16)
        key = _derive_key(password.encode('utf-8'), salt, iterations=iterations)
        f = Fernet(key)
        ct = f.encrypt(plaintext)
        hdr = struct.pack(HDR_FMT, MAGIC, VER_V1, len(salt), iterations) + salt
        data = hdr + ct
        _write_atomic(output_path, data)
    else:
        # legacy: external salt file
        salt = _get_or_create_salt()
        key = _derive_key(password.encode('utf-8'), salt)
        f = Fernet(key)
        _write_atomic(output_path, f.encrypt(plaintext))


def reencrypt_files(paths: list[str], *, old_password: str, new_password: str) -> list[tuple[str, str]]:
    """
    v0+v1 aware: decrypt first; if any fail, return errors. Then write all as v1 (embedded).
    """
    decrypted: dict[str, bytes] = {}
    errs: list[tuple[str,str]] = []

    # Phase 1: decrypt all (accept both formats)
    for p in paths:
        try:
            pt = decrypt_to_memory(p, prompt_password=False, password=old_password)
            decrypted[p] = pt
        except Exception as e:
            errs.append((p, f"error: {e}"))

    if errs:
        return errs

    # Phase 2: re-encrypt all to v1 (embedded salt, fresh params)
    results: list[tuple[str,str]] = []
    for p, pt in decrypted.items():
        try:
            encrypt_bytes_to_file(pt, p, password=new_password, iterations=300_000, embed_salt=True)
            results.append((p, "ok"))
        except Exception as e:
            results.append((p, f"error: {e}"))
    return results
