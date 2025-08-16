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

def find_client_secret_file2() -> Union[str, None]:
    from setup_wizard import update_body

    pattern = re.compile(r"client_secret_([\w\-]+)\.apps\.googleusercontent\.com\.json")
    candidates = []
    errors = []

    for fname in os.listdir(CREDENTIALS_DIR):
        # Only consider files that match the expected pattern
        m = pattern.fullmatch(fname)
        if not m:
            continue

        full_path = os.path.join(CREDENTIALS_DIR, fname)
        candidates.append(full_path)
        try:
            with open(full_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            container = data.get("installed") or data.get("web")
            if not container:
                errors.append((full_path, "missing 'installed' or 'web' container"))
                continue

            client_id_from_filename = m.group(1)
            client_id_in_file = container.get("client_id", "")
            if client_id_from_filename in client_id_in_file:
                print(f"✅ Valid client secret found: {fname}")
                return full_path
            else:
                errors.append((full_path, f"client_id mismatch: {client_id_in_file}"))
        except Exception as e:
            errors.append((full_path, f"read/parse error: {e}"))

    # Nothing valid — show one consolidated error, not per-file spam
    msgs = [
        "❌ Client secret file could not be found.",
        f"❌ No valid client secret file found in {CREDENTIALS_DIR}.",
        f"Candidates checked: {candidates}" if candidates else "No candidates matched the expected filename pattern."
    ]
    if errors:
        msgs.append("Errors:")
        msgs += [f"• {p}: {err}" for p, err in errors]

    update_body([urwid.Text(m) for m in msgs] + [
        urwid.Divider(),
        urwid.AttrMap(urwid.Button("Retry", on_press=lambda btn: find_client_secret_file()), None, 'reversed')
    ])
    return None

CLIENT_SECRET_FILE = find_client_secret_file2()

# secure_store.py (or a paths module)
def slug(value: str) -> str:
    # Replace invalid filename characters with underscores
    return re.sub(r'[^\w\-]', '_', value)

def get_token_plain_path(email: str) -> str:
    return os.path.join(CREDENTIALS_DIR, f"{slug(email)}.token.pickle")

def get_token_encrypted_path(email: str) -> str:
    return os.path.join(CREDENTIALS_DIR, f"{slug(email)}.token.pickle.enc")

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

SALT_LEN = 16  # whatever your legacy used (keep it constant)

def _get_legacy_salt_or_error() -> bytes:
    """
    Decrypt-time helper for v0 (external-salt) files.
    Never creates salt. Fails fast if missing or malformed.
    """
    if not os.path.exists(SALT_FILE):
        raise Exception("❌ Missing legacy salt sidecar for v0 format.")

    with open(SALT_FILE, "rb") as f:
        salt = f.read()

    if len(salt) != SALT_LEN:
        raise Exception(f"❌ Legacy salt sidecar is corrupt (expected {SALT_LEN} bytes, got {len(salt)}).")

    return salt

def _derive_key_pbkdf2(password_bytes: bytes, salt: bytes, iterations: int) -> bytes:
    # your existing _derive_key; ensure it returns urlsafe_b64 Fernet key
    return _derive_key(password_bytes, salt, iterations=iterations)

def _verify_v1_file(p: str, old_pw: str) -> None:
    with open(p, "rb") as f:
        peek = f.read(2)
        if _looks_like_pickle(peek):
            raise Exception(f"❌ The file {p} is plaintext pickle; re-run setup to create a real .enc.")
        head = peek + f.read(11 - len(peek))
        try:
            magic, ver, salt_len, iter_count = struct.unpack(HDR_FMT, head)
        except struct.error as e:
            raise Exception(f"❌ Unrecognized header for {p}: {e}")

        if magic != MAGIC or ver != VER_V1:
            raise DeferPassword("not v1")  # signal to try v0 path below

        if not (1 <= salt_len <= 64):
            raise Exception(f"❌ Corrupt header in {p}: invalid salt_len={salt_len}")
        salt = f.read(salt_len)
        if len(salt) != salt_len:
            raise Exception(f"❌ Truncated salt in {p}")
        ciphertext = f.read()
        key = _derive_key_pbkdf2(old_pw.encode("utf-8"), salt, iterations=iter_count or _current_pbkdf2_iters())
        try:
            Fernet(key).decrypt(ciphertext)
        except InvalidToken:
            raise Exception("❌ Invalid password or file integrity check failed (v1).")

def _verify_v0_file(p: str, old_pw: str) -> None:
    # v0 has no MTUI header; whole file is ciphertext; salt is in sidecar
    ciphertext = open(p, "rb").read()
    salt = _get_legacy_salt_or_error()
    # Try current + legacy iteration counts
    for iters in ( _current_pbkdf2_iters(), *LEGACY_PBKDF2_ITERS ):
        key = _derive_key_pbkdf2(old_pw.encode("utf-8"), salt, iterations=iters)
        try:
            Fernet(key).decrypt(ciphertext)
            return
        except InvalidToken:
            continue
    raise Exception("❌ Invalid password, wrong salt, or KDF mismatch (v0).")

SALT_LEN = 16  # same as above

def _generate_salt() -> bytes:
    return os.urandom(SALT_LEN)

def _get_or_create_legacy_salt_for_encrypt() -> bytes:
    """
    Encrypt-time helper for v0 (external-salt) format.
    Creates the salt if it doesn't exist, atomically, with 0600 perms.
    """
    if os.path.exists(SALT_FILE):
        with open(SALT_FILE, "rb") as f:
            salt = f.read()
        if len(salt) == SALT_LEN:
            return salt
        # Corrupt or wrong size → rebuild safely
        # (Optional: back it up first)
    
    # Create atomically with restrictive perms
    dir_ = os.path.dirname(SALT_FILE) or "."
    os.makedirs(dir_, exist_ok=True)

    # Write to a temp file first
    fd, tmp_path = tempfile.mkstemp(dir=dir_, prefix=".salt.", text=False)
    try:
        os.write(fd, _generate_salt())
        os.fchmod(fd, 0o600)  # owner read/write only
    finally:
        os.close(fd)

    # Atomic replace
    os.replace(tmp_path, SALT_FILE)

    with open(SALT_FILE, "rb") as f:
        salt = f.read()

    if len(salt) != SALT_LEN:
        raise Exception("❌ Failed to create a valid legacy salt sidecar.")

    return salt

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
    salt = _get_or_create_legacy_salt_for_encrypt()
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
    salt = _get_legacy_salt_or_error()
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

def _looks_like_pickle(head: bytes) -> bool:
    # Pickle protocol 4/5 starts with 0x80 0x04/0x05
    return len(head) >= 2 and head[0] == 0x80 and head[1] in (0x04, 0x05)

def decrypt_to_memory(input_path, *, prompt_password=True, password: Union[str, None] = None):
    if not os.path.exists(input_path):
        raise FileNotFoundError(input_path)

    if password is None:
        if not prompt_password:
            raise DeferPassword("Password prompt deferred.")
        password = _get_password().decode('utf-8')

    hdr_len = struct.calcsize(HDR_FMT)  # ← 11 bytes for "!4sBHI"

    with open(input_path, "rb") as f:
        # Quick plaintext-pickle sniff (don’t advance more than needed)
        peek = f.read(2)
        if _looks_like_pickle(peek):
            raise Exception("❌ File is plaintext pickle, not encrypted. Wrong file path or botched setup.")
        # Finish reading the exact header
        head = peek + f.read(hdr_len - len(peek))  # total == hdr_len

        try:
            magic, ver, salt_len, iterations = struct.unpack(HDR_FMT, head)
        except struct.error as e:
            raise Exception(f"❌ Unrecognized header (expected {hdr_len} bytes per {HDR_FMT}): {e}")

        if magic == MAGIC and ver == VER_V1:
            if not (1 <= salt_len <= 64):
                raise Exception("❌ Corrupt file: invalid salt length.")
            salt = f.read(salt_len)
            if len(salt) != salt_len:
                raise Exception("❌ Corrupt file: truncated salt.")
            ciphertext = f.read()
            # PBKDF2 → 32-byte key → urlsafe base64 for Fernet
            key = _derive_key(password.encode('utf-8'), salt, iterations=iterations or _current_pbkdf2_iters())
            try:
                return Fernet(key).decrypt(ciphertext)
            except InvalidToken:
                raise Exception("❌ Invalid password or file integrity check failed.")

        # Only do v0 if the header is not MTUI v1.
        # And critically: do NOT create a new salt during decrypt.
        remaining = f.read()
        salt = _get_legacy_salt_or_error()  # replace _get_or_create_salt()
        for iters in ( _current_pbkdf2_iters(), *LEGACY_PBKDF2_ITERS ):
            try:
                key = _derive_key(password.encode('utf-8'), salt, iterations=iters)
                return Fernet(key).decrypt(head + remaining)
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
        salt = _get_or_create_legacy_salt_for_encrypt()
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
