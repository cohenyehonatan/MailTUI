# main.py

import logging
import os
import sys
import pickle
import re
import getpass

from MailTUI.setup_wizard import EMAIL_REGEX
from auth import get_gmail_service
from ui import EmailApp
from mail_api import get_email_client
from auth import authenticate
from mailtui_profile import load_profiles, get_profile, save_profile, debug_log
from typing import List, Union

logging.basicConfig(filename='MailTUI.log',level=logging.DEBUG)
log = logging.getLogger(__name__)

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "tests")))

def token_is_valid(token_file):
    if not token_file:
        return False
    if os.path.exists(token_file):
        with open(token_file, 'rb') as token:
            creds = pickle.load(token)
            return creds and creds.valid
    return False


def _collect_encrypted_assets(profiles) -> list[str]:
    paths = set()

    # 1) profile tokens
    for _, prof in (profiles.get('users') or {}).items():
        tf = (prof or {}).get("token_file")
        if isinstance(tf, str) and tf.endswith(".enc") and os.path.exists(tf):
            paths.add(os.path.abspath(tf))

    # 2) orphan tokens in credentials dir
    from secure_store import CREDENTIALS_DIR
    for fname in os.listdir(CREDENTIALS_DIR):
        if fname.endswith(".token.pickle.enc"):
            paths.add(os.path.abspath(os.path.join(CREDENTIALS_DIR, fname)))

    # 3) encrypted client secret (optional)
    try:
        from secure_store import CLIENT_SECRET_FILE
        if isinstance(CLIENT_SECRET_FILE, str):
            enc_secret = f"{CLIENT_SECRET_FILE}.enc"
            if os.path.exists(enc_secret):
                paths.add(os.path.abspath(enc_secret))
    except Exception:
        pass

    return sorted(paths)


def _prompt_new_password_twice() -> Union[str, None]:
    """Ask for a new password twice; return it or None if mismatch/weak."""
    pw1 = getpass.getpass("Enter NEW encryption password: ")
    pw2 = getpass.getpass("Re-enter NEW encryption password: ")
    if pw1 != pw2:
        print("❌ Passwords do not match.")
        return None
    # naive strength check; tune as you like
    if len(pw1) < 8:
        print("❌ Password too short (min 8).")
        return None
    return pw1

def handle_reset_password(profiles) -> None:
    """Interactive flow for 'r' — reset encryption password for all assets."""
    targets = _collect_encrypted_assets(profiles)
    if not targets:
        print("ℹ️  No encrypted assets found to re-encrypt.")
        return

    # List targets and formats first
    print("You are about to re-encrypt the following files:")
    for p in targets:
        print(f"  • {p}  [{_detect_cipher_format(p)}]")

    confirm = input("Proceed? (y/N): ").strip().lower()
    if confirm != 'y':
        print("❎ Cancelled.")
        return

    # 1) Ask for CURRENT password before dry-run
    old_pw = getpass.getpass("Enter CURRENT encryption password: ")

    # 2) Dry-run: verify we can decrypt everything with old_pw
    print("🔍 Dry-run: verifying current password against all targets...")
    probe_errs = []
    from secure_store import decrypt_to_memory
    try:
        from secure_store import DeferPassword  # optional if you've defined it
    except Exception:
        DeferPassword = type("DeferPassword", (Exception,), {})

    for p in targets:
        try:
            # Preferred path: modern API that accepts password=
            _ = decrypt_to_memory(p, prompt_password=False, password=old_pw)
        except DeferPassword:
            # Fallback for legacy behavior where decrypt_to_memory refuses passwordless calls
            try:
                from secure_store import _get_or_create_salt, _derive_key
                from cryptography.fernet import Fernet
                with open(p, "rb") as f:
                    ciphertext = f.read()
                salt = _get_or_create_salt()
                key = _derive_key(old_pw.encode('utf-8'), salt)
                Fernet(key).decrypt(ciphertext)  # raises if wrong
            except Exception as e2:
                probe_errs.append((p, str(e2)))
        except Exception as e:
            probe_errs.append((p, str(e)))

    if probe_errs:
        print("❌ Dry-run failed; nothing changed.")
        for p, msg in probe_errs:
            print("  •", p, "->", msg)
        print("Hint: This can happen if your PBKDF2 iteration count changed since the file was encrypted.")
        print("      Add a compat shim (try old iteration counts) or re-create the token.")
        print("Tip: If format is v0 (external salt), make sure the original salt file is present.")
        print("If the salt is gone, you’ll need to re-run OAuth to mint new tokens.")
        return

    # 3) Ask for NEW password and confirm
    new_pw = _prompt_new_password_twice()
    if not new_pw:
        return

    # 4) Re-encrypt
    try:
        from secure_store import reencrypt_files
    except ImportError:
        print("❌ secure_store.reencrypt_files() not found. Did you add the helper?")
        return

    results = reencrypt_files(targets, old_password=old_pw, new_password=new_pw)

    ok = [p for p, r in results if r == "ok"]
    err = [(p, r) for p, r in results if not r.startswith("ok")]

    if ok:
        print("✅ Re-encrypted:")
        for p in ok:
            print("  •", p)

    if err:
        print("⚠️  Some files failed:")
        for p, r in err:
            print(f"  • {p}: {r}")
    else:
        print("🎉 Done. All encrypted assets now use your new password.")

def _detect_cipher_format(path: str) -> str:
    try:
        with open(path, "rb") as f:
            head = f.read(11)
        import struct
        MAGIC = b"MTUI"
        HDR_FMT = "!4sBHI"
        try:
            magic, ver, salt_len, iterations = struct.unpack(HDR_FMT, head)
            if magic == MAGIC and ver == 1:
                return f"v1 (embedded salt, iter={iterations})"
        except struct.error:
            pass
        return "v0 (external salt file)"
    except Exception:
        return "unknown"

STEP_LABELS = {
    "email_entry": "step 1, email entry",
    "consent": "step 2, consent screen",
    "provider": "step 3, provider selection",
    "auth_method_select": "MS OAuth2/Modern Auth mode selection",
    "device_code_wait": "waiting for device code",
    "imap_auth": "generic IMAP provider authentication",
    "google_oauth": "Google OAuth2 setup",
    "done": "Setup Complete",
}

def main():
    from mailtui_profile import ensure_test_profile
    ensure_test_profile()  # always ensure it's there
    creds = None  # Initialize creds to avoid unbound variable error
    profile = None  # Initialize profile to avoid unbound variable error
    email = None  # Initialize email to avoid unbound variable error

    profiles = load_profiles()
    if profiles['users']:
        print("Available accounts:")
        for i, (email, profile) in enumerate(profiles['users'].items(), start=1):
            display_email = email
            setup_done = profile.get("setup_done", False)
            step = profile.get("step", "email_entry")
            human_readable_step = STEP_LABELS.get(step, step)

            if not setup_done and not token_is_valid(profile.get("token_file")):
                display_email += f"  -- setup not completed, last step: {human_readable_step}!"

            if profile["provider"] == "local":
                display_email += "  [TEST]"

            print(f"{i}. {display_email}")

        choice = input("Choose a profile number, type 'new', 'd' to delete, 'r' to reset encryption password, or 'v' to verify decryption: ").strip().lower()
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(profiles['users']):
                email = list(profiles['users'].keys())[idx]
                profile = get_profile(email)
                if profile['provider'] == 'gmail':
                    step = profile.get("step")
                    setup_done = profile.get("setup_done", False)

                    if not setup_done or step != "done":
                        import setup_wizard
                        # prime wizard state so it knows what to show
                        setup_wizard.STATE["email"] = email
                        setup_wizard.STATE["provider"] = profile.get("provider") or "gmail"
                        setup_wizard.STATE["step"] = profile.get("step") or "provider"
                        setup_wizard.main()   # <-- creates loop, sets STATE["loop"], runs loop
                        return

                    token_file = profile.get("token_file") or "credentials/token.pickle.enc"
                    # Now it’s safe to allow password prompt:
                    creds = get_gmail_service(token_file, allow_password_prompt=True)

                    if not creds:
                        # token missing/invalid → re-enter wizard
                        from setup_wizard import start_setup
                        start_setup()
                        return

                    save_profile(
                        email=email,
                        provider='gmail',
                        token_file=profile['token_file'],
                        consent=True,
                        encryption_enabled=profile.get("settings", {}).get("encryption_enabled", False),
                        setup_done=True,
                        step="done"
                    )

                elif profile['provider'] == 'local':
                    # Inject local client using .eml files
                    from tests.test_MailTUI import load_eml_file, LocalGmailService
                    test_email_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "tests/test_emails"))

                    class LocalEmailClient:
                        def __init__(self, messages):
                            self._messages = messages

                        def search(self, query, page_token=None):
                            return [{'id': m['id']} for m in self._messages], None, None

                        @property
                        def service(self):
                            # Return a fake service object that mimics Gmail API chaining
                            class FakeService:
                                def __init__(self, messages):
                                    self._messages = {m['id']: m['service'] for m in messages}

                                def users(self):
                                    return self

                                def messages(self):
                                    return self

                                def get(self, userId=None, id=None, format='full', metadataHeaders=None):
                                    return self._messages.get(id)

                            return FakeService(self._messages)

                    messages = []
                    for fname in os.listdir(test_email_dir):
                        if fname.endswith('.eml'):
                            path = os.path.join(test_email_dir, fname)
                            msg = load_eml_file(path)
                            service = LocalGmailService(msg)
                            messages.append({'id': fname, 'service': service})

                    creds = None  # not needed for local
                    client = LocalEmailClient(messages)
                    app = EmailApp(client)
                    app.preview_source = 'local'
                    app.run()
                    return
                
                elif profile.get("provider") == "office365_modern" and not profile.get("auth_metadata"):
                    log.debug(f"[{email}] has office365_modern set but no metadata — falling back")
                    profile["provider"] = "outlook"
                    save_profile(email=email, provider='outlook')

                else:
                    if not profile.get("setup_done", False):
                        print(f"⚠ Setup for {email} is incomplete. Launching setup wizard...")
                        import setup_wizard
                        setup_wizard.STATE["email"] = email
                        setup_wizard.STATE["provider"] = profile["provider"]
                        setup_wizard.STATE["step"] = profile["step"] if profile.get("step") else "email_entry"
                        setup_wizard.main()
                        return
                    creds = authenticate(email, client_type=profile['provider'])  # or restore IMAP connection

            else:
                print("❌ Invalid profile number.")
                return

        elif choice == 'd':
            to_delete = input("Enter the profile number or email address to delete: ").strip()
            # allow numeric selection or raw email
            if to_delete.isdigit():
                idx = int(to_delete) - 1
                if 0 <= idx < len(profiles['users']):
                    email = list(profiles['users'].keys())[idx]
                else:
                    print("❌ Invalid profile number.")
                    return
            else:
                if not re.fullmatch(EMAIL_REGEX, to_delete):
                    print("❌ Invalid email format.")
                    return
                email = to_delete

            if email not in profiles['users']:
                print(f"❌ No such profile: {email}")
                return

            confirm = input(f"⚠ Are you sure you want to permanently delete the profile for {email}? (y/n): ").strip().lower()
            if confirm == 'y':
                from mailtui_profile import delete_profile
                if delete_profile(email):
                    print(f"✅ Profile for {email} deleted.")
                    debug_log(f"✅ Profile for {email} deleted.")
                else:
                    print(f"❌ Failed to delete profile for {email}.")
                    debug_log(f"❌ Failed to delete profile for {email}.")
            else:
                print("❎ Cancelled.")
            return           

        elif choice == 'new':
            import setup_wizard
            setup_wizard.STATE.update({"email": "", "provider": "", "step": "email_entry"})
            res = setup_wizard.main()

            # Get email/profile even if wizard didn't return a dict
            if isinstance(res, dict) and res.get("email"):
                email = res["email"]
            else:
                email = setup_wizard.STATE.get("email")
                if not email:
                    profiles = load_profiles()
                    if profiles.get("users"):
                        email = list(profiles["users"].keys())[-1]
            if not email:
                print("⚠ Setup did not return a usable profile.")
                return

            profile = get_profile(email)
            provider = profile.get("provider")
            token_file = profile.get("token_file")

            if provider == 'gmail':
                creds = get_gmail_service(token_file, allow_password_prompt=True)
                if not creds:
                    # wizard again if decrypt/refresh failed
                    setup_wizard.STATE.update({"email": email, "provider": "gmail", "step": "provider"})
                    setup_wizard.main()
                    return
            else:
                creds = authenticate(email, client_type=provider)

            client = get_email_client(email, creds, provider)
            app = EmailApp(client)
            app.run()
            return


        elif choice == 'r':
            handle_reset_password(profiles)
            return
        elif choice == 'v':
            targets = _collect_encrypted_assets(profiles)
            if not targets:
                print("ℹ️  Nothing to verify.")
                return
            path = targets[0]  # or add a picker
            from secure_store import decrypt_to_memory
            try:
                _ = decrypt_to_memory(path, prompt_password=True)
                print(f"✅ Decrypt OK: {path}")
            except Exception as e:
                print(f"❌ Decrypt failed: {e}")
            return
    else:
        import setup_wizard
        setup_wizard.main()
        return

    if email is None or profile is None:
        print("❌ No profile selected. Exiting.")
        return

    client = get_email_client(email, creds, profile['provider'])
    app = EmailApp(client)
    app.run()

if __name__ == '__main__':
    main()