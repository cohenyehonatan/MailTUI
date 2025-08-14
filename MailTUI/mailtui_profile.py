# mailtui_profile.py

import os
import json
from datetime import datetime

PROFILE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', '.mailtui_profile')
PROFILE_FILE = os.path.abspath(PROFILE_FILE)

def debug_log(msg):
    with open("/tmp/mailtui-debug.log", "a") as f:
        f.write(f"{msg}\n")

def delete_profile(email):
    data = load_profiles()
    if email in data["users"]:
        del data["users"][email]
        debug_log(f"[PROFILE] Deleted profile for {email}")
        save_profiles(data)
        return True
    return False

def load_profiles():
    if not os.path.exists(PROFILE_FILE):
        return {"users": {}, "last_used": None}
    with open(PROFILE_FILE, 'r') as f:
        data = json.load(f)
    return data

def save_profiles(data):
    if not PROFILE_FILE.endswith(".mailtui_profile"):
        raise RuntimeError(f"🚨 Refusing to write to suspicious file path: {PROFILE_FILE}")
    
    with open(PROFILE_FILE, 'w') as f:
        json.dump(data, f, indent=2)
        f.flush()
        os.fsync(f.fileno())

def save_profile(email, provider=None, token_file=None, imap=None, consent=True,
                 client_id=None, encryption_enabled=False, auth_metadata=None,
                 setup_done=False, step=None):
    data = load_profiles()
    existing = data["users"].get(email, {})

    merged = {
        "provider": provider or existing.get("provider", ""),
        "token_file": token_file if token_file is not None else existing.get("token_file"),
        "imap": imap if imap is not None else existing.get("imap"),
        "oauth_client": {
            "client_id": client_id or existing.get("oauth_client", {}).get("client_id", "default"),
            "source": "user-provided" if client_id else existing.get("oauth_client", {}).get("source", "default")
        },
        "consent": {
            "accepted": consent,
            "timestamp": datetime.now().isoformat()
        },
        "settings": {
            "encryption_enabled": encryption_enabled
        },
        "auth_metadata": auth_metadata or existing.get("auth_metadata", {}),
        "setup_done": setup_done or existing.get("setup_done", False),
        "step": step or existing.get("step"),
    }

    data["users"][email] = merged
    data["last_used"] = email

    debug_log(f"[PROFILE] Saved profile for {email} with step='{step}'")

    save_profiles(data)


def get_profile(email):
    data = load_profiles()
    return data['users'].get(email)

def ensure_test_profile():
    data = load_profiles()
    test_email = "test@local.dev"
    data['users'][test_email] = {
        "provider": "local",
        "token_file": None,
        "imap": None,
        "oauth_client": {"client_id": "test", "source": "test"},
        "consent": {"accepted": True, "timestamp": datetime.now().isoformat()},
        "settings": {"encryption_enabled": False},
        "auth_metadata": {},
        "setup_done": True,
        "step": None,
        "is_test": True
    }
    data['last_used'] = test_email
    save_profiles(data)
    return test_email