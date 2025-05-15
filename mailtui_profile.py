# mailtui_profile.py

import os
import json
from datetime import datetime

PROFILE_FILE = '.mailtui_profile'

def load_profiles():
    if not os.path.exists(PROFILE_FILE):
        return {"users": {}, "last_used": None}
    with open(PROFILE_FILE, 'r') as f:
        return json.load(f)

def save_profiles(data):
    with open(PROFILE_FILE, 'w') as f:
        json.dump(data, f, indent=2)

def save_profile(email, provider, token_file=None, imap=None, consent=True,
                 client_id=None, encryption_enabled=False, auth_metadata=None, setup_done=False, step=None):
    data = load_profiles()
    data['users'][email] = {
        "provider": provider,
        "token_file": token_file,
        "imap": imap,
        "oauth_client": {
            "client_id": client_id or "default",
            "source": "user-provided" if client_id else "default"
        },
        "consent": {
            "accepted": consent,
            "timestamp": datetime.now().isoformat()
        },
        "settings": {
            "encryption_enabled": encryption_enabled,
        },
        "auth_metadata": auth_metadata or {},
        "setup_done": setup_done,
        "step": step
    }
    data['last_used'] = email
    save_profiles(data)


def get_profile(email):
    data = load_profiles()
    return data['users'].get(email)