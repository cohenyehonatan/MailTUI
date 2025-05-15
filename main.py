# main.py

from auth import get_gmail_service
from ui import EmailApp
from mail_api import get_email_client
from auth import authenticate
import os
from mailtui_profile import load_profiles, get_profile, save_profile
import pickle

def token_is_valid(token_file):
    if not token_file:
        return False
    if os.path.exists(token_file):
        with open(token_file, 'rb') as token:
            creds = pickle.load(token)
            return creds and creds.valid
    return False

def main():
    profiles = load_profiles()
    if profiles['users']:
        print("Available accounts:")
        for i, (email, profile) in enumerate(profiles['users'].items(), start=1):
            display_email = email
            if not profile.get("setup_done", False) and not token_is_valid(profile.get("token_file")):
                display_email += "  -- setup not completed!"
            print(f"{i}. {display_email}")
        choice = input("Choose a profile number or type 'new': ").strip()
        if choice.isdigit():
            email = list(profiles['users'].keys())[int(choice)-1]
            profile = get_profile(email)
            if profile['provider'] == 'gmail':
                creds = get_gmail_service(profile['token_file'])  # pass path
                if creds and not profile.get("setup_done", False):
                    save_profile(
                        email=email,
                        provider='gmail',
                        token_file=profile['token_file'],
                        consent=True,
                        encryption_enabled=profile.get("settings", {}).get("encryption_enabled", False),
                        setup_done=True
                    )

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
        elif choice == 'new':
            import setup_wizard
            setup_wizard.main()
            return
    else:
        import setup_wizard
        setup_wizard.main()
        return

    client = get_email_client(email, creds, profile['provider'])
    app = EmailApp(client)
    app.run()

if __name__ == '__main__':
    main()