# main.py

from auth import get_gmail_service
from ui import EmailApp
from mail_api import get_email_client
from auth import authenticate
import os
import sys
from mailtui_profile import load_profiles, get_profile, save_profile
import pickle

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "tests")))

def token_is_valid(token_file):
    if not token_file:
        return False
    if os.path.exists(token_file):
        with open(token_file, 'rb') as token:
            creds = pickle.load(token)
            return creds and creds.valid
    return False

def main():
    from mailtui_profile import ensure_test_profile
    ensure_test_profile()  # always ensure it's there

    profiles = load_profiles()
    if profiles['users']:
        print("Available accounts:")
        for i, (email, profile) in enumerate(profiles['users'].items(), start=1):
            display_email = email
            if not profile.get("setup_done", False) and not token_is_valid(profile.get("token_file")):
                display_email += "  -- setup not completed!"
            display_email += "  [TEST]" if profile['provider'] == 'local' else ""
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

            elif profile['provider'] == 'local':
                # Inject local client using .eml files
                from test_MailTUI import load_eml_file, LocalGmailService
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
            new_profile = setup_wizard.main()
            if new_profile:
                email = new_profile["email"]
                provider = new_profile["provider"]
                token_file = new_profile.get("token_file")

                if provider == 'gmail':
                    creds = get_gmail_service(token_file)
                else:
                    creds = authenticate(email, client_type=provider)

                client = get_email_client(email, creds, provider)
                app = EmailApp(client)
                app.run()
                return
            else:
                print("⚠ Setup did not return a usable profile.")
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