# setup_wizard.py

import urwid
import os
import pickle
import json
from client_detector import detect_mx_provider
from auth import get_gmail_service, authenticate_imap_ui, KNOWN_PROVIDERS, retry_auth_factory
from secure_store import decrypt_to_memory
from mailtui_profile import save_profile, load_profiles

STATE = {
    "email": "",
    "provider": "",
    "step": "welcome",
}

frame = urwid.Frame(urwid.Filler(urwid.Text("Initializing..."), valign='top'))

# Navigation helpers
def exit_app(button=None):
    raise urwid.ExitMainLoop()

def update_body(new_body):
    if isinstance(new_body, urwid.ListBox):
        frame.body = new_body  # no filler
    else:
        frame.body = urwid.Filler(new_body, valign='top')

def show_google_oauth_setup_guide(button=None, step=1):
    steps = {
        1: ["🔧 Step 1: Create a Google Cloud Project",
            "1. Go to: https://console.cloud.google.com/projectcreate",
            "2. Create a new project and name it 'MailTUI'",
            "3. Wait ~30 seconds for it to appear in your Console"],

        2: ["⚙ Step 2: Enable the Gmail API",
            "1. Go to: https://console.cloud.google.com/apis/library/gmail.googleapis.com",
            "2. Select your 'MailTUI' project at the top",
            "3. Click 'Enable' to activate the Gmail API"],

        3: ["🪪 Step 3: Create OAuth Credentials",
            "1. Go to: https://console.cloud.google.com/apis/credentials",
            "2. Click 'Create Credentials' > 'OAuth client ID'",
            "3. Choose 'Desktop App' and name it 'MailTUI Desktop'",
            "4. Download the credentials JSON file"],

        4: ["👥 Step 3.5: Add a Test User (or multiple)",
            "1. Go to: https://console.cloud.google.com/auth/audience?project=MailTUI",
            "2. Scroll to 'Test users'",
            "3. Click 'Add users'",
            "4. Disregard the warning about the 'Testing' status, enter your Gmail address into the field, click Save, and disregard any warnings",
            "5. Repeat number 4 for any other addresses you want to allow",
            "6. Make sure the address(es) is/are in the 'User information' list"],

        5: ["📁 Step 4: Move the Credentials File",
            "1. Move your downloaded file from step 3 to this path:",
            "   ./credentials/client_secret.json",
            "2. Rename it if necessary to match exactly"],
    }

    lines = steps[step]
    text_widgets = [urwid.Text(line) for line in lines]

    nav_buttons = []
    if step < 5:
        nav_buttons.append(urwid.Button("Next", on_press=lambda btn: show_google_oauth_setup_guide(step=step + 1)))
    else:
        nav_buttons.append(urwid.Button("Check & Continue", on_press=check_for_credentials))

    if step > 1:
        nav_buttons.append(urwid.Button("Back", on_press=lambda btn: show_google_oauth_setup_guide(step=step - 1)))

    nav_buttons.append(urwid.Button("Exit", on_press=exit_app))
    update_body(urwid.Pile(text_widgets + [urwid.Divider()] + nav_buttons))

def check_for_credentials(button=None):
    plaintext = decrypt_to_memory("credentials/client_secret.enc")
    if not plaintext:
        plaintext = decrypt_to_memory("credentials/client_secrets.enc")
    token_data = json.loads(plaintext)
    if os.path.exists("credentials/client_secret.json") or os.path.exists("credentials/client_secrets.json"):
        show_gmail_setup()
    else:
        update_body(urwid.Pile([
            urwid.Text("❌ File not found: credentials/client_secret.json"),
            urwid.Text("Please ensure you've moved and renamed the downloaded file correctly."),
            urwid.Divider(),
            urwid.Button("Try Again", on_press=lambda btn: show_google_oauth_setup_guide(step=5)),
            urwid.Button("Exit", on_press=exit_app)
        ]))

def show_email_entry():
    STATE["step"] = "email_entry"
    email_edit = urwid.Edit("📧 What email will you be using with MailTUI?\n")

    def on_submit(btn):
        email = email_edit.edit_text.strip()
        if not email or "@" not in email:
            update_body(urwid.Pile([
                urwid.Text("⚠ Invalid email. Please try again."),
                urwid.Button("Back", on_press=show_email_entry)
            ]))
            return
        STATE["email"] = email
        STATE["provider"] = detect_mx_provider(email)
        show_welcome()

        save_profile(
            email=STATE["email"],
            provider=STATE.get("provider", ""),
            step=STATE["step"]
        )


    body = urwid.Pile([
        urwid.Text("📨 Welcome to MailTUI Setup!\n", align='center'),
        urwid.Text("Before we begin, enter your email so we can detect your provider and personalize the setup.\n", align='center'),
        urwid.Divider(),
        email_edit,
        urwid.Divider(),
        urwid.AttrMap(urwid.Button("Continue", on_press=on_submit), None, focus_map='reversed'),
        urwid.AttrMap(urwid.Button("Exit", on_press=exit_app), None, focus_map='reversed'),
    ])

    update_body(urwid.Filler(body, valign='top'))


def show_welcome(button=None):
    STATE["step"] = "welcome"
    email_domain = STATE['email'].split('@')[-1].lower()
    email_edit = urwid.Edit("Enter your email: ")

    def on_continue(btn):
        if not STATE["email"] or "@" not in STATE["email"]:
            update_body(urwid.Pile([
                urwid.Text("⚠ Invalid email. Please go back and enter a valid one."),
                urwid.Button("Back", on_press=show_email_entry)
            ]))
            return
        show_provider_screen()

    # List of domains for which you want to show the warning
    sensitive_domains = ["edu", "gov", "org", "fiu.edu", "dadeschools.net", "students.dadeschools.net"]

    listbox_content = [
        urwid.Text("📬 MailTUI Setup Wizard\n", align='center'),
        urwid.Text(f"Setting up for: {STATE['email']}\n", align='center'),
        urwid.Text(f"Welcome to MailTUI, {STATE['email']}! We're glad you're here.\n", align='center'),
        urwid.Text(f"It looks like you're using a {email_domain} address — nice!", align='center'),
        urwid.Divider(),

        urwid.Text("Before we get started, there are a few things we need to get out of the way:\n", align='center'),
        urwid.Divider(),

        urwid.Text(f"MailTUI is a nearly fully offline-capable yet 100% open-source, auditable, and inspectable mail client (like Gmail, Outlook, or Thunderbird), but for your terminal. This means that once authenticated for {STATE['email']}, it can:\n", align='center'),
        urwid.Text(
            "• Download and locally store emails for offline access\n"
            "• Let you search, browse, and read messages without an internet connection\n"
            "• Display plain-text or HTML email content within the terminal\n"
            "• Save and optionally encrypt .eml files to disk\n"
            "• Decrypt and open previously saved encrypted messages\n"
            "• Filter and search across large mailboxes quickly\n"
            "• Work independently of your email provider\n"
            f"• Store potentially sensitive data about the ways in which email addresses from {email_domain} authenticate with your organization's identity provider, such as internal tokens and URLs, locally for your convenience and ease of use\n"
            "• Integrate with system-level encryption or secure local storage\n", align='center'),
        urwid.Divider(),
    ]

    # Show warning only for sensitive domains
    if any(email_domain.endswith(domain) for domain in sensitive_domains):
        listbox_content += [
            urwid.Text(f"⚠️  Warning: If you're using a work, school, or organizational email address (which seems likely based on your domain, {email_domain}), note that MailTUI stores mail data locally and does not sync it back to your provider. Your IT administrator(s) may have certain policies regarding emails and third-party apps, encryption, or offline data storage.\n", align='center'),
            urwid.Text("We therefore strongly recommend checking with them before proceeding with setup if you're unsure about anything.\n", align='center'),
            urwid.Divider(),
        ]

    listbox_content += [
        urwid.Text("By continuing, you acknowledge and accept the risks of local email storage and agree not to hold MailTUI or its developers liable for any data loss, security breaches, misuse, or other consequences of connecting it to your email address(es), whether they be organizationally managed or not.\n", align='center'),
        urwid.Divider(),

        urwid.AttrMap(urwid.Button("I Understand the Risks and Accept Them", on_press=on_continue), None, focus_map='reversed'),
        urwid.AttrMap(urwid.Button("Exit Setup", on_press=exit_app), None, focus_map='reversed'),
    ]

    update_body(urwid.ListBox(urwid.SimpleFocusListWalker(listbox_content)))

    save_profile(
        email=STATE["email"],
        provider=STATE.get("provider", ""),
        step=STATE["step"]
    )




def show_provider_screen(button=None):
    email = STATE["email"]
    provider = STATE["provider"]
    STATE["step"] = "provider"
    info_text = [urwid.Text(f"📧 Email: {email}"),
                 urwid.Text(f"🔍 Detected provider: {provider.upper()}"),
                 urwid.Divider()]

    if provider in KNOWN_PROVIDERS and provider != "gmail":
        info = KNOWN_PROVIDERS[provider].copy()
        if provider == "outlook":
            domain = email.split('@')[-1].lower()
            if domain in {"outlook.com", "hotmail.com", "live.com", "msn.com"}:
                info['app_password_info'] = "https://support.microsoft.com/en-us/account-billing/how-to-get-and-use-app-passwords-5896ed9b-4263-e681-128a-a6f2979a7944"
            else:
                info['app_password_info'] = "https://support.microsoft.com/en-us/account-billing/app-passwords-for-a-work-or-school-account-d6dc8c6d-4bf7-4851-ad95-6d07799387e9"

        info_text += [
            urwid.Text("🔐 IMAP Setup Instructions:"),
            urwid.Text(f"• Server(s): {info['imap_server']}"),
            urwid.Text(f"• Port: {info['imap_port']}"),
            urwid.Text(f"• App password setup:"),
            urwid.Text(info['app_password_info']),
        ]

    buttons = [urwid.Button("Start Setup", on_press=start_setup),
               urwid.Button("Go Back", on_press=lambda btn: show_welcome()),
               urwid.Button("Exit", on_press=exit_app)]

    update_body(urwid.Pile(info_text + [urwid.Divider()] + buttons))

    save_profile(
        email=STATE["email"],
        provider=STATE.get("provider", ""),
        step=STATE["step"]
    )


def start_setup(button=None):
    if STATE["provider"] == "gmail":
        STATE["step"] = "google_oauth"
        plaintext = decrypt_to_memory("credentials/client_secret.enc")
        if not plaintext:
            plaintext = decrypt_to_memory("credentials/client_secrets.enc")
        token_data = json.loads(plaintext)
        if not os.path.exists("credentials/client_secret.json"):
            show_google_oauth_setup_guide()
        else:
            show_gmail_setup()
    else:
        STATE["step"] = "imap_auth"
        show_imap_setup()
        
from secure_store import encrypt_file

def show_gmail_setup(button=None):
    try:
        creds = get_gmail_service()
        if creds:
            from mailtui_profile import save_profile
            STATE["step"] = "done"
            email = STATE["email"]
            token_file = 'credentials/token.pickle'

            # Save plaintext token first
            save_profile(
                email=email,
                provider='gmail',
                token_file=token_file,
                consent=True,
                client_id=STATE.get("client_id"),
                encryption_enabled=STATE.get("encrypt_eml", False),
                setup_done=True,
                step=STATE["step"]
            )

            # Encrypt the saved token
            encrypt_file(token_file)

            # Delete plaintext
            os.remove(token_file)

            update_body(urwid.Pile([
                urwid.Text("✅ Gmail authentication successful."),
                urwid.Text("Token encrypted and saved to token.pickle.enc"),
                urwid.Divider(),
                urwid.Button("Exit", on_press=exit_app)
            ]))
        else:
            raise Exception("Returned credentials were None.")
    except Exception as e:
        update_body(urwid.Pile([
            urwid.Text("❌ Gmail setup failed."),
            urwid.Text(str(e)),
            urwid.Divider(),
            urwid.Button("Retry", on_press=show_gmail_setup),
            urwid.Button("Go Back", on_press=show_provider_screen)
        ]))
        import traceback
        update_body(urwid.Pile([
            urwid.Text("❌ IMAP setup failed."),
            urwid.Text(f"Error: {str(e)}"),
            urwid.Divider(),
            urwid.Text("Traceback:"),
            urwid.Text(traceback.format_exc()),
            urwid.Divider(),
            urwid.Button("Re-authenticate", on_press=retry_auth_factory(email)),
            urwid.Button("Go Back", on_press=show_provider_screen)
        ]))

def show_imap_setup(button=None):
    try:
        email = STATE["email"]

        try:
            conn = authenticate_imap_ui(email, STATE["provider"])
            if not conn:
                raise RuntimeError("IMAP login failed: No connection object returned.")
        except Exception as e:
            import traceback
            tb = traceback.format_exc()
            update_body(urwid.Pile([
                urwid.Text("⚠ authenticate_imap_ui raised an unexpected error"),
                urwid.Text(f"Error: {str(e)}"),
                urwid.Divider(),
                urwid.Text("Traceback:"),
                *[urwid.Text(line) for line in (tb or "No traceback available").splitlines()],
                urwid.Divider(),
                urwid.Button("Go Back", on_press=show_provider_screen)
            ]))
            return


        if conn == "modern_auth_required":
            from auth import authenticate_modern_auth
            update_body(urwid.Pile([
                urwid.Text("🔐 Microsoft Modern Auth required."),
                urwid.Text("Please choose your login method."),
                urwid.Divider()
            ]))
            authenticate_modern_auth(email)
            return

        elif conn:
            from mailtui_profile import save_profile
            STATE["step"] = "done"
            save_profile(
                email=email,
                provider=STATE["provider"],

                imap={
                    "username": email,
                    "server": "imap.mail.icloud.com",
                    "port": 993
                },
                consent=True,
                encryption_enabled=STATE.get("encrypt_eml", False),
                setup_done=True,
                step=STATE["step"]
            )

            update_body(urwid.Pile([
                urwid.Text("✅ IMAP login successful."),
                urwid.Text("You can now use MailTUI."),
                urwid.Divider(),
                urwid.Button("Exit", on_press=exit_app)
            ]))
            return

    except Exception as e:
        import traceback
        tb = traceback.format_exc()

        update_body(urwid.Pile([
            urwid.Text("❌ IMAP setup failed."),
            urwid.Text(f"Error: {str(e)}"),
            urwid.Divider(),
            urwid.Text("Traceback:"),
            *[urwid.Text(line) for line in (tb or "No traceback available").splitlines()],
            urwid.Divider(),
            urwid.Button("Re-authenticate", on_press=retry_auth_factory(email)),
            urwid.Button("Go Back", on_press=show_provider_screen)
        ]))

def main():
    if not os.path.exists("credentials"):
        os.makedirs("credentials")

    STATE["email"] = ""
    STATE["provider"] = ""
    if not STATE.get("step"):
        STATE["step"] = "email_entry"

    if STATE["step"] == "imap_auth":
        show_imap_setup()
    elif STATE["step"] == "google_oauth":
        show_google_oauth_setup_guide()
    elif STATE["email"]:
        show_provider_screen()
    else:
        show_email_entry()

    urwid.MainLoop(frame, palette=[('reversed', 'standout', '')]).run()

    if STATE.get("email"):
        return load_profiles(STATE["email"])
    return None

if __name__ == '__main__':
    main()
