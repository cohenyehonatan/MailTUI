# setup_wizard.py

import urwid
import os
import pickle
import json
import re
from client_detector import detect_mx_provider
from auth import get_gmail_service, KNOWN_PROVIDERS  # only safe imports here
from mailtui_profile import save_profile, load_profiles
import threading
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request

STATE = {
    "email": "",
    "provider": "",
    "step": "welcome",
    "loop": None,
}

EMAIL_REGEX = re.compile(r"^([!#-'*+/-9=?A-Z^-~-]+(\.[!#-'*+/-9=?A-Z^-~-]+)*|\"([]!#-[^-~ \t]|(\\[\t -~]))+\")@([0-9A-Za-z]([0-9A-Za-z-]{0,61}[0-9A-Za-z])?(\.[0-9A-Za-z]([0-9A-Za-z-]{0,61}[0-9A-Za-z])?)*|\[((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}|IPv6:((((0|[1-9A-Fa-f][0-9A-Fa-f]{0,3}):){6}|::((0|[1-9A-Fa-f][0-9A-Fa-f]{0,3}):){5}|[0-9A-Fa-f]{0,4}::((0|[1-9A-Fa-f][0-9A-Fa-f]{0,3}):){4}|(((0|[1-9A-Fa-f][0-9A-Fa-f]{0,3}):)?(0|[1-9A-Fa-f][0-9A-Fa-f]{0,3}))?::((0|[1-9A-Fa-f][0-9A-Fa-f]{0,3}):){3}|(((0|[1-9A-Fa-f][0-9A-Fa-f]{0,3}):){0,2}(0|[1-9A-Fa-f][0-9A-Fa-f]{0,3}))?::((0|[1-9A-Fa-f][0-9A-Fa-f]{0,3}):){2}|(((0|[1-9A-Fa-f][0-9A-Fa-f]{0,3}):){0,3}(0|[1-9A-Fa-f][0-9A-Fa-f]{0,3}))?::(0|[1-9A-Fa-f][0-9A-Fa-f]{0,3}):|(((0|[1-9A-Fa-f][0-9A-Fa-f]{0,3}):){0,4}(0|[1-9A-Fa-f][0-9A-Fa-f]{0,3}))?::)((0|[1-9A-Fa-f][0-9A-Fa-f]{0,3}):(0|[1-9A-Fa-f][0-9A-Fa-f]{0,3})|(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3})|(((0|[1-9A-Fa-f][0-9A-Fa-f]{0,3}):){0,5}(0|[1-9A-Fa-f][0-9A-Fa-f]{0,3}))?::(0|[1-9A-Fa-f][0-9A-Fa-f]{0,3})|(((0|[1-9A-Fa-f][0-9A-Fa-f]{0,3}):){0,6}(0|[1-9A-Fa-f][0-9A-Fa-f]{0,3}))?::)|(?!IPv6:)[0-9A-Za-z-]*[0-9A-Za-z]:[!-Z^-~]+)])$")

RESET = "\033[22m"
BOLD = "\033[1m"

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

frame = urwid.Frame(
    urwid.ListBox(
        urwid.SimpleFocusListWalker([urwid.Text("Initializing...")])
    )
)

def pad(txt):
    return urwid.Padding(urwid.Text(txt), align='left', width=('relative', 90))

# Navigation helpers
def exit_app(button=None):
    if STATE.get("email"):
        from mailtui_profile import save_profile
        step = STATE.get("step") or "incomplete"
        save_profile(
            email=STATE["email"],
            provider=STATE.get("provider", ""),
            step=step,
            setup_done=False
        )
        print(f"💾 [exit_app] Saved partial profile for {STATE['email']} at step '{step}'")
    raise urwid.ExitMainLoop()

# def update_body(new_body):
#     if isinstance(new_body, urwid.ListBox):
#         if isinstance(new_body, urwid.ListBox):
#             focus = new_body.body.get_focus()
#             if focus:
#                 if focus and hasattr(focus[0], 'get_text'):
#                     body_text = focus[0].get_text()[0] if focus[0] is not None else "No text available"
#                 else:
#                     body_text = "No focus available"

#                 frame.body = urwid.Filler(urwid.Text(body_text), valign='top')

#             else:
#                 frame.body = urwid.Filler(urwid.Text("No focus available"), valign='top')
#         else:
#             frame.body = urwid.Filler(new_body, valign='top')
#     else:
#         frame.body = urwid.Filler(new_body, valign='top')

def _wrap_center(w):
    if isinstance(w, urwid.Text) and getattr(w, "align", "left") != "left":
        return urwid.Padding(w, align='center', width=('relative', 90))
    return w

def update_body(new_body):
    if isinstance(new_body, list):
        new_body = [ _wrap_center(w) for w in new_body ]
        new_body = urwid.ListBox(urwid.SimpleFocusListWalker(new_body))
    elif isinstance(new_body, urwid.ListBox):
        walker = new_body.body
        for i in range(len(walker)): # pyright: ignore[reportArgumentType]
            walker[i] = _wrap_center(walker[i]) # pyright: ignore[reportIndexIssue]
    frame.body = new_body
    # try to draw if a loop exists
    loop = STATE.get("loop") or globals().get("MAIN_LOOP")
    if loop and getattr(loop, "screen", None):
        try:
            loop.draw_screen()
        except Exception:
            pass


def show_google_oauth_setup_guide(button=None, step=1):
    email = STATE.get("email", "<your_email@example.com>")

    # if CLIENT_SECRET_FILE:
    #     display_path = os.path.abspath(CLIENT_SECRET_FILE)
    # else:
    #     display_path = os.path.join(os.path.abspath(CREDENTIALS_DIR), "client_secret_<client_id>.apps.googleusercontent.com.json")

    from secure_store import CREDENTIALS_DIR
    display_path = os.path.join(os.path.abspath(CREDENTIALS_DIR), "client_secret_<client_id>.apps.googleusercontent.com.json")

    steps = {
        1: ["🔧 Step 1: Create a Google Cloud Project",
            "1. Go to: https://console.cloud.google.com/projectcreate",
            "2. Create a new project and name it 'MailTUI'",
            "3. Wait ~30 seconds for it to appear in your Console"],

        2: ["⚙ Step 2: Enable the Gmail API",
            "1. Go to: https://console.cloud.google.com/apis/library/gmail.googleapis.com",
            "2. Select your 'MailTUI' project at the top",
            "3. Click 'Enable' to activate the Gmail API"],

        3: ["🪪 Step 3: Create and Configure the OAuth Consent Screen",
            "1. Go to: https://console.cloud.google.com/apis/credentials",
            "2. On the page titled 'Create OAuth client ID' you should see after clicking 'Create Credentials', click 'Configure consent screen' in the yellow banner",
            "3. Click 'Get started', enter 'MailTUI Desktop' for the 'App name'",
            "4. Fill in the 'User support email' and select 'External' for the audience after clicking 'Next', then click 'Next' again",
            f"5. Enter {email} as the 'User support email' and in the 'Email addresses' field, then click 'Next'",
            "6. Read the terms and agree to them by checking the box next to 'I agree to the Google API Services: User Data Policy.', then click 'Continue'",
            "7. Click 'Create' to finish configuring the consent screen"],

        4: ["🪪 Step 3.5: Create OAuth Credentials",
            "1. Go back to: https://console.cloud.google.com/apis/credentials",
            "2. Click 'Create Credentials' > 'OAuth client ID'",
            "3. Choose 'Desktop App' for the 'Application type' and name it 'MailTUI Desktop', then click 'Create'",
            "4. Note: As the dialog says, after you close it, you will not be able to see the client secret anymore",
            "5. Download the credentials JSON file by clicking the 'Download JSON' button, then close the dialog by clicking 'OK'"],

        5: [
            "👥 Step 4: Add a Test User (or multiple)",
            "1. Go to: https://console.cloud.google.com/auth/audience?project=MailTUI",
            "2. Scroll to 'Test users'",
            "3. Click 'Add users'",
            f"4. Enter {email} into the field, click 'Save', and disregard any warnings",
            "5. Repeat number 4 for any other addresses you want to allow",
            f"6. Make sure {email} is now listed under 'User information'"
        ],

        6: ["📁 Step 5: Move the Credentials File",
            "1. Move your downloaded credentials JSON file from step 4 to:",
            f"   {display_path}",
            "2. Do not rename the file — just place it exactly as downloaded",
            "   (MailTUI will automatically detect and validate it by content)"],
    }

    lines = steps[step]
    text_widgets = [urwid.Text(line) for line in lines]

    nav_buttons = []
    if step < 6:
        nav_buttons.append(urwid.AttrMap(urwid.Button("Next", on_press=lambda btn: show_google_oauth_setup_guide(step=step + 1)), None, 'reversed'))
    else:
        nav_buttons.append(urwid.AttrMap(urwid.Button("Check & Continue", on_press=check_for_credentials), None, 'reversed'))

    if step > 1:
        nav_buttons.append(urwid.AttrMap(urwid.Button("Back", on_press=lambda btn: show_google_oauth_setup_guide(step=step - 1)), None, 'reversed'))

    nav_buttons.append(urwid.AttrMap(urwid.Button("Exit", on_press=exit_app), None, 'reversed'))
    # update_body(urwid.Pile(text_widgets + [urwid.Divider()] + nav_buttons))
    update_body(text_widgets + [urwid.Divider()] + nav_buttons)  # simple list of flows

def check_for_credentials(button=None):
    from secure_store import CLIENT_SECRET_FILE, decrypt_to_memory
    ENCRYPTED_CLIENT_SECRET = f"{CLIENT_SECRET_FILE}.enc" if isinstance(CLIENT_SECRET_FILE, str) else None
    if ENCRYPTED_CLIENT_SECRET and os.path.exists(ENCRYPTED_CLIENT_SECRET):
        try:
            plaintext = decrypt_to_memory(ENCRYPTED_CLIENT_SECRET)
            token_data = json.loads(plaintext)
            get_gmail_service()
            return
        except Exception as e:
            print(f"❌ Failed to decrypt: {e}")
    
    elif isinstance(CLIENT_SECRET_FILE, str) and os.path.exists(CLIENT_SECRET_FILE):
        try:
            with open(CLIENT_SECRET_FILE) as f:
                token_data = json.load(f)
            get_gmail_service()
            return
        except Exception as e:
            print(f"❌ Failed to load JSON: {e}")

    # Only reach this if both branches failed
    STATE["step"] = "google_oauth_guide"
    show_google_oauth_setup_guide(step=5)

def show_email_entry(button=None):
    email_edit = urwid.Edit("📧 What email will you be using with MailTUI?\n")

    def on_submit(btn):
        email = email_edit.edit_text.strip()
        if not email or not re.fullmatch(EMAIL_REGEX, email):
            update_body([
                urwid.Padding(urwid.Text("⚠ Invalid email. Please try again.", align='center'), align='center', width=('relative', 90)),
                urwid.Divider(),
                urwid.AttrMap(urwid.Button("Back", on_press=show_email_entry), None, focus_map='reversed'),
            ])
            return

        STATE["email"] = email
        STATE["provider"] = detect_mx_provider(email)
        STATE["step"] = "email_entry"

        save_profile(email=STATE["email"], provider=STATE.get("provider", ""), step="email_entry")
        show_consent()

    body_items = [
        urwid.Padding(urwid.Text("📨 Welcome to MailTUI Setup!\n", align='center'), align='center', width=('relative', 90)),
        urwid.Padding(urwid.Text("Before we begin, enter your email so we can detect your provider and personalize the setup.\n", align='center'), align='center', width=('relative', 90)),
        urwid.Divider(),
        email_edit,  # Edit is a flow widget ✅
        urwid.Divider(),
        urwid.AttrMap(urwid.Button("Continue", on_press=on_submit), None, focus_map='reversed'),
        urwid.AttrMap(urwid.Button("Exit", on_press=exit_app), None, focus_map='reversed'),
    ]

    update_body(body_items)  # <- list, update_body will wrap into ListBox



def show_consent(button=None):
    STATE["step"] = "consent"
    email = STATE.get("email", "")
    email_domain = email.split('@')[-1].lower()

    print(f"🔍 DEBUG: STATE before save_profile in show_consent:")
    print(f"  email={email}")
    print(f"  provider={STATE.get('provider')}")
    print(f"  step={STATE.get('step')}")

    save_profile(
        email=email,
        provider=STATE.get("provider", ""),
        step="consent"
    )

    print(f"[debug] save_profile is from: {save_profile.__module__}")

    sensitive_domains = ["edu", "gov", "org", "fiu.edu", "dadeschools.net", "students.dadeschools.net"]

    def on_continue(btn):
        show_provider_screen()

    listbox_content = [
        urwid.Padding(urwid.Text("📬 MailTUI Setup Wizard\n", align='center'), align='center', width=('relative', 90)),
        urwid.Padding(urwid.Text(f"Setting up for: {email}\n", align='center'), align='center', width=('relative', 90)),
        urwid.Padding(urwid.Text(f"Welcome to MailTUI, {email}! We're glad you're here.\n", align='center'), align='center', width=('relative', 90)),
        urwid.Padding(urwid.Text(f"It looks like you're using a {email_domain} address — nice!", align='center'), align='center', width=('relative', 90)),
        urwid.Divider(),

        urwid.Padding(urwid.Text("Before we get started, there are a few things we need to get out of the way:\n", align='center'), align='center', width=('relative', 90)),
        urwid.Divider(),

        urwid.Padding(urwid.Text(f"MailTUI is a nearly fully offline-capable yet 100% open-source, auditable, and inspectable mail client (like Gmail, Outlook, or Thunderbird), but for your terminal. This means that once authenticated for {email}, it can:\n", align='center'), align='center', width=('relative', 90)),
        urwid.Padding(urwid.Text(
            "• Download and locally store emails for offline access\n"
            "• Let you search, browse, and read messages without an internet connection\n"
            "• Display plain-text or HTML email content within the terminal\n"
            "• Save and optionally encrypt .eml files to disk\n"
            "• Decrypt and open previously saved encrypted messages\n"
            "• Filter and search across large mailboxes quickly\n"
            "• Work independently of your email provider\n"
            f"• Store potentially sensitive data about the ways in which email addresses from {email_domain} authenticate with your organization's identity provider, such as internal tokens and URLs, locally for your convenience and ease of use\n"
            "• Integrate with system-level encryption or secure local storage\n", align='center')),
        urwid.Divider(),
    ]

    # Show warning only for sensitive domains
    if any(email_domain.endswith(domain) for domain in sensitive_domains):
        listbox_content += [
            urwid.Padding(urwid.Text(
                f"⚠️  Warning: If you're using a work, school, or organizational email address (which seems likely based on your domain, {email_domain}), "
                "note that MailTUI stores mail data locally and does not sync it back to your provider. Your IT administrator(s) may have certain policies "
                "regarding emails and third-party apps, encryption, or offline data storage.\n", align='center'),
                align='center', width=('relative', 90)),
            urwid.Padding(urwid.Text(
                "We therefore strongly recommend checking with them before proceeding with setup if you're unsure about anything.\n", align='center'),
                align='center', width=('relative', 90)),
            urwid.Divider(),
        ]

    listbox_content += [
        urwid.Padding(urwid.Text(
            "By continuing, you acknowledge and accept the risks of local email storage and agree not to hold MailTUI or its developers liable for any data loss, "
            "security breaches, misuse, or other consequences of connecting it to your email address(es), whether they be organizationally managed or not.\n", align='center'),
            align='center', width=('relative', 90)),
        urwid.Divider(),

        urwid.AttrMap(urwid.Button("I Understand the Risks and Accept Them", on_press=on_continue), None, focus_map='reversed'),
        urwid.AttrMap(urwid.Button("Back", on_press=show_email_entry), None, focus_map='reversed'),
        urwid.AttrMap(urwid.Button("Exit Setup", on_press=exit_app), None, focus_map='reversed'),
    ]


    # update_body(urwid.ListBox(urwid.SimpleFocusListWalker(listbox_content)))
    update_body(listbox_content)  # let update_body wrap to ListBox

def show_provider_screen(button=None):
    email = STATE["email"]
    provider = STATE["provider"]
    STATE["step"] = "provider"

    info_text = [
        pad(f"📧 Email: {email}"),
        pad(f"🔍 Detected provider: {provider.upper()}"),
        urwid.Divider()
    ]

    if provider in KNOWN_PROVIDERS and provider != "gmail":
        info = KNOWN_PROVIDERS[provider].copy()

        if provider == "outlook":
            domain = email.split('@')[-1].lower()
            if domain in {"outlook.com", "hotmail.com", "live.com", "msn.com"}:
                info['app_password_info'] = "https://support.microsoft.com/en-us/account-billing/how-to-get-and-use-app-passwords-5896ed9b-4263-e681-128a-a6f2979a7944"
            else:
                info['app_password_info'] = "https://support.microsoft.com/en-us/account-billing/app-passwords-for-a-work-or-school-account-d6dc8c6d-4bf7-4851-ad95-6d07799387e9"

        info_text += [
            pad("🔐 IMAP Setup Instructions:"),
            pad(f"• Server(s): {info['imap_server']}"),
            pad(f"• Port: {info['imap_port']}"),
            pad("• App password setup:"),
            pad(info['app_password_info']),
        ]

    buttons = [
        urwid.AttrMap(urwid.Button("Start Setup", on_press=start_setup), None, focus_map='reversed'),
        urwid.AttrMap(urwid.Button("Go Back", on_press=lambda btn: show_consent()), None, focus_map='reversed'),
        urwid.AttrMap(urwid.Button("Exit", on_press=exit_app), None, focus_map='reversed')
    ]

    update_body(urwid.Filler(urwid.Pile(info_text + [urwid.Divider()] + buttons), valign='top'))

    save_profile(
        email=STATE["email"],
        provider=STATE.get("provider", ""),
        step=STATE["step"]
    )

def _oauth_in_thread(loop, *, cfg_json_path=None, cfg_json_text=None):
    """Run Google OAuth on a worker thread, then update the TUI."""
    def worker():
        try:
            if cfg_json_path:
                flow = InstalledAppFlow.from_client_secrets_file(cfg_json_path, SCOPES)
            else:
                if cfg_json_text is None:
                    raise ValueError("cfg_json_text cannot be None")
                flow = InstalledAppFlow.from_client_config(json.loads(cfg_json_text), SCOPES)

            # This blocks the worker thread (not the UI)
            creds = flow.run_local_server(port=0)  # opens browser then waits
        except Exception as e:
            def show_err(loop, e=e):
                update_body([
                    urwid.Text("❌ Google OAuth failed.", align='center'),
                    urwid.Text(str(e), align='center'),
                    urwid.Divider(),
                    urwid.AttrMap(urwid.Button("Back", on_press=show_provider_screen), None, 'reversed'),
                ])
            loop.set_alarm_in(0, lambda *_: show_err(loop))
            return

        def finish(loop, creds=creds):
            show_gmail_setup(creds)
        loop.set_alarm_in(0, lambda *_: finish(loop))

    threading.Thread(target=worker, daemon=True).start()

def _prompt_password_and_decrypt(enc_path):
    """Show an in-TUI password prompt, decrypt client secret, then OAuth."""
    edit = urwid.Edit(("","🔑 Enter password for client secret: "), mask='*')
    msg  = urwid.Text("", align='center')

    def on_submit(btn=None):
        pwd = edit.edit_text
        if not pwd:
            msg.set_text("Password required.")
            return
        try:
            from secure_store import decrypt_to_memory
            plaintext = decrypt_to_memory(enc_path, prompt_password=False, password=pwd)
        except Exception as e:
            msg.set_text(f"Decrypt failed: {e}")
            return

        # Swap screen to "Opening browser..." and kick OAuth on a worker thread
        update_body([
            urwid.Text("🌐 Opening Google OAuth in your browser…", align='center'),
            urwid.Text("Please complete the consent flow, then return here.", align='center'),
        ])
        loop = STATE.get("loop")
        _oauth_in_thread(loop, cfg_json_text=plaintext)

    pile = urwid.Pile([
        urwid.Divider(),
        urwid.Padding(edit, align='center', width=('relative', 70)),
        urwid.Divider(),
        urwid.Padding(msg, align='center', width=('relative', 80)),
        urwid.Divider(),
        urwid.AttrMap(urwid.Button("Continue", on_press=on_submit), None, 'reversed'),
        urwid.AttrMap(urwid.Button("Cancel", on_press=show_provider_screen), None, 'reversed'),
    ])
    update_body(urwid.Filler(pile, valign="top"))

def start_setup(button=None):
    from secure_store import CLIENT_SECRET_FILE
    STATE["step"] = "google_oauth"

    # Resolve paths
    cfg_path = CLIENT_SECRET_FILE if isinstance(CLIENT_SECRET_FILE, str) else None
    enc_path = f"{cfg_path}.enc" if cfg_path else None

    if cfg_path and os.path.exists(cfg_path):
        # Plain JSON available → run OAuth in background
        update_body([
            urwid.Text("🌐 Opening Google OAuth in your browser…", align='center'),
            urwid.Text("Please complete the consent flow, then return here.", align='center'),
        ])
        loop = STATE.get("loop")
        _oauth_in_thread(loop, cfg_json_path=cfg_path)
        return

    if enc_path and os.path.exists(enc_path):
        # Encrypted JSON → ask for password inside the TUI
        _prompt_password_and_decrypt(enc_path)
        return

    # Neither secret found → send to guide
    STATE["step"] = "google_oauth_guide"
    show_google_oauth_setup_guide(step=5)
        
def show_gmail_setup(creds=None):
    email = STATE.get("email", "<unknown>")
    loop = STATE["loop"]

    try:
        # 🔒 DO NOT re-call get_gmail_service() here — wizard already has creds.
        if not creds or not creds.valid:
            raise Exception("No valid Gmail credentials passed to setup. Restart OAuth.")

        from mailtui_profile import save_profile
        from secure_store import get_token_path, encrypt_bytes_to_file

        # Optional: mark a mid-stage before writing anything
        STATE["step"] = "oauth_complete"

        token_file = get_token_path()

        # 1) Save plaintext token (temporary)
        with open(token_file, 'wb') as f:
            pickle.dump(creds, f)

        with open(token_file, "rb") as f:
            plaintext = f.read()

        from secure_store import _get_password, encrypt_bytes_to_file
        password = _get_password(always_confirm=True).decode("utf-8")

        with open(token_file, "rb") as f:
            plaintext = f.read()

        # 2) Save initial profile BEFORE encrypting (so we have a record)
        save_profile(
            email=email,
            provider='gmail',
            token_file=token_file,
            consent=True,
            client_id=STATE.get("client_id"),
            encryption_enabled=bool(STATE.get("encrypt_eml", False)),
            setup_done=False,            # not done yet
            step=STATE["step"]
        )

        # 3) write v1 (embedded salt + explicit iterations)
        encrypted_path = token_file + ".enc"
        encrypt_bytes_to_file(
            plaintext, encrypted_path,
            password=password, iterations=300_000, embed_salt=True
        )

        # 4) Save final profile
        STATE["step"] = "done"
        save_profile(
            email=email,
            provider='gmail',
            token_file=encrypted_path,
            consent=True,
            client_id=STATE.get("client_id"),
            encryption_enabled=bool(STATE.get("encrypt_eml", False)),
            setup_done=True,
            step=STATE["step"]
        )

        # 5) Cleanup plaintext
        if os.path.exists(token_file):
            os.remove(token_file)

        update_body(urwid.Filler(urwid.Pile([
            urwid.Text("✅ Gmail authentication successful.", align='center'),
            urwid.Text("Token encrypted and saved to token.pickle.enc", align='center'),
            urwid.Divider(),
            urwid.AttrMap(urwid.Button("Exit", on_press=exit_app), None, focus_map='reversed')
        ]), valign="top"))

    except Exception as e:
        import traceback
        update_body(urwid.Filler(urwid.Pile([
            urwid.Text("❌ IMAP setup failed.", align='center'),
            urwid.Text(f"Error: {str(e)}", align='center'),
            urwid.Divider(),
            urwid.Text("Traceback:", align='center'),
            urwid.Text(traceback.format_exc(), align='center'),
            urwid.Divider(),
            urwid.AttrMap(urwid.Button("Re-authenticate (Open Setup Guide)", on_press=lambda btn: show_google_oauth_setup_guide(step=1)), None, focus_map='reversed'),
            urwid.AttrMap(urwid.Button("Go Back", on_press=show_provider_screen), None, focus_map='reversed')
        ]), valign="top"))

def on_success(result):
    pass  # placeholder

def on_error(err):
    update_body([
        urwid.Text("⚠ IMAP auth failed"),
        urwid.Text(str(err)),
        urwid.Divider(),
        urwid.AttrMap(urwid.Button("Go Back", on_press=show_provider_screen), None, 'reversed')
    ])

def show_imap_setup(button=None):
    from auth import retry_auth_factory
    from mailtui_profile import load_profiles, save_profile
    from client_detector import ensure_metadata_for_email

    email = STATE["email"]

    if STATE.get("provider") == "office365_modern":
        issuer, metadata, tenant_id, domain = ensure_metadata_for_email(email)
    else:
        issuer = metadata = tenant_id = domain = None

    # --- callback when IMAP auth succeeds ---
    def imap_handle_success(conn):
        if conn == "modern_auth_required":
            from auth import authenticate_modern_auth
            update_body([
                urwid.Text(f"🔐 Microsoft Modern Auth is required for domain {domain} (tenant ID {tenant_id}), of which your email {email} is a part.", align='center'),
                urwid.Text("Please choose your login method.", align='center'),
                urwid.Divider()
            ])
            authenticate_modern_auth(email, STATE["loop"])
            return

        # Save profile and show success
        STATE["step"] = "done"
        save_profile(
            email=email,
            provider=STATE["provider"],
            imap={
                "username": conn.username,
                "server": conn.server,
                "port": conn.port,
                "tls": conn.tls,
            },
            consent=True,
            encryption_enabled=bool(STATE.get("encrypt_eml", False)),
            setup_done=True,
            step=STATE["step"]
        )

        update_body([
            urwid.Text("✅ IMAP login successful.", align='center'),
            urwid.Text("You can now use MailTUI.", align='center'),
            urwid.Divider(),
            urwid.AttrMap(urwid.Button("Exit", on_press=exit_app), None, focus_map='reversed')
        ])

    # --- callback when IMAP auth errors ---
    def handle_error(e):
        import traceback
        tb = traceback.format_exc()
        update_body([
            urwid.Text("❌ IMAP setup failed.", align='center'),
            urwid.Text(f"Error: {str(e)}", align='center'),
            urwid.Divider(),
            urwid.Text("Traceback:", align='center'),
            *[urwid.Text(line, align='center') for line in (tb or "No traceback available").splitlines()],
            urwid.Divider(),
            urwid.AttrMap(urwid.Button("Re-authenticate",
                                       on_press=lambda btn: retry_auth_factory(
                                           STATE.get("email", ""),
                                           STATE.get("loop", MAIN_LOOP)
                                       )), None, focus_map='reversed'),
            urwid.AttrMap(urwid.Button("Go Back", on_press=show_provider_screen), None, focus_map='reversed')
        ])

    # Hand control to the TUI form
    from auth import authenticate_imap_ui
    authenticate_imap_ui(email, STATE["provider"], on_success=imap_handle_success, on_error=handle_error)


def main():
    if not os.path.exists("credentials"):
        os.makedirs("credentials")

    if not STATE.get("step"):
        STATE["step"] = "email_entry"

    loop = urwid.MainLoop(frame, palette=[('reversed', 'bold', 'default', '')])
    global MAIN_LOOP
    MAIN_LOOP = loop
    STATE["loop"] = loop

    resume_from_step()

    loop.run()

    if STATE.get("email"):
        profiles = load_profiles()
        prof = profiles["users"].get(STATE["email"], {})
        return {
            "email": STATE["email"],
            "provider": prof.get("provider") or STATE.get("provider"),
            "token_file": prof.get("token_file"),
            "setup_done": prof.get("setup_done", False),
            "step": prof.get("step"),
        }
    return None

def resume_from_step():
    step = STATE.get("step", "email_entry")
    email = STATE.get("email")
    loop = STATE.get("loop", MAIN_LOOP)

    if step == "email_entry":
        show_email_entry()
    elif step == "consent":
        show_consent()
    elif step == "provider":
        show_provider_screen()
    elif step == "auth_method_select":
        from auth import authenticate_modern_auth
        authenticate_modern_auth(email, loop)
    elif step == "device_code_wait":
        from auth import run_device_code_flow
        run_device_code_flow(email, loop)
    elif step == "imap_auth":
        show_imap_setup()
    elif step == "google_oauth":
        start_setup()
    else:
        # fallback
        show_email_entry(loop)

if __name__ == '__main__':
    main()
