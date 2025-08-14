# auth.py

import os
import imaplib
import smtplib
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
import google.auth.exceptions
import json, pickle
import urwid
import base64
from client_detector import detect_mx_provider
from getpass import getpass
from pathlib import Path
import imaplib, ssl
from mailtui_profile import get_profile
import logging
logging.basicConfig(filename='MailTUI.log',level=logging.DEBUG)
log = logging.getLogger(__name__)

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MS_SCOPE = "https://outlook.office.com/IMAP.AccessAsUser.All https://outlook.office.com/SMTP.Send offline_access"

def copy_to_clipboard(text):
    import subprocess
    try:
        subprocess.run("pbcopy", text=True, input=text)
    except Exception as e:
        print(f"Clipboard copy failed: {e}")

def show_oauth_prompt(auth_url, flow):
    import urwid
    import webbrowser
    from setup_wizard import update_body, exit_app

    # Read-only URL display (Edit invites typing/mouse selection that TUI won’t support well)
    url_display = urwid.Text(auth_url)

    def redraw_notice(lines, back_cb):
        """Helper to render a small notice screen, always with Filler->Pile to keep sizing sane."""
        notice = urwid.Filler(
            urwid.Pile(
                [urwid.Text(l) if not isinstance(l, urwid.Widget) else l for l in lines] + [
                    urwid.Divider(),
                    urwid.Button("Back", on_press=lambda btn: back_cb())
                ]
            ),
            valign="top",
        )
        update_body(notice)

    def on_copy(_):
        import subprocess, shutil
        msg = None
        try:
            # Try platform-specific clipboard utilities
            if shutil.which("pbcopy"):
                subprocess.run(["pbcopy"], input=auth_url, text=True, check=True)
                msg = "✅ Copied URL to clipboard (pbcopy)."
            elif shutil.which("wl-copy"):
                subprocess.run(["wl-copy"], input=auth_url, text=True, check=True)
                msg = "✅ Copied URL to clipboard (wl-copy)."
            elif shutil.which("xclip"):
                subprocess.run(["xclip", "-selection", "clipboard"], input=auth_url, text=True, check=True)
                msg = "✅ Copied URL to clipboard (xclip)."
            else:
                # Python fallback if user has pyperclip installed
                try:
                    import pyperclip
                    pyperclip.copy(auth_url)
                    msg = "✅ Copied URL to clipboard (pyperclip)."
                except Exception:
                    raise FileNotFoundError("No clipboard utility found (pbcopy/wl-copy/xclip) and pyperclip not available.")
        except Exception as e:
            redraw_notice(
                [("⚠️ Failed to copy:",), (str(e),)],
                back_cb=lambda: show_oauth_prompt(auth_url, flow)
            )
            return

        # If we got here, copy worked
        redraw_notice(
            [msg],
            back_cb=lambda: show_oauth_prompt(auth_url, flow)
        )

    code_edit = urwid.Edit("🔑 Enter the authorization code:\n")

    def on_open_browser(_):
        try:
            webbrowser.open(auth_url)
            redraw_notice(
                ["🌐 Opened the URL in your default browser."],
                back_cb=lambda: show_oauth_prompt(auth_url, flow)
            )
        except Exception as e:
            redraw_notice(
                ["⚠️ Failed to open browser.", str(e)],
                back_cb=lambda: show_oauth_prompt(auth_url, flow)
            )

    def on_submit(btn):
        from setup_wizard import update_body, show_gmail_setup
        from secure_store import encrypt_file, get_token_path
        import pickle, traceback, os

        code = code_edit.edit_text.strip()
        try:
            # Exchange code for tokens
            flow.fetch_token(code=code)
            creds = flow.credentials

            # Save token (unencrypted here; if you have encrypt_file, call it explicitly)
            token_file = get_token_path()
            os.makedirs(os.path.dirname(token_file), exist_ok=True)
            with open(token_file, 'wb') as token:
                pickle.dump(creds, token)

            # Continue setup with valid creds
            show_gmail_setup(creds=creds)

        except Exception as e:
            tb = traceback.format_exc()
            notice = urwid.Filler(
                urwid.Pile([
                    urwid.Text("❌ Failed to fetch token."),
                    urwid.Text(str(e)),
                    urwid.Text(tb),
                    urwid.Button("Retry", on_press=lambda btn: show_oauth_prompt(auth_url, flow)),
                ]),
                valign="top",
            )
            update_body(notice)

    widgets = [
        urwid.Text("👉 Visit the following URL in your browser to authorize the app:"),
        urwid.Divider(),
        url_display,
        urwid.Divider(),
        urwid.Button("📋 Copy URL to Clipboard", on_press=on_copy),
        urwid.Button("🌐 Open in Browser", on_press=on_open_browser),
        urwid.Divider(),
        code_edit,
        urwid.Divider(),
        urwid.Button("Submit Code", on_press=on_submit),
        urwid.Button("Cancel", on_press=exit_app)
    ]

    # IMPORTANT: always wrap with Filler(Pile(...)) so flow widgets get a (cols,) size
    update_body(urwid.Filler(urwid.Pile(widgets), valign="top"))

def get_gmail_service(token_file=None, *, allow_password_prompt=False):
    from secure_store import decrypt_to_memory, CLIENT_SECRET_FILE, get_token_path, DeferPassword
    if not token_file:
        token_file = get_token_path()

    creds = None
    if token_file.endswith(".enc") and os.path.exists(token_file):
        try:
            decrypted = decrypt_to_memory(token_file, prompt_password=allow_password_prompt)
            creds = pickle.loads(decrypted)
        except DeferPassword:
            creds = None
        except Exception as e:
            print(f"⚠️ Failed to decrypt token file: {e}")
            creds = None
    elif os.path.exists(token_file):
        with open(token_file, 'rb') as f:
            creds = pickle.load(f)

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
            except google.auth.exceptions.RefreshError:
                print("⚠️  Token invalid or expired — clearing saved credentials.")
                try: os.remove(token_file)
                except FileNotFoundError: pass
                return get_gmail_service(token_file, allow_password_prompt=allow_password_prompt)
        else:
            # Don’t start OAuth here during selection; the wizard handles that.
            return None

    # Persist if needed
    if creds:
        with open(token_file, 'wb') as f:
            pickle.dump(creds, f)
    return creds

KNOWN_PROVIDERS = {
    'outlook': {
        'imap_server': 'imap-mail.outlook.com',
        'smtp_server': 'smtp-mail.outlook.com',
        'imap_port': 993,
        'app_password_info': 'https://support.microsoft.com/en-us/account-billing/app-passwords-for-a-work-or-school-account-d6dc8c6d-4bf7-4851-ad95-6d07799387e9'
    },
    'apple': {
        'imap_server': ['imap.mail.me.com', 'imap.mail.icloud.com'],
        'smtp_server': ['smtp.mail.me.com', 'smtp.mail.icloud.com'],
        'imap_port': 993,
        'app_password_info': 'https://support.apple.com/en-us/HT204397'
    },
    'yahoo': {
        'imap_server': 'imap.mail.yahoo.com',
        'smtp_server': 'smtp.mail.yahoo.com',
        'imap_port': 993,
        'app_password_info': 'https://help.yahoo.com/kb/SLN15241.html'
    },
    'zoho': {
        'imap_server': 'imap.zoho.com',
        'smtp_server': 'smtp.zoho.com',
        'imap_port': 993,
        'app_password_info': 'https://www.zoho.com/mail/help/adminconsole/two-factor-authentication.html'
    },
    'gmail': {
        'imap_server': 'imap.gmail.com',
        'smtp_server': 'smtp.gmail.com',
        'imap_port': 993,
        'app_password_info': 'https://support.google.com/mail/answer/185833'
    }
}

def poll_for_token(device_resp, metadata, email, lines, loop):
    from setup_wizard import update_body
    import time
    import urwid
    
    token_url = metadata["token_endpoint"]
    client_id = "33fb5b1b-db86-4cd9-ad37-32afda5db81f"
    scope = MS_SCOPE
    interval = int(device_resp.get("interval", 5))

    while True:
        time.sleep(interval)
        poll_data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": client_id,
            "device_code": device_resp["device_code"],
            "scope": scope
        }
        resp = requests.post(token_url, data=poll_data)

        if resp.status_code == 200:
            access_token = resp.json()["access_token"]
            def on_success(loop, _):
                lines.append(urwid.Text("✅ Auth success!"))
                update_body(urwid.ListBox(urwid.SimpleFocusListWalker(lines)))
                build_imap_connection(email, access_token)
            loop.set_alarm_in(0.1, on_success)
            break

        elif resp.status_code in (400, 428):
            err = resp.json()
            if err.get("error") in ("authorization_pending", "slow_down"):
                continue
            elif err.get("error") == "expired_token":
                def on_expired(loop, _):
                    lines.append(urwid.Text("⏳ That device code has expired. Please try again."))
                    lines.append(urwid.Divider())
                    lines.append(urwid.Button(
                        "🔁 Retry Login",
                        on_press=lambda btn: loop.set_alarm_in(0.1, lambda *_: run_device_code_flow(email, loop))
                    ))
                    update_body(urwid.ListBox(urwid.SimpleFocusListWalker(lines)))
                loop.set_alarm_in(0.1, on_expired)
                break
            else:
                def on_error(loop, _):
                    update_body(urwid.Pile([
                        urwid.Text(f"❌ Device flow error: {err}"),
                        urwid.Button("Go Back", on_press=lambda btn: authenticate_modern_auth(email, loop))
                    ]))
                loop.set_alarm_in(0.1, on_error)
                break
        else:
            def on_http_error(loop, _):
                update_body(urwid.Pile([
                    urwid.Text(f"❌ HTTP Error: {resp.text}"),
                    urwid.Button("Go Back", on_press=lambda btn: authenticate_modern_auth(email, loop))
                ]))
            loop.set_alarm_in(0.1, on_http_error)
            break

import requests
from urllib.parse import urlencode

def authenticate_modern_auth(email, loop):
    domain = email.split("@")[-1].lower()
    if domain in {"gmail.com", "googlemail.com"}:
        raise RuntimeError(f"💥 Cannot use Microsoft Modern Auth for Google email '{email}'")
    from setup_wizard import update_body, show_provider_screen, STATE
    from mailtui_profile import load_profiles, save_profile
    from client_detector import ensure_metadata_for_email

    result = ensure_metadata_for_email(email)
    if result is None:
        raise ValueError(f"Failed to retrieve metadata for email: {email}")
    issuer, metadata, tenant_id, domain = result

    tenant_id = issuer.split("/")[-2]
    client_id = "33fb5b1b-db86-4cd9-ad37-32afda5db81f"
    scope = MS_SCOPE

    options = [
        urwid.Text(f"🔐 Microsoft Modern Auth is required for domain {domain} (tenant ID {tenant_id}), of which your email {email} is a part."),
        urwid.Text("Please choose your login method:"),
        urwid.Divider(),
    ]

    token_ep = metadata.get("token_endpoint", "")
    device_ep = metadata.get("device_authorization_endpoint", "")

    STATE["step"] = "auth_method_select"
    save_profile(email=email, provider=STATE.get("provider", ""), step=STATE["step"])

    # Only show Device Code if we know it's v2
    if "v2.0" in token_ep and "v2.0" in device_ep:
        options.append(
            urwid.Button(
                "🔐 Device Code (recommended for terminal users)",
                on_press=lambda btn: handle_modern_auth(email, lambda e: run_device_code_flow(e, loop), STATE)
            )
        )
    else:
        print("[INFO] OAuth v1.0 detected — Device Code flow disabled.")

    # ✅ Always show browser login, even if v1
    options.append(
        urwid.Button(
            "🌐 Browser Login (Auth Code Flow)",
            on_press=lambda btn: handle_modern_auth(email, lambda e: run_auth_code_flow(e, loop), STATE)
        )
    )

    options.extend([
        urwid.Divider(),
        urwid.Button("Go Back", on_press=show_provider_screen)
    ])

    update_body(urwid.ListBox(urwid.SimpleFocusListWalker(options)))

from setup_wizard import STATE  # import if not already

def retry_auth_factory(email, loop):
    from setup_wizard import update_body, show_provider_screen

    domain = email.split("@")[-1].lower()

    def retry_auth(btn):
        if domain in {"gmail.com", "googlemail.com"}:
            update_body(urwid.Pile([
                urwid.Text(f"❌ This email domain ({domain}) uses Google OAuth, not Microsoft Auth."),
                urwid.Text("Please return to the setup guide and complete Google OAuth properly."),
                urwid.Divider(),
                urwid.Button("Back", on_press=show_provider_screen)
            ]))
            return

        authenticate_modern_auth(email, loop)

    return retry_auth

def run_device_code_flow(email, loop):
    STATE["loop"] = loop
    from setup_wizard import update_body, show_provider_screen
    from mailtui_profile import load_profiles, save_profile
    from client_detector import get_openid_metadata_for_flow
    import threading
    import urwid
    from spinner import urwid_spinner

    profiles = load_profiles()
    profile = profiles["users"].get(email)
    metadata = profile.get("auth_metadata")

    if metadata:
        run_device_code_flow_continue(email, metadata)
        return

    spinner_text = urwid.Text("⏳ Fetching OpenID metadata...")
    update_body(urwid.Filler(spinner_text))

    stop_flag = [False]
    urwid_spinner(loop, spinner_text, stop_flag)

    def fetch_metadata():
        try:
            result = get_openid_metadata_for_flow(email)
            stop_flag[0] = True
            if not result:
                raise Exception(f"⚠ No OpenID metadata found for domain {email.split('@')[-1]}")
            profile["auth_metadata"] = result
            save_profile(email=email, provider="office365_modern", auth_metadata=result)

            # IMPORTANT: must call on main thread!
            def continue_flow(loop, user_data=None):
                run_device_code_flow_continue(email, result)

            loop.set_alarm_in(0.1, continue_flow)

        except Exception as e:
            stop_flag[0] = True
            def show_error(loop, user_data=None):
                update_body(urwid.Pile([
                    urwid.Text("❌ Metadata fetch failed."),
                    urwid.Text(str(e)),
                    urwid.Divider(),
                    urwid.Button("Go Back", on_press=lambda btn: show_provider_screen())
                ]))
            loop.set_alarm_in(0.1, show_error)

    threading.Thread(target=fetch_metadata).start()

def run_device_code_flow_continue(email, metadata):
    loop = STATE["loop"]
    from setup_wizard import update_body
    import urwid, requests, time
    from mailtui_profile import load_profiles, save_profile

    issuer = metadata.get("issuer", "")
    if not issuer or "/" not in issuer:
        raise Exception("❌ Invalid issuer in metadata — cannot determine tenant ID.")

    tenant_id = issuer.split("/")[-2]
    client_id = "33fb5b1b-db86-4cd9-ad37-32afda5db81f"
    scope = MS_SCOPE

    lines = [
        urwid.Text("📲 Initiating Microsoft Device Code Flow..."),
        urwid.Divider()
    ]
    update_body(urwid.ListBox(urwid.SimpleFocusListWalker(lines)))

    # Device Code Flow
    data = {"client_id": client_id, "scope": scope}
    resp = requests.post(metadata["device_authorization_endpoint"], data=data)
    resp.raise_for_status()
    device_resp = resp.json()

    lines.append(urwid.Text(device_resp["message"]))
    lines.append(urwid.Divider())
    lines.append(urwid.Button("🔙 Go Back", on_press=lambda btn: authenticate_modern_auth(email, loop)))
    update_body(urwid.ListBox(urwid.SimpleFocusListWalker(lines)))

    STATE["step"] = "device_code_wait"
    save_profile(email=email, provider=STATE.get("provider", ""), step=STATE["step"])

    import time
    interval = int(device_resp.get("interval", 5))
    
    def poll_for_token(device_resp, metadata, email, lines, loop):
        token_url = metadata["token_endpoint"]
        client_id = "33fb5b1b-db86-4cd9-ad37-32afda5db81f"
        scope = MS_SCOPE
        interval = int(device_resp.get("interval", 5))

        while True:
            time.sleep(interval)
            poll_data = {
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "client_id": client_id,
                "device_code": device_resp["device_code"],
                "scope": scope
            }
            resp = requests.post(token_url, data=poll_data)

            if resp.status_code == 200:
                access_token = resp.json()["access_token"]
                def on_success(loop, _):
                    lines.append(urwid.Text("✅ Auth success!"))
                    update_body(urwid.ListBox(urwid.SimpleFocusListWalker(lines)))
                    build_imap_connection(email, access_token)
                loop.set_alarm_in(0.1, on_success)
                break

            elif resp.status_code in (400, 428):
                err = resp.json()
                if err.get("error") in ("authorization_pending", "slow_down"):
                    continue
                elif err.get("error") == "expired_token":
                    def on_expired(loop, _):
                        lines.append(urwid.Text("⏳ That device code has expired. Please try again."))
                        lines.append(urwid.Divider())
                        lines.append(urwid.Button(
                            "🔁 Retry Login",
                            on_press=lambda btn: loop.set_alarm_in(0.1, lambda *_: run_device_code_flow(email, loop))
                        ))
                        update_body(urwid.ListBox(urwid.SimpleFocusListWalker(lines)))
                    loop.set_alarm_in(0.1, on_expired)
                    break
                else:
                    def on_error(loop, _):
                        update_body(urwid.Pile([
                            urwid.Text(f"❌ Device flow error: {err}"),
                            urwid.Button("Go Back", on_press=lambda btn: authenticate_modern_auth(email, loop))
                        ]))
                    loop.set_alarm_in(0.1, on_error)
                    break
            else:
                def on_http_error(loop, _):
                    update_body(urwid.Pile([
                        urwid.Text(f"❌ HTTP Error: {resp.text}"),
                        urwid.Button("Go Back", on_press=lambda btn: authenticate_modern_auth(email, loop))
                    ]))
                loop.set_alarm_in(0.1, on_http_error)
                break

def run_auth_code_flow(email, loop):
    STATE["loop"] = loop
    from setup_wizard import update_body, show_provider_screen
    from mailtui_profile import load_profiles, save_profile
    from client_detector import get_openid_metadata_for_flow
    from spinner import urwid_spinner

    import urwid
    import threading

    profiles = load_profiles()
    profile = profiles["users"].get(email)
    metadata = profile.get("auth_metadata")

    # If metadata already exists, skip spinner and continue immediately
    if metadata:
        run_auth_code_flow_continue(email, metadata)
        return

    email_domain = email.split('@')[-1]
    print(f"🔍 Checking OAuth requirement for {email_domain}")

    # UI: Show spinner
    spinner_text = urwid.Text("⏳ Fetching OpenID metadata...")
    update_body(urwid.Filler(spinner_text))
    stop_flag = [False]
    urwid_spinner(loop, spinner_text, stop_flag)

    # Background fetch thread
    def fetch_metadata():
        try:
            result = get_openid_metadata_for_flow(email)
            stop_flag[0] = True
            if not result:
                raise Exception(f"⚠ No OpenID metadata found for domain {email.split('@')[-1]}")
            profile["auth_metadata"] = result
            save_profile(email=email, provider="office365_modern", auth_metadata=result)

            # Resume on UI thread
            def continue_flow(loop, user_data=None):
                run_auth_code_flow_continue(email, result)

            loop.set_alarm_in(0.1, continue_flow)

        except Exception as e:
            stop_flag[0] = True

            def show_error(loop, user_data=None):
                update_body(urwid.Pile([
                    urwid.Text("❌ Metadata fetch failed."),
                    urwid.Text(str(e)),
                    urwid.Divider(),
                    urwid.Button("Go Back", on_press=lambda btn: show_provider_screen())
                ]))

            loop.set_alarm_in(0.1, show_error)

    threading.Thread(target=fetch_metadata).start()

def run_auth_code_flow_continue(email, metadata):
    from setup_wizard import update_body
    import urwid, uuid, webbrowser, requests
    from http.server import BaseHTTPRequestHandler, HTTPServer

    issuer = metadata.get("issuer", "")
    if not issuer or "/" not in issuer:
        raise Exception("❌ Invalid issuer in metadata — cannot determine tenant ID.")

    tenant_id = issuer.split("/")[-2]
    client_id = "33fb5b1b-db86-4cd9-ad37-32afda5db81f"
    redirect_uri = "http://localhost:8765"
    scope = MS_SCOPE
    state = str(uuid.uuid4())

    auth_url = (
        f"{metadata['authorization_endpoint']}?"
        f"client_id={client_id}&"
        f"response_type=code&"
        f"redirect_uri={redirect_uri}&"
        f"response_mode=query&"
        f"scope={scope}&"
        f"state={state}&"
        f"prompt=select_account"
    )

    webbrowser.open(auth_url)

    update_body(urwid.Pile([
        urwid.Text("🌐 A browser window should have opened."),
        urwid.Text("Please log in and authorize MailTUI."),
        urwid.Divider(),
        urwid.Text("Waiting for redirect with authorization code..."),
    ]))

    from typing import Optional
    class AuthServer(HTTPServer):
        def __init__(self, server_address, RequestHandlerClass):
            super().__init__(server_address, RequestHandlerClass)
            self.auth_code: Optional[str] = None

    class AuthHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            from urllib.parse import urlparse, parse_qs
            from typing import cast

            # Tell the type checker "this is our subclass"
            server = cast(AuthServer, self.server)

            query = parse_qs(urlparse(self.path).query)
            code = query.get("code", [None])[0]

            if code:
                self.send_response(200)
                self.end_headers()
                self.wfile.write("✅ Auth successful. You may close this window.".encode())
                server.auth_code = code  # No more warning
            else:
                self.send_response(400)
                self.end_headers()
                self.wfile.write("❌ Missing authorization code.".encode())

    server = AuthServer(("localhost", 8765), AuthHandler)
    server.handle_request()
    auth_code = getattr(server, "auth_code", None)

    if not auth_code:
        raise Exception("❌ Failed to get auth code from browser redirect.")

    # Exchange auth code for access token
    token_data = {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "code": auth_code,
        "redirect_uri": redirect_uri,
        "scope": scope
    }

    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    resp = requests.post(metadata["token_endpoint"], data=token_data, headers=headers)
    resp.raise_for_status()

    access_token = resp.json()["access_token"]
    return build_imap_connection(email, access_token)

def handle_modern_auth(email, flow_func, state, encryption_enabled=False):
    from setup_wizard import update_body, show_provider_screen
    try:
        imap_conn = flow_func(email)
        if imap_conn:
            from mailtui_profile import save_profile
            from setup_wizard import exit_app

            state["step"] = "done"
            save_profile(
                email=email,
                provider="office365_modern",
                imap={
                    "username": email,
                    "server": "outlook.office365.com",
                    "port": 993
                },
                consent=True,
                encryption_enabled=state.get("encrypt_eml", False),
                setup_done=True,
                step=state["step"]  # ✅ make sure step gets passed into save_profile!
            )

            update_body(urwid.Pile([
                urwid.Text("✅ Office365 authentication successful."),
                urwid.Text("You can now use MailTUI."),
                urwid.Divider(),
                urwid.Button("Exit", on_press=exit_app),
                urwid.Button("Cancel Setup", on_press=exit_app)
            ]))
    except Exception as e:
        import traceback
        update_body(urwid.Pile([
            urwid.Text("❌ IMAP setup failed."),
            urwid.Text(f"Error: {str(e)}"),
            urwid.Divider(),
            urwid.Text("Traceback:"),
            urwid.Text(traceback.format_exc()),
            urwid.Divider(),
            urwid.Button("Re-authenticate", on_press=retry_auth_factory(email, STATE["loop"])),
            urwid.Button("Go Back", on_press=show_provider_screen)
        ]))

def build_imap_connection(email, access_token):
    import imaplib, base64

    server = 'outlook.office365.com'
    port = 993
    conn = imaplib.IMAP4_SSL(server, port)

    xoauth2_string = f"user={email}\x01auth=Bearer {access_token}\x01\x01"
    auth_string = base64.b64encode(xoauth2_string.encode("utf-8"))

    try:
        conn.authenticate("XOAUTH2", lambda x: auth_string)
        return conn
    except imaplib.IMAP4.error as e:
        raise Exception(f"IMAP XOAUTH2 authentication failed: {e}")
    except Exception as e:
        raise Exception(f"General IMAP connection error: {e}")

def build_smtp_connection(email, access_token):
    server = "smtp.office365.com"
    port = 587

    xoauth2_string = f"user={email}\x01auth=Bearer {access_token}\x01\x01"
    auth_string = base64.b64encode(xoauth2_string.encode("utf-8")).decode()

    smtp = smtplib.SMTP(server, port)
    smtp.ehlo()
    smtp.starttls()
    smtp.ehlo()
    smtp.docmd("AUTH", "XOAUTH2 " + auth_string)
    return smtp

def authenticate_imap_ui(email: str, client_type: str = 'imap', on_success=None, on_error=None):
    import ssl, imaplib, socket, urwid
    from setup_wizard import update_body  # Keep only the necessary import

    DEFAULT_IMAP_PORT_SSL = 993
    DEFAULT_IMAP_PORT_PLAIN = 143

    class IMAPAuthResult:
        def __init__(self, conn=None, server=None, port=None, username=None, tls="ssl"):
            self.conn = conn
            self.server = server
            self.port = port
            self.username = username
            self.tls = tls

    def _ssl_context(verify=True):
        ctx = ssl.create_default_context()
        if verify:
            ctx.check_hostname = True
            ctx.verify_mode = ssl.CERT_REQUIRED
        return ctx

    def _imap_login(server, port, username, password, tls_mode="ssl", timeout=10):
        socket.setdefaulttimeout(timeout)
        try:
            if tls_mode == "ssl":
                conn = imaplib.IMAP4_SSL(server, port, ssl_context=_ssl_context())
            else:
                conn = imaplib.IMAP4(server, port)
                typ, caps = conn.capability()
                if b"STARTTLS" not in b" ".join(caps):
                    conn.logout()
                    raise RuntimeError("Server does not advertise STARTTLS on this port")
                conn.starttls(ssl_context=_ssl_context())
            conn.login(username, password)
            return conn
        except socket.gaierror as e:
            raise RuntimeError(f"DNS resolution failed for {server}: {e}") from e
        except TimeoutError as e:
            raise RuntimeError(f"TCP timeout connecting to {server}:{port} ({tls_mode})") from e
        except OSError as e:
            raise RuntimeError(f"TCP connect failed to {server}:{port} ({tls_mode}): {e}") from e


    domain = email.split("@")[-1].lower()

    # ---------- build UI widgets (do NOT read .edit_text yet) ----------
    lines = [
        urwid.Text(("title", "📬 MailTUI Setup Wizard – Step 1")),
        urwid.Text("--- IMAP Authentication ---"),
        urwid.Divider(),
    ]

    known = client_type in KNOWN_PROVIDERS
    servers = []  # Initialize servers with a default empty list
    if known:
        info = KNOWN_PROVIDERS[client_type].copy()
        if client_type == "outlook":
            if domain in {"outlook.com", "hotmail.com", "live.com", "msn.com"}:
                info["app_password_info"] = "https://support.microsoft.com/en-us/account-billing/how-to-get-and-use-app-passwords-5896ed9b-4263-e681-128a-a6f2979a7944"
            else:
                info["app_password_info"] = "https://support.microsoft.com/en-us/account-billing/app-passwords-for-a-work-or-school-account-d6dc8c6d-4bf7-4851-ad95-6d07799387e9"

        lines += [
            urwid.Text(f"✔ Detected provider: {client_type.upper()}"),
            urwid.Text(f"  IMAP server(s): {info['imap_server']}"),
            urwid.Text(f"  Port: {info['imap_port']}"),
        ]
        if "app_password_info" in info:
            lines.append(urwid.Text(f"  App password help: {info['app_password_info']}"))

        servers = info["imap_server"]
        if not isinstance(servers, list):
            servers = [servers]
        port_default = int(info.get("imap_port", DEFAULT_IMAP_PORT_SSL))
        prefer_starttls = bool(info.get("prefer_starttls", False))

        # Still allow override if you want; otherwise skip these edits.
        server_edit = None
        port_edit = None
    else:
        lines.append(urwid.Text("⚠ Unknown provider. Please enter your IMAP settings manually."))
        server_edit = urwid.Edit("IMAP server: ")
        port_edit = urwid.Edit("Port (default 993): ")
        lines += [server_edit, port_edit]
        port_default = DEFAULT_IMAP_PORT_SSL
        prefer_starttls = False  # will recompute after submit

    usernames = [email, email.split("@")[0]]
    password_edit = urwid.Edit(f"Password (or app-specific password) for {email}: ", mask="*")
    lines.append(password_edit)

    status = urwid.Text("")              # place for progress/errors
    submit_btn = urwid.Button("Connect") # user action
    lines += [urwid.Divider(), submit_btn, urwid.Divider(), status]

    update_body(lines)  # <-- render the form now

    # ---------- when user clicks Connect, THEN read .edit_text ----------
    def on_submit(_button):
        # Disable button to avoid double-submits (optional)
        _button.set_label("Connecting…")

        # Collect inputs
        if known:
            servers_local = servers[:]  # from provider
            port_text = ""              # no override
            port = port_default
        else:
            server = server_edit.edit_text.strip() if server_edit else ""
            servers_local = [server] if server else []
            port_text = port_edit.edit_text.strip() if port_edit else ""
            port = int(port_text) if port_text else port_default

        password = password_edit.edit_text
        prefer = prefer_starttls if known else (port == DEFAULT_IMAP_PORT_PLAIN)

        if not servers_local or not password:
            status.set_text("⚠ Please fill in server and password.")
            _button.set_label("Connect")
            return

        tried = 0
        last_err = None

        # Show that we’re starting
        status.set_text("🔐 Attempting IMAP login(s)...")
        update_body(lines)

        if port == 993:
            tls_modes = ("ssl",)
        elif port == 143:
            tls_modes = ("starttls",)
        else:
            tls_modes = ("starttls", "ssl") if prefer_starttls else ("ssl", "starttls")


        for user in usernames:
            for server in servers_local:
                for tls_mode in tls_modes:
                    tried += 1
                    lines.insert(-1, urwid.Text(f"Trying {user}@{server}:{port} with {tls_mode.upper()}..."))
                    update_body(lines)
                    try:
                        conn = _imap_login(server, port, user, password, tls_mode=tls_mode)
                        try:
                            conn.capability()
                        except Exception:
                            pass
                        lines.insert(-1, urwid.Text(f"✅ IMAP login successful: {user}@{server}:{port} ({tls_mode})"))
                        update_body(lines)
                        # You can return or transition to the next screen here.
                        result = IMAPAuthResult(conn=conn, server=server, port=port, username=user, tls=tls_mode)

                        lines.insert(-1, urwid.Text(
                            f"✅ IMAP login successful: {user}@{server}:{port} ({tls_mode})"
                        ))
                        update_body(lines)

                        if callable(on_success):
                            on_success(result)
                            return
                        else:
                            # if nobody wants the live conn, close it
                            try:
                                conn.logout()
                            except Exception:
                                pass

                    except Exception as e:
                        last_err = e
                        lines.insert(-1, urwid.Text(f"❌ {type(e).__name__}: {e}"))
                        update_body(lines)
                        if callable(on_error):
                            on_error(e)


        status.set_text(f"⚠ All {tried} login attempts failed. Last error: {last_err!r}" if last_err else "⚠ All login attempts failed.")
        _button.set_label("Connect")

    urwid.connect_signal(submit_btn, "click", on_submit)

def authenticate(email: str, client_type: str = ""):
    if not client_type:
        from client_detector import detect_mx_provider
        client_type = detect_mx_provider(email)
    print(f"🔎 Detected provider: {client_type}")

    if client_type == 'gmail':
        return get_gmail_service()

    if client_type in ('imap', 'generic', 'apple', 'yahoo', 'outlook'):
        # Synchronous IMAP connect from saved profile
        profile = get_profile(email) or {}
        imap_cfg = profile.get('imap', {})
        server = imap_cfg.get('server')
        port = int(imap_cfg.get('port', 993))
        username = imap_cfg.get('username', email)
        tls = imap_cfg.get('tls', 'ssl')

        if not server:
            raise RuntimeError(f"No IMAP server saved for {email}. Run setup first.")

        import getpass
        password = getpass.getpass(f"Password for {username}@{server}: ")

        ctx = ssl.create_default_context()
        if tls == 'ssl' or port == 993:
            conn = imaplib.IMAP4_SSL(server, port, ssl_context=ctx)
        else:
            conn = imaplib.IMAP4(server, port)
            conn.starttls(ssl_context=ctx)

        conn.login(username, password)
        return conn
    
    # Default fallback path for all known and unknown IMAP providers
    return authenticate_imap_ui(email, client_type=client_type, on_success=lambda res: print(f"✅ IMAP auth success: {res.server}:{res.port} as {res.username}"), on_error=lambda err: print(f"❌ IMAP auth error: {err}"))