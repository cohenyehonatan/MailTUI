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
from secure_store import decrypt_to_memory
from client_detector import detect_mx_provider
from getpass import getpass
from pathlib import Path
import logging
logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CLIENT_SECRET_FILE_ALT = os.path.join(BASE_DIR, 'credentials', 'token.pickle')
CLIENT_SECRET_FILE = os.path.join(BASE_DIR, 'credentials', 'client_secrets.json')
CLIENT_SECRET_FILE_ALT = os.path.join(BASE_DIR, 'credentials', 'client_secret.json')
MS_SCOPE = "https://outlook.office.com/IMAP.AccessAsUser.All https://outlook.office.com/SMTP.Send offline_access"

def get_gmail_service(token_file='credentials/token.pickle'):
    creds = None
    if os.path.exists(token_file):
        with open(token_file, 'rb') as token:
            creds = pickle.load(token)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            try:
                creds.refresh(Request())
            except google.auth.exceptions.RefreshError:
                print("⚠️  Token invalid or expired — clearing saved credentials.")
                os.remove(token_file)
                return get_gmail_service(token_file)  # restart flow safely
        else:
            # Try encrypted client secret first
            secret_file = None
            if os.path.exists(CLIENT_SECRET_FILE + '.enc'):
                json_data = decrypt_to_memory(CLIENT_SECRET_FILE + '.enc')
                creds_dict = json.loads(json_data)

                with open("tmp_client_secret.json", "w") as temp:
                    json.dump(creds_dict, temp)
                secret_file = "tmp_client_secret.json"
            elif os.path.exists(CLIENT_SECRET_FILE):
                secret_file = CLIENT_SECRET_FILE
            else:
                print("CLIENT_SECRET_FILE:", CLIENT_SECRET_FILE)
                print("Exists?", os.path.exists(CLIENT_SECRET_FILE))
                print("CLIENT_SECRET_FILE_ALT:", CLIENT_SECRET_FILE_ALT)
                print("Exists?", os.path.exists(CLIENT_SECRET_FILE_ALT))

                if os.path.exists(CLIENT_SECRET_FILE_ALT + '.enc'):
                    json_data = decrypt_to_memory(CLIENT_SECRET_FILE_ALT + '.enc')
                    creds_dict = json.loads(json_data)
                    with open("tmp_client_secret.json", "w") as temp:
                        json.dump(creds_dict, temp)
                    secret_file = "tmp_client_secret.json"
                elif os.path.exists(CLIENT_SECRET_FILE_ALT):
                    secret_file = CLIENT_SECRET_FILE_ALT
                elif os.path.exists(CLIENT_SECRET_FILE) or os.path.exists(CLIENT_SECRET_FILE + '.enc'):
                    # This path was already checked above, but just in case
                    secret_file = CLIENT_SECRET_FILE
                else:
                    raise FileNotFoundError("No valid client_secret file found.")

            flow = InstalledAppFlow.from_client_secrets_file(
                secret_file,
                SCOPES,
                redirect_uri="urn:ietf:wg:oauth:2.0:oob"
            )


            auth_url, _ = flow.authorization_url(prompt='consent')
            print(f"👉 Please visit this URL to authorize the application:\n{auth_url}")

            code = input("🔑 Enter the authorization code: ").strip()
            flow.fetch_token(code=code)

            creds = flow.credentials

            # Clean up temp file
            if secret_file == "tmp_client_secret.json":
                os.remove(secret_file)

        with open(token_file, 'wb') as token:
            pickle.dump(creds, token)

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

import requests
from urllib.parse import urlencode

def authenticate_modern_auth(email):
    from setup_wizard import update_body, show_provider_screen
    from mailtui_profile import load_profiles

    profiles = load_profiles()
    profile = profiles["users"].get(email)
    metadata = profile.get("auth_metadata", {})
    issuer = metadata.get("issuer", "")
    if not issuer or "/" not in issuer:
        raise Exception("❌ Invalid issuer in metadata — cannot determine tenant ID.")

    tenant_id = issuer.split("/")[-2]
    client_id = "33fb5b1b-db86-4cd9-ad37-32afda5db81f"
    scope = MS_SCOPE

    if not metadata:
        raise Exception("⚠ No OpenID metadata found for modern auth domain.")

    options = [
        urwid.Text("Choose your preferred Microsoft login method:"),
        urwid.Divider(),
        urwid.Button("🔐 Device Code (recommended for terminal users)", on_press=lambda btn: handle_modern_auth(email, run_device_code_flow)),
        urwid.Button("🌐 Browser Login (Auth Code Flow)", on_press=lambda btn: handle_modern_auth(email, run_auth_code_flow)),

        urwid.Divider(),
        urwid.Button("Go Back", on_press=show_provider_screen)
    ]
    update_body(urwid.Pile(options))

def retry_auth_factory(email):
    def retry_auth(btn):
        authenticate_modern_auth(email)
    return retry_auth

def run_device_code_flow(email):
    from setup_wizard import update_body
    from mailtui_profile import load_profiles

    profiles = load_profiles()
    profile = profiles["users"].get(email)
    metadata = profile.get("auth_metadata", {})
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
    update_body(urwid.ListBox(urwid.SimpleFocusListWalker(lines)))

    import time
    interval = int(device_resp.get("interval", 5))
    while True:
        time.sleep(interval)
        poll_data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": client_id,
            "device_code": device_resp["device_code"]
        }
        poll_resp = requests.post(metadata["token_endpoint"], data=poll_data)
        if poll_resp.status_code == 200:
            token_data = poll_resp.json()
            access_token = token_data["access_token"]
            lines.append(urwid.Text("✅ Auth success!"))
            update_body(urwid.ListBox(urwid.SimpleFocusListWalker(lines)))
            return build_imap_connection(email, access_token)
        elif poll_resp.status_code in (400, 428):
            err = poll_resp.json()
            if err.get("error") in ("authorization_pending", "slow_down"):
                continue
            else:
                raise Exception(f"❌ Device flow error: {err}")
        else:
            raise Exception(f"❌ Auth failed: {poll_resp.text}")

def run_auth_code_flow(email):
    from setup_wizard import update_body
    from mailtui_profile import load_profiles
    import webbrowser

    profiles = load_profiles()
    profile = profiles["users"].get(email)
    metadata = profile.get("auth_metadata", {})
    issuer = metadata.get("issuer", "")
    if not issuer or "/" not in issuer:
        raise Exception("❌ Invalid issuer in metadata — cannot determine tenant ID.")

    tenant_id = issuer.split("/")[-2]
    client_id = "33fb5b1b-db86-4cd9-ad37-32afda5db81f"
    redirect_uri = "http://localhost:8765"
    scope = MS_SCOPE

    import uuid
    state = str(uuid.uuid4())

    # Construct auth URL
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
        urwid.Text("Waiting on redirect with authorization code..."),
    ]))

    # Start local server to listen for redirect
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class AuthHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            from urllib.parse import urlparse, parse_qs
            query = parse_qs(urlparse(self.path).query)
            code = query.get("code", [None])[0]
            if code:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"Auth successful. You may close this window.")
                self.server.auth_code = code
            else:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"Authorization code missing.")

    server = HTTPServer(("localhost", 8765), AuthHandler)
    server.handle_request()
    auth_code = getattr(server, "auth_code", None)

    if not auth_code:
        raise Exception("❌ Failed to get auth code from browser redirect.")

    # Exchange code for token
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

def handle_modern_auth(email, flow_func):
    from setup_wizard import update_body, show_provider_screen
    try:
        imap_conn = flow_func(email)
        if imap_conn:
            from mailtui_profile import save_profile
            from setup_wizard import STATE, exit_app

            STATE["step"] = "done"
            save_profile(
                email=email,
                provider="office365_modern",
                imap={
                    "username": email,
                    "server": "outlook.office365.com",
                    "port": 993
                },
                consent=True,
                encryption_enabled=STATE.get("encrypt_eml", False),
                setup_done=True
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
            urwid.Button("Re-authenticate", on_press=retry_auth_factory(email)),
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

def authenticate_imap_ui(email: str, client_type: str = 'imap'):
    from setup_wizard import update_body
    domain = email.split('@')[-1].lower()
    lines = []

    lines.append(urwid.Text(("title", "📬 MailTUI Setup Wizard – Step 1")))
    lines.append(urwid.Text("--- IMAP Authentication ---"))
    lines.append(urwid.Divider())

    if client_type == 'office365_modern':
        print("🔐 Using Microsoft OAuth2 for Office365/Entra ID")
        return "modern_auth_required"

    if client_type in KNOWN_PROVIDERS:
        info = KNOWN_PROVIDERS[client_type].copy()
        if client_type == "outlook":
            if domain in {"outlook.com", "hotmail.com", "live.com", "msn.com"}:
                info['app_password_info'] = "https://support.microsoft.com/en-us/account-billing/how-to-get-and-use-app-passwords-5896ed9b-4263-e681-128a-a6f2979a7944"
            else:
                info['app_password_info'] = "https://support.microsoft.com/en-us/account-billing/app-passwords-for-a-work-or-school-account-d6dc8c6d-4bf7-4851-ad95-6d07799387e9"

        lines.append(urwid.Text(f"✔ Detected provider: {client_type.upper()}"))
        lines.append(urwid.Text(f"  IMAP server(s): {info['imap_server']}"))
        lines.append(urwid.Text(f"  Port: {info['imap_port']}"))
        lines.append(urwid.Text(f"  App password help: {info['app_password_info']}"))

        servers = info['imap_server']
        if not isinstance(servers, list):
            servers = [servers]
        port = info['imap_port']
    else:
        lines.append(urwid.Text("⚠ Unknown provider. Please enter your IMAP settings manually."))
        server = input("IMAP server: ").strip()
        port = int(input("Port (default 993): ").strip() or "993")
        servers = [server]

    usernames = [email, email.split('@')[0]]
    password = getpass(f"Password (or app-specific password) for {email}: ")

    lines.append(urwid.Divider())
    lines.append(urwid.Text("🔐 Attempting IMAP login(s)..."))
    lines.append(urwid.Divider())

    # Try each combination
    for user in usernames:
        for server in servers:
            status_line = urwid.Text(f"Trying {user}@{server}:{port}...")
            lines.append(status_line)
            update_body(urwid.ListBox(urwid.SimpleFocusListWalker(lines)))
            try:
                conn = imaplib.IMAP4_SSL(server, port)
                conn.login(user, password)
                success_msg = f"✅ IMAP login successful with username {user}, server {server}, and port {port}"
                lines.append(urwid.Text(success_msg))
                update_body(urwid.ListBox(urwid.SimpleFocusListWalker(lines)))
                return conn
            except Exception as e:
                fail_msg = f"❌ Failed with {user}@{server}: {e}"
                lines.append(urwid.Text(fail_msg))
                update_body(urwid.ListBox(urwid.SimpleFocusListWalker(lines)))

    # Final fallback
    lines.append(urwid.Divider())
    lines.append(urwid.Text("⚠ All login attempts failed. Falling back to manual setup."))

    update_body(urwid.ListBox(urwid.SimpleFocusListWalker(lines)))
    return None

def authenticate(email: str, client_type: str = None):
    if not client_type:
        client_type = detect_mx_provider(email)
    print(f"🔎 Detected provider: {client_type}")

    if client_type == 'gmail':
        print("✅ Using Gmail API via OAuth for Gmail account")
        return get_gmail_service()
    
    # Default fallback path for all known and unknown IMAP providers
    return authenticate_imap_ui(email, client_type=client_type)
    