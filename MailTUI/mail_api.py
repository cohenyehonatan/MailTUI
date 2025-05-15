# mail_api.py

import base64
import codecs
import re
import os
from bs4 import BeautifulSoup
from client_detector import detect_mx_provider
from email_clients import EmailClient
from googleapiclient.discovery import build

class GmailClient(EmailClient):
    def __init__(self, creds):
        self.service = build('gmail', 'v1', credentials=creds)

    def search(self, query, max_results=10, page_token=None):
        result = self.service.users().messages().list(
            userId='me',
            q=query,
            maxResults=max_results,
            pageToken=page_token
        ).execute()
        return result.get('messages', []), result.get('nextPageToken'), result.get('resultSizeEstimate', 0)

    def fetch_headers(self, msg_id):
        msg = self.service.users().messages().get(
            userId='me', id=msg_id, format='metadata',
            metadataHeaders=['From', 'Subject', 'Date']
        ).execute()
        headers = msg['payload']['headers']
        return {h['name']: h['value'] for h in headers}

    def fetch_preview(self, msg_id):
        return get_message_preview(self.service, msg_id)

    def fetch_html(self, msg_id):
        return get_html_body(self.service, msg_id)

    def download_eml(self, msg_id, filename):
        msg = self.service.users().messages().get(userId='me', id=msg_id, format='raw').execute()
        raw = base64.urlsafe_b64decode(msg['raw'].encode())
        with open(filename, 'wb') as f:
            f.write(raw)
        return filename

class OutlookModernClient(EmailClient):
    def __init__(self, service):
        self.service = service

    def search(self, query, max_results=10, page_token=None):
        return search_messages(self.service, query, max_results, page_token)

    def fetch_headers(self, message_id):
        return get_message_headers(self.service, message_id)

    def fetch_preview(self, message_id):
        return get_message_preview(self.service, message_id)

    def download_eml(self, message_id, filename):
        return save_eml(self.service, message_id, filename)

class IMAPClient(EmailClient):
    def __init__(self, email, connection):
        self.email = email
        self.conn = connection

    def search(self, query, max_results=10, page_token=None):
        return search_messages(self.conn, query, max_results, page_token)

    def fetch_headers(self, message_id):
        return get_message_headers(self.conn, message_id)

    def fetch_preview(self, message_id):
        return get_message_preview(self.conn, message_id)

    def download_eml(self, message_id, filename):
        return save_eml(self.conn, message_id, filename)
    
class OutlookIMAPClient(IMAPClient):
    def __init__(self, email, imap_conn):
        super().__init__(email, imap_conn)

def get_email_client(email, creds, client_type):
    if client_type == "gmail":
        return GmailClient(creds)
    elif client_type == "outlook":
        return OutlookIMAPClient(email, creds)
    elif client_type == "office365_modern":
        return OutlookModernClient(creds)
    elif client_type in ("apple", "yahoo", "generic", "imap"):
        return IMAPClient(email, creds)
    else:
        raise ValueError(f"Unsupported email provider: {client_type}")


def get_message_preview(service, msg_id):
    msg = service.users().messages().get(userId='me', id=msg_id, format='full').execute()

    def walk_parts(part):
        if part['mimeType'] == 'text/plain':
            return decode_body(part)
        if part['mimeType'] == 'text/html':
            html = decode_body(part)
            if html:
                soup = BeautifulSoup(html, 'html.parser')
                return soup.get_text(separator="\n")
        for sub in part.get('parts', []):
            result = walk_parts(sub)
            if result:
                return result
        return None

    return walk_parts(msg['payload'])

def search_messages(service, query, max_results=10, page_token=None):
    request = service.users().messages().list(
        userId='me',
        q=query,
        maxResults=max_results,
        pageToken=page_token
    )
    result = request.execute()
    return result.get('messages', []), result.get('nextPageToken'), result.get('resultSizeEstimate', 0)

def get_message_headers(service, msg_id):
    msg = service.users().messages().get(userId='me', id=msg_id, format='metadata', metadataHeaders=['From', 'Subject', 'Date']).execute()
    headers = msg['payload']['headers']
    return {h['name']: h['value'] for h in headers}

def get_html_body(service, msg_id):
    msg = service.users().messages().get(userId='me', id=msg_id, format='full').execute()

    def walk_parts(part):
        if part['mimeType'] == 'text/html':
            html = decode_body(part)
            if html:
                return html
        for sub in part.get('parts', []):
            result = walk_parts(sub)
            if result:
                return result
        return None

    return walk_parts(msg['payload'])

def decode_body(part):
    data = part['body'].get('data')
    if not data:
        return None

    raw = base64.urlsafe_b64decode(data)

    charset = 'utf-8'
    for header in part.get('headers', []):
        if header['name'].lower() == 'content-type':
            match = re.search(r'charset=["\']?([\w\-]+)', header['value'], re.IGNORECASE)
            if match:
                charset = match.group(1).lower()

    try:
        return raw.decode(charset, errors='strict')
    except UnicodeDecodeError:
        try:
            return raw.decode('latin1').encode('utf-8').decode('utf-8', errors='replace')
        except Exception:
            pass

    try:
        return raw.decode('utf-8', errors='replace')
    except:
        return raw.decode('ascii', errors='replace')

def unescape_preview(preview: str) -> str:
    try:
        raw_bytes = codecs.decode(preview, 'unicode_escape').encode('latin1')
    except Exception:
        raw_bytes = preview.encode('latin1', errors='replace')

    try:
        preview = raw_bytes.decode('windows-1252')
    except Exception:
        preview = raw_bytes.decode('utf-8', errors='replace')

    preview = preview.replace('\\n', '\n').replace('\\t', '\t').replace('\\r', '')
    preview = preview.replace('\r', '')
    preview = re.sub(r'\n{3,}', '\n\n', preview)
    preview = '\n'.join(line.strip() for line in preview.splitlines())

    return preview.strip()

from secure_store import encrypt_file

def save_eml(service, msg_id, filename, encrypt=False):
    from base64 import urlsafe_b64decode
    import email
    from googleapiclient.errors import HttpError

    try:
        msg = service.users().messages().get(userId='me', id=msg_id, format='raw').execute()
        raw = msg['raw']
        raw_bytes = urlsafe_b64decode(raw.encode('UTF-8'))

        temp_path = filename + ".tmp"
        with open(temp_path, "wb") as f:
            f.write(raw_bytes)

        if encrypt:
            enc_filename = filename + ".enc" if not filename.endswith(".eml") else filename + ".enc"
            encrypt_file(temp_path, enc_filename)
            os.remove(temp_path)
        else:
            os.rename(temp_path, filename)


        print(f"✅ Email saved as {'encrypted' if encrypt else 'plaintext'} file: {filename}")

    except HttpError as error:
        print(f"❌ An error occurred: {error}")
