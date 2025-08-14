# mail_api.py

import base64
import codecs
import re
import os
from bs4 import BeautifulSoup
from client_detector import detect_mx_provider
from typing import Union
from email_clients import EmailClient
from googleapiclient.discovery import build
import imaplib, ssl
from email.parser import BytesParser
from email.policy import default as email_default_policy
from mailtui_profile import get_profile
import getpass
import shutil
import tempfile
from secure_store import encrypt_file

class GmailClient(EmailClient):
    def __init__(self, creds):
        self.service = build('gmail', 'v1', credentials=creds)

    def search(self, query, max_results=10, page_token=None) -> Union[None, tuple[list[dict], Union[str, None], int]]:
        result = self.service.users().messages().list(
            userId='me',
            q=query,
            maxResults=max_results,
            pageToken=page_token
        ).execute()
        return result.get('messages', []), result.get('nextPageToken'), result.get('resultSizeEstimate', 0)

    def fetch_headers(self, message_id):
        msg = self.service.users().messages().get(
            userId='me', id=message_id, format='metadata',
            metadataHeaders=['From', 'Subject', 'Date']
        ).execute()
        headers = msg['payload']['headers']
        return {h['name']: h['value'] for h in headers}

    def fetch_preview(self, message_id) -> Union[str, None]:
        return _gmail_get_message_preview(self.service, message_id)

    def fetch_html(self, msg_id):
        return _gmail_get_html_body(self.service, msg_id)

    def download_eml(self, message_id, filename):
        # direct
        msg = self.service.users().messages().get(userId='me', id=message_id, format='raw').execute()
        import base64
        raw = base64.urlsafe_b64decode(msg['raw'].encode())
        with open(filename, 'wb') as f:
            f.write(raw)
        return filename
    
    def fetch_all_headers_text(self, message_id) -> str:
        """
        Return the exact header block as text (up to the first blank line),
        preserving folding/whitespace exactly like Mail.app shows.
        """
        msg = self.service.users().messages().get(
            userId='me', id=message_id, format='raw'
        ).execute()
        import base64
        raw_bytes = base64.urlsafe_b64decode(msg['raw'].encode('utf-8'))
        raw = raw_bytes.decode('utf-8', errors='replace')
        # Slice header block: everything before the first blank line
        head, _, _ = raw.partition('\r\n\r\n')
        if not head:
            head, _, _ = raw.partition('\n\n')
        return head or raw  # fallback if weird line endings

    def fetch_raw_source(self, message_id) -> str:
        """
        Return the entire raw MIME source decoded to text (best-effort).
        """
        msg = self.service.users().messages().get(
            userId='me', id=message_id, format='raw'
        ).execute()
        import base64
        raw_bytes = base64.urlsafe_b64decode(msg['raw'].encode('utf-8'))
        return raw_bytes.decode('utf-8', errors='replace')

class OutlookModernClient(EmailClient):
    def __init__(self, service):
        self.service = service

    def search(self, query, max_results=10, page_token=None) -> Union[None, tuple[list[dict], Union[str, None], int]]:
        return search_messages(self.service, query, max_results, page_token)

    def fetch_headers(self, message_id):
        return get_message_headers(self.service, message_id)

    def fetch_preview(self, message_id):
        return self.service.fetch_preview(message_id)

    def download_eml(self, message_id, filename):
        return save_eml(self.service, message_id, filename)
class IMAPClient(EmailClient):
    def __init__(self, email, connection):
        self.email = email
        self.conn = connection  # may be None

    def _ensure_conn(self):
        if self.conn is None:
            self.conn = _connect_imap_from_profile(self.email)

    def search(self, query, max_results=10, page_token=None) -> Union[None, tuple[list[dict], Union[str, None], int]]:
        self._ensure_conn()
        messages, next_page_token, estimate = imap_search(self.conn, query, max_results, page_token)
        return messages, str(next_page_token) if next_page_token is not None else None, estimate if estimate is not None else 0

    def fetch_headers(self, message_id):
        self._ensure_conn()
        return imap_fetch_headers(self.conn, str(message_id).encode())

    def fetch_preview(self, message_id):
        self._ensure_conn()
        return imap_fetch_preview(self.conn, str(message_id).encode())

    def fetch_html(self, message_id):  # <-- add this
        self._ensure_conn()
        return imap_fetch_html(self.conn, str(message_id).encode())

    def download_eml(self, message_id, filename):
        self._ensure_conn()
        return imap_download_eml(self.conn, str(message_id).encode(), filename)
    
    def fetch_all_headers_text(self, message_id) -> str:
        """
        Fetch the wire-format header block via IMAP (BODY.PEEK[HEADER]),
        keeping original folding/whitespace.
        """
        self._ensure_conn()
        return imap_fetch_header_text(self.conn, str(message_id).encode())

    def fetch_raw_source(self, message_id) -> str:
        """
        Fetch the full raw MIME, decode to text (best-effort).
        """
        self._ensure_conn()
        typ, data = self.conn.uid("FETCH", str(message_id), "(BODY.PEEK[])")
        if typ != "OK" or not data or data[0] is None:
            raise RuntimeError("IMAP FETCH full message failed")
        raw_bytes = data[0][1]
        # Don't be fancy: show bytes as utf-8 with fallback so you see *something*
        try:
            return raw_bytes.decode('utf-8', errors='replace')
        except Exception:
            return raw_bytes.decode('latin1', errors='replace')

    
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
    
def get_message_preview(client_or_service, msg_id):
    """Compat wrapper: accepts EmailClient or Gmail service."""
    # New path: client interface
    if hasattr(client_or_service, "fetch_preview"):
        return client_or_service.fetch_preview(msg_id)
    # Legacy path: raw Gmail service
    if hasattr(client_or_service, "users"):
        return _gmail_get_message_preview(client_or_service, msg_id)
    raise TypeError("Unsupported object passed to get_message_preview()")

def get_html_body(client_or_service, msg_id):
    """Compat wrapper: accepts EmailClient or Gmail service."""
    if hasattr(client_or_service, "fetch_html"):
        return client_or_service.fetch_html(msg_id)
    if hasattr(client_or_service, "users"):
        return _gmail_get_html_body(client_or_service, msg_id)
    raise TypeError("Unsupported object passed to get_html_body()")


def _gmail_get_message_preview(service, msg_id):
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

def imap_select_inbox(conn):
    typ, _ = conn.select("INBOX", readonly=True)
    if typ != "OK":
        raise RuntimeError("IMAP SELECT INBOX failed")

def imap_search(conn, query, max_results=10, page_token=None):
    """
    Returns (messages, next_page_token, estimate)
    - messages: [{'id': uid_str}, ...] newest first
    - next_page_token: int offset or None
    - estimate: None (we can compute len(all_uids) if you want)
    """
    imap_select_inbox(conn)

    q = (query or "").strip()
    # Prefer TEXT search (matches headers+body) for a simple UX
    # Try explicit UTF-8 first; dovecot usually supports it.
    try:
        typ, data = conn.uid("SEARCH", "CHARSET", "UTF-8", "TEXT", q) if q else conn.uid("SEARCH", None, "ALL")
    except imaplib.IMAP4.error:
        # Fallback: no CHARSET support
        typ, data = conn.uid("SEARCH", None, "TEXT", q) if q else conn.uid("SEARCH", None, "ALL")

    if typ != "OK" or not data or not data[0]:
        return [], None, None

    all_uids = data[0].split()
    # newest first
    all_uids = list(reversed(all_uids))

    start = int(page_token or 0)
    end = start + max_results
    page_uids = all_uids[start:end]
    next_token = end if end < len(all_uids) else None

    messages = [{"id": uid.decode()} for uid in page_uids]
    return messages, next_token, None


def imap_fetch_headers(conn, uid):
    imap_select_inbox(conn)
    # Fetch common headers
    typ, data = conn.uid("FETCH", uid, '(BODY.PEEK[HEADER.FIELDS (From Subject Date)])')
    if typ != "OK" or not data or data[0] is None:
        raise RuntimeError("IMAP FETCH headers failed")

    raw = data[0][1]
    msg = BytesParser(policy=email_default_policy).parsebytes(raw)
    headers = {
        "From": msg.get("From", ""),
        "Subject": msg.get("Subject", ""),
        "Date": msg.get("Date", ""),
    }
    return headers


def imap_fetch_preview(conn, uid, max_bytes=4096):
    imap_select_inbox(conn)
    # Grab a small slice of the text body as preview (server-side partial fetch)
    # Try HTML first? Simpler: fetch TEXT chunk.
    typ, data = conn.uid("FETCH", uid, f"(BODY.PEEK[TEXT]<0.{max_bytes}>)")
    if typ != "OK" or not data or data[0] is None:
        return None
    preview = data[0][1].decode(errors="replace")
    # Normalize whitespace a bit
    preview = re.sub(r'\s+\n', '\n', preview)
    preview = re.sub(r'\n{3,}', '\n\n', preview)
    return preview.strip()[:max_bytes]


def imap_download_eml(conn, uid, filename):
    imap_select_inbox(conn)
    typ, data = conn.uid("FETCH", uid, "(BODY.PEEK[])")
    if typ != "OK" or not data or data[0] is None:
        raise RuntimeError("IMAP FETCH full message failed")
    raw = data[0][1]
    with open(filename, "wb") as f:
        f.write(raw)
    return filename

def _connect_imap_from_profile(email):
    profile = get_profile(email)
    imap_cfg = (profile or {}).get("imap", {})
    server = imap_cfg.get("server")
    port = int(imap_cfg.get("port", 993))
    username = imap_cfg.get("username", email)
    tls = imap_cfg.get("tls", "ssl")  # "ssl" or "starttls"

    if not server:
        raise RuntimeError(f"No IMAP server saved for {email}")

    # TODO: replace with your secure store
    password = getpass.getpass(f"Password for {username}@{server}: ")

    if port == 993 or tls == "ssl":
        conn = imaplib.IMAP4_SSL(server, port)  # use your ssl_context if you have one
    else:
        conn = imaplib.IMAP4(server, port)
        conn.starttls()
    conn.login(username, password)
    return conn

def imap_fetch_html(conn, uid):
    """
    Return the text/html body of a message as a Unicode string, or None if not present.
    Prefers inline/related/alternative HTML parts over attachments.
    """
    imap_select_inbox(conn)
    # Fetch the full message so we can correctly walk nested multiparts.
    typ, data = conn.uid("FETCH", uid, "(BODY.PEEK[])")
    if typ != "OK" or not data or data[0] is None:
        return None

    raw = data[0][1]
    msg = BytesParser(policy=email_default_policy).parsebytes(raw)

    def _decode_part_to_str(part):
        payload = part.get_payload(decode=True) or b""
        # Try declared charset, then fall back sanely
        charset = (part.get_content_charset()
                   or part.get_param('charset')
                   or 'utf-8')
        try:
            return payload.decode(charset, errors="strict")
        except Exception:
            try:
                return payload.decode('utf-8', errors='replace')
            except Exception:
                return payload.decode('latin1', errors='replace')

    # First pass: true text/html, not marked as attachment
    for part in msg.walk():
        if part.get_content_type() == "text/html":
            disp = (part.get("Content-Disposition") or "").lower()
            if "attachment" in disp:
                continue
            return _decode_part_to_str(part)

    # Second pass: accept html even if disposition is missing/odd
    for part in msg.walk():
        if part.get_content_type() == "text/html":
            return _decode_part_to_str(part)

    # No HTML found -> None (caller can fall back to preview/plain if desired)
    return None

def imap_fetch_header_text(conn, uid) -> str:
    """
    Return the entire header block as text using BODY.PEEK[HEADER].
    This preserves exactly what the server has on disk (line folding etc.).
    """
    imap_select_inbox(conn)
    typ, data = conn.uid("FETCH", uid, "(BODY.PEEK[HEADER])")
    if typ != "OK" or not data or data[0] is None:
        raise RuntimeError("IMAP FETCH header block failed")
    raw = data[0][1]
    # Best-effort decode; headers SHOULD be ASCII + encoded-words, but servers vary.
    try:
        return raw.decode('utf-8', errors='replace')
    except Exception:
        return raw.decode('latin1', errors='replace')

def search_messages(service, query, max_results=10, page_token=None):
    request = service.users().messages().list(
        userId='me',
        q=query,
        maxResults=max_results,
        pageToken=page_token
    )
    result = request.execute()
    return result.get('messages', []), result.get('nextPageToken'), result.get('resultSizeEstimate', 0)

def get_message_headers(client_like, message_id):
    """
    Accepts either:
      - an IMAPClient with .fetch_headers(message_id)
      - a Gmail API wrapper with .service and your old code path
    """
    # IMAP path
    if hasattr(client_like, "fetch_headers"):
        return client_like.fetch_headers(message_id)
     # Gmail path (example; adapt to your old code)
    service = getattr(client_like, "service", None)
    if service is not None:
        msg = service.users().messages().get(userId='me', id=message_id, format='metadata', metadataHeaders=['From', 'Subject', 'Date']).execute()
        headers = msg['payload']['headers']
        return {h['name']: h['value'] for h in headers}
    raise TypeError("Unsupported client passed to get_message_headers()")

def _gmail_get_html_body(service, msg_id):
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

def save_eml(client_or_service, msg_id, filename, encrypt=False):
    """
    Compat wrapper:
      - If given an EmailClient (GmailClient/IMAPClient), calls .download_eml(...)
      - If given a raw Gmail `service`, fetches format='raw' and writes it
    Returns the path written.
    """
    # ensure target directory exists
    target_dir = os.path.dirname(filename) or "."
    os.makedirs(target_dir, exist_ok=True)

    # temp path to write first (atomic-ish move later)
    fd, temp_path = tempfile.mkstemp(prefix="mailtui_", suffix=".eml", dir=target_dir)
    os.close(fd)

    out_path = filename
    try:
        # --- Preferred path: EmailClient interface (IMAP or Gmail wrapper) ---
        if hasattr(client_or_service, "download_eml"):
            client_or_service.download_eml(msg_id, temp_path)

        # --- Legacy path: raw Gmail service object ---
        elif hasattr(client_or_service, "users"):
            try:
                from googleapiclient.errors import HttpError
            except Exception:
                # don't hard-crash if the lib isn't installed; raise a clearer error
                raise RuntimeError("googleapiclient is required for saving via raw Gmail service")
            try:
                msg = client_or_service.users().messages().get(
                    userId='me', id=msg_id, format='raw'
                ).execute()
            except HttpError as e:
                # clean up the temp file and re-raise
                try: os.remove(temp_path)
                except Exception: pass
                raise

            raw = msg['raw']
            raw_bytes = base64.urlsafe_b64decode(raw.encode('utf-8'))
            with open(temp_path, "wb") as f:
                f.write(raw_bytes)

        else:
            raise TypeError("Unsupported object passed to save_eml(); pass an EmailClient or Gmail service")

        # --- Optional encryption step ---
        if encrypt:
            # if caller didn't add .enc, add it
            out_path = filename if filename.endswith(".enc") else (filename + ".enc")
            encrypt_file(temp_path, out_path)
            os.remove(temp_path)
        else:
            # atomic-ish move to final location
            shutil.move(temp_path, filename)
            out_path = filename

        print(f"✅ Email saved as {'encrypted' if encrypt else 'plaintext'} file: {out_path}")
        return out_path

    except Exception:
        # best-effort cleanup
        try: os.remove(temp_path)
        except Exception: pass
        raise