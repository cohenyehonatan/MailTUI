import base64
import os
import sys
from email import policy
from email.parser import BytesParser

# Make parent directory importable
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from mail_api import get_message_preview, get_html_body, get_message_headers

# Load .eml into fake Gmail-like service
def load_eml_file(filepath):
    with open(filepath, 'rb') as f:
        return BytesParser(policy=policy.default).parse(f)

class LocalGmailService:
    def __init__(self, eml_message):
        self._msg = eml_message

    def users(self): return self
    def messages(self): return self
    def get(self, userId=None, id=None, format='full', metadataHeaders=None): return self
    def execute(self): return {'payload': self._walk(self._msg)}

    def _walk(self, part):
        payload = {
            'mimeType': part.get_content_type(),
            'headers': [{'name': k, 'value': v} for k, v in part.items()]
        }
        if part.is_multipart():
            payload['parts'] = [self._walk(p) for p in part.iter_parts()]
        else:
            payload['body'] = {
                'data': base64.urlsafe_b64encode(part.get_payload(decode=True)).decode('utf-8')
            }
        return payload

def test_local_email_preview(filepath):
    try:
        service = LocalGmailService(load_eml_file(filepath))

        print(f"\n--- Testing: {os.path.basename(filepath)} ---")

        preview = get_message_preview(service, "dummy_id")
        print("Preview:\n", preview)

        headers = get_message_headers(service, "dummy_id")
        print("\nHeaders:")
        for k, v in headers.items():
            print(f"{k}: {v}")

        html_body = get_html_body(service, "dummy_id")
        if html_body:
            print("\nHTML Body:\n", html_body[:200] + '...')
        else:
            print("\nNo HTML content found.")
    except Exception as e:
        print(f"⚠️ Error processing {filepath}: {e}")

def run_preview_on_all_emails():
    EMAILS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../test_emails"))
    if not os.path.exists(EMAILS_DIR):
        print("⚠️ Directory does not exist:", EMAILS_DIR)
        return

    for filename in os.listdir(EMAILS_DIR):
        if filename.startswith('.') or not filename.endswith('.eml'):
            continue
        filepath = os.path.join(EMAILS_DIR, filename)
        if os.path.isfile(filepath):
            test_local_email_preview(filepath)

if __name__ == "__main__":
    run_preview_on_all_emails()