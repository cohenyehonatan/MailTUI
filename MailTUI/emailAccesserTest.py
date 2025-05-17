import base64
from email import policy
from email.parser import BytesParser
from mail_api import get_message_preview, get_html_body, get_message_headers

def get_local_service_from_eml(filepath):
    msg = load_eml_file(filepath)
    return LocalGmailService(msg)

def load_eml_file(filepath):
    with open(filepath, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)
    return msg

class LocalGmailService:
    def __init__(self, eml_message):
        self._msg = eml_message

    def users(self):
        return self

    def messages(self):
        return self

    def get(self, userId=None, id=None, format='full', metadataHeaders=None):
        return self  # Chaining mimic

    def execute(self):
        # Convert email.message.Message to fake Gmail API payload
        return self._convert_to_gmail_payload(self._msg)

    def _convert_to_gmail_payload(self, msg):
        def walk(part):
            payload = {
                'mimeType': part.get_content_type(),
                'headers': [{'name': k, 'value': v} for k, v in part.items()]
            }
            if part.is_multipart():
                payload['parts'] = [walk(p) for p in part.iter_parts()]
            else:
                payload['body'] = {
                    'data': base64.urlsafe_b64encode(part.get_payload(decode=True)).decode('utf-8')
                }
            return payload

        return {
            'payload': walk(msg)
        }

def save_eml(service, message_id, filename):
    raw_msg = service.users().messages().get(userId='me', id=message_id, format='raw').execute()
    raw_data = raw_msg['raw']
    eml_bytes = base64.urlsafe_b64decode(raw_data.encode('UTF-8'))
    
    with open(filename, 'wb') as f:
        f.write(eml_bytes)
    print(f"Saved: {filename}")

def test_local_email_preview(filepath):
    service = get_local_service_from_eml(filepath)
    preview = get_message_preview(service, "dummy_id")
    print("Preview:\n", preview)

    headers = get_message_headers(service, "dummy_id")
    print("\nHeaders:")
    for k, v in headers.items():
        print(f"{k}: {v}")

    html_body = get_html_body(service, "dummy_id")
    print("\nHTML Body:\n", html_body[:200] + '...') if html_body else print("\nNo HTML content found.")