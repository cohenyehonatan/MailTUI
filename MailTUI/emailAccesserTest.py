from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import imaplib
import os
import pickle
import base64

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']
CLIENT_SECRET_FILE = '/Users/jonathancohen/emailAccesser/client_secrets.json'
TOKEN_FILE = 'token.pickle'

def get_gmail_service():
    creds = None
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, 'rb') as token:
            creds = pickle.load(token)
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(CLIENT_SECRET_FILE, SCOPES)
            creds = flow.run_local_server(port=0)
        with open(TOKEN_FILE, 'wb') as token:
            pickle.dump(creds, token)
    return build('gmail', 'v1', credentials=creds)

def save_eml(service, message_id, filename):
    raw_msg = service.users().messages().get(userId='me', id=message_id, format='raw').execute()
    raw_data = raw_msg['raw']
    eml_bytes = base64.urlsafe_b64decode(raw_data.encode('UTF-8'))
    
    with open(filename, 'wb') as f:
        f.write(eml_bytes)
    print(f"Saved: {filename}")

def search_and_download():
    service = get_gmail_service()
    query = input("Enter Gmail search query (e.g. from:dropbox subject:login): ")
    
    results = service.users().messages().list(userId='me', q=query, maxResults=5).execute()
    messages = results.get('messages', [])
    
    if not messages:
        print("No messages found.")
        return
    
    for i, msg in enumerate(messages):
        msg_data = service.users().messages().get(userId='me', id=msg['id'], format='metadata', metadataHeaders=['Subject', 'From', 'Date']).execute()
        headers = msg_data['payload']['headers']
        hdr = {h['name']: h['value'] for h in headers}
        print(f"[{i}] From: {hdr.get('From')} | Subject: {hdr.get('Subject')} | Date: {hdr.get('Date')}")
    
    choice = int(input("Enter the number of the email to download as .eml: "))
    selected_msg_id = messages[choice]['id']
    save_eml(service, selected_msg_id, f"email_{selected_msg_id}.eml")

search_and_download()