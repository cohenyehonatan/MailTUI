# 📬 MailTUI — A Beautiful, Offline-Capable Terminal Email Client

**MailTUI** is a privacy-first, offline-friendly terminal mail client (like Gmail or Outlook — but in your terminal). It's 2025, after all, and after looking for something like this myself for *months*, I've decided to make it myself. It’s 100% open-source, fully auditable, and lets you read, search, preview, and locally store your emails using keyboard-driven workflows.

---

## Preview

![MailTUI demo](docs/preview.gif)  
_or [watch a live Asciinema demo](https://asciinema.org/a/xyz123)_

---

## Features

### 🔒 Secure by Design
- Modern OAuth2 login for Gmail (Google) and Outlook/Office365 (Microsoft)
- Read-only by default — no email sending, no IMAP writes
- Local encryption using PBKDF2 + Fernet, optional password enforcement
- Offline search and preview — no resync required once downloaded
- No telemetry. No external API calls. No bullshit.

### 💻 Terminal-First UX
- Google-style search (e.g., `from:me after:2023/01/01 has:attachment`)
- Clean HTML or plaintext previews, rendered in the terminal
- One-key `.eml` export + decryption support
- Lightweight `urwid` TUI interface — fast, clean, minimal

### 🛠️ Fully Configurable
- Works with any IMAP provider: Gmail, iCloud, Yahoo, Zoho, Fastmail, custom domains
- Saved profiles — no repeated setup
- Works with system-level encryption, network/VPN constraints, or air-gapped setups

---

## Why MailTUI?

- You're tired of bloated webmail clients.
- You want to search, browse, and read email **offline**.
- You care about privacy, encryption, and control.
- You live in the terminal — and your email should too.

---

## Installation

```bash
git clone https://github.com/[myname]/mailtui.git
cd mailtui
pip install -r requirements.txt
```

---

Usage

`<your Python location> main.py`

First-time users will be guided through a step-by-step setup wizard. Returning users can choose from saved profiles. 

---

Setup Wizard

When asked to choose a profile, type `new`, then follow the instructions in the wizard.

The wizard auto-detects providers based on domain and DNS records, supports Gmail, Microsoft 365, Yahoo, Zoho, and even enterprise/education domains using Modern Auth/OAuth2 when needed, and walks you through *all* of the setup process, for *any* provider. No worries.

---

Keyboard Shortcuts

```text
enter        → Search for emails
1-9          → Open email preview
n / p        → Next / Previous page
d            → Download email as .eml
b            → Clear preview pane
f            → Show filter picker
→            → Apply filter to search
H            → General help
?            → Filter cheat sheet
esc / q      → Close or quit
```

---

Profile Management

MailTUI automatically saves connected accounts to ~/.mailtui_profile.json.

---

Requirements
- Python 3.10+ (ideal, though tested on 3.9–3.13)
- pip

`pip install -r requirements.txt`

---

Troubleshooting
* OAuth2 fails? Make sure you’re using the correct account/option when creating or using your OAuth2 credentials, and that you have entered the correct email address.
* Can’t find credentials? Make sure your `client_secret.json` is placed under `./credentials/` for Gmail, else contact your IT team.
* IMAP login failed? You probably need an app-specific password. The wizard provides provider-specific instructions.

---

License

MailTUI is open-source under the [MPL-2.0 (Mozilla Public License Version 2.0)](LICENSE).

---

Credits

Built by [Your Name]. Inspired by the tools I wish existed. Contributions welcome!