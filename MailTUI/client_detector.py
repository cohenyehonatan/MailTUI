# client_detector.py

import logging
logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

import requests
import dns.resolver
from mailtui_profile import save_profile

def is_modern_auth_required(email: str) -> bool:
    try:
        res = requests.get("https://login.microsoftonline.com/getuserrealm.srf", params={"login": email})
        data = res.json()
        return data.get("NameSpaceType") in {"Managed", "Federated"}
    except Exception as e:
        log.debug(f"[HRD lookup failed]: {e}")
        return False

def is_definitely_modern_auth(email: str, domain: str) -> bool:
    return is_modern_auth_required(email) and get_openid_metadata(domain)

def get_openid_metadata(domain: str) -> dict:
    try:
        res = requests.get(f"https://login.microsoftonline.com/{domain}/.well-known/openid-configuration", timeout=3)
        if res.status_code == 200:
            data = res.json()
            # Optional: validate presence of core fields
            required_fields = {"token_endpoint", "authorization_endpoint", "issuer"}
            if all(field in data for field in required_fields):
                return data
    except Exception as e:
        log.debug(f"[OpenID config fetch failed for {domain}]: {e}")
    return {}

def detect_mx_provider(email: str) -> str:
    domain = email.split('@')[-1].lower()

    try:
        # --- Step 1: MX record lookup ---
        answers = dns.resolver.resolve(domain, 'MX')
        mx_hosts = [str(r.exchange).lower().rstrip('.') for r in answers]
        log.debug(f"[MX Lookup for {domain}]:")
        for mx in mx_hosts:
            log.debug(f"  → {mx}")

        mx_str = ' '.join(mx_hosts)

        # --- Step 2: Match MX host content ---
        if 'google' in mx_str or 'googlemail' in mx_str or 'gmail-smtp' in mx_str:
            return 'gmail'
        if 'outlook' in mx_str or 'office365' in mx_str or 'protection.outlook' in mx_str:
            metadata = get_openid_metadata(domain)
            if is_modern_auth_required(email) and metadata:
                save_profile(
                    email=email,
                    provider='office365_modern',
                    auth_metadata=metadata
                )
                return 'office365_modern'

            save_profile(email=email, provider='outlook')
            return 'outlook'
        if 'icloud' in mx_str or 'me.com' in mx_str or 'mail.me.com' in mx_str:
            return 'apple'
        if 'yahoodns.net' in mx_str or 'yahoo.com' in mx_str:
            return 'yahoo'
        if 'zoho' in mx_str:
            return 'zoho'
        if 'fastmail' in mx_str:
            return 'fastmail'

        # --- Step 3: Fallback to TXT record heuristic ---
        try:
            txt_records = dns.resolver.resolve(domain, 'TXT')
            txt_str = ' '.join(str(r).lower() for r in txt_records)

            if 'spf.protection.outlook.com' in txt_str or 'ms=' in txt_str or 'd365' in txt_str:
                metadata = get_openid_metadata(domain)
                if is_modern_auth_required(email) and metadata:
                    save_profile(
                        email=email,
                        provider='office365_modern',
                        auth_metadata=metadata
                    )
                    return 'office365_modern'

                save_profile(email=email, provider='outlook')
                return 'outlook'
            if 'include:_spf.google.com' in txt_str or 'google-site-verification' in txt_str:
                return 'gmail'
            if 'zoho' in txt_str:
                return 'zoho'
            if 'icloud.com' in txt_str or 'apple-domain-verification' in txt_str:
                return 'apple'
            if 'yahoo' in txt_str:
                return 'yahoo'
        except Exception as e:
            log.debug(f"[TXT lookup failed]: {e}")

    except Exception as e:
        log.debug(f"[MX detection failed for {domain}]: {e}")

    log.debug("⚠ Could not detect known provider. Defaulting to manual IMAP.")
    return 'imap'