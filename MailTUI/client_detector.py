# client_detector.py

import email
import logging
logging.basicConfig(filename='MailTUI.log',level=logging.DEBUG)
log = logging.getLogger(__name__)

import requests
from dns.resolver import resolve
from dns.resolver import NoAnswer, NXDOMAIN
from mailtui_profile import save_profile

def get_openid_metadata_tenant(domain: str) -> dict:
    """Strict: tenant-only. No `common` fallback. Use for detection."""
    url = f"https://login.microsoftonline.com/{domain}/v2.0/.well-known/openid-configuration"
    try:
        r = requests.get(url, timeout=3)
        if r.status_code == 200:
            data = r.json()
            required = {"token_endpoint","authorization_endpoint","issuer","device_authorization_endpoint"}
            if all(k in data for k in required):
                return data
    except Exception:
        pass
    return {}

def get_openid_metadata_for_flow(email: str) -> dict:
    """Permissive: try tenant first, then `common`. Use inside auth flows."""
    domain = email.split('@')[-1]
    urls = [
        f"https://login.microsoftonline.com/{domain}/v2.0/.well-known/openid-configuration",
        "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration",
    ]
    for url in urls:
        try:
            r = requests.get(url, timeout=3)
            if r.status_code == 200:
                data = r.json()
                required = {"token_endpoint","authorization_endpoint","issuer","device_authorization_endpoint"}
                if all(k in data for k in required):
                    return {**data, "_source_url": url}
        except Exception:
            pass
    return {}

def is_modern_auth_required(email: str) -> bool:
    try:
        r = requests.get("https://login.microsoftonline.com/getuserrealm.srf", params={"login": email}, timeout=3)
        data = r.json()
        # Only trust HRD if it clearly says AAD (Managed or Federated)
        return data.get("NameSpaceType") in {"Managed", "Federated"}
    except Exception:
        return False

def is_definitely_modern_auth(email: str, domain: str) -> bool:
    # strict check: HRD + tenant metadata
    return is_modern_auth_required(email) and bool(get_openid_metadata_tenant(domain))

# def get_openid_metadata(email: str) -> dict:
#     domain = email.split('@')[-1]

#     urls = [
#         f"https://login.microsoftonline.com/{domain}/v2.0/.well-known/openid-configuration",
#         "https://login.microsoftonline.com/common/v2.0/.well-known/openid-configuration"
#     ]

#     for url in urls:
#         try:
#             res = requests.get(url, timeout=3)
#             if res.status_code == 200:
#                 data = res.json()
#                 required = {"token_endpoint", "authorization_endpoint", "issuer", "device_authorization_endpoint"}
#                 if all(k in data for k in required):
#                     return data
#                 else:
#                     log.debug(f"[{email}] OpenID metadata at {url} is incomplete.")
#             else:
#                 log.debug(f"[{email}] OpenID metadata fetch failed at {url} with status {res.status_code}")
#         except Exception as e:
#             log.debug(f"[{email}] OpenID config fetch failed at {url}: {e}")

#     return {}

# ensure_metadata_for_email: only call this when provider == 'office365_modern'
def ensure_metadata_for_email(email, provider="office365_modern"):
    from mailtui_profile import load_profiles, save_profile, debug_log
    profiles = load_profiles()
    profile = profiles["users"].get(email) or {}
    metadata = profile.get("auth_metadata")

    if not metadata:
        # permissive (tenant then common) ONLY during flow
        metadata = get_openid_metadata_for_flow(email)
        if not metadata:
            d = email.split('@')[-1].lower()
            raise Exception(f"⚠ No OpenID metadata found for modern auth domain {d}.")
        save_profile(email=email, provider=provider, auth_metadata=metadata)

    issuer = metadata.get("issuer", "")
    if not issuer or "/" not in issuer:
        raise Exception("❌ Invalid issuer in metadata — cannot determine tenant ID.")

    tenant_id = issuer.split("/")[-2]
    domain = email.split('@')[-1].lower()
    return issuer, metadata, tenant_id, domain

def detect_mx_provider(email: str) -> str:
    domain = email.split('@')[-1].lower()
    log.info(f"[detect] domain={domain}")

    try:
        # --- Step 1: MX record lookup ---
        answers = resolve(domain, 'MX')
        from typing import cast
        import dns.rdtypes.ANY.MX

        mx_hosts = [
            str(cast(dns.rdtypes.ANY.MX.MX, r).exchange).lower().rstrip('.')
            for r in answers
        ]
        log.debug(f"[MX Lookup for {domain}]:")
        for mx in mx_hosts:
            log.debug(f"  → {mx}")

        mx_str = ' '.join(mx_hosts)
        log.info(f"[detect] mx_str={mx_str}")

        # --- Step 2: Match MX host content ---
        if 'google' in mx_str or 'googlemail' in mx_str or 'gmail-smtp' in mx_str:
            return 'gmail'
        if 'outlook' in mx_str or 'office365' in mx_str or 'protection.outlook' in mx_str:
            # 1) HRD must say Managed/Federated
            log.info(f"[detect] hrd={is_modern_auth_required(email)}")
            if is_modern_auth_required(email):
                # 2) Tenant metadata must exist (STRICT — no `common` here)
                log.info(f"[detect] tenant_meta_exists={bool(get_openid_metadata_tenant(domain))}")
                meta = get_openid_metadata_tenant(domain)
                if meta:
                    save_profile(email=email, provider='office365_modern', auth_metadata=meta)
                    return 'office365_modern'
            # Otherwise it's classic Outlook IMAP
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
            txt_records = resolve(domain, 'TXT')
            txt_str = ' '.join(str(r).lower() for r in txt_records)
            log.info(f"[detect] txt={txt_str if 'txt_str' in locals() else '<none>'}")

            outlookish = (
                'spf.protection.outlook.com' in txt_str
                or 'ms=' in txt_str
                or 'd365' in txt_str
            )

            if outlookish and is_modern_auth_required(email):
                meta = get_openid_metadata_tenant(domain)  # STRICT, no `common`
                if meta:
                    from setup_wizard import STATE
                    save_profile(
                        email=email,
                        provider='office365_modern',
                        auth_metadata=meta,
                        step=STATE.get("step", "detected")
                    )
                    return 'office365_modern'
                # TXT smells like Outlook but no tenant metadata → treat as classic Outlook
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