"""
Gmail OAuth2 integration for CyberGuard AI.

Flow:
1. User visits GET /gmail/auth  → redirected to Google consent screen
2. Google redirects back to GET /gmail/callback?code=...
3. Backend exchanges code for tokens, stores them in data/gmail_token.json
4. Mobile app calls POST /gmail/scan → backend fetches real inbox + scans

Token is stored locally (personal use only — never leaves your Mac).
"""

from __future__ import annotations

import json
import base64
import re
from pathlib import Path

import structlog

logger = structlog.get_logger()

TOKEN_PATH = Path("data/gmail_token.json")
CREDS_PATH = Path("config/gmail_credentials.json")

SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]


def _get_credentials():
    """Load stored OAuth credentials, refresh if expired."""
    from google.oauth2.credentials import Credentials
    from google.auth.transport.requests import Request

    if not TOKEN_PATH.exists():
        return None

    creds = Credentials.from_authorized_user_file(str(TOKEN_PATH), SCOPES)

    if creds and creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
            _save_token(creds)
        except Exception as e:
            logger.warning("gmail_token_refresh_failed", error=str(e))
            TOKEN_PATH.unlink(missing_ok=True)
            return None

    return creds if creds and creds.valid else None


def _save_token(creds) -> None:
    TOKEN_PATH.parent.mkdir(parents=True, exist_ok=True)
    TOKEN_PATH.write_text(creds.to_json())


def is_connected() -> bool:
    return _get_credentials() is not None


def get_auth_url(redirect_uri: str) -> str:
    """Return the Google OAuth consent URL."""
    from google_auth_oauthlib.flow import Flow

    if not CREDS_PATH.exists():
        raise FileNotFoundError(
            "Gmail credentials not found at config/gmail_credentials.json. "
            "See the app Settings → Connect Gmail for setup instructions."
        )

    flow = Flow.from_client_secrets_file(
        str(CREDS_PATH),
        scopes=SCOPES,
        redirect_uri=redirect_uri,
    )
    auth_url, _ = flow.authorization_url(
        access_type="offline",
        include_granted_scopes="true",
        prompt="consent",
    )
    return auth_url


def exchange_code(code: str, redirect_uri: str) -> None:
    """Exchange authorization code for tokens and save them."""
    from google_auth_oauthlib.flow import Flow

    flow = Flow.from_client_secrets_file(
        str(CREDS_PATH),
        scopes=SCOPES,
        redirect_uri=redirect_uri,
    )
    flow.fetch_token(code=code)
    _save_token(flow.credentials)
    logger.info("gmail_connected", email=_get_user_email())


def disconnect() -> None:
    TOKEN_PATH.unlink(missing_ok=True)
    logger.info("gmail_disconnected")


def _get_user_email() -> str:
    """Return the authenticated user's email address."""
    try:
        from googleapiclient.discovery import build
        creds = _get_credentials()
        if not creds:
            return ""
        service = build("gmail", "v1", credentials=creds)
        profile = service.users().getProfile(userId="me").execute()
        return profile.get("emailAddress", "")
    except Exception:
        return ""


def fetch_inbox(max_results: int = 50, label: str = "INBOX") -> list[dict]:
    """
    Fetch real emails from Gmail inbox.

    Returns a list of dicts ready for phishing detection:
    subject, body, sender_name, sender_email, reply_to,
    attachments, urls, message_id, date, to
    """
    from googleapiclient.discovery import build

    creds = _get_credentials()
    if not creds:
        raise PermissionError("Gmail not connected. Visit /gmail/auth first.")

    service = build("gmail", "v1", credentials=creds)

    # List message IDs
    result = service.users().messages().list(
        userId="me",
        labelIds=[label],
        maxResults=max_results,
    ).execute()

    messages = result.get("messages", [])
    if not messages:
        return []

    emails = []
    for msg_ref in messages:
        try:
            msg = service.users().messages().get(
                userId="me",
                id=msg_ref["id"],
                format="full",
            ).execute()
            parsed = _parse_message(msg)
            if parsed:
                emails.append(parsed)
        except Exception as e:
            logger.warning("gmail_fetch_message_failed", msg_id=msg_ref["id"], error=str(e))

    return emails


def _parse_message(msg: dict) -> dict | None:
    """Convert a raw Gmail API message into phishing detector input format."""
    try:
        headers = {
            h["name"]: h["value"]
            for h in msg.get("payload", {}).get("headers", [])
        }

        from_header = headers.get("From", "")
        sender_name, sender_email = _parse_from_header(from_header)
        reply_to = headers.get("Reply-To", "")

        body_text, body_html, attachments = _extract_parts(msg.get("payload", {}))

        # Use HTML for richer phishing signals, fall back to text
        body = body_html or body_text or msg.get("snippet", "")
        urls = _extract_urls(body_text + " " + body_html)

        return {
            "message_id": msg.get("id", ""),
            "subject": headers.get("Subject", "(no subject)"),
            "body": body,
            "sender_name": sender_name,
            "sender_email": sender_email,
            "reply_to": reply_to,
            "attachments": attachments,
            "urls": urls,
            "date": headers.get("Date", ""),
            "to": headers.get("To", ""),
        }
    except Exception as e:
        logger.warning("gmail_parse_failed", error=str(e))
        return None


def _extract_parts(payload: dict) -> tuple[str, str, list[str]]:
    """Recursively extract text, html, and attachment names from MIME parts."""
    body_text = ""
    body_html = ""
    attachments: list[str] = []

    mime_type = payload.get("mimeType", "")
    parts = payload.get("parts", [])

    if mime_type == "text/plain":
        body_text = _decode_body(payload.get("body", {}))
    elif mime_type == "text/html":
        body_html = _decode_body(payload.get("body", {}))
    elif mime_type.startswith("multipart/"):
        for part in parts:
            t, h, a = _extract_parts(part)
            body_text += t
            body_html += h
            attachments.extend(a)
    else:
        filename = payload.get("filename", "")
        if filename:
            attachments.append(filename)

    return body_text, body_html, attachments


def _decode_body(body: dict) -> str:
    data = body.get("data", "")
    if not data:
        return ""
    try:
        return base64.urlsafe_b64decode(data + "==").decode("utf-8", errors="replace")
    except Exception:
        return ""


def _parse_from_header(from_header: str) -> tuple[str, str]:
    match = re.match(r'^"?([^"<]*)"?\s*<?([^>]+@[^>]+)>?$', from_header.strip())
    if match:
        return match.group(1).strip().strip('"'), match.group(2).strip()
    email_match = re.search(r'[\w.+-]+@[\w.-]+\.\w+', from_header)
    if email_match:
        return "", email_match.group(0)
    return "", from_header


def _extract_urls(text: str) -> list[str]:
    return re.findall(r'https?://[^\s<>"\')\]}]+', text)
