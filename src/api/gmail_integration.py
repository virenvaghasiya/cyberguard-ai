"""
Gmail Integration for CyberGuard AI.

Handles OAuth2 authentication with Google and fetching emails
for phishing analysis. Users sign in with their own Google account
and the app gets read-only access to their inbox.

Setup requires:
1. A Google Cloud project with Gmail API enabled
2. OAuth 2.0 credentials (client_id and client_secret)
3. These stored in config/gmail_credentials.json

See docs/gmail_setup.md for step-by-step instructions.
"""

from __future__ import annotations

import re

import structlog

logger = structlog.get_logger()


def parse_email_for_scanning(raw_email: dict) -> dict:
    """
    Convert a raw Gmail API message into the format our
    phishing detector expects.

    Args:
        raw_email: Dict with keys from Gmail API response:
            - headers (dict with From, To, Subject, etc.)
            - snippet (preview text)
            - body_text (decoded body, if available)
            - body_html (decoded HTML body, if available)

    Returns:
        Dict ready for PhishingEmailDetector.analyze()
    """
    headers = raw_email.get("headers", {})

    # Parse sender
    from_header = headers.get("From", "")
    sender_name, sender_email = _parse_from_header(from_header)

    # Parse reply-to
    reply_to = headers.get("Reply-To", "")

    # Get body content
    body = raw_email.get("body_text", "") or raw_email.get("snippet", "")
    html_body = raw_email.get("body_html", "")

    # Use HTML body if available (more signals for phishing detection)
    if html_body:
        body = html_body

    # Extract attachment filenames
    attachments = raw_email.get("attachments", [])

    # Extract URLs from body
    urls = _extract_urls(body)

    return {
        "subject": headers.get("Subject", ""),
        "body": body,
        "sender_name": sender_name,
        "sender_email": sender_email,
        "reply_to": reply_to,
        "attachments": attachments,
        "urls": urls,
        "message_id": raw_email.get("messageId", ""),
        "date": headers.get("Date", ""),
        "to": headers.get("To", ""),
    }


def _parse_from_header(from_header: str) -> tuple[str, str]:
    """
    Parse the From header into display name and email.

    Examples:
        "John Doe <john@example.com>" -> ("John Doe", "john@example.com")
        "john@example.com" -> ("", "john@example.com")
        "\"PayPal Security\" <fake@evil.xyz>" -> ("PayPal Security", "fake@evil.xyz")
    """
    # Match "Name <email>" pattern
    match = re.match(r'^"?([^"<]*)"?\s*<?([^>]+@[^>]+)>?$', from_header.strip())
    if match:
        name = match.group(1).strip().strip('"')
        email = match.group(2).strip()
        return name, email

    # Just an email address
    email_match = re.search(r'[\w.+-]+@[\w.-]+\.\w+', from_header)
    if email_match:
        return "", email_match.group(0)

    return "", from_header


def _extract_urls(text: str) -> list[str]:
    """Extract URLs from text or HTML content."""
    url_pattern = r'https?://[^\s<>"\')\]}]+'
    return re.findall(url_pattern, text)


def format_scan_result(email_data: dict, analysis_result: dict) -> dict:
    """
    Combine original email data with phishing analysis into
    a clean result for the frontend.
    """
    is_phishing = analysis_result.get("is_phishing", False)
    score = analysis_result.get("phishing_score", 0)

    # Determine verdict
    if is_phishing and score >= 15:
        verdict = "danger"
        verdict_label = "Dangerous"
    elif is_phishing and score >= 10:
        verdict = "warning"
        verdict_label = "Suspicious"
    elif is_phishing:
        verdict = "caution"
        verdict_label = "Caution"
    elif score >= 3:
        verdict = "monitor"
        verdict_label = "Monitor"
    else:
        verdict = "safe"
        verdict_label = "Safe"

    return {
        "message_id": email_data.get("message_id", ""),
        "subject": email_data.get("subject", "(no subject)"),
        "sender_name": email_data.get("sender_name", ""),
        "sender_email": email_data.get("sender_email", ""),
        "date": email_data.get("date", ""),
        "verdict": verdict,
        "verdict_label": verdict_label,
        "phishing_score": round(score, 1),
        "confidence": analysis_result.get("confidence", 0),
        "severity": analysis_result.get("severity"),
        "indicator_count": analysis_result.get("details", {}).get("indicator_count", 0),
        "indicators": analysis_result.get("details", {}).get("indicators", []),
        "features": {
            "suspicious_urls": analysis_result.get("features", {}).get("suspicious_url_count", 0),
            "urgency_score": round(analysis_result.get("features", {}).get("urgency_score", 0), 2),
            "threat_score": round(analysis_result.get("features", {}).get("threat_score", 0), 2),
            "reward_score": round(analysis_result.get("features", {}).get("reward_score", 0), 2),
            "sender_mismatch": analysis_result.get("features", {}).get("sender_name_email_mismatch", False),
            "brand_impersonation": analysis_result.get("features", {}).get("sender_domain_mismatch", False),
            "dangerous_attachment": analysis_result.get("features", {}).get("dangerous_attachment", False),
            "has_form": analysis_result.get("features", {}).get("has_form", False),
        },
    }
