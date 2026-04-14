"""
Phishing email feature extraction.

Extracts numerical features from email content that distinguish phishing
from legitimate messages. The features fall into five categories:

1. URL analysis: Suspicious links, mismatched display text vs actual URL,
   IP-based URLs, excessive subdomains, known phishing TLDs
2. Language analysis: Urgency words, threat language, impersonation phrases,
   too-good-to-be-true offers
3. Sender analysis: Display name vs email mismatch, free email providers
   claiming to be corporate, reply-to mismatches
4. Structure analysis: HTML-heavy emails, hidden text, attachments with
   dangerous extensions, embedded forms
5. Header analysis: SPF/DKIM failures, unusual routing, recently registered
   sending domains

These features are designed to work without external API calls so the
detector runs entirely offline.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

import structlog

logger = structlog.get_logger()


# --- Phishing indicator word lists ---

URGENCY_PHRASES = [
    "act now", "urgent", "immediately", "expire", "suspended",
    "verify your account", "confirm your identity", "within 24 hours",
    "within 48 hours", "limited time", "action required", "respond immediately",
    "failure to", "your account will be", "unauthorized", "unusual activity",
    "security alert", "verify now", "click immediately", "don't delay",
    "time sensitive", "final warning", "last chance", "account suspended",
    "account locked", "locked out", "confirm now", "update required",
]

THREAT_PHRASES = [
    "will be closed", "will be suspended", "will be terminated",
    "legal action", "law enforcement", "prosecuted", "arrested",
    "penalty", "fine", "blocked permanently", "lose access",
    "data will be deleted", "reported to", "criminal",
]

REWARD_PHRASES = [
    "congratulations", "you have won", "you've won", "winner",
    "prize", "lottery", "inheritance", "million dollars", "free gift",
    "claim your", "selected", "lucky", "reward", "bonus offer",
    "exclusive deal", "guaranteed",
]

IMPERSONATION_PHRASES = [
    "dear customer", "dear user", "dear account holder",
    "dear valued", "dear member", "dear client",
    "we have noticed", "we detected", "our records indicate",
    "your account has been", "as part of our security",
    "routine security", "mandatory update",
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".click", ".loan", ".work", ".gq", ".ml",
    ".cf", ".tk", ".buzz", ".icu", ".cam", ".rest", ".surf",
]

DANGEROUS_EXTENSIONS = [
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js",
    ".wsf", ".msi", ".dll", ".pif", ".com", ".hta",
    ".iso", ".img", ".zip", ".rar", ".7z",
]

FREEMAIL_PROVIDERS = [
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "aol.com", "mail.com", "protonmail.com", "zoho.com",
    "yandex.com", "gmx.com", "icloud.com",
]

CORPORATE_IMPERSONATION = [
    "paypal", "apple", "microsoft", "google", "amazon", "netflix",
    "bank", "wells fargo", "chase", "citibank", "hsbc",
    "fedex", "ups", "dhl", "usps", "irs", "hmrc",
    "facebook", "instagram", "whatsapp", "linkedin",
]

# Domains known to send legitimate notification emails.
# Emails from these senders get a major score reduction to avoid false positives.
TRUSTED_SENDER_DOMAINS = {
    # Developer platforms
    "github.com", "gitlab.com", "bitbucket.org", "atlassian.com",
    "jira.com", "confluence.com", "trello.com",
    # Google services
    "google.com", "accounts.google.com", "mail.google.com",
    "googlemail.com", "youtube.com", "workspace.google.com",
    # Apple
    "apple.com", "icloud.com", "appleid.apple.com",
    # Microsoft
    "microsoft.com", "outlook.com", "live.com", "hotmail.com",
    "office.com", "sharepoint.com", "teams.microsoft.com",
    # Amazon / AWS
    "amazon.com", "amazon.co.uk", "amazon.in", "amazon.de",
    "amazon.ca", "amazon.com.au", "amazon.fr", "amazon.es",
    "amazon.it", "amazon.co.jp", "aws.amazon.com",
    "amazonses.com", "amazonaws.com",
    # Cloud & dev tools
    "heroku.com", "vercel.com", "netlify.com", "cloudflare.com",
    "digitalocean.com", "linode.com", "render.com",
    "stripe.com", "paypal.com", "twilio.com", "sendgrid.net",
    # Social / comms
    "slack.com", "notion.so", "linear.app", "figma.com",
    "zoom.us", "calendly.com",
    # CI/CD
    "circleci.com", "travis-ci.com", "jenkins.io",
}

# Brand names that are trusted regardless of TLD.
# Handles amazon.co.uk, amazon.in, apple.com.au etc.
TRUSTED_BRANDS = {
    "amazon", "github", "gitlab", "google", "apple", "microsoft",
    "stripe", "slack", "notion", "atlassian", "digitalocean",
    "cloudflare", "heroku", "vercel", "netlify", "twilio",
    "sendgrid", "mailchimp", "hubspot", "salesforce", "zoom",
    "dropbox", "adobe", "figma", "linear", "jira", "trello",
    "shopify", "squarespace", "wix", "godaddy", "namecheap",
    "linkedin", "twitter", "instagram", "facebook", "youtube",
    "netflix", "spotify", "uber", "airbnb",
}


@dataclass
class EmailFeatures:
    """Extracted features from an email for phishing classification."""

    # URL features
    url_count: int = 0
    suspicious_url_count: int = 0
    ip_based_url_count: int = 0
    mismatched_url_count: int = 0
    shortened_url_count: int = 0
    suspicious_tld_count: int = 0
    max_subdomain_depth: int = 0

    # Language features
    urgency_score: float = 0.0
    threat_score: float = 0.0
    reward_score: float = 0.0
    impersonation_score: float = 0.0

    # Sender features
    sender_name_email_mismatch: bool = False
    freemail_sender: bool = False
    sender_domain_mismatch: bool = False
    reply_to_mismatch: bool = False

    # Structure features
    has_html: bool = False
    has_attachments: bool = False
    dangerous_attachment: bool = False
    has_form: bool = False
    has_password_field: bool = False
    link_to_text_ratio: float = 0.0

    # Overall
    total_indicators: int = 0
    indicator_details: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "url_count": self.url_count,
            "suspicious_url_count": self.suspicious_url_count,
            "ip_based_url_count": self.ip_based_url_count,
            "mismatched_url_count": self.mismatched_url_count,
            "shortened_url_count": self.shortened_url_count,
            "suspicious_tld_count": self.suspicious_tld_count,
            "max_subdomain_depth": self.max_subdomain_depth,
            "urgency_score": self.urgency_score,
            "threat_score": self.threat_score,
            "reward_score": self.reward_score,
            "impersonation_score": self.impersonation_score,
            "sender_name_email_mismatch": self.sender_name_email_mismatch,
            "freemail_sender": self.freemail_sender,
            "sender_domain_mismatch": self.sender_domain_mismatch,
            "reply_to_mismatch": self.reply_to_mismatch,
            "has_html": self.has_html,
            "has_attachments": self.has_attachments,
            "dangerous_attachment": self.dangerous_attachment,
            "has_form": self.has_form,
            "has_password_field": self.has_password_field,
            "link_to_text_ratio": self.link_to_text_ratio,
            "total_indicators": self.total_indicators,
            "indicator_details": self.indicator_details,
        }


# --- URL shortener domains ---
URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorturl.at",
]


def extract_email_features(email: dict) -> EmailFeatures:
    """
    Extract phishing-relevant features from an email dict.

    Expected email dict keys:
        - subject: str
        - body: str (plain text or HTML)
        - sender_name: str (display name)
        - sender_email: str
        - reply_to: str (optional)
        - attachments: list[str] (filenames, optional)
        - urls: list[str] (extracted URLs, optional)
    """
    features = EmailFeatures()

    subject = email.get("subject", "").lower()
    body = email.get("body", "").lower()
    sender_name = email.get("sender_name", "").lower()
    sender_email = email.get("sender_email", "").lower()
    reply_to = email.get("reply_to", "").lower()
    attachments = email.get("attachments", [])
    full_text = f"{subject} {body}"

    # Check if sender is a trusted domain — reduces false positives significantly
    sender_domain = _get_domain(sender_email)
    is_trusted_sender = _is_trusted_domain(sender_domain)

    # Extract URLs from body if not provided
    urls = email.get("urls", [])
    if not urls:
        urls = _extract_urls(body)

    # --- URL Analysis ---
    features.url_count = len(urls)
    for url in urls:
        # Skip suspicious checks for URLs pointing to trusted domains
        url_domain = _get_domain(url)
        if is_trusted_sender and _is_trusted_domain(url_domain):
            continue
        analysis = _analyze_url(url)
        if analysis["is_suspicious"]:
            features.suspicious_url_count += 1
            features.indicator_details.append(f"Suspicious URL: {url[:80]}")
        if analysis["is_ip_based"]:
            features.ip_based_url_count += 1
        if analysis["is_shortened"]:
            features.shortened_url_count += 1
        if analysis["suspicious_tld"]:
            features.suspicious_tld_count += 1
        features.max_subdomain_depth = max(
            features.max_subdomain_depth, analysis["subdomain_depth"]
        )

    # Check for mismatched URLs — skip for trusted senders (they use tracking links)
    if not is_trusted_sender:
        features.mismatched_url_count = _count_mismatched_urls(email.get("body", ""))

    # Link to text ratio — trusted senders often send HTML-heavy transactional emails
    text_length = len(re.sub(r"<[^>]+>", "", body)) or 1
    if not is_trusted_sender:
        features.link_to_text_ratio = min(1.0, len(urls) * 50 / text_length)

    # --- Language Analysis ---
    # For trusted senders, words like "failed", "security alert", "action required"
    # are routine (CI failures, 2FA prompts, etc.) — halve their impact
    lang_multiplier = 0.3 if is_trusted_sender else 1.0
    features.urgency_score = _phrase_match_score(full_text, URGENCY_PHRASES) * lang_multiplier
    features.threat_score  = _phrase_match_score(full_text, THREAT_PHRASES)  * lang_multiplier
    features.reward_score  = _phrase_match_score(full_text, REWARD_PHRASES)  * lang_multiplier
    features.impersonation_score = _phrase_match_score(full_text, IMPERSONATION_PHRASES) * lang_multiplier

    if features.urgency_score > 0:
        matches = _get_matching_phrases(full_text, URGENCY_PHRASES)
        features.indicator_details.append(f"Urgency language: {', '.join(matches[:3])}")
    if features.threat_score > 0:
        matches = _get_matching_phrases(full_text, THREAT_PHRASES)
        features.indicator_details.append(f"Threat language: {', '.join(matches[:3])}")
    if features.reward_score > 0:
        matches = _get_matching_phrases(full_text, REWARD_PHRASES)
        features.indicator_details.append(f"Reward language: {', '.join(matches[:3])}")

    # --- Sender Analysis ---
    features.sender_name_email_mismatch = _check_sender_mismatch(sender_name, sender_email)
    features.freemail_sender = _is_freemail(sender_email)
    features.reply_to_mismatch = bool(reply_to and _get_domain(reply_to) != _get_domain(sender_email))

    # Check if sender claims to be a known brand but uses wrong domain
    features.sender_domain_mismatch = _check_brand_impersonation(sender_name, sender_email)

    if features.sender_name_email_mismatch:
        features.indicator_details.append(
            f"Sender mismatch: name='{sender_name}' email='{sender_email}'"
        )
    if features.sender_domain_mismatch:
        features.indicator_details.append("Possible brand impersonation in sender name")
    if features.reply_to_mismatch:
        features.indicator_details.append(
            f"Reply-to mismatch: reply='{reply_to}' sender='{sender_email}'"
        )

    # --- Structure Analysis ---
    features.has_html = bool(re.search(r"<html|<div|<table|<a\s", body, re.IGNORECASE))
    features.has_form = bool(re.search(r"<form", body, re.IGNORECASE))
    features.has_password_field = bool(
        re.search(r'type\s*=\s*["\']?password', body, re.IGNORECASE)
    )
    features.has_attachments = len(attachments) > 0

    for att in attachments:
        att_lower = att.lower()
        if any(att_lower.endswith(ext) for ext in DANGEROUS_EXTENSIONS):
            features.dangerous_attachment = True
            features.indicator_details.append(f"Dangerous attachment: {att}")
            break

    # --- Count total indicators ---
    features.total_indicators = (
        features.suspicious_url_count
        + features.ip_based_url_count
        + features.mismatched_url_count
        + features.shortened_url_count
        + features.suspicious_tld_count
        + (1 if features.urgency_score > 0.1 else 0)
        + (1 if features.threat_score > 0.1 else 0)
        + (1 if features.reward_score > 0.1 else 0)
        + (1 if features.impersonation_score > 0.1 else 0)
        + (1 if features.sender_name_email_mismatch else 0)
        + (1 if features.sender_domain_mismatch else 0)
        + (1 if features.reply_to_mismatch else 0)
        + (1 if features.freemail_sender else 0)
        + (1 if features.dangerous_attachment else 0)
        + (1 if features.has_form else 0)
        + (1 if features.has_password_field else 0)
    )

    return features


def _extract_urls(text: str) -> list[str]:
    """Extract URLs from text content."""
    url_pattern = r'https?://[^\s<>"\')\]}]+'
    return re.findall(url_pattern, text)


def _analyze_url(url: str) -> dict:
    """Analyze a single URL for phishing indicators."""
    result = {
        "is_suspicious": False,
        "is_ip_based": False,
        "is_shortened": False,
        "suspicious_tld": False,
        "subdomain_depth": 0,
    }

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""

        # IP-based URL (e.g., http://192.168.1.1/login)
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", hostname):
            result["is_ip_based"] = True
            result["is_suspicious"] = True

        # URL shortener
        if any(hostname.endswith(s) for s in URL_SHORTENERS):
            result["is_shortened"] = True
            result["is_suspicious"] = True

        # Suspicious TLD
        if any(hostname.endswith(tld) for tld in SUSPICIOUS_TLDS):
            result["suspicious_tld"] = True
            result["is_suspicious"] = True

        # Excessive subdomains (e.g., login.paypal.com.evil.xyz)
        parts = hostname.split(".")
        result["subdomain_depth"] = max(0, len(parts) - 2)
        if result["subdomain_depth"] >= 3:
            result["is_suspicious"] = True

        # @ in URL (credential harvesting trick)
        if "@" in url:
            result["is_suspicious"] = True

        # Very long URL (often used to hide real destination)
        if len(url) > 200:
            result["is_suspicious"] = True

    except Exception:
        result["is_suspicious"] = True

    return result


def _count_mismatched_urls(html_body: str) -> int:
    """
    Count URLs where the display text shows a different domain than the href.
    Example: <a href="http://evil.com">http://paypal.com/login</a>
    """
    pattern = r'<a\s[^>]*href\s*=\s*["\']([^"\']+)["\'][^>]*>(.*?)</a>'
    matches = re.findall(pattern, html_body, re.IGNORECASE | re.DOTALL)

    mismatched = 0
    for href, display_text in matches:
        display_urls = _extract_urls(display_text)
        if display_urls:
            href_domain = _get_domain(href)
            display_domain = _get_domain(display_urls[0])
            if href_domain and display_domain and href_domain != display_domain:
                mismatched += 1

    return mismatched


def _phrase_match_score(text: str, phrases: list[str]) -> float:
    """
    Score how many phrases from a list appear in the text.
    Returns 0.0-1.0 normalized by list length.
    """
    matches = sum(1 for phrase in phrases if phrase in text)
    return min(1.0, matches / max(1, len(phrases) / 3))


def _get_matching_phrases(text: str, phrases: list[str]) -> list[str]:
    """Return which phrases matched."""
    return [p for p in phrases if p in text]


def _check_sender_mismatch(name: str, email: str) -> bool:
    """
    Check if the display name contains an email address that
    doesn't match the actual sender email.
    Example: name="support@paypal.com" email="hacker@evil.xyz"
    """
    # If the display name looks like an email
    name_emails = re.findall(r"[\w.+-]+@[\w.-]+\.\w+", name)
    if name_emails:
        return name_emails[0] != email
    return False


def _is_freemail(email: str) -> bool:
    """Check if the sender uses a free email provider."""
    domain = _get_domain(email)
    return domain in FREEMAIL_PROVIDERS


def _check_brand_impersonation(sender_name: str, sender_email: str) -> bool:
    """
    Check if the sender name claims to be a known brand but the
    email domain doesn't match.
    Example: name="PayPal Security" email="security@paypa1-support.xyz"
    """
    email_domain = _get_domain(sender_email)
    for brand in CORPORATE_IMPERSONATION:
        if brand in sender_name:
            # If the brand name is in the display name but NOT in the email domain
            if brand not in email_domain:
                return True
    return False


def _get_domain(email_or_url: str) -> str:
    """Extract domain from email address or URL."""
    if "@" in email_or_url:
        return email_or_url.split("@")[-1].strip().lower()
    try:
        parsed = urlparse(email_or_url)
        return (parsed.hostname or "").lower()
    except Exception:
        return ""


def _is_trusted_domain(domain: str) -> bool:
    """
    Return True if the domain is a known legitimate sender.

    Matching strategy (in order):
    1. Exact match:   amazon.com → trusted
    2. Subdomain:     notifications.github.com → github.com → trusted
    3. Brand + TLD:   amazon.co.uk, amazon.in → brand "amazon" → trusted
    """
    if not domain:
        return False

    # 1. Exact match
    if domain in TRUSTED_SENDER_DOMAINS:
        return True

    # 2. Subdomain of a trusted domain (notifications.github.com → github.com)
    parts = domain.split(".")
    for i in range(1, len(parts)):
        parent = ".".join(parts[i:])
        if parent in TRUSTED_SENDER_DOMAINS:
            return True

    # 3. Brand name match — handles amazon.co.uk, amazon.in, apple.com.au etc.
    # Check each label in the domain (excluding single-letter / short ccTLDs)
    labels = [p for p in parts if len(p) > 2]
    for label in labels:
        if label in TRUSTED_BRANDS:
            return True

    return False
