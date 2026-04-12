"""Tests for phishing email feature extraction."""

import pytest
from src.detectors.phishing_features import extract_email_features


def _make_email(**overrides) -> dict:
    """Create a base email dict with optional overrides."""
    base = {
        "subject": "Hello",
        "body": "This is a normal email.",
        "sender_name": "John Doe",
        "sender_email": "john@company.com",
        "reply_to": "",
        "attachments": [],
    }
    base.update(overrides)
    return base


def test_clean_email_low_indicators():
    """A normal email should have few indicators."""
    email = _make_email()
    features = extract_email_features(email)
    assert features.total_indicators == 0


def test_urgency_detection():
    """Urgency phrases should be detected."""
    email = _make_email(
        subject="Urgent: Action Required",
        body="Your account will be suspended within 24 hours unless you verify your account.",
    )
    features = extract_email_features(email)
    assert features.urgency_score > 0


def test_threat_detection():
    """Threat phrases should be detected."""
    email = _make_email(
        body="Your account will be closed and legal action will be taken.",
    )
    features = extract_email_features(email)
    assert features.threat_score > 0


def test_reward_detection():
    """Reward/lottery phrases should be detected."""
    email = _make_email(
        subject="Congratulations! You have won a prize!",
        body="You've won a free gift! Claim your reward now.",
    )
    features = extract_email_features(email)
    assert features.reward_score > 0


def test_suspicious_url_detection():
    """URLs with suspicious TLDs should be flagged."""
    email = _make_email(
        body="Click here: http://verify-account.xyz/login",
    )
    features = extract_email_features(email)
    assert features.url_count >= 1
    assert features.suspicious_tld_count >= 1


def test_ip_based_url():
    """IP-based URLs should be flagged."""
    email = _make_email(
        body="Login at http://192.168.1.100/bank/login",
    )
    features = extract_email_features(email)
    assert features.ip_based_url_count >= 1


def test_shortened_url():
    """URL shorteners should be flagged."""
    email = _make_email(
        body="Check this out: http://bit.ly/3abc123",
    )
    features = extract_email_features(email)
    assert features.shortened_url_count >= 1


def test_sender_name_email_mismatch():
    """Display name containing a different email should be flagged."""
    email = _make_email(
        sender_name="support@paypal.com",
        sender_email="hacker@evil.xyz",
    )
    features = extract_email_features(email)
    assert features.sender_name_email_mismatch is True


def test_brand_impersonation():
    """Sender claiming to be a brand with wrong domain should be flagged."""
    email = _make_email(
        sender_name="PayPal Security Team",
        sender_email="security@paypa1-support.xyz",
    )
    features = extract_email_features(email)
    assert features.sender_domain_mismatch is True


def test_freemail_detection():
    """Free email providers should be identified."""
    email = _make_email(sender_email="someone@gmail.com")
    features = extract_email_features(email)
    assert features.freemail_sender is True


def test_reply_to_mismatch():
    """Mismatched reply-to should be flagged."""
    email = _make_email(
        sender_email="support@company.com",
        reply_to="different@evil.com",
    )
    features = extract_email_features(email)
    assert features.reply_to_mismatch is True


def test_dangerous_attachment():
    """Executable attachments should be flagged."""
    email = _make_email(attachments=["invoice.exe"])
    features = extract_email_features(email)
    assert features.dangerous_attachment is True
    assert features.has_attachments is True


def test_safe_attachment():
    """PDF attachments should not be flagged as dangerous."""
    email = _make_email(attachments=["report.pdf"])
    features = extract_email_features(email)
    assert features.dangerous_attachment is False
    assert features.has_attachments is True


def test_embedded_form():
    """HTML forms should be detected."""
    email = _make_email(
        body='<html><form action="http://evil.com"><input type="password"></form></html>',
    )
    features = extract_email_features(email)
    assert features.has_form is True
    assert features.has_password_field is True


def test_mismatched_url_in_html():
    """URLs where display text shows different domain than href should be caught."""
    email = _make_email(
        body='<a href="http://evil.com/steal">http://paypal.com/login</a>',
    )
    features = extract_email_features(email)
    assert features.mismatched_url_count >= 1


def test_multiple_indicators_compound():
    """An email with many indicators should have a high total count."""
    email = _make_email(
        subject="Urgent: Verify your account immediately",
        body=(
            "Dear Customer, your account will be suspended. "
            "Click here: http://192.168.1.1/verify "
            "Failure to act will result in legal action."
        ),
        sender_name="PayPal",
        sender_email="alert@paypa1.xyz",
        attachments=["verify.exe"],
    )
    features = extract_email_features(email)
    assert features.total_indicators >= 4
