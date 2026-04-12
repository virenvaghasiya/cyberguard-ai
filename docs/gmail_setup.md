# Setting Up Gmail Scanning

CyberGuard Mail Scanner can scan Gmail inboxes for phishing threats.
This guide explains how to set it up.

## Current Status

### What works now (Demo Mode)
- Open `mail-scanner/index.html` in your browser
- Start the API server: `python -m src.main --serve`
- Click "Try Demo Scan" to see the scanner in action with sample phishing/legitimate emails

### What's coming next (Gmail Integration)
- Sign in with Google to scan your real inbox
- Automatic scanning of new emails
- Push notifications for dangerous emails

## How It Works

1. The scanner reads email **headers and text only** (subject, sender, body)
2. Each email runs through CyberGuard's phishing detector
3. The detector checks 20+ phishing indicators:
   - Suspicious URLs (IP-based, shortened, bad TLDs)
   - Urgency/threat language
   - Sender spoofing and brand impersonation
   - Dangerous attachments
   - Embedded forms and password fields
4. Each email gets a verdict: Safe, Monitor, Caution, Suspicious, or Dangerous
5. Results display on the mobile-friendly web interface

## Privacy

- **Read-only access**: We only read email metadata and text
- **No storage**: Emails are analyzed in memory and never saved to disk
- **No forwarding**: Your emails are never sent to any third party
- **Local processing**: All phishing analysis runs on your local machine

## For Production Deployment

To make this accessible from any phone (not just your local network):

1. Deploy the CyberGuard API to a cloud server (AWS, GCP, or DigitalOcean)
2. Set up Google OAuth credentials in Google Cloud Console
3. Point the mail-scanner app to your cloud API URL
4. Share the URL with your partner — she signs in with her own Google account

See the main README for deployment instructions.
