# CyberGuard AI

An AI-powered personal cybersecurity system that detects and automatically responds to cyber threats in real-time, with a companion iPhone app for monitoring on the go.

## What is this?

CyberGuard AI is an **Intrusion Prevention System (IPS)** — not just a detector. It watches your Mac's network traffic, running processes, system logs, emails, and files. When it spots an attack, it does not just alert you — it automatically blocks the attacker, kills malicious processes, and quarantines dangerous files.

Think of it as a personal antivirus + firewall + network monitor + email security tool, all in one, controlled from your iPhone.

---

## Modules Built ✅

| Module | Status | What it does |
|---|---|---|
| Network Anomaly Detector | ✅ Complete | Isolation Forest ML — detects DDoS, port scans, data exfiltration, C2 beacons |
| Log Analyzer | ✅ Complete | Detects brute-force logins, privilege escalation, web scanning from real system logs |
| Vulnerability Scanner | ✅ Complete | Async port scanner with banner grabbing across 40+ risky ports |
| Phishing Email Detector | ✅ Complete | 15+ signal heuristic scoring — trusted sender whitelist prevents false positives |
| Live Network Connections | ✅ Complete | Real TCP connections via netstat — color-coded by risk, auto-refresh every 5 seconds |
| System Stats Monitor | ✅ Complete | Real CPU, memory, disk, and network I/O via psutil |
| Real System Logs | ✅ Complete | macOS `log show` — filter by auth / network / security events |
| Gmail Inbox Scanner | ✅ Complete | Full Gmail OAuth2 with PKCE — scans real inbox for phishing |
| REST API + WebSocket | ✅ Complete | FastAPI backend with JWT auth and real-time alert streaming to iPhone |
| iPhone App | ✅ Complete | React Native + Expo — Dashboard, Alerts, Live Network, Scanner, Settings |

---

## Roadmap — Auto-Defense (IPS) 🔜

The system currently **detects** attacks and alerts you. The next phases make it **automatically respond**.

| Phase | Name | What it adds |
|---|---|---|
| Phase 5 | Live Packet Capture | Capture real packets with scapy — feed live traffic into ML anomaly detector |
| Phase 6 | Auto IP Blocking | Automatically block attacker IPs via macOS `pfctl` firewall — expires after configurable time |
| Phase 7 | Process Monitor | Detect crypto miners, reverse shells, C2 agents — optional auto-kill |
| Phase 8 | File Scanner | SHA-256 hash checking against malware databases, Downloads folder watcher |
| Phase 9 | Rules Engine | "If brute force → block IP for 2 hours + push notification" — YAML config, no code needed |
| Phase 10 | Threat Intel Feed | Auto-check IPs against AbuseIPDB, Spamhaus, Emerging Threats |

See [CYBERGUARD_AI_PLAN.md](CYBERGUARD_AI_PLAN.md) for the full detailed build plan with code design, file structure, and step-by-step implementation for each phase.

---

## Quick Start

### Prerequisites

- Python 3.10+
- Node.js 18+ (for mobile app)
- [Expo Go](https://expo.dev/go) on your iPhone

### Backend

```bash
git clone https://github.com/virenvaghasiya/cyberguard-ai.git
cd cyberguard-ai

python -m venv venv
source venv/bin/activate

pip install -r requirements.txt

# Start the API server (accessible on your local network)
python -m src.main --serve
```

### Mobile App

```bash
cd mobile
npm install
npx expo start
```

Scan the QR code with Expo Go on your iPhone. In the app Settings tab, set the Backend URL to `http://<your-mac-ip>:8000`.

### Run Tests

```bash
pytest tests/ -v
```

### Gmail Setup

To scan your real Gmail inbox, follow the setup guide: [docs/gmail_setup.md](docs/gmail_setup.md)

---

## Project Structure

```
cyberguard-ai/
├── src/
│   ├── core/              # Pipeline manager, event bus, base detector class
│   ├── detectors/         # Network, log, vuln, phishing detectors
│   ├── capture/           # Packet capture, flow aggregation (Phase 5)
│   ├── defense/           # Firewall manager, rules engine, block store (Phase 6-9)
│   └── api/               # FastAPI server, JWT auth, WebSocket, Gmail OAuth
├── mobile/                # React Native iPhone app (Expo)
│   └── src/
│       ├── screens/       # Dashboard, Alerts, Network, Scanner, Settings
│       ├── components/    # AlertCard, StatCard, SeverityBadge
│       └── services/      # API client, WebSocket auto-reconnect
├── tests/                 # Unit and integration tests (pytest)
├── config/                # YAML config (default + local override)
├── data/
│   ├── sample/            # Sample datasets
│   └── models/            # Trained ML model artifacts
├── docs/                  # Gmail setup guide, configuration reference
├── CYBERGUARD_AI_PLAN.md  # Full build plan with all phases
└── .github/workflows/     # CI: ruff lint, bandit security scan, pytest
```

---

## Architecture

```
┌────────────────────────────────────────────────────────────┐
│                     iPhone App (Expo)                       │
│  Dashboard │ Alerts │ Network │ Scanner │ Defense │ Settings │
└────────────────────────┬───────────────────────────────────┘
                         │ REST API + WebSocket
┌────────────────────────▼───────────────────────────────────┐
│                   FastAPI Backend                           │
├──────────┬──────────┬──────────┬──────────┬────────────────┤
│ Network  │   Log    │  Vuln    │ Phishing │  Gmail OAuth   │
│ Anomaly  │ Analyzer │ Scanner  │ Detector │  Inbox Scanner │
├──────────┴──────────┴──────────┴──────────┴────────────────┤
│                  Core Detection Engine                       │
│            (Async Pipeline + Event Bus)                      │
├─────────────────────────────────────────────────────────────┤
│              Real Data Sources (no fake data)               │
│    netstat │ psutil │ macOS log show │ Gmail API           │
├─────────────────────────────────────────────────────────────┤
│              Auto-Defense Engine (coming Phase 6-9)         │
│    pfctl firewall │ Process kill │ File quarantine         │
│    Rules engine (YAML) │ iOS push notifications            │
└─────────────────────────────────────────────────────────────┘
```

---

## Default Credentials

The API server uses JWT authentication. Default credentials (override via env vars):

| Env Var | Default |
|---|---|
| `CYBERGUARD_USER` | `admin` |
| `CYBERGUARD_PASSWORD` | `cyberguard` |
| `CYBERGUARD_SECRET` | auto-generated |

---

## CI Status

Every push runs:
- **ruff** — Python linting and formatting
- **bandit** — Security vulnerability scan (medium+ severity)
- **pytest** — 101 automated tests

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.
