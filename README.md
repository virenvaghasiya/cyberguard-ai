# CyberGuard AI

An AI-powered cybersecurity defense system that detects and responds to cyber threats in real-time, with a companion iPhone app for monitoring on the go.

## Overview

CyberGuard AI uses machine learning and behavioral analysis to protect against cyberattacks. The system monitors network traffic, analyzes logs, scans for vulnerabilities, and detects phishing emails — all accessible from a native iOS app via REST API and WebSocket.

## Modules

| Module | Status | Description |
|--------|--------|-------------|
| Network Traffic Anomaly Detector | ✅ Complete | Isolation Forest ML detection of DDoS, exfiltration, port scans, C2 beacons |
| Log Analysis & Alert Engine | ✅ Complete | Auth log + web log analysis — brute force, privilege escalation, web scanning |
| Vulnerability Scanner | ✅ Complete | Async port scanner with banner grabbing across 40+ risky ports |
| Phishing Email Detector | ✅ Complete | Rule + heuristic NLP detection of phishing indicators |
| REST API + WebSocket | ✅ Complete | FastAPI backend with JWT auth and real-time alert streaming |
| iPhone App | ✅ Complete | React Native + Expo app with live dashboard, alerts, and scanner |

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

# Run demo (network anomaly detection)
python -m src.main --demo

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

## Project Structure

```
cyberguard-ai/
├── src/
│   ├── core/              # Pipeline manager, event bus, base detector class
│   ├── detectors/         # Network, log, vuln, phishing, port scan, C2 detectors
│   ├── utils/             # Sample data generators, shared utilities
│   └── api/               # FastAPI server, JWT auth, WebSocket manager
├── mobile/                # React Native iPhone app (Expo)
│   └── src/
│       ├── screens/       # Dashboard, Alerts, Network, Scanner, Settings
│       ├── components/    # AlertCard, FindingCard, StatCard, SeverityBadge
│       └── services/      # API client, WebSocket auto-reconnect service
├── tests/                 # Unit and integration tests (pytest)
├── config/                # YAML configuration (default + local override)
├── data/
│   ├── sample/            # Sample traffic datasets
│   └── models/            # Trained ML model artifacts
└── .github/workflows/     # CI: ruff lint, bandit security scan, pytest
```

## Default Credentials

The API server uses JWT authentication. Default credentials (override via env vars):

| Env Var | Default |
|---------|---------|
| `CYBERGUARD_USER` | `admin` |
| `CYBERGUARD_PASSWORD` | `cyberguard` |
| `CYBERGUARD_SECRET` | auto-generated |

## Configuration

Copy the example config and adjust for your environment:

```bash
cp config/default.yaml config/local.yaml
```

Key settings in `config/default.yaml`:
- `api.host` — set to `0.0.0.0` to allow iPhone connections on local network
- `api.port` — default `8000`
- `log_analyzer.brute_force_threshold` — failed logins before alert fires
- `vulnerability_scanner.timeout` — seconds per port probe

## Architecture

```
┌─────────────────────────────────────────────┐
│                 CyberGuard AI               │
├──────────┬──────────┬──────────┬────────────┤
│ Network  │   Log    │  Vuln    │  Phishing  │
│ Detector │ Analyzer │ Scanner  │  Detector  │
├──────────┴──────────┴──────────┴────────────┤
│              Core Detection Engine          │
│         (Event Bus + Pipeline Manager)      │
├─────────────────────────────────────────────┤
│           ML Models & Threat Intel          │
├─────────────────────────────────────────────┤
│        Alert Manager & Response Engine      │
└─────────────────────────────────────────────┘
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.
