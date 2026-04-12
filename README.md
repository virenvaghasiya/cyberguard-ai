# CyberGuard AI

An AI-powered cybersecurity defense system designed to identify, prevent, and respond to cyber threats in real-time.

## Overview

CyberGuard AI uses machine learning and behavioral analysis to protect individuals and organizations from cyberattacks. The system monitors network traffic, detects anomalies, and provides automated incident response capabilities.

## Current Modules

| Module | Status | Description |
|--------|--------|-------------|
| Network Traffic Anomaly Detector | ✅ Active | ML-based detection of anomalous network traffic patterns |
| Log Analysis & Alert Engine | 🔜 Planned | Centralized log correlation and alerting |
| Vulnerability Scanner | 🔜 Planned | Continuous vulnerability assessment and prioritization |
| Phishing Email Detector | 🔜 Planned | NLP-based phishing detection |

## Quick Start

### Prerequisites

- Python 3.10+
- pip

### Installation

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/cyberguard-ai.git
cd cyberguard-ai

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt

# Install in development mode
pip install -e .
```

### Run the Anomaly Detector (Demo)

```bash
# Generate sample traffic data and run detection
python -m src.main --demo

# Run with a custom PCAP or CSV file
python -m src.main --input data/sample/traffic.csv

# Start the API server
python -m src.api.server
```

### Run Tests

```bash
pytest tests/ -v
```

## Project Structure

```
cyberguard-ai/
├── src/
│   ├── core/              # Core engine: pipeline, event bus, base classes
│   ├── detectors/          # Detection modules (network, log, phishing, etc.)
│   ├── models/             # ML model definitions and training scripts
│   ├── utils/              # Shared utilities (logging, config, metrics)
│   └── api/                # REST API for external integrations
├── tests/                  # Unit and integration tests
├── config/                 # Configuration files
├── data/
│   ├── sample/             # Sample datasets for testing
│   └── models/             # Trained model artifacts
├── docs/                   # Documentation
├── scripts/                # Setup, deployment, and utility scripts
└── .github/workflows/      # CI/CD pipelines
```

## Configuration

Copy the example config and adjust for your environment:

```bash
cp config/default.yaml config/local.yaml
```

See [docs/configuration.md](docs/configuration.md) for full configuration reference.

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
