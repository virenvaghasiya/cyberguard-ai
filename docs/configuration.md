# Configuration Reference

CyberGuard AI uses YAML configuration files. The system loads config in this order:

1. `config/default.yaml` — base defaults (shipped with the repo)
2. `config/local.yaml` — your local overrides (git-ignored)

## Quick Setup

```bash
cp config/default.yaml config/local.yaml
# Edit config/local.yaml with your settings
```

## Configuration Sections

### `app`

General application settings.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `name` | string | "CyberGuard AI" | Application name |
| `version` | string | "0.1.0" | Version string |
| `log_level` | string | "INFO" | Logging level (DEBUG, INFO, WARNING, ERROR) |
| `log_format` | string | "json" | Log format (json or console) |

### `network_detector`

Network traffic anomaly detection module.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | true | Enable/disable this detector |
| `interface` | string | null | Network interface to capture from (null = file mode) |
| `input_file` | string | null | Path to CSV/PCAP file for batch analysis |
| `batch_size` | int | 1000 | Number of flows per analysis batch |

### `network_detector.model`

ML model configuration.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `type` | string | "isolation_forest" | Model type |
| `contamination` | float | 0.05 | Expected anomaly proportion (0.01–0.5) |
| `n_estimators` | int | 200 | Number of trees in the forest |
| `model_path` | string | "data/models/..." | Where to save/load the trained model |

### `network_detector.alerting`

Alert generation thresholds.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `score_threshold` | float | -0.3 | Anomaly score threshold |
| `min_confidence` | float | 0.7 | Minimum confidence to fire alert |
| `cooldown_seconds` | int | 60 | Suppress duplicate alerts within window |

### `api`

REST API server settings.

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `host` | string | "0.0.0.0" | Bind address |
| `port` | int | 8000 | Port number |
| `cors_origins` | list | ["http://localhost:3000"] | Allowed CORS origins |
| `auth_enabled` | bool | false | Enable API authentication |
