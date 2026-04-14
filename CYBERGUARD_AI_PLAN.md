# CyberGuard AI — Master Build Plan

> **Goal:** Build a personal AI-powered cybersecurity system that not only *detects* attacks on your Mac but automatically *responds* and *blocks* them — a real Intrusion Prevention System (IPS), not just a detector.

---

## What We Have Built vs. What We Are Building

| Capability | IDS (what we built) | IPS (what we are building) |
|---|---|---|
| See suspicious traffic | ✅ Yes | ✅ Yes |
| Alert you to threats | ✅ Yes | ✅ Yes |
| Automatically block attacker | ❌ No | ✅ Phase 6 |
| Capture actual packets | ❌ No | ✅ Phase 5 |
| Kill malicious processes | ❌ No | ✅ Phase 7 |
| Scan files for malware | ❌ No | ✅ Phase 8 |
| Auto-apply response rules | ❌ No | ✅ Phase 9 |

---

## Phase 1 — Core Detection Engine ✅ COMPLETE

**Goal:** Build the foundational detection infrastructure.

### What was built
- `src/core/pipeline.py` — Async detection pipeline manager
- `src/core/event_bus.py` — Pub/sub event bus for alert routing
- `src/core/base_detector.py` — Abstract base class all detectors inherit from
- `src/core/alert_manager.py` — Alert deduplication and severity classification

### Key decisions
- Used asyncio throughout so all detectors run concurrently without blocking each other
- Event bus pattern means new detectors can be plugged in without touching existing code
- Alerts have severity (info / medium / high / critical) and a detector source tag

---

## Phase 2 — AI/ML Detectors ✅ COMPLETE

**Goal:** Four real detectors that catch specific attack categories.

### Detectors built

#### 2a. Network Anomaly Detector
- File: `src/detectors/network_anomaly.py`
- Model: Isolation Forest (sklearn) trained on network flow features
- Detects: DDoS floods, data exfiltration (high bytes out), port scans (many destinations), C2 beacon patterns (regular low-byte intervals)
- Input: CSV network flow data or live feature extraction
- Output: anomaly score 0-1, attack category, confidence

#### 2b. Log Analyzer
- File: `src/detectors/log_analyzer.py`
- Method: Rule-based pattern matching + frequency analysis
- Detects: Brute force login (N failures in window), privilege escalation (sudo after repeated failure), web scanning (too many 404s), SSH key tampering
- Input: Raw syslog / auth.log / web access log text
- Output: Matched rules, timeline of suspicious events

#### 2c. Vulnerability Scanner
- File: `src/detectors/vuln_scanner.py`
- Method: Async TCP port probing with banner grabbing
- Covers: 40+ risky ports (22=SSH, 23=Telnet, 3389=RDP, 3306=MySQL, 27017=MongoDB, etc.)
- Input: Target IP / hostname
- Output: Open ports, service banners, CVE references for known-bad configurations

#### 2d. Phishing Email Detector
- File: `src/detectors/phishing_detector.py` + `src/detectors/phishing_features.py`
- Method: Heuristic scoring across 15+ signals
- Signals: Mismatched URLs, lookalike domains, urgency language, spoofed sender, suspicious attachments, link-to-text ratio, free hosting domains
- Trusted sender whitelist: 40+ domains (GitHub, Amazon, Google, Apple, Stripe, etc.) with brand-label matching so `amazon.co.uk` is treated same as `amazon.com`
- Input: Email object (subject, body, sender, URLs, attachments)
- Output: Phishing score 0-100, triggered indicators, verdict

---

## Phase 3 — Real-Time API & iPhone App ✅ COMPLETE

**Goal:** Expose detectors via REST API + WebSocket, build iPhone companion app.

### Backend (FastAPI)
- File: `src/api/server.py`
- JWT authentication (python-jose + PBKDF2 hashing)
- REST endpoints: `/health`, `/detectors`, `/events`, `/scan/*`, `/network/*`, `/gmail/*`
- WebSocket `/ws` — streams alerts to iPhone in real time as they fire
- CORS enabled for local network access from iPhone

### iPhone App (React Native + Expo)
- `mobile/src/screens/DashboardScreen.js` — Live threat feed, severity counts, system health
- `mobile/src/screens/AlertScreen.js` — Full alert list with filter by severity
- `mobile/src/screens/NetworkScreen.js` — 3 tabs: Live connections (5s refresh), Anomalies, System stats (3s refresh)
- `mobile/src/screens/ScanScreen.js` — Gmail scanner, system logs viewer, vulnerability scanner
- `mobile/src/screens/SettingsScreen.js` — Backend URL, credentials, token management
- `mobile/src/services/api.js` — API client with timeout handling
- `mobile/src/services/websocket.js` — Auto-reconnect WebSocket with exponential backoff

---

## Phase 4 — Real Data Sources ✅ COMPLETE

**Goal:** Remove all demo/fake data. Everything uses real system data.

### What was replaced

| Before | After |
|---|---|
| Fake generated network flows | `netstat -anp tcp` — real live TCP connections, no root needed |
| Hardcoded sample emails | Gmail OAuth2 with PKCE — real inbox via Google API |
| No system logs | macOS `log show` — real system logs filtered by type (auth/network/security) |
| Fake CPU/memory stats | `psutil` — real CPU %, memory, disk, network I/O |

### Key files
- `src/api/system_monitor.py` — Live connections, system stats, real log fetching
- `src/api/gmail_oauth.py` — Full Gmail OAuth2 flow (consent → callback → token → fetch inbox)
- `docs/gmail_setup.md` — Step-by-step Google Cloud Console setup guide

### Technical challenges solved
- **psutil needs root** for `net_connections()` on macOS → switched to `netstat` subprocess (no root)
- **Gmail PKCE code_verifier lost between requests** → stored `_pending_flow` as a module-level global so same flow object is reused in callback
- **Amazon OTP flagged as phishing** → brand-label matching checks each domain label against trusted brands set, so `amazon.co.uk` matches `amazon`

---

## Phase 5 — Live Packet Capture 🔜 NEXT

**Goal:** Capture real network packets on your Mac and feed them into the anomaly detector instead of reading CSVs.

### Why this matters
Right now the network anomaly detector reads pre-made CSV files or individual `netstat` snapshots. Phase 5 gives it a live, continuous feed of every packet coming in/out of your Mac — so it can catch attacks the moment they start.

### What to build

#### 5a. Packet Sniffer (`src/capture/packet_sniffer.py`)
- Use `scapy` (or `pyshark` wrapping tshark) to sniff on the active interface
- Requires: `sudo` on macOS (or set capabilities on Python binary)
- Capture: IP src/dst, port src/dst, protocol, packet size, TCP flags
- Run as an async background task that streams packets into a queue

#### 5b. Flow Aggregator (`src/capture/flow_aggregator.py`)
- Group individual packets into 5-second flows
- Compute per-flow features: bytes sent/recv, packet count, duration, mean inter-arrival time
- Output a feature dict matching the format the Isolation Forest model expects

#### 5c. Live Feed Integration (`src/api/server.py`)
- New endpoint: `GET /network/capture/start` — start sniffing (requires server to be run with sudo or capabilities)
- New endpoint: `GET /network/capture/stop`
- WebSocket push: when anomaly score > 0.7, push alert to iPhone immediately

#### 5d. App UI (`mobile/src/screens/NetworkScreen.js`)
- Add "Capture" tab with start/stop button
- Live packet rate graph (packets/sec)
- Instant alert card when anomaly detected

### Dependencies to add
```
scapy>=2.5.0
```

### Estimated effort: 2 days

---

## Phase 6 — Auto-Defense / IP Blocking Engine 🔜

**Goal:** When an attack is confirmed, automatically block the attacker's IP at the firewall level — no manual action required.

### Why this matters
Right now CyberGuard detects a brute force attack and sends you an alert. You have to manually decide what to do. Phase 6 makes the system act: it adds the attacker's IP to macOS's built-in `pf` firewall, blocking all future connections from that IP automatically.

### What to build

#### 6a. Firewall Manager (`src/defense/firewall.py`)
```python
class FirewallManager:
    BLOCK_TABLE = "cyberguard_blocklist"

    async def block_ip(self, ip: str, reason: str, duration_seconds: int = 3600):
        """Add IP to pf blocklist. Duration 0 = permanent."""
        # pfctl -t cyberguard_blocklist -T add <ip>
        ...

    async def unblock_ip(self, ip: str):
        # pfctl -t cyberguard_blocklist -T delete <ip>
        ...

    async def list_blocked(self) -> list[dict]:
        # pfctl -t cyberguard_blocklist -T show
        ...

    async def setup_pf_rule(self):
        """Create the pf anchor rule if not already present."""
        # Writes /etc/pf.anchors/cyberguard
        # Adds 'anchor cyberguard' to /etc/pf.conf
        # pfctl -f /etc/pf.conf
        ...
```

- Uses macOS `pfctl` (packet filter control) — built-in, no extra install
- Requires `sudo` — server must run with elevated permissions for auto-block to work
- Blocked IPs auto-expire after configurable duration (default 1 hour)
- Maintains a SQLite table of blocked IPs with timestamps and reasons

#### 6b. Block List Store (`src/defense/block_store.py`)
- SQLite database: `data/blocklist.db`
- Schema: `ip, reason, blocked_at, expires_at, attack_type, auto_unblocked`
- Background task: every 60 seconds, unblock IPs whose `expires_at` has passed
- Persistence: survives server restarts (reapplies pf rules on startup)

#### 6c. API Endpoints (`src/api/server.py`)
```
GET  /defense/blocklist          — list all currently blocked IPs
POST /defense/block              — manually block an IP {ip, reason, duration_hours}
POST /defense/unblock            — manually unblock {ip}
GET  /defense/history            — full block/unblock audit log
```

#### 6d. iPhone App (`mobile/src/screens/DefenseScreen.js`) — New Screen
- Show active blocklist with countdown timers
- "Block IP" manual action on any connection in the Live tab
- Push notification when an IP is auto-blocked

### Setup required (one-time)
```bash
# Run once as root to set up the pf anchor
sudo python -m src.defense.setup_pf
```

This adds to `/etc/pf.conf`:
```
table <cyberguard_blocklist> persist
block drop from <cyberguard_blocklist> to any
```

### Estimated effort: 3 days

---

## Phase 7 — Process Monitor & Kill Engine 🔜

**Goal:** Detect malicious processes (crypto miners, reverse shells, keyloggers) and optionally kill them automatically.

### Why this matters
Not all attacks come through the network. Some malware runs as a process on your Mac — a crypto miner consuming 100% CPU, a reverse shell phoning home, or a keylogger reading your keystrokes. Phase 7 makes CyberGuard watch every running process.

### What to build

#### 7a. Process Scanner (`src/detectors/process_monitor.py`)
```python
class ProcessMonitor(BaseDetector):
    SUSPICIOUS_PROCESS_NAMES = {
        "nc", "ncat", "netcat",           # netcat reverse shells
        "cryptominer", "xmrig", "minerd", # crypto miners
        "msfconsole", "msfvenom",         # Metasploit
        "mimikatz",                       # credential dumper
        "cobaltstrike", "beacon",         # C2 agents
    }

    async def scan(self) -> list[ProcessAlert]:
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cpu_percent',
                                          'connections', 'open_files']):
            # Check: name in suspicious list
            # Check: CPU > 80% sustained (crypto miner heuristic)
            # Check: has outbound TCP connection to non-browser port
            # Check: opened files in /tmp or unusual paths
            # Check: process spawned from unusual parent (e.g. bash spawned from Python)
            ...
```

- Runs every 30 seconds as a background task
- CPU spike detection: track rolling average, alert if 3-minute average > 70%
- Suspicious network connections: process has connection to known C2 ports (4444, 1337, 31337)
- Unusual parent: browser spawned a shell, shell spawned Python, etc.

#### 7b. Process Kill API
```
GET  /processes/suspicious        — list processes flagged as suspicious
POST /processes/kill/{pid}        — kill a specific process (requires confirmation)
POST /processes/kill/auto-enable  — enable auto-kill for critical-severity processes
```

#### 7c. iPhone UI
- New tab in the existing Scan screen: "Processes"
- Show running processes sorted by risk
- Swipe-to-kill action with confirmation dialog
- Badge count in tab bar if suspicious processes found

### Estimated effort: 2 days

---

## Phase 8 — File Scanner & Download Monitor 🔜

**Goal:** Scan files for known malware using hash databases, and watch the Downloads folder for new dangerous files.

### Why this matters
When you download a file, CyberGuard should instantly check if it is known malware — like what your antivirus does, but without sending your files to a third-party cloud service.

### What to build

#### 8a. Hash Scanner (`src/detectors/file_scanner.py`)
- Download NSRL (National Software Reference Library) hash database — free, ~5GB
- Or use VirusTotal API (free tier: 500 requests/day) for hash lookups
- SHA-256 hash each new file, look up against local hash DB
- Flag exact matches as malware, report family name and threat category

#### 8b. Downloads Watcher (`src/capture/downloads_watcher.py`)
```python
import watchdog.observers  # pip install watchdog

class DownloadsWatcher:
    WATCH_PATHS = [
        Path.home() / "Downloads",
        Path.home() / "Desktop",
        Path("/tmp"),
    ]

    def on_created(self, event):
        """Triggered when a new file appears."""
        asyncio.create_task(self.scan_file(event.src_path))

    async def scan_file(self, path: str):
        # 1. Compute SHA-256
        # 2. Check local hash DB
        # 3. If not found locally, check VirusTotal API
        # 4. Check file extension (exe, dmg, pkg, scr, vbs = risky)
        # 5. For scripts: check content for suspicious patterns
        # 6. Emit alert if any risk found
        ...
```

#### 8c. Static Analysis Helpers
- Executable check: `file` command to detect actual executables regardless of extension
- Script analysis: look for base64-encoded payloads, obfuscated strings, unusual curl/wget commands
- Office macro detection: check .docm, .xlsm for embedded macros

#### 8d. API + iPhone
```
POST /scan/file          — scan a specific file path
GET  /scan/file/history  — recent file scan results
```
iPhone: "File Scan" tab — drag-and-drop file path, show hash, verdict, VirusTotal link

### Dependencies to add
```
watchdog>=4.0.0
```

### Estimated effort: 3 days

---

## Phase 9 — Auto-Response Rules Engine 🔜

**Goal:** Define automated response rules in plain English. When a threat matches, the system picks the right response automatically.

### Why this matters
Instead of hard-coding "always block for 1 hour", you want to say: "If I see a brute force attack, block the IP for 2 hours and send me a push notification." Phase 9 is the brain that connects detections to responses.

### What to build

#### 9a. Rules Engine (`src/defense/rules_engine.py`)
```python
# Example rules (stored in config/defense_rules.yaml)
EXAMPLE_RULES = [
    {
        "name": "Block brute force attackers",
        "trigger": {"detector": "log_analyzer", "attack_type": "brute_force", "severity": "high"},
        "actions": [
            {"type": "block_ip", "duration_hours": 2},
            {"type": "push_notification", "message": "Brute force blocked: {ip}"},
            {"type": "log_event"},
        ]
    },
    {
        "name": "Kill crypto miner",
        "trigger": {"detector": "process_monitor", "attack_type": "crypto_miner", "severity": "critical"},
        "actions": [
            {"type": "kill_process", "pid": "{pid}"},
            {"type": "block_ip", "duration_hours": 24},
            {"type": "push_notification", "message": "Crypto miner killed: {process_name}"},
        ]
    },
    {
        "name": "Quarantine malicious download",
        "trigger": {"detector": "file_scanner", "verdict": "malware"},
        "actions": [
            {"type": "quarantine_file", "path": "{file_path}"},
            {"type": "push_notification", "message": "Malware quarantined: {filename}"},
        ]
    },
    {
        "name": "Alert on suspicious process (no auto-kill)",
        "trigger": {"detector": "process_monitor", "severity": "medium"},
        "actions": [
            {"type": "push_notification", "message": "Suspicious process: {process_name} (PID {pid})"},
        ]
    },
]
```

#### 9b. Action Handlers
Each action type maps to a handler function:
- `block_ip` → calls `FirewallManager.block_ip()`
- `kill_process` → calls `psutil.Process(pid).terminate()`
- `quarantine_file` → moves file to `~/CyberGuardQuarantine/` and strips execute permission
- `push_notification` → iOS push via APNs (Apple Push Notification Service)
- `log_event` → writes structured entry to audit log
- `webhook` → POST to a URL (e.g. Slack, Discord, n8n)

#### 9c. Rules Config File (`config/defense_rules.yaml`)
- YAML format — human-readable, easy to edit without coding
- Hot-reload: server watches the file for changes, applies new rules without restart
- Rule priority ordering: higher priority rules evaluated first
- Cooldown: prevent same rule firing twice within N minutes for same attacker

#### 9d. API + iPhone
```
GET  /defense/rules              — list all active rules
POST /defense/rules              — add a new rule
PUT  /defense/rules/{name}       — update a rule
DEL  /defense/rules/{name}       — delete a rule
GET  /defense/rules/history      — log of which rules fired and what actions were taken
```

iPhone: "Rules" tab in Defense screen — toggle rules on/off, see recent rule activations

#### 9e. iOS Push Notifications
- Uses Expo Push Notifications (simplest path — no Apple Developer account needed for local testing)
- Server calls Expo's push endpoint when a rule fires
- User must allow notifications in iPhone when prompted

### Dependencies to add
```
exponent-server-sdk>=2.1.0   # Expo push notifications
watchdog>=4.0.0              # Config file hot-reload
```

### Estimated effort: 4 days

---

## Phase 10 — Threat Intelligence Feed 🔜 (Future)

**Goal:** Automatically cross-reference attackers against public threat intelligence databases.

### What to build
- Pull blocklists from AbuseIPDB, Emerging Threats, Spamhaus
- Cache locally (updated daily) so lookups are instant and offline
- Auto-tag IPs seen in threat feeds with source and category (e.g. "known botnet C2")
- Feed results into rules engine: IPs in threat feeds get auto-blocked immediately

---

## Tech Stack Summary

| Layer | Technology |
|---|---|
| Backend language | Python 3.11+ |
| API framework | FastAPI + Uvicorn |
| ML / anomaly detection | scikit-learn (Isolation Forest) |
| Real-time streaming | WebSocket (FastAPI native) |
| Packet capture | scapy (Phase 5) |
| Firewall control | macOS pfctl (Phase 6) |
| Process monitoring | psutil |
| File watching | watchdog (Phase 8) |
| Database | SQLite via aiosqlite (Phase 6+) |
| Mobile app | React Native + Expo |
| Push notifications | Expo Push API (Phase 9) |
| Auth | JWT (python-jose) + PBKDF2 |
| Logging | structlog (JSON structured) |
| CI | GitHub Actions (ruff + bandit + pytest) |

---

## Build Order Recommendation

```
Phase 5 (Packet Capture) → Phase 6 (IP Blocking) → Phase 7 (Process Monitor)
         ↓
Phase 9 (Rules Engine) — connects all detectors to all response actions
         ↓
Phase 8 (File Scanner) → Phase 10 (Threat Intel)
```

Start with Phase 6 (IP Blocking) if you want the most immediately useful auto-defense feature. It requires no new packages and can use data from the Phase 4 live connections we already have.

---

## Progress Tracker

| Phase | Name | Status |
|---|---|---|
| 1 | Core Detection Engine | ✅ Complete |
| 2 | AI/ML Detectors (Network + Log + Vuln + Phishing) | ✅ Complete |
| 3 | REST API + iPhone App | ✅ Complete |
| 4 | Real Data Sources (live connections, Gmail, system logs) | ✅ Complete |
| 5 | Live Packet Capture (scapy) | 🔜 Not started |
| 6 | Auto-Defense / IP Blocking Engine | 🔜 Not started |
| 7 | Process Monitor & Kill Engine | 🔜 Not started |
| 8 | File Scanner & Download Monitor | 🔜 Not started |
| 9 | Auto-Response Rules Engine | 🔜 Not started |
| 10 | Threat Intelligence Feed | 🔜 Future |
