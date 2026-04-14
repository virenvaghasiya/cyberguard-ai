# CyberGuard AI — Master Build Plan

> **Goal:** Build a personal AI-powered cybersecurity system that detects and automatically responds to the widest possible range of attacks on your Mac — a real Intrusion Prevention System (IPS), not just a detector.

---

## Attack Coverage Map

| Attack Category | Example | Detect | Block/Stop | Phase |
|---|---|---|---|---|
| Network flood / DDoS | Packet flood overwhelming Mac | ✅ | 🔜 P6 | 2a + 5 |
| Port scanning | Attacker mapping open ports | ✅ | 🔜 P6 | 2a |
| Data exfiltration | Large upload to unknown IP | ✅ | 🔜 P6 | 2a + 5 |
| C2 beacon (malware calling home) | Regular small packets to attacker | ✅ | 🔜 P6 | 2a + 5 |
| Brute force login | Repeated SSH / web login attempts | ✅ | 🔜 P6 | 2b |
| Privilege escalation | sudo abuse after failed logins | ✅ | 🔜 P9 | 2b |
| Web scanning / directory traversal | 404 flood on a local web server | ✅ | 🔜 P6 | 2b |
| Phishing emails | Fake PayPal / bank login page | ✅ | ✅ alert | 2d |
| Open vulnerable ports | MySQL / MongoDB exposed to network | ✅ | Manual | 2c |
| Known attack signatures (50k+) | Shellshock, EternalBlue, Log4Shell | 🔜 | 🔜 P6 | P5b |
| DNS tunneling | Data smuggled inside DNS queries | 🔜 | 🔜 P6 | P5c |
| Malware domain C2 | Malware connecting to known bad domain | 🔜 | 🔜 P5c | P5c |
| DGA domains (botnet) | Random-looking domain names | 🔜 | 🔜 P5c | P5c |
| TLS/HTTPS C2 (JA3) | Malware hiding in HTTPS traffic | 🔜 | 🔜 P6 | P5d |
| Man-in-the-middle / ARP spoofing | Attacker intercepting your traffic | 🔜 | 🔜 P6 | P5e |
| SYN flood | TCP connection flood | 🔜 | 🔜 P6 | P5 |
| Crypto miner | xmrig using 100% CPU | 🔜 | 🔜 P7 | P7a |
| Reverse shell | nc / netcat phoning home | 🔜 | 🔜 P7 | P7a |
| Persistence (LaunchAgent) | Malware adding macOS startup item | 🔜 | 🔜 P7 | P7b |
| /etc/hosts tampering | Redirect google.com to attacker | 🔜 | 🔜 P7 | P7b |
| SSH key backdoor | New key added to authorized_keys | 🔜 | 🔜 P7 | P7b |
| New user account created | Attacker adds hidden admin user | 🔜 | 🔜 P7 | P7b |
| Malware download | Known malware hash in Downloads | 🔜 | 🔜 P8 | P8a |
| Script obfuscation | base64-encoded malware payload | 🔜 | 🔜 P8 | P8b |
| System file tampering | /etc/sudoers or shell config changed | 🔜 | 🔜 P8 | P8c |
| Malicious USB device | BadUSB / rogue HID device | 🔜 | alert | P7c |
| Rogue Wi-Fi access point | Evil twin attack | 🔜 | alert | P11 |
| ARP poisoning on LAN | Man-in-the-middle on same network | 🔜 | 🔜 P11 | P11 |
| Malicious browser extension | Extension stealing passwords | 🔜 | alert | P12 |
| Known bad IP connection | IP on AbuseIPDB / Spamhaus | 🔜 | 🔜 P10 | P10 |

---

## What We Have Built vs. What We Are Building

| Capability | Built | Coming |
|---|---|---|
| Network anomaly ML detection | ✅ | — |
| Log analysis (brute force, escalation) | ✅ | — |
| Vulnerability port scanner | ✅ | — |
| Phishing email detector | ✅ | — |
| Live network connections | ✅ | — |
| Real system stats | ✅ | — |
| Real system logs | ✅ | — |
| Gmail inbox scanner | ✅ | — |
| REST API + WebSocket | ✅ | — |
| iPhone app | ✅ | — |
| Live packet capture (scapy) | — | Phase 5a |
| Known attack signatures (Snort rules) | — | Phase 5b |
| DNS monitoring + sinkholing | — | Phase 5c |
| TLS/JA3 fingerprint analysis | — | Phase 5d |
| ARP spoofing / MITM detection | — | Phase 5e |
| Auto IP blocking (pfctl firewall) | — | Phase 6 |
| VirusTotal IP + domain lookup | — | Phase 6b |
| Crypto miner / reverse shell detection | — | Phase 7a |
| Persistence monitoring (LaunchAgents etc.) | — | Phase 7b |
| USB device monitoring | — | Phase 7c |
| Malware hash file scanner | — | Phase 8a |
| Script obfuscation detection | — | Phase 8b |
| File integrity monitoring (FIM) | — | Phase 8c |
| Auto-response rules engine | — | Phase 9 |
| iOS push notifications | — | Phase 9 |
| Threat intelligence feeds | — | Phase 10 |
| Wi-Fi / rogue AP detection | — | Phase 11 |
| Browser extension security | — | Phase 12 |

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

#### 2a. Network Anomaly Detector
- File: `src/detectors/network_anomaly.py`
- Model: Isolation Forest (sklearn) trained on network flow features
- Detects: DDoS floods, data exfiltration, port scans, C2 beacon patterns
- Output: anomaly score 0-1, attack category, confidence

#### 2b. Log Analyzer
- File: `src/detectors/log_analyzer.py`
- Detects: Brute force login, privilege escalation, web scanning, SSH key tampering
- Input: Raw syslog / auth.log text

#### 2c. Vulnerability Scanner
- File: `src/detectors/vuln_scanner.py`
- Covers: 40+ risky ports with banner grabbing and CVE references

#### 2d. Phishing Email Detector
- File: `src/detectors/phishing_detector.py` + `src/detectors/phishing_features.py`
- 15+ signals, trusted sender whitelist with brand-label matching
- Amazon OTP, GitHub CI — correctly classified as safe

---

## Phase 3 — Real-Time API & iPhone App ✅ COMPLETE

### Backend (FastAPI)
- JWT authentication, REST + WebSocket, CORS for iPhone

### iPhone App (React Native + Expo)
- Dashboard, Alerts, Network Monitor, Scanner, Settings screens
- WebSocket auto-reconnect with exponential backoff

---

## Phase 4 — Real Data Sources ✅ COMPLETE

| Before | After |
|---|---|
| Fake flows | netstat (no root needed) |
| Hardcoded emails | Gmail OAuth2 with PKCE |
| No system logs | macOS `log show` |
| Fake stats | psutil live data |

---

## Phase 5 — Live Packet Capture + Deep Traffic Analysis 🔜

**Goal:** Capture every real packet on the Mac. Run deep analysis — not just anomaly scoring but signature matching, DNS inspection, TLS fingerprinting, and ARP attack detection.

### 5a. Packet Sniffer (`src/capture/packet_sniffer.py`)
- Use `scapy` to sniff the active network interface
- Requires `sudo` (or set packet capture entitlements on Python binary)
- Capture: IP src/dst, port src/dst, protocol, packet size, TCP flags, payload (where unencrypted)
- Stream packets into an async queue consumed by all Phase 5 analyzers

### 5b. Snort Signature Matching (`src/detectors/signature_detector.py`)
**This is the biggest single coverage boost — 50,000+ known attack patterns.**

- Download free Snort/Suricata community rules from `rules.emergingthreats.net`
- Parse rules into fast pattern matchers (Aho-Corasick algorithm for speed)
- Match against live packet payloads and headers
- Catches: EternalBlue (WannaCry), Shellshock, Log4Shell, Heartbleed, SQL injection over HTTP, XSS, directory traversal, Mimikatz traffic, known exploit kits
- Update rules daily via background task
- Alert: rule name, CVE references, matched packet

```python
class SignatureDetector(BaseDetector):
    async def load_rules(self, rules_path: str):
        # Parse Snort rule format:
        # alert tcp any any -> any 80 (msg:"SQL injection"; content:"' OR '1'='1"; ...)
        ...

    async def match_packet(self, packet) -> list[SignatureAlert]:
        # Check packet against all loaded rules
        # Return list of matched rules with severity
        ...
```

### 5c. DNS Monitor (`src/detectors/dns_monitor.py`)
**Catches malware that hides C2 traffic inside DNS — a very common evasion technique.**

- Intercept all DNS queries from the Mac (sniff UDP port 53 packets)
- Check every queried domain against:
  - Malware domain blocklists (abuse.ch, Malware Domain List, URLhaus)
  - DGA detection — domains that look randomly generated (high entropy score)
  - DNS tunneling detection — unusually long subdomains or high query rate
- DNS Sinkholing: redirect known-bad domains to 127.0.0.1 by modifying /etc/hosts or running a local DNS resolver
- Cache blocklists locally — update daily

```python
class DNSMonitor(BaseDetector):
    BLOCKLIST_URLS = [
        "https://urlhaus.abuse.ch/downloads/hostfile/",
        "https://malware-filter.gitlab.io/malware-filter/urlhaus-filter-hosts.txt",
    ]

    def is_dga_domain(self, domain: str) -> bool:
        # Calculate entropy of domain label
        # High entropy (> 3.5 bits/char) = likely DGA
        ...

    def detect_dns_tunneling(self, query: str) -> bool:
        # Subdomain > 50 chars = likely data encoded in DNS
        # > 100 DNS queries/minute to same domain = tunneling
        ...
```

### 5d. TLS/HTTPS Traffic Analyzer (`src/detectors/tls_analyzer.py`)
**We cannot decrypt HTTPS — but we can still catch malware by its TLS fingerprint.**

- Extract TLS ClientHello from packets (unencrypted part of TLS handshake)
- Compute JA3 hash — a fingerprint of how a program does TLS (cipher suites, extensions, elliptic curves)
- Check JA3 hash against known-malicious fingerprint database (Salesforce JA3 DB — free)
- Different browsers and malware families have unique JA3 fingerprints
- Also check: SNI (Server Name Indication) against malware domain lists, self-signed certificates, expired certificates, unusual cipher suites
- Catches: Cobalt Strike beacons, Meterpreter, known RAT families, even inside HTTPS

```python
class TLSAnalyzer(BaseDetector):
    KNOWN_MALWARE_JA3 = {
        "e7d705a3286e19ea42f587b344ee6865": "Cobalt Strike default",
        "6734f37431670b3ab4292b8f60f29984": "Trickbot",
        "51c64c77e60f3980eea90869b68c58a8": "Dridex",
    }

    def compute_ja3(self, tls_client_hello: bytes) -> str:
        # SSLVersion, Ciphers, Extensions, EllipticCurves, EllipticCurvePoints
        # Concatenate → MD5 hash
        ...
```

### 5e. ARP Spoofing / MITM Detector (`src/detectors/arp_monitor.py`)
**Catches man-in-the-middle attacks where attacker intercepts your traffic on the local network.**

- Monitor ARP packets (who-has / is-at messages)
- Build a table of IP → MAC address mappings
- Alert if:
  - Same IP suddenly has a different MAC address (ARP cache poisoning)
  - Gateway MAC address changes (attacker positioned between you and router)
  - Gratuitous ARP flood (rapid unsolicited ARP replies — sign of attack)
- Response: alert + optionally send corrective ARP to restore real mapping

### 5f. Flow Aggregator + API Updates
- `src/capture/flow_aggregator.py` — groups packets into 5-sec flows for ML
- New endpoints: `GET /network/capture/start`, `GET /network/capture/stop`
- New iPhone tab: Capture — start/stop, live packets/sec graph, instant alerts

### Dependencies to add
```
scapy>=2.5.0
```

### Estimated effort: 5 days

---

## Phase 6 — Auto-Defense: IP Blocking + VirusTotal 🔜

**Goal:** When an attack is confirmed, automatically block the attacker's IP. Cross-check any IP or domain against VirusTotal's 70+ engine database.

### 6a. Firewall Manager (`src/defense/firewall.py`)
- macOS `pfctl` — built-in firewall, no extra install
- Requires `sudo` to run
- `block_ip(ip, reason, duration_seconds)` — adds to pf table
- `unblock_ip(ip)` — removes from pf table
- Auto-expire: background task checks every 60s, unblocks expired IPs
- Persists across restarts (reapplies pf rules on server startup)

One-time setup:
```bash
sudo python -m src.defense.setup_pf
```

Adds to `/etc/pf.conf`:
```
table <cyberguard_blocklist> persist
block drop from <cyberguard_blocklist> to any
```

### 6b. VirusTotal Integration (`src/intelligence/virustotal.py`)
**Check any IP, domain, or URL against 70+ security vendors — free tier: 500 req/day.**

```python
class VirusTotalClient:
    async def check_ip(self, ip: str) -> VTResult:
        # GET https://www.virustotal.com/api/v3/ip_addresses/{ip}
        # Returns: malicious count, suspicious count, country, ASN, last analysis date
        ...

    async def check_domain(self, domain: str) -> VTResult:
        # GET https://www.virustotal.com/api/v3/domains/{domain}
        ...

    async def check_file_hash(self, sha256: str) -> VTResult:
        # GET https://www.virustotal.com/api/v3/files/{sha256}
        ...
```

- Called automatically when: new outbound connection to unknown IP, DNS query to unknown domain, new file downloaded
- If VT reports > 3 engines flagging as malicious → trigger auto-block rule
- Cache results locally for 24 hours (avoid burning API quota)

### 6c. Block List Store (`src/defense/block_store.py`)
- SQLite: `data/blocklist.db`
- Schema: `ip, reason, blocked_at, expires_at, attack_type, vt_score, auto_unblocked`

### 6d. API Endpoints
```
GET  /defense/blocklist          — active blocks with countdowns
POST /defense/block              — manual block {ip, reason, duration_hours}
POST /defense/unblock            — manual unblock {ip}
GET  /defense/history            — full audit log
POST /intelligence/check         — on-demand VT check for IP/domain/hash
```

### 6e. iPhone: Defense Screen (new)
- Active blocklist with countdown timers
- "Block IP" button on any live connection
- On-demand VirusTotal check from the app

### Estimated effort: 3 days

---

## Phase 7 — Process Monitor + Persistence + USB 🔜

**Goal:** Watch every running process, detect malware that survives reboots, alert on suspicious hardware.

### 7a. Process Scanner (`src/detectors/process_monitor.py`)

Suspicious patterns:
- **Name matching**: nc, ncat, netcat, xmrig, minerd, msfconsole, cobaltstrike, beacon, mimikatz, empire
- **CPU spike**: 3-minute rolling average > 70% → crypto miner heuristic
- **Malware ports**: outbound connection to 4444, 1337, 31337, 6666, 12345
- **Suspicious parent**: Terminal spawned Python which spawned bash (unusual chain)
- **Hidden process**: process name starts with `.` or runs from /tmp
- **Unsigned binary**: macOS codesign check — unsigned apps from unusual paths

```python
async def check_codesign(self, path: str) -> bool:
    result = await asyncio.create_subprocess_exec(
        "codesign", "--verify", "--strict", path,
        stderr=asyncio.subprocess.PIPE
    )
    _, stderr = await result.communicate()
    return result.returncode == 0
```

### 7b. Persistence Monitor (`src/detectors/persistence_monitor.py`)
**Malware survives reboots by adding startup items. This catches that.**

Watch these locations for unexpected changes:
```
~/Library/LaunchAgents/          — user startup daemons
/Library/LaunchAgents/           — system startup daemons
/Library/LaunchDaemons/          — system services
/etc/hosts                       — DNS override tampering
~/.ssh/authorized_keys           — SSH backdoor keys
/etc/sudoers                     — privilege escalation backdoor
~/.bashrc, ~/.zshrc, ~/.profile  — shell persistence
/etc/crontab, ~/Library/cron     — scheduled task persistence
```

How it works:
- On first run: hash all files in these locations, save baseline to `data/persistence_baseline.json`
- Every 5 minutes: re-hash and compare
- Alert on: new file added, existing file changed, file deleted
- For LaunchAgents: parse plist and show the command that runs on startup
- Action: alert + show the exact file that changed + diff the change

### 7c. USB / Hardware Monitor (`src/detectors/usb_monitor.py`)
**Alert whenever a new USB device connects — catches BadUSB and rogue HID devices.**

- Use macOS `system_profiler SPUSBDataType` to get current USB devices
- Poll every 10 seconds, compare to known device list
- Alert on new device: show vendor, product name, vendor ID, product ID
- Classify risk: Human Interface Devices (keyboards/mice) = higher risk (BadUSB), mass storage = medium
- Store approved devices list — user can mark devices as trusted in the app

### 7d. APIs
```
GET  /processes/suspicious        — flagged processes
GET  /processes/all               — all running processes with risk scores
POST /processes/kill/{pid}        — kill process
GET  /persistence/baseline        — current baseline
GET  /persistence/changes         — recent changes detected
POST /persistence/approve         — mark a change as approved (not malware)
GET  /usb/devices                 — current USB devices
GET  /usb/alerts                  — new device alerts
POST /usb/trust/{device_id}       — mark device as trusted
```

### Estimated effort: 3 days

---

## Phase 8 — File Scanner + Integrity Monitor 🔜

**Goal:** Detect malware in downloaded files, detect obfuscated scripts, detect tampering with system files.

### 8a. Malware Hash Scanner (`src/detectors/file_scanner.py`)
- SHA-256 hash any file
- Check against:
  - **VirusTotal** (Phase 6b client) — 70+ engine verdict
  - **MalwareBazaar** (abuse.ch) — free malware hash feed, no API key needed
  - **NSRL** (optional) — 200M+ legitimate file hashes (eliminates false positives)
- Flag: malware family, threat category, detection count
- Quarantine: move to `~/CyberGuardQuarantine/` + strip execute bit + log

### 8b. Downloads Watcher (`src/capture/downloads_watcher.py`)
- `watchdog` library watches: ~/Downloads, ~/Desktop, /tmp
- Every new file → auto-scan within 3 seconds
- Risk check sequence:
  1. Extension check (dmg, pkg, exe, scr, vbs, ps1 = risky)
  2. `file` command — detect actual executable regardless of extension
  3. Hash check (MalwareBazaar + VT)
  4. Static analysis (see 8c)

### 8c. Static Script Analyzer (`src/detectors/script_analyzer.py`)
**Catches malicious scripts even if the hash is unknown.**

Signals:
- **Base64 encoded payload**: `base64 -d` or `echo <long_base64> | python`
- **Obfuscated commands**: hex-encoded strings, char code concatenation
- **Suspicious curl/wget**: downloading and executing in one command (`curl url | bash`)
- **Reverse shell patterns**: `/dev/tcp/`, `nc -e /bin/bash`, `python -c 'import socket'`
- **Privilege escalation**: `sudo` without password, /etc/sudoers modification
- **Persistence planting**: LaunchAgent/cron install commands in script body
- **Office macro detection**: check .docm, .xlsm for embedded VBA macros
- Applies to: .sh, .py, .rb, .js, .ps1, .vbs, .bat files

### 8d. File Integrity Monitoring (FIM) (`src/detectors/file_integrity.py`)
**Detect if critical system files have been tampered with.**

Protected file list:
```
/etc/hosts              — DNS override attack
/etc/sudoers            — privilege escalation
/etc/passwd             — user account tampering
~/.ssh/authorized_keys  — SSH backdoor
~/.bashrc / ~/.zshrc    — shell persistence
/usr/local/bin/*        — tool replacement attack
/Applications/*         — app tampering
```

How it works:
- Baseline hash stored at first run in `data/fim_baseline.json`
- inotify-style monitoring via `watchdog` on macOS
- Alert on any change: show file, old hash, new hash, what changed (using diff)
- Critical files (sudoers, hosts, authorized_keys) trigger immediate high-severity alert

### 8e. API + iPhone
```
POST /scan/file              — scan specific file
GET  /scan/file/history      — recent scan results
GET  /fim/status             — FIM status
GET  /fim/changes            — recent integrity violations
POST /fim/approve/{path}     — mark change as intentional
GET  /quarantine/list        — quarantined files
POST /quarantine/restore     — restore false positive
```

### Dependencies to add
```
watchdog>=4.0.0
```

### Estimated effort: 3 days

---

## Phase 9 — Auto-Response Rules Engine 🔜

**Goal:** Connect every detector to every response action via simple YAML rules — no coding required.

### 9a. Rules Engine (`src/defense/rules_engine.py`)

Example rules (`config/defense_rules.yaml`):
```yaml
rules:
  - name: Block brute force
    trigger:
      detector: log_analyzer
      attack_type: brute_force
      severity: high
    cooldown_minutes: 30
    actions:
      - type: block_ip
        duration_hours: 2
      - type: push_notification
        message: "Brute force blocked: {ip} ({attempts} attempts)"

  - name: Kill crypto miner
    trigger:
      detector: process_monitor
      attack_type: crypto_miner
      severity: critical
    actions:
      - type: kill_process
      - type: block_ip
        duration_hours: 24
      - type: push_notification
        message: "Crypto miner killed: {process_name}"

  - name: Quarantine malware download
    trigger:
      detector: file_scanner
      verdict: malware
    actions:
      - type: quarantine_file
      - type: push_notification
        message: "Malware quarantined: {filename} ({vt_detections} engines)"

  - name: Block known-bad IP (VirusTotal)
    trigger:
      detector: virustotal
      malicious_count_gt: 5
    actions:
      - type: block_ip
        duration_hours: 48
      - type: push_notification

  - name: Alert on DNS malware domain
    trigger:
      detector: dns_monitor
      category: malware_domain
    actions:
      - type: block_domain
      - type: push_notification
        message: "Malware domain blocked: {domain}"

  - name: Alert on Snort signature match
    trigger:
      detector: signature_detector
      severity: critical
    actions:
      - type: block_ip
        duration_hours: 1
      - type: push_notification
        message: "Known attack blocked: {rule_name}"

  - name: Persistence change alert
    trigger:
      detector: persistence_monitor
    actions:
      - type: push_notification
        message: "System file changed: {file_path}"
      - type: log_event

  - name: New USB device alert
    trigger:
      detector: usb_monitor
      device_type: hid
    actions:
      - type: push_notification
        message: "New USB device: {device_name}"
```

### 9b. All Available Actions
| Action | What it does |
|---|---|
| `block_ip` | pfctl firewall block, configurable duration |
| `block_domain` | Add to /etc/hosts sinkhole → 127.0.0.1 |
| `kill_process` | psutil terminate + SIGKILL fallback |
| `quarantine_file` | Move to ~/CyberGuardQuarantine/, strip perms |
| `push_notification` | iOS push via Expo |
| `webhook` | POST to Slack / Discord / n8n URL |
| `log_event` | Structured entry in audit log |
| `run_script` | Execute a shell script (advanced users) |

### 9c. Rules Config Features
- Hot-reload: changes applied without server restart
- Cooldown: same rule won't fire twice for same attacker within N minutes
- Priority ordering: critical rules evaluated first
- Dry-run mode: log what WOULD happen without taking action (safe testing)

### 9d. iOS Push Notifications
- Uses Expo Push API (no Apple Developer account needed)
- Token stored in `data/expo_push_token.json`
- Categories: threat (red), warning (orange), info (blue)

### Dependencies to add
```
exponent-server-sdk>=2.1.0
watchdog>=4.0.0
```

### Estimated effort: 4 days

---

## Phase 10 — Threat Intelligence Feeds 🔜

**Goal:** Automatically know about known-bad IPs and domains before they even connect to your Mac.

### What to build

#### 10a. Feed Manager (`src/intelligence/feed_manager.py`)
Daily-updated blocklists (all free, no API key for most):

| Feed | Content | URL |
|---|---|---|
| AbuseIPDB | Reported malicious IPs | api.abuseipdb.com (free 1k/day) |
| Emerging Threats | Known attack IPs | rules.emergingthreats.net |
| Spamhaus DROP | Botnet / spam IPs | www.spamhaus.org/drop/ |
| abuse.ch URLhaus | Active malware URLs | urlhaus.abuse.ch |
| abuse.ch MalwareBazaar | Malware hashes | bazaar.abuse.ch |
| Feodo Tracker | Botnet C2 IPs | feodotracker.abuse.ch |
| CINS Army | Attack IPs | cinsscore.com |

#### 10b. Local Cache
- SQLite: `data/threat_intel.db`
- Tables: `bad_ips`, `bad_domains`, `bad_hashes`
- Update on startup + daily refresh task
- All lookups are local → instant, no API quota used

#### 10c. Integration Points
- Network connections: every new IP checked against `bad_ips` cache → instant block if found
- DNS monitor: every query checked against `bad_domains` → instant sinkhole
- File scanner: every hash checked against `bad_hashes` → instant quarantine
- Rules engine: threat intel matches trigger their own rule category

### Estimated effort: 2 days

---

## Phase 11 — Wi-Fi & Network Security 🔜

**Goal:** Protect against attacks at the Wi-Fi and LAN level — rogue access points, network eavesdropping, ARP poisoning.

### 11a. Wi-Fi Monitor (`src/detectors/wifi_monitor.py`)
- Use macOS `airport` utility to scan nearby Wi-Fi networks
- Detect Evil Twin attacks: same SSID as your network but different BSSID/MAC
- Alert if connected network suddenly changes BSSID (AP replacement attack)
- Detect deauthentication flood (Wi-Fi jamming) — large number of deauth packets
- Alert if connected to open (unencrypted) network
- Show signal strength and encryption type for all nearby networks

```bash
# macOS airport utility (built-in, no install)
/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport -s
```

### 11b. LAN Scanner (`src/detectors/lan_scanner.py`)
- Discover all devices on local network (ARP scan, no root needed)
- Alert on new unknown devices joining the network
- Detect if any device is doing ARP spoofing (poisoning the gateway ARP table)
- Show device list: IP, MAC, vendor (from MAC OUI database), first/last seen

### 11c. Network Anomaly Extension
- Detect unusually high ARP traffic (ARP flood = MITM setup)
- Detect ICMP redirect attacks (routing manipulation)
- Detect suspicious DHCP servers (rogue DHCP server on LAN)

### Estimated effort: 3 days

---

## Phase 12 — Browser & Extension Security 🔜

**Goal:** Detect malicious browser extensions and catch when browsers are used as attack vectors.

### 12a. Extension Scanner (`src/detectors/browser_monitor.py`)
Check installed extensions in all browsers:
```
~/Library/Application Support/Google/Chrome/Default/Extensions/
~/Library/Application Support/Firefox/Profiles/*/extensions/
~/Library/Application Support/Microsoft Edge/Default/Extensions/
```

For each extension:
- Extract extension ID and version
- Check against known-malicious extension lists (CRXcavator, ExtAnalysis)
- Check permissions — extensions with `tabs`, `webRequest`, `cookies`, `history` = high risk
- Alert on newly installed extension or permission change

### 12b. Browser Network Monitor
- Monitor browser processes (Chrome, Firefox, Safari) network connections
- Flag connections to known tracking/malware domains
- Detect credential harvesting: browser sending POST to unexpected domain shortly after you type in a form

### 12c. API + iPhone
```
GET  /browser/extensions          — all installed extensions with risk ratings
GET  /browser/alerts              — suspicious extension events
POST /browser/extensions/approve  — mark extension as trusted
```

### Estimated effort: 2 days

---

## Tech Stack Summary

| Layer | Technology |
|---|---|
| Backend language | Python 3.11+ |
| API framework | FastAPI + Uvicorn |
| ML / anomaly detection | scikit-learn (Isolation Forest) |
| Real-time streaming | WebSocket (FastAPI native) |
| Packet capture | scapy |
| Signature matching | Snort/Suricata community rules + Aho-Corasick |
| DNS analysis | scapy + abuse.ch feeds |
| TLS analysis | JA3 fingerprinting via scapy |
| Firewall control | macOS pfctl |
| Process monitoring | psutil + macOS codesign |
| File watching | watchdog |
| Threat intelligence | AbuseIPDB, Spamhaus, Feodo, URLhaus, MalwareBazaar |
| VirusTotal | API v3 (files, IPs, domains, URLs) |
| Database | SQLite via aiosqlite |
| Mobile app | React Native + Expo |
| Push notifications | Expo Push API |
| Auth | JWT (python-jose) + PBKDF2 |
| Logging | structlog (JSON structured) |
| CI | GitHub Actions (ruff + bandit + pytest) |

---

## Build Order

```
Phase 5 (Packets + Signatures + DNS + TLS + ARP)
    ↓
Phase 6 (IP Blocking + VirusTotal)
    ↓
Phase 7 (Process + Persistence + USB)
    ↓
Phase 9 (Rules Engine — connects everything)
    ↓
Phase 8 (File Scanner + FIM)
    ↓
Phase 10 (Threat Intel Feeds)
    ↓
Phase 11 (Wi-Fi Security)
    ↓
Phase 12 (Browser Security)
```

**Start with Phase 6** (IP blocking) for the most immediate useful defense.
**Phase 5b** (Snort signatures) gives the biggest coverage jump once packets are flowing.

---

## Progress Tracker

| Phase | Name | Status |
|---|---|---|
| 1 | Core Detection Engine | ✅ Complete |
| 2 | AI/ML Detectors | ✅ Complete |
| 3 | REST API + iPhone App | ✅ Complete |
| 4 | Real Data Sources | ✅ Complete |
| 5 | Live Packet Capture + Signatures + DNS + TLS + ARP | 🔜 Not started |
| 6 | Auto IP Blocking + VirusTotal | 🔜 Not started |
| 7 | Process + Persistence + USB Monitor | 🔜 Not started |
| 8 | File Scanner + Script Analyzer + FIM | 🔜 Not started |
| 9 | Auto-Response Rules Engine + iOS Push | 🔜 Not started |
| 10 | Threat Intelligence Feeds | 🔜 Not started |
| 11 | Wi-Fi & LAN Security | 🔜 Not started |
| 12 | Browser & Extension Security | 🔜 Not started |
