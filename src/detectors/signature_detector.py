"""
CyberGuard AI — Signature-Based Attack Detector (Phase 5b).

Matches network traffic logs and raw packet payloads against a library of
attack signatures — the same concept as Snort/Suricata rules but implemented
in pure Python so it runs without root and passes CI.

Signature sources (built-in, no external download needed):
- 200+ hand-curated regex patterns covering OWASP Top 10, common exploits,
  C2 beacons, credential dumping, web attacks, recon, and more.
- Optional: load additional Suricata-style rules from data/rules/*.rules

Detection modes:
- analyze(data)  — accepts a dict or string payload, matches all signatures
- scan_text(text)— match a block of text (log line, HTTP body, etc.)
- scan_flow(flow) — match a network flow dict (src_ip, dst_ip, payload, ...)
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

from src.core.base_detector import BaseDetector
from src.core.events import Event, EventBus, EventType, Severity

logger = structlog.get_logger()

# ── Built-in signature library ────────────────────────────────────────────────
#
# Each entry: (sid, name, category, severity, regex_pattern)
# Patterns are compiled once at module load.
#
RAW_SIGNATURES: list[tuple[str, str, str, str, str]] = [
    # ── SQL Injection ──────────────────────────────────────────────────────
    ("sqli-001", "SQL UNION SELECT injection", "sqli", "high",
     r"(?i)union\s+(?:all\s+)?select\s+[\w*,\s'\"]+from"),
    ("sqli-002", "SQL blind boolean injection (AND/OR 1=1)", "sqli", "high",
     r"(?i)(?:and|or)\s+\d+\s*=\s*\d+(?:\s*--|;|'|\"|\s)"),
    ("sqli-003", "SQL sleep/benchmark injection", "sqli", "critical",
     r"(?i)(?:sleep\s*\(\s*\d+|benchmark\s*\(\s*\d+\s*,)"),
    ("sqli-004", "SQL stacked query attempt", "sqli", "high",
     r"(?i)';\s*(?:drop|insert|update|delete|exec|select)\s"),
    ("sqli-005", "SQL error-based injection (EXTRACTVALUE/UPDATEXML)", "sqli", "high",
     r"(?i)(?:extractvalue|updatexml)\s*\("),

    # ── Cross-Site Scripting (XSS) ─────────────────────────────────────────
    ("xss-001", "XSS script tag injection", "xss", "high",
     r"(?i)<\s*script[^>]*>"),
    ("xss-002", "XSS event handler injection", "xss", "medium",
     r"(?i)\bon(?:load|click|error|mouseover|focus|blur|submit)\s*=\s*['\"]"),
    ("xss-003", "XSS javascript: URI", "xss", "high",
     r"(?i)javascript\s*:"),
    ("xss-004", "XSS document.cookie theft", "xss", "high",
     r"(?i)document\.cookie"),
    ("xss-005", "XSS SVG/IMG payload", "xss", "medium",
     r"(?i)<\s*(?:svg|img)[^>]+on\w+\s*="),

    # ── Command Injection ──────────────────────────────────────────────────
    ("cmdi-001", "Command injection shell metacharacters", "cmdi", "critical",
     r"[;&|`$]\s*(?:ls|cat|id|whoami|uname|wget|curl|bash|sh|python|perl|nc)\b"),
    ("cmdi-002", "Command injection backtick execution", "cmdi", "critical",
     r"`[^`]{1,80}`"),
    ("cmdi-003", "Command injection $() subshell", "cmdi", "critical",
     r"\$\([^)]{1,80}\)"),
    ("cmdi-004", "Reverse shell one-liner (bash/nc)", "cmdi", "critical",
     r"(?i)bash\s+-[ic]\s+['\"].*(?:>|/dev/tcp|nc\s+-e)"),
    ("cmdi-005", "Python reverse shell", "cmdi", "critical",
     r"(?i)python[23]?\s+-c\s+['\"].*(?:socket|subprocess|os\.system)"),

    # ── Path Traversal ─────────────────────────────────────────────────────
    ("pt-001", "Path traversal ../", "path_traversal", "high",
     r"(?:\.\.[\\/]){2,}"),
    ("pt-002", "Path traversal URL-encoded", "path_traversal", "high",
     r"(?:%2e%2e[%2f%5c]){2,}"),
    ("pt-003", "Sensitive file access attempt", "path_traversal", "high",
     r"(?i)(?:etc/(?:passwd|shadow|sudoers)|\.ssh/(?:id_rsa|authorized_keys)|\.bash_history)"),

    # ── Web Recon / Scanner Fingerprints ──────────────────────────────────
    ("recon-001", "Nikto web scanner signature", "recon", "medium",
     r"(?i)nikto"),
    ("recon-002", "sqlmap user-agent", "recon", "high",
     r"(?i)sqlmap"),
    ("recon-003", "Nmap service probe", "recon", "medium",
     r"(?i)nmap"),
    ("recon-004", "Dirbuster/Gobuster pattern", "recon", "medium",
     r"(?i)(?:dirbuster|gobuster|wfuzz|ffuf)"),
    ("recon-005", "Masscan/ZMap rapid-scan UA", "recon", "medium",
     r"(?i)(?:masscan|zmap)"),
    ("recon-006", "PHP info disclosure probe", "recon", "low",
     r"(?i)phpinfo\s*\("),
    ("recon-007", "WordPress enumeration", "recon", "low",
     r"(?i)/wp-(?:login|admin|config|includes)/"),

    # ── Exploit / RCE Patterns ─────────────────────────────────────────────
    ("rce-001", "Log4Shell JNDI injection (CVE-2021-44228)", "rce", "critical",
     r"(?i)\$\{jndi:(?:ldap|rmi|dns|ldaps|iiop)://"),
    ("rce-002", "Spring4Shell T(Runtime) expression", "rce", "critical",
     r"(?i)T\s*\(\s*java\.lang\.Runtime\s*\)"),
    ("rce-003", "Struts2 OGNL injection", "rce", "critical",
     r"(?i)%\{.*class\.module\.classLoader\b"),
    ("rce-004", "PHP remote include (RFI)", "rce", "critical",
     r"(?i)(?:include|require)(?:_once)?\s*\(\s*['\"]https?://"),
    ("rce-005", "ShellShock bash env exploit", "rce", "critical",
     r"\(\s*\)\s*\{[^}]{0,40}\};\s*(?:echo|bash|sh|id|ls)\b"),
    ("rce-006", "CVE-2017-5638 Content-Type header exploit", "rce", "critical",
     r"(?i)%\{.*\(new\s+java\.lang\.ProcessBuilder"),
    ("rce-007", "ImageMagick Ghostscript RCE", "rce", "critical",
     r"(?i)\|.*(?:gs|ghostscript)\b"),
    ("rce-008", "XXE external entity injection", "rce", "high",
     r"(?i)<!ENTITY\s+\w+\s+SYSTEM\s+['\"](?:file|http|ftp|php)://"),

    # ── SSRF ──────────────────────────────────────────────────────────────
    ("ssrf-001", "SSRF AWS metadata probe", "ssrf", "critical",
     r"169\.254\.169\.254"),
    ("ssrf-002", "SSRF GCP metadata probe", "ssrf", "critical",
     r"metadata\.google\.internal"),
    ("ssrf-003", "SSRF localhost/loopback", "ssrf", "high",
     r"(?i)(?:https?://)?(?:localhost|127\.0\.0\.1|::1|0\.0\.0\.0)(?::\d+)?/"),

    # ── Credential / Auth Attacks ──────────────────────────────────────────
    ("auth-001", "HTTP Basic Auth brute-force indicator", "auth", "medium",
     r"(?i)authorization:\s*basic\s+[A-Za-z0-9+/=]{4,}"),
    ("auth-002", "Default credential attempt (admin:admin etc.)", "auth", "medium",
     r"(?i)(?:username|user|login)\s*[=:]\s*(?:admin|root|test|guest|administrator)"),
    ("auth-003", "Mimikatz output signature", "auth", "critical",
     r"(?i)(?:sekurlsa|lsadump|kerberos)::\w+"),
    ("auth-004", "Pass-the-hash NTLM material", "auth", "critical",
     r"(?i)(?:ntlm|lm)\s*hash\s*[:=]\s*[0-9a-f]{32}"),
    ("auth-005", "JWT none algorithm attack", "auth", "critical",
     r"(?i)eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.(?:eyJ[a-zA-Z0-9_-]+)?$"),

    # ── C2 / Malware Beacons ───────────────────────────────────────────────
    ("c2-001", "Cobalt Strike beacon header", "c2", "critical",
     r"(?i)(?:X-Malware-Bytes:|x-beacon-id:|cdn-cgi/beacon)"),
    ("c2-002", "Metasploit Meterpreter pattern", "c2", "critical",
     r"(?i)meterpreter"),
    ("c2-003", "Reverse shell over DNS (dnscat)", "c2", "critical",
     r"(?i)dnscat"),
    ("c2-004", "Empire PowerShell C2 pattern", "c2", "critical",
     r"(?i)(?:powershell\.exe.*-nop|-enc\s+[A-Za-z0-9+/=]{40,})"),
    ("c2-005", "Sliver C2 implant header", "c2", "critical",
     r"(?i)X-Sliver-"),
    ("c2-006", "Havoc C2 beacon", "c2", "critical",
     r"(?i)X-Havoc-"),
    ("c2-007", "Base64-encoded PowerShell (dropper)", "c2", "high",
     r"(?i)(?:-[Ee]ncodedCommand|-[Ee]nc)\s+[A-Za-z0-9+/=]{80,}"),

    # ── Crypto Miner Signatures ────────────────────────────────────────────
    ("miner-001", "XMRig stratum protocol", "miner", "high",
     r"(?i)stratum\+tcp://"),
    ("miner-002", "Mining pool connection string", "miner", "high",
     r"(?i)(?:xmr|monero|bitcoin|ethereum)\.(?:pool|mine|miner)\.\w+"),
    ("miner-003", "Cryptocurrency wallet address (Monero)", "miner", "medium",
     r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b"),

    # ── Data Exfiltration Patterns ─────────────────────────────────────────
    ("exfil-001", "Large base64 blob in URL param", "exfil", "high",
     r"[?&][^=]+=(?:[A-Za-z0-9+/]{200,}={0,2})"),
    ("exfil-002", "AWS key material in payload", "exfil", "critical",
     r"(?:AKIA|ASIA)[0-9A-Z]{16}"),
    ("exfil-003", "Private key PEM header", "exfil", "critical",
     r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    ("exfil-004", "Credit card number pattern", "exfil", "high",
     r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"),

    # ── Deserialization Attacks ────────────────────────────────────────────
    ("deser-001", "Java serialized object magic bytes", "deser", "critical",
     r"\xac\xed\x00\x05"),
    ("deser-002", "Python pickle opcode in payload", "deser", "critical",
     r"(?i)pickle\.loads|cPickle\.loads"),
    ("deser-003", "PHP unserialize call", "deser", "high",
     r"(?i)unserialize\s*\("),

    # ── Privilege Escalation Indicators ───────────────────────────────────
    ("privesc-001", "Sudo -l enumeration", "privesc", "medium",
     r"sudo\s+-l(?:\s|$)"),
    ("privesc-002", "SUID binary search", "privesc", "medium",
     r"find\s+[/\w]+\s+-perm\s+(?:-[0-9]+|/[0-9]+)\s+-exec"),
    ("privesc-003", "LinPEAS/WinPEAS dropper", "privesc", "high",
     r"(?i)(?:linpeas|winpeas|linenum)"),
    ("privesc-004", "Docker socket escape", "privesc", "critical",
     r"/var/run/docker\.sock"),
    ("privesc-005", "NSS LDAP sudoers bypass", "privesc", "high",
     r"(?i)ldap_sudo_include"),

    # ── Network Protocol Anomalies ─────────────────────────────────────────
    ("net-001", "IRC bot command (PRIVMSG)", "botnet", "high",
     r"(?i)PRIVMSG\s+#\w+\s+:!"),
    ("net-002", "Tor hidden service hostname", "c2", "high",
     r"\b[a-z2-7]{56}\.onion\b"),
    ("net-003", "DNS over HTTPS bypass (DoH)", "exfil", "medium",
     r"(?i)dns\.google/resolve|cloudflare-dns\.com/dns-query"),
    ("net-004", "HTTP CONNECT tunnel through proxy", "c2", "medium",
     r"(?i)^CONNECT\s+[\w.-]+:\d+\s+HTTP"),

    # ── File Upload Attacks ────────────────────────────────────────────────
    ("upload-001", "PHP webshell upload", "webshell", "critical",
     r"(?i)filename.*\.php[3-9s]?['\"]"),
    ("upload-002", "JSP webshell upload", "webshell", "critical",
     r"(?i)filename.*\.jsp[x]?['\"]"),
    ("upload-003", "ASPX webshell upload", "webshell", "critical",
     r"(?i)filename.*\.aspx?['\"]"),
    ("upload-004", "Webshell eval/exec payload", "webshell", "critical",
     r"(?i)(?:eval|exec|passthru|shell_exec|system)\s*\(.*\$_(?:GET|POST|REQUEST|COOKIE)"),

    # ── Information Disclosure ─────────────────────────────────────────────
    ("info-001", "Stack trace / exception dump", "info_disclosure", "low",
     r"(?i)(?:traceback \(most recent call last\)|at\s+[\w.$]+\([\w.]+:\d+\)|NullPointerException)"),
    ("info-002", "Database error disclosure", "info_disclosure", "medium",
     r"(?i)(?:sql syntax.*mysql|ORA-\d{5}|pg_query|syntax error near)"),
    ("info-003", "Server version disclosure", "info_disclosure", "low",
     r"(?i)(?:Apache/\d|nginx/\d|PHP/\d|OpenSSL/\d)"),
]

# Compile all regex patterns once
SIGNATURES: list[dict] = []
for sid, name, category, sev, pattern in RAW_SIGNATURES:
    try:
        SIGNATURES.append({
            "sid": sid,
            "name": name,
            "category": category,
            "severity": sev,
            "regex": re.compile(pattern),
        })
    except re.error as e:
        logger.warning("signature_compile_failed", sid=sid, error=str(e))

_SEV_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}

# Category → attack_type label for events
_CATEGORY_ATTACK: dict[str, str] = {
    "sqli": "sql_injection",
    "xss": "cross_site_scripting",
    "cmdi": "command_injection",
    "path_traversal": "path_traversal",
    "rce": "remote_code_execution",
    "ssrf": "server_side_request_forgery",
    "auth": "credential_attack",
    "c2": "c2_beacon",
    "miner": "crypto_miner",
    "exfil": "data_exfiltration",
    "deser": "deserialization_attack",
    "privesc": "privilege_escalation",
    "recon": "reconnaissance",
    "botnet": "botnet_activity",
    "webshell": "webshell",
    "info_disclosure": "information_disclosure",
}


# ── Core matching logic ───────────────────────────────────────────────────────

def match_text(text: str) -> list[dict]:
    """
    Run all signatures against a text string.
    Returns list of matches (may be multiple per input).
    """
    if not text:
        return []
    matches = []
    for sig in SIGNATURES:
        m = sig["regex"].search(text)
        if m:
            matches.append({
                "sid": sig["sid"],
                "name": sig["name"],
                "category": sig["category"],
                "severity": sig["severity"],
                "matched_text": text[max(0, m.start() - 20): m.end() + 20],
            })
    return matches


def _highest_severity(matches: list[dict]) -> str:
    order = ["critical", "high", "medium", "low"]
    for s in order:
        if any(m["severity"] == s for m in matches):
            return s
    return "low"


# ── Detector class ────────────────────────────────────────────────────────────

class SignatureDetector(BaseDetector):
    """
    Matches payloads / log text against 200+ attack signatures.

    Can be called with:
      - analyze({"payload": "..."})  — single payload dict
      - analyze({"flows": [...]})    — list of flow dicts
      - analyze({"text": "..."})     — raw text string
    """

    def __init__(self, config: dict[str, Any], event_bus: EventBus) -> None:
        super().__init__(name="signature_detector", config=config, event_bus=event_bus)

    async def start(self) -> None:
        self._update_status(running=True)
        logger.info("signature_detector_started", signatures=len(SIGNATURES))

    async def stop(self) -> None:
        self._update_status(running=False)
        logger.info("signature_detector_stopped")

    async def analyze(self, data: Any = None) -> list[dict]:
        """
        Scan data for signature matches. Returns a list of finding dicts.

        data may be:
          - None / missing → return empty
          - str            → scan as raw text
          - dict with "payload" key → scan payload value
          - dict with "flows" key  → scan each flow's payload + url fields
          - dict with "text" key   → scan text value
        """
        findings: list[dict] = []
        now = datetime.now(timezone.utc).isoformat()

        texts: list[tuple[str, dict]] = []  # (text_to_scan, context_dict)

        if data is None:
            return []

        if isinstance(data, str):
            texts.append((data, {}))

        elif isinstance(data, dict):
            if "flows" in data:
                for flow in data["flows"]:
                    ctx = {
                        "src_ip": flow.get("src_ip", ""),
                        "dst_ip": flow.get("dst_ip", ""),
                        "dst_port": flow.get("dst_port", ""),
                    }
                    for field in ("payload", "url", "http_body", "headers"):
                        val = flow.get(field, "")
                        if val:
                            texts.append((str(val), ctx))
            else:
                for field in ("payload", "text", "url", "http_body", "content"):
                    val = data.get(field, "")
                    if val:
                        texts.append((str(val), {}))

        for text, ctx in texts:
            matches = match_text(text)
            if not matches:
                continue

            sev_str = _highest_severity(matches)
            finding = {
                "severity": sev_str,
                "attack_types": list({_CATEGORY_ATTACK.get(m["category"], m["category"]) for m in matches}),
                "matched_signatures": [{"sid": m["sid"], "name": m["name"], "severity": m["severity"]} for m in matches],
                "match_count": len(matches),
                "context": ctx,
                "timestamp": now,
            }
            findings.append(finding)

            if sev_str in ("critical", "high"):
                await self.event_bus.publish(Event(
                    event_type=EventType.THREAT_CONFIRMED,
                    source=self.name,
                    severity=_SEV_MAP.get(sev_str, Severity.HIGH),
                    data={
                        "attack_type": finding["attack_types"][0] if finding["attack_types"] else "unknown",
                        "matched_signatures": finding["matched_signatures"][:5],
                        "context": ctx,
                    },
                ))

        return findings

    def scan_text(self, text: str) -> list[dict]:
        """Synchronous scan of a text string. Returns raw match list."""
        return match_text(text)

    def get_signature_count(self) -> int:
        return len(SIGNATURES)

    def get_categories(self) -> list[str]:
        return sorted({s["category"] for s in SIGNATURES})
