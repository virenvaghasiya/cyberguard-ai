"""
CyberGuard AI — File Scanner, Script Analyzer & FIM (Phase 8).

Three detection engines in one module:

8a  FileScannerDetector
    - SHA-256 hash each file against a local malware hash database
    - Pulls hashes from data/malware_hashes.txt (one hash per line)
    - Can also query VirusTotal (optional, requires VT_API_KEY env var)

8b  ScriptAnalyzer
    - Static analysis of scripts for obfuscation/dropper indicators
    - Detects: eval(base64), char-code XOR loops, long hex strings,
      PowerShell encoded commands, Python exec(compile(...)), etc.

8c  FileIntegrityMonitor (FIM)
    - Watches user-configurable paths for file changes (add/modify/delete)
    - Maintains a rolling hash baseline in data/fim_baseline.json
    - Default watch paths: ~/Desktop, ~/Downloads, /tmp, ~/.ssh
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

from src.core.base_detector import BaseDetector
from src.core.events import Event, EventBus, EventType, Severity

logger = structlog.get_logger()

# ── Paths ─────────────────────────────────────────────────────────────────────
MALWARE_HASH_DB = Path("data/malware_hashes.txt")
FIM_BASELINE_PATH = Path("data/fim_baseline.json")

HOME = Path.home()

# Default directories for FIM
FIM_WATCH_DIRS: list[Path] = [
    HOME / "Downloads",
    HOME / "Desktop",
    Path("/tmp"),
    HOME / ".ssh",
]

# Extensions considered executable / high-risk
HIGH_RISK_EXTS = {
    ".sh", ".bash", ".zsh", ".py", ".rb", ".pl", ".php",
    ".js", ".ps1", ".psm1", ".psd1", ".vbs", ".bat", ".cmd",
    ".exe", ".dll", ".dylib", ".so", ".elf",
}

# ── Malware hash database ─────────────────────────────────────────────────────

def _load_hash_db() -> set[str]:
    """Load known-malware SHA-256 hashes from the local database file."""
    if not MALWARE_HASH_DB.exists():
        return set()
    hashes: set[str] = set()
    try:
        for line in MALWARE_HASH_DB.read_text().splitlines():
            line = line.strip().lower()
            if len(line) == 64 and all(c in "0123456789abcdef" for c in line):
                hashes.add(line)
    except OSError:
        pass
    return hashes


_HASH_DB: set[str] = _load_hash_db()


def _sha256(path: Path) -> str | None:
    """SHA-256 hash a file. Returns None if unreadable or > 100 MB."""
    try:
        if path.stat().st_size > 100 * 1024 * 1024:
            return None  # skip very large files
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


# ── VirusTotal hash lookup (optional) ─────────────────────────────────────────

async def _vt_lookup(sha256: str) -> dict | None:
    """
    Query VirusTotal for a hash. Returns detection dict or None.
    Requires VT_API_KEY environment variable. Silently skips if not set.
    """
    api_key = os.environ.get("VT_API_KEY", "")
    if not api_key:
        return None
    try:
        import aiohttp
        url = f"https://www.virustotal.com/api/v3/files/{sha256}"
        async with aiohttp.ClientSession() as session:
            async with session.get(url, headers={"x-apikey": api_key}, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    return {
                        "malicious": stats.get("malicious", 0),
                        "suspicious": stats.get("suspicious", 0),
                        "total": sum(stats.values()),
                    }
                elif resp.status == 404:
                    return {"malicious": 0, "suspicious": 0, "total": 0, "unknown": True}
    except Exception:
        pass
    return None


# ── Script analyzer patterns ───────────────────────────────────────────────────

_SCRIPT_PATTERNS: list[tuple[str, str, str, str]] = [
    # (name, severity, category, regex)
    ("PowerShell encoded command", "critical", "dropper",
     r"(?i)-[Ee]ncodedCommand\s+[A-Za-z0-9+/=]{40,}"),
    ("PowerShell download cradle", "critical", "dropper",
     r"(?i)(?:Net\.WebClient|Invoke-WebRequest|wget|curl).*(?:DownloadString|DownloadFile|iex|Invoke-Expression)"),
    ("Python exec(compile(...))", "critical", "dropper",
     r"(?i)exec\s*\(\s*compile\s*\("),
    ("Python eval(base64.b64decode(...))", "critical", "obfuscation",
     r"(?i)eval\s*\(\s*(?:base64\.b64decode|__import__\s*\(\s*['\"]base64)"),
    ("Shell base64 decode + eval", "critical", "obfuscation",
     r"(?i)echo\s+[A-Za-z0-9+/=]{40,}\s*\|\s*base64\s+-d"),
    ("Long hex string (shellcode)", "high", "shellcode",
     r"(?:\\x[0-9a-fA-F]{2}){20,}"),
    ("XOR decryption loop (obfuscation)", "high", "obfuscation",
     r"(?i)for\s+\w+\s+in\s+range.*\bxor\b.*chr\s*\("),
    ("JavaScript eval(atob(...))", "high", "obfuscation",
     r"(?i)eval\s*\(\s*atob\s*\("),
    ("PHP base64 + eval (webshell)", "critical", "webshell",
     r"(?i)eval\s*\(\s*(?:base64_decode|str_rot13|gzinflate|gzuncompress)\s*\("),
    ("Python subprocess + base64 (dropper)", "critical", "dropper",
     r"(?i)subprocess.*base64"),
    ("Netcat reverse shell in script", "critical", "reverse_shell",
     r"(?i)nc\s+-[el]+\s+\S+\s+\d{2,5}"),
    ("Python socket reverse shell", "critical", "reverse_shell",
     r"(?i)socket\.connect\s*\(.*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}.*\d{2,5}"),
    ("Bash /dev/tcp reverse shell", "critical", "reverse_shell",
     r"/dev/tcp/\S+/\d{2,5}"),
    ("Cron job injected via script", "high", "persistence",
     r"(?i)crontab\s+-[li]"),
    ("LaunchAgent via script (macOS persistence)", "high", "persistence",
     r"(?i)launchctl\s+load\s+.*\.plist"),
    ("chmod +x on downloaded file", "medium", "dropper",
     r"chmod\s+[+]?x\s+"),
    ("wget/curl + execute pattern", "high", "dropper",
     r"(?i)(?:wget|curl)\s+.*\|\s*(?:bash|sh|python|perl)"),
    ("setuid/setgid privilege set", "high", "privesc",
     r"(?i)os\.set(?:uid|gid|euid|egid)\s*\("),
    ("rm -rf / destructive wipe", "critical", "destructive",
     r"rm\s+(?:-[rRf]+\s+){0,3}/(?:\s|$)"),
    ("dd if=/dev/zero disk wipe", "critical", "destructive",
     r"(?i)dd\s+if=/dev/(?:zero|urandom)\s+of=/dev/"),
]

_COMPILED_SCRIPT_PATTERNS = [
    {
        "name": name,
        "severity": sev,
        "category": cat,
        "regex": re.compile(pattern),
    }
    for name, sev, cat, pattern in _SCRIPT_PATTERNS
]

_SCRIPT_SEV_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}


def _analyze_script_content(content: str) -> list[dict]:
    """Run script analysis patterns against text content."""
    matches = []
    for p in _COMPILED_SCRIPT_PATTERNS:
        if p["regex"].search(content):
            matches.append({
                "pattern": p["name"],
                "severity": p["severity"],
                "category": p["category"],
            })
    return matches


def _is_likely_obfuscated(content: str) -> bool:
    """Heuristic: flag content with unusually high entropy or long strings."""
    # Detect very long lines (obfuscated scripts often have one giant line)
    for line in content.splitlines():
        if len(line) > 2000:
            return True
    # Detect high base64 density
    b64_chars = sum(1 for c in content if c in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
    if len(content) > 200 and b64_chars / len(content) > 0.9:
        return True
    return False


def analyze_file_content(path: Path) -> list[dict]:
    """
    Read a script file and run static analysis.
    Returns list of match dicts. Returns empty list on unreadable files.
    """
    if path.suffix.lower() not in HIGH_RISK_EXTS:
        return []
    try:
        content = path.read_text(errors="replace")
    except (OSError, PermissionError):
        return []

    matches = _analyze_script_content(content)
    if _is_likely_obfuscated(content):
        matches.append({
            "pattern": "Suspected obfuscated content (high-entropy / long lines)",
            "severity": "high",
            "category": "obfuscation",
        })
    return matches


# ── FIM baseline ───────────────────────────────────────────────────────────────

def _load_fim_baseline() -> dict[str, str | None]:
    if not FIM_BASELINE_PATH.exists():
        return {}
    try:
        return json.loads(FIM_BASELINE_PATH.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def _save_fim_baseline(snapshot: dict[str, str | None]) -> None:
    FIM_BASELINE_PATH.parent.mkdir(parents=True, exist_ok=True)
    FIM_BASELINE_PATH.write_text(json.dumps(snapshot, indent=2))


def _collect_fim_snapshot(watch_dirs: list[Path] | None = None) -> dict[str, str | None]:
    """Hash all files in the watched directories."""
    dirs = watch_dirs or FIM_WATCH_DIRS
    snapshot: dict[str, str | None] = {}
    for d in dirs:
        if not d.exists():
            continue
        try:
            for f in d.iterdir():
                if f.is_file():
                    snapshot[str(f)] = _sha256(f)
        except (OSError, PermissionError):
            continue
    return snapshot


# ── Main Detector ─────────────────────────────────────────────────────────────

class FileScanner(BaseDetector):
    """
    Phase 8: file hash scanning, script static analysis, and FIM.

    analyze(data) accepts:
      - {"paths": [...]}   — scan specific files
      - {"dirs": [...]}    — scan all files in directories
      - None               — run FIM diff against baseline
    """

    def __init__(self, config: dict[str, Any], event_bus: EventBus) -> None:
        super().__init__(name="file_scanner", config=config, event_bus=event_bus)
        self._hash_db = _HASH_DB

    async def start(self) -> None:
        self._update_status(running=True)
        logger.info("file_scanner_started", hash_db_size=len(self._hash_db))

    async def stop(self) -> None:
        self._update_status(running=False)
        logger.info("file_scanner_stopped")

    # ── Public helpers ─────────────────────────────────────────────────────

    def take_fim_baseline(self, watch_dirs: list[str] | None = None) -> dict:
        dirs = [Path(d) for d in watch_dirs] if watch_dirs else None
        snapshot = _collect_fim_snapshot(dirs)
        _save_fim_baseline(snapshot)
        logger.info("fim_baseline_taken", file_count=len(snapshot))
        return {
            "baseline_taken": True,
            "files_watched": len(snapshot),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    async def scan_file(self, path_str: str) -> dict:
        """
        Scan a single file: hash check + VirusTotal lookup + script analysis.
        """
        path = Path(path_str)
        now = datetime.now(timezone.utc).isoformat()

        if not path.exists():
            return {"error": "File not found", "path": path_str}

        result: dict[str, Any] = {
            "path": path_str,
            "name": path.name,
            "extension": path.suffix.lower(),
            "size_bytes": 0,
            "sha256": None,
            "in_malware_db": False,
            "vt_detections": None,
            "script_matches": [],
            "risk": "clean",
            "reasons": [],
            "timestamp": now,
        }

        try:
            result["size_bytes"] = path.stat().st_size
        except OSError:
            pass

        # Hash
        sha = _sha256(path)
        result["sha256"] = sha

        if sha:
            # Local hash DB check
            if sha in self._hash_db:
                result["in_malware_db"] = True
                result["risk"] = "critical"
                result["reasons"].append("SHA-256 matches known malware hash database")

            # VirusTotal (non-blocking, best-effort)
            vt = await _vt_lookup(sha)
            if vt:
                result["vt_detections"] = vt
                if vt.get("malicious", 0) > 2:
                    result["risk"] = "critical"
                    result["reasons"].append(
                        f"VirusTotal: {vt['malicious']}/{vt['total']} engines flagged as malicious"
                    )

        # Script static analysis
        script_matches = await asyncio.get_event_loop().run_in_executor(
            None, analyze_file_content, path
        )
        result["script_matches"] = script_matches

        if script_matches:
            severities = {m["severity"] for m in script_matches}
            if "critical" in severities and result["risk"] != "critical":
                result["risk"] = "critical"
            elif "high" in severities and result["risk"] == "clean":
                result["risk"] = "high"
            elif "medium" in severities and result["risk"] == "clean":
                result["risk"] = "medium"
            result["reasons"].extend(m["pattern"] for m in script_matches)

        return result

    async def analyze(self, data: Any = None) -> list[dict]:
        """
        Main analysis entry point.

        With data=None: run FIM diff against stored baseline.
        With data={"paths": [...]}: scan specific files.
        With data={"dirs": [...]}: scan all files in listed directories.
        """
        now = datetime.now(timezone.utc).isoformat()
        findings: list[dict] = []

        if data is None:
            # FIM mode
            findings = await self._run_fim(now)
        elif isinstance(data, dict):
            paths: list[str] = []
            if "paths" in data:
                paths = data["paths"]
            elif "dirs" in data:
                for d in data["dirs"]:
                    dp = Path(d)
                    if dp.exists():
                        try:
                            paths.extend(str(f) for f in dp.iterdir() if f.is_file())
                        except OSError:
                            pass
            for p in paths:
                result = await self.scan_file(p)
                if result.get("risk", "clean") != "clean":
                    findings.append(result)

        # Publish high/critical findings
        for f in findings:
            if f.get("risk") in ("high", "critical"):
                sev = Severity.CRITICAL if f["risk"] == "critical" else Severity.HIGH
                await self.event_bus.publish(Event(
                    event_type=EventType.THREAT_CONFIRMED,
                    source=self.name,
                    severity=sev,
                    data={
                        "attack_type": "malicious_file",
                        "path": f.get("path", ""),
                        "reasons": f.get("reasons", [])[:3],
                    },
                ))

        return findings

    async def _run_fim(self, now: str) -> list[dict]:
        """Compare current filesystem state against stored FIM baseline."""
        baseline = _load_fim_baseline()
        if not baseline:
            self.take_fim_baseline()
            return []

        current = await asyncio.get_event_loop().run_in_executor(
            None, _collect_fim_snapshot, None
        )
        findings: list[dict] = []
        all_paths = set(baseline.keys()) | set(current.keys())

        for path_str in all_paths:
            old_hash = baseline.get(path_str)
            new_hash = current.get(path_str)

            if old_hash == new_hash:
                continue

            change_type = "added" if old_hash is None else ("deleted" if new_hash is None else "modified")
            path_obj = Path(path_str)
            ext = path_obj.suffix.lower()

            severity = "high" if ext in HIGH_RISK_EXTS else "medium"
            findings.append({
                "path": path_str,
                "change_type": change_type,
                "severity": severity,
                "attack_type": "file_integrity_violation",
                "old_hash": old_hash,
                "new_hash": new_hash,
                "timestamp": now,
            })

        return findings

    def fim_approve(self, path_str: str) -> bool:
        """Mark a FIM change as approved (update baseline for this path)."""
        baseline = _load_fim_baseline()
        current = _collect_fim_snapshot()
        if path_str not in current:
            return False
        baseline[path_str] = current[path_str]
        _save_fim_baseline(baseline)
        return True

    def get_hash_db_size(self) -> int:
        return len(self._hash_db)

    async def reload_hash_db(self) -> int:
        """Reload malware hash database from disk."""
        self._hash_db = _load_hash_db()
        return len(self._hash_db)
