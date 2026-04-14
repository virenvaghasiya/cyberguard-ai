"""
CyberGuard AI — Persistence Monitor (Phase 7b).

Detects malware that survives reboots by watching critical system locations:
- macOS LaunchAgents / LaunchDaemons
- /etc/hosts (DNS hijacking)
- ~/.ssh/authorized_keys (SSH backdoor)
- /etc/sudoers (privilege escalation)
- Shell config files (.bashrc, .zshrc, .profile)
- Crontab entries

On first run: takes a baseline snapshot (hashes all watched files).
On each scan: re-hashes and reports changes.
"""

from __future__ import annotations

import hashlib
import json
import plistlib
import sys
from datetime import datetime, timezone
from pathlib import Path

import structlog

from src.core.base_detector import BaseDetector
from src.core.events import Event, EventBus, EventType, Severity
from typing import Any

logger = structlog.get_logger()

BASELINE_PATH = Path("data/persistence_baseline.json")

HOME = Path.home()

# Files and directories to watch
WATCH_PATHS: list[Path] = [
    # SSH backdoor
    HOME / ".ssh" / "authorized_keys",
    # Privilege escalation
    Path("/etc/sudoers"),
    # DNS hijacking
    Path("/etc/hosts"),
    Path("/etc/passwd"),
    # Shell persistence
    HOME / ".bashrc",
    HOME / ".zshrc",
    HOME / ".profile",
    HOME / ".bash_profile",
]

# Directories to watch (every file inside)
WATCH_DIRS: list[Path] = [
    HOME / "Library" / "LaunchAgents",
    Path("/Library/LaunchAgents"),
    Path("/Library/LaunchDaemons"),
    Path("/etc/cron.d"),
    Path("/var/spool/cron"),
]

# macOS-only paths (skip on Linux)
MACOS_ONLY: set[Path] = {
    HOME / "Library" / "LaunchAgents",
    Path("/Library/LaunchAgents"),
    Path("/Library/LaunchDaemons"),
}


def _is_macos() -> bool:
    return sys.platform == "darwin"


def _hash_file(path: Path) -> str | None:
    """SHA-256 hash a file. Returns None if unreadable."""
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


def _collect_watched_files() -> dict[str, str | None]:
    """Return {path_str: sha256_or_None} for all watched paths."""
    snapshot: dict[str, str | None] = {}

    for p in WATCH_PATHS:
        if not _is_macos() and p in MACOS_ONLY:
            continue
        snapshot[str(p)] = _hash_file(p)

    for d in WATCH_DIRS:
        if not _is_macos() and d in MACOS_ONLY:
            continue
        if not d.exists():
            continue
        for f in d.iterdir():
            if f.is_file():
                snapshot[str(f)] = _hash_file(f)

    return snapshot


def _load_baseline() -> dict[str, str | None]:
    if not BASELINE_PATH.exists():
        return {}
    try:
        return json.loads(BASELINE_PATH.read_text())
    except (json.JSONDecodeError, OSError):
        return {}


def _save_baseline(snapshot: dict[str, str | None]) -> None:
    BASELINE_PATH.parent.mkdir(parents=True, exist_ok=True)
    BASELINE_PATH.write_text(json.dumps(snapshot, indent=2))


def _parse_launchagent(path: Path) -> str:
    """Extract the command a LaunchAgent runs, for display."""
    try:
        with open(path, "rb") as f:
            data = plistlib.load(f)
        prog = data.get("ProgramArguments") or data.get("Program") or []
        if isinstance(prog, list):
            return " ".join(prog)
        return str(prog)
    except Exception:
        return "(could not parse)"


def _risk_for_path(path_str: str, change_type: str) -> tuple[str, str]:
    """Return (severity, attack_type) based on which file changed."""
    p = path_str.lower()

    if "authorized_keys" in p:
        return "critical", "ssh_backdoor"
    if "sudoers" in p:
        return "critical", "privilege_escalation"
    if "/etc/hosts" in p:
        return "high", "dns_hijacking"
    if "launchagent" in p or "launchdaemon" in p:
        return "high", "persistence_launchagent"
    if "cron" in p:
        return "high", "persistence_cron"
    if any(x in p for x in (".bashrc", ".zshrc", ".profile", ".bash_profile")):
        return "medium", "shell_persistence"
    if "/etc/passwd" in p:
        return "high", "user_account_tampering"

    return "medium", "file_tampering"


class PersistenceMonitor(BaseDetector):
    """Detects malware persistence by comparing file hashes to a baseline."""

    def __init__(self, config: dict[str, Any], event_bus: EventBus) -> None:
        super().__init__(name="persistence_monitor", config=config, event_bus=event_bus)

    async def start(self) -> None:
        self._update_status(running=True)
        logger.info("persistence_monitor_started")

    async def stop(self) -> None:
        self._update_status(running=False)
        logger.info("persistence_monitor_stopped")

    def take_baseline(self) -> dict:
        """
        Snapshot current state of all watched locations.
        Call this once on first run — or after approving a known-good change.
        """
        snapshot = _collect_watched_files()
        _save_baseline(snapshot)
        logger.info("persistence_baseline_taken", file_count=len(snapshot))
        return {
            "baseline_taken": True,
            "files_watched": len(snapshot),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    async def analyze(self, data=None) -> list[dict]:
        """
        Compare current state to baseline.
        Returns list of changes (new files, modified files, deleted files).
        """
        baseline = _load_baseline()
        if not baseline:
            # No baseline yet — take one silently and return empty
            self.take_baseline()
            return []

        current = _collect_watched_files()
        findings: list[dict] = []
        now = datetime.now(timezone.utc).isoformat()

        all_paths = set(baseline.keys()) | set(current.keys())

        for path_str in all_paths:
            old_hash = baseline.get(path_str)
            new_hash = current.get(path_str)

            if old_hash == new_hash:
                continue  # unchanged

            if old_hash is None:
                change_type = "added"
            elif new_hash is None:
                change_type = "deleted"
            else:
                change_type = "modified"

            severity, attack_type = _risk_for_path(path_str, change_type)

            # For LaunchAgents, show what command runs
            extra: dict = {}
            path_obj = Path(path_str)
            if (
                path_obj.suffix in (".plist",)
                and change_type != "deleted"
                and path_obj.exists()
            ):
                extra["launch_command"] = _parse_launchagent(path_obj)

            finding = {
                "path": path_str,
                "change_type": change_type,
                "severity": severity,
                "attack_type": attack_type,
                "old_hash": old_hash,
                "new_hash": new_hash,
                "timestamp": now,
                **extra,
            }
            findings.append(finding)
            logger.warning(
                "persistence_change_detected",
                path=path_str,
                change=change_type,
                severity=severity,
            )

            # Publish event
            sev_map = {
                "critical": Severity.CRITICAL,
                "high": Severity.HIGH,
                "medium": Severity.MEDIUM,
                "low": Severity.LOW,
            }
            await self.event_bus.publish(Event(
                event_type=EventType.THREAT_CONFIRMED,
                source=self.name,
                severity=sev_map.get(severity, Severity.MEDIUM),
                data={
                    "attack_type": attack_type,
                    "path": path_str,
                    "change_type": change_type,
                },
            ))

        return findings

    def approve_change(self, path_str: str) -> bool:
        """
        Mark a change as intentional (update baseline for this path only).
        Returns True if the path was found and baseline updated.
        """
        baseline = _load_baseline()
        current = _collect_watched_files()
        if path_str not in current:
            return False
        baseline[path_str] = current[path_str]
        _save_baseline(baseline)
        logger.info("persistence_change_approved", path=path_str)
        return True
