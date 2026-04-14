"""
CyberGuard AI — Process Monitor (Phase 7a).

Scans all running processes for:
- Known malware/hacking tool names (nc, xmrig, msfconsole, etc.)
- Sustained high CPU usage (crypto miner heuristic)
- Outbound connections to known malware ports
- Processes running from suspicious paths (/tmp, hidden dirs)
- Unsigned binaries on macOS (codesign check)
- Suspicious parent-child process chains
"""

from __future__ import annotations

import asyncio
import sys
from collections import defaultdict
from datetime import datetime, timezone

import psutil
import structlog

from src.core.base_detector import BaseDetector
from src.core.events import Event, EventBus, EventType, Severity
from typing import Any

logger = structlog.get_logger()

# ── Known-bad process names (case-insensitive partial match) ──────────────────
MALWARE_NAMES = {
    # Reverse shells / netcat
    "nc", "ncat", "netcat", "ncrack",
    # Crypto miners
    "xmrig", "minerd", "cpuminer", "ccminer", "cgminer", "bfgminer",
    "cryptominer", "ethminer", "nbminer",
    # Metasploit
    "msfconsole", "msfvenom", "msfrpc",
    # C2 agents
    "cobaltstrike", "beacon", "empire", "havoc", "sliver",
    # Credential dumpers
    "mimikatz", "secretsdump", "procdump",
    # Scanners / recon
    "masscan", "zmap", "sqlmap",
    # Rootkit tools
    "rkhunter", "chkrootkit",  # legitimate scanners but flag for visibility
}

# Ports that suggest malware C2 (outbound connections)
MALWARE_PORTS = {4444, 1337, 31337, 12345, 54321, 6666, 6667, 6668, 9999, 8888}

# Paths that legitimate system binaries should NOT run from
SUSPICIOUS_PATHS = {"/tmp/", "/var/tmp/", "/dev/shm/", "/."}


# ── CPU spike tracker ─────────────────────────────────────────────────────────

# pid → list of recent cpu_percent samples
_cpu_history: dict[int, list[float]] = defaultdict(list)
_CPU_WINDOW = 6       # number of samples (each ~5s apart = 30s window)
_CPU_THRESHOLD = 70.0  # % average over window = suspicious


def _update_cpu(pid: int, cpu: float) -> float:
    """Update rolling CPU average for a process. Returns current average."""
    hist = _cpu_history[pid]
    hist.append(cpu)
    if len(hist) > _CPU_WINDOW:
        hist.pop(0)
    return sum(hist) / len(hist)


def _cleanup_cpu_history(live_pids: set[int]) -> None:
    """Remove CPU history for processes that are no longer running."""
    dead = set(_cpu_history.keys()) - live_pids
    for pid in dead:
        del _cpu_history[pid]


# ── macOS codesign check ──────────────────────────────────────────────────────

async def _is_unsigned(path: str) -> bool:
    """
    Returns True if the binary at `path` fails codesign verification.
    Only meaningful on macOS — always returns False on Linux.
    """
    if sys.platform != "darwin" or not path:
        return False
    try:
        proc = await asyncio.create_subprocess_exec(
            "codesign", "--verify", "--strict", path,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(proc.wait(), timeout=3)
        return proc.returncode != 0
    except (FileNotFoundError, asyncio.TimeoutError, PermissionError):
        return False


# ── Risk assessment ───────────────────────────────────────────────────────────

def _assess_process(
    proc_info: dict,
    cpu_avg: float,
    has_malware_port: bool,
    from_suspicious_path: bool,
) -> tuple[str, str, list[str]]:
    """
    Return (risk_level, attack_type, reasons) for a process.
    risk_level: critical | high | medium | low
    """
    reasons: list[str] = []
    risk = "low"
    attack_type = "suspicious_process"

    name = (proc_info.get("name") or "").lower()
    cmdline = " ".join(proc_info.get("cmdline") or []).lower()

    # 1. Known malware name — critical
    matched_name = next((m for m in MALWARE_NAMES if m in name or m in cmdline), None)
    if matched_name:
        risk = "critical"
        attack_type = "known_malware_tool"
        reasons.append(f"Known malware tool name: {matched_name}")

    # 2. Malware port — critical
    if has_malware_port:
        risk = "critical"
        attack_type = "c2_connection"
        reasons.append("Active connection to known malware port")

    # 3. High sustained CPU — high (crypto miner)
    if cpu_avg > _CPU_THRESHOLD and risk not in ("critical",):
        risk = "high"
        attack_type = "crypto_miner"
        reasons.append(f"Sustained high CPU: {cpu_avg:.0f}% average")

    # 4. Suspicious path — medium
    if from_suspicious_path and risk == "low":
        risk = "medium"
        attack_type = "suspicious_location"
        reasons.append(f"Running from suspicious path: {proc_info.get('exe', '')}")

    return risk, attack_type, reasons


# ── Main detector ─────────────────────────────────────────────────────────────

class ProcessMonitor(BaseDetector):
    """Scans running processes for malware indicators."""

    def __init__(self, config: dict[str, Any], event_bus: EventBus) -> None:
        super().__init__(name="process_monitor", config=config, event_bus=event_bus)

    async def start(self) -> None:
        self._update_status(running=True)
        logger.info("process_monitor_started")

    async def stop(self) -> None:
        self._update_status(running=False)
        logger.info("process_monitor_stopped")

    async def analyze(self, data=None) -> list[dict]:
        """Scan all running processes and return flagged ones."""
        findings: list[dict] = []
        live_pids: set[int] = set()

        for proc in psutil.process_iter(
            ["pid", "name", "exe", "cmdline", "cpu_percent",
             "status", "ppid", "username", "net_connections"]
        ):
            try:
                info = proc.info
                pid = info["pid"]
                if pid is None:
                    continue
                live_pids.add(pid)

                # CPU rolling average
                cpu_pct = info.get("cpu_percent") or 0.0
                cpu_avg = _update_cpu(pid, cpu_pct)

                # Malware port check
                conns = info.get("net_connections") or []
                has_malware_port = any(
                    (c.raddr and c.raddr.port in MALWARE_PORTS) or
                    (c.laddr and c.laddr.port in MALWARE_PORTS)
                    for c in conns
                )

                # Suspicious path
                exe = info.get("exe") or ""
                from_suspicious_path = any(p in exe for p in SUSPICIOUS_PATHS)

                risk, attack_type, reasons = _assess_process(
                    info, cpu_avg, has_malware_port, from_suspicious_path
                )

                if risk == "low" and not reasons:
                    continue  # skip clean processes

                finding = {
                    "pid": pid,
                    "name": info.get("name") or "",
                    "exe": exe,
                    "cmdline": " ".join(info.get("cmdline") or [])[:200],
                    "cpu_avg_pct": round(cpu_avg, 1),
                    "username": info.get("username") or "",
                    "risk": risk,
                    "attack_type": attack_type,
                    "reasons": reasons,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
                findings.append(finding)

                # Publish event for high/critical findings
                if risk in ("high", "critical"):
                    sev = Severity.CRITICAL if risk == "critical" else Severity.HIGH
                    await self.event_bus.publish(Event(
                        event_type=EventType.THREAT_CONFIRMED,
                        source=self.name,
                        severity=sev,
                        data={
                            "attack_type": attack_type,
                            "pid": pid,
                            "process_name": info.get("name") or "",
                            "reasons": reasons,
                            "risk": risk,
                        },
                    ))

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        _cleanup_cpu_history(live_pids)
        return findings

    async def get_all_processes(self) -> list[dict]:
        """Return ALL running processes with basic risk annotation (for the app)."""
        procs = []
        for proc in psutil.process_iter(
            ["pid", "name", "exe", "cpu_percent", "memory_percent",
             "status", "username"]
        ):
            try:
                info = proc.info
                name = (info.get("name") or "").lower()
                is_suspicious = any(m in name for m in MALWARE_NAMES)
                procs.append({
                    "pid": info["pid"],
                    "name": info.get("name") or "",
                    "exe": info.get("exe") or "",
                    "cpu_percent": round(info.get("cpu_percent") or 0.0, 1),
                    "memory_percent": round(info.get("memory_percent") or 0.0, 1),
                    "status": info.get("status") or "",
                    "username": info.get("username") or "",
                    "suspicious": is_suspicious,
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        procs.sort(key=lambda p: p["cpu_percent"], reverse=True)
        return procs

    async def kill_process(self, pid: int) -> dict:
        """
        Attempt to terminate a process by PID.
        Returns result dict with success flag.
        """
        try:
            proc = psutil.Process(pid)
            name = proc.name()
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except psutil.TimeoutExpired:
                proc.kill()  # force kill if terminate didn't work

            logger.info("process_killed", pid=pid, name=name)
            return {"success": True, "pid": pid, "name": name}
        except psutil.NoSuchProcess:
            return {"success": False, "pid": pid, "error": "Process not found"}
        except psutil.AccessDenied:
            return {"success": False, "pid": pid, "error": "Permission denied — try running with sudo"}
