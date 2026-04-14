"""
Real-time system monitoring for CyberGuard AI.

Provides:
- Live network connections (via psutil)
- Real macOS system logs (via `log show` CLI)
- Process list with suspicious pattern detection
"""

from __future__ import annotations

import asyncio
import subprocess
from datetime import datetime, timezone, timedelta

import psutil
import structlog

logger = structlog.get_logger()

# Ports considered suspicious when seen in active connections
SUSPICIOUS_PORTS = {
    23: "Telnet",
    445: "SMB",
    1433: "MSSQL",
    1521: "Oracle DB",
    2375: "Docker (unauth)",
    2376: "Docker TLS",
    3306: "MySQL",
    3389: "RDP",
    4444: "Metasploit default",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis (unauth)",
    8080: "HTTP Alt",
    8443: "HTTPS Alt",
    9200: "Elasticsearch",
    27017: "MongoDB (unauth)",
}

KNOWN_MALWARE_PORTS = {4444, 1337, 31337, 12345, 54321, 6666, 6667, 6668}


def get_live_connections() -> dict:
    """
    Return all active TCP connections on this machine with risk analysis.
    Uses netstat (no root required on macOS/Linux).
    """
    connections = []
    suspicious_count = 0

    try:
        # netstat -anp tcp works on macOS without root
        result = subprocess.run(
            ["netstat", "-anp", "tcp"],
            capture_output=True, text=True, timeout=10
        )
        lines = result.stdout.splitlines()
    except Exception as e:
        logger.warning("netstat_failed", error=str(e))
        # Fallback: try psutil per-process
        return _get_connections_via_psutil()

    seen = set()
    for line in lines:
        parts = line.split()
        # netstat output: Proto Recv-Q Send-Q Local Foreign State [PID/Program]
        if len(parts) < 5 or parts[0] not in ("tcp4", "tcp6", "tcp"):
            continue
        status = parts[5] if len(parts) > 5 else parts[-1]
        if status not in ("ESTABLISHED", "LISTEN", "CLOSE_WAIT"):
            continue

        local  = parts[3]
        remote = parts[4]

        key = (local, remote, status)
        if key in seen:
            continue
        seen.add(key)

        # Extract remote port
        remote_port = 0
        try:
            remote_port = int(remote.rsplit(".", 1)[-1]) if "." in remote else int(remote.rsplit(":", 1)[-1])
        except (ValueError, IndexError):
            pass

        local_port = 0
        try:
            local_port = int(local.rsplit(".", 1)[-1]) if "." in local else int(local.rsplit(":", 1)[-1])
        except (ValueError, IndexError):
            pass

        # Risk assessment
        risk = "low"
        risk_reason = None

        if remote_port in KNOWN_MALWARE_PORTS or local_port in KNOWN_MALWARE_PORTS:
            risk = "critical"
            risk_reason = f"Known malware port ({remote_port or local_port})"
        elif remote_port in SUSPICIOUS_PORTS and status == "ESTABLISHED":
            risk = "high"
            risk_reason = f"Connected to {SUSPICIOUS_PORTS[remote_port]} port"
        elif local_port in SUSPICIOUS_PORTS and status == "LISTEN":
            risk = "medium"
            risk_reason = f"Listening on {SUSPICIOUS_PORTS[local_port]} port"

        entry = {
            "local": local,
            "remote": remote if remote not in ("*.*", "0.0.0.0:*", "*:*") else "",
            "status": status,
            "pid": None,
            "process": "",
            "risk": risk,
            "risk_reason": risk_reason,
            "remote_port": remote_port,
        }
        connections.append(entry)

        if risk in ("critical", "high"):
            suspicious_count += 1

    # Enrich with process names where possible (only our own processes)
    _enrich_with_process_names(connections)

    risk_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    connections.sort(key=lambda c: risk_order.get(c["risk"], 4))

    return {
        "total": len(connections),
        "suspicious": suspicious_count,
        "connections": connections,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def _enrich_with_process_names(connections: list) -> None:
    """Try to add process names from psutil for processes we own."""
    try:
        for proc in psutil.process_iter(["pid", "name", "connections"]):
            try:
                for conn in proc.info.get("connections") or []:
                    laddr = f"{conn.laddr.ip}.{conn.laddr.port}" if conn.laddr else ""
                    for entry in connections:
                        if laddr and laddr in entry["local"] and not entry["process"]:
                            entry["process"] = proc.info["name"]
                            entry["pid"] = proc.info["pid"]
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue
    except Exception:
        pass


def _get_connections_via_psutil() -> dict:
    """Fallback: iterate our own processes for their connections."""
    connections = []
    suspicious_count = 0
    try:
        for proc in psutil.process_iter(["pid", "name", "connections"]):
            try:
                for conn in proc.info.get("connections") or []:
                    if conn.status not in ("ESTABLISHED", "LISTEN"):
                        continue
                    laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else ""
                    raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else ""
                    remote_port = conn.raddr.port if conn.raddr else 0
                    local_port  = conn.laddr.port if conn.laddr else 0
                    risk = "low"
                    risk_reason = None
                    if remote_port in KNOWN_MALWARE_PORTS:
                        risk = "critical"
                        risk_reason = f"Malware port {remote_port}"
                    elif remote_port in SUSPICIOUS_PORTS:
                        risk = "high"
                        risk_reason = f"Suspicious: {SUSPICIOUS_PORTS[remote_port]}"
                    connections.append({
                        "local": laddr, "remote": raddr, "status": conn.status,
                        "pid": proc.info["pid"], "process": proc.info["name"],
                        "risk": risk, "risk_reason": risk_reason, "remote_port": remote_port,
                    })
                    if risk in ("critical", "high"):
                        suspicious_count += 1
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue
    except Exception as e:
        logger.warning("psutil_fallback_failed", error=str(e))

    return {
        "total": len(connections),
        "suspicious": suspicious_count,
        "connections": connections,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


def get_system_stats() -> dict:
    """CPU, memory, disk, and network I/O stats."""
    net_io = psutil.net_io_counters()
    return {
        "cpu_percent": psutil.cpu_percent(interval=0.1),
        "memory": {
            "total_gb": round(psutil.virtual_memory().total / 1e9, 1),
            "used_percent": psutil.virtual_memory().percent,
            "available_gb": round(psutil.virtual_memory().available / 1e9, 1),
        },
        "disk": {
            "total_gb": round(psutil.disk_usage("/").total / 1e9, 1),
            "used_percent": psutil.disk_usage("/").percent,
        },
        "network_io": {
            "bytes_sent_mb": round(net_io.bytes_sent / 1e6, 1),
            "bytes_recv_mb": round(net_io.bytes_recv / 1e6, 1),
            "packets_sent": net_io.packets_sent,
            "packets_recv": net_io.packets_recv,
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


async def get_real_logs(hours: int = 1, log_type: str = "all") -> str:
    """
    Fetch real macOS system logs using the `log show` command.

    Args:
        hours:    How many hours back to look (default 1)
        log_type: "auth", "network", "security", or "all"

    Returns:
        Raw log text ready for the LogAnalyzer detector.
    """
    predicates = {
        "auth": (
            'eventMessage CONTAINS[c] "authentication" OR '
            'eventMessage CONTAINS[c] "login" OR '
            'eventMessage CONTAINS[c] "sudo" OR '
            'eventMessage CONTAINS[c] "password" OR '
            'eventMessage CONTAINS[c] "sshd" OR '
            'eventMessage CONTAINS[c] "pam"'
        ),
        "network": (
            'eventMessage CONTAINS[c] "connection" OR '
            'eventMessage CONTAINS[c] "firewall" OR '
            'eventMessage CONTAINS[c] "blocked" OR '
            'eventMessage CONTAINS[c] "refused"'
        ),
        "security": (
            'eventMessage CONTAINS[c] "error" OR '
            'eventMessage CONTAINS[c] "failed" OR '
            'eventMessage CONTAINS[c] "denied" OR '
            'eventMessage CONTAINS[c] "invalid" OR '
            'eventMessage CONTAINS[c] "unauthorized"'
        ),
        "all": (
            'eventMessage CONTAINS[c] "error" OR '
            'eventMessage CONTAINS[c] "failed" OR '
            'eventMessage CONTAINS[c] "authentication" OR '
            'eventMessage CONTAINS[c] "login" OR '
            'eventMessage CONTAINS[c] "sudo" OR '
            'eventMessage CONTAINS[c] "connection" OR '
            'eventMessage CONTAINS[c] "denied"'
        ),
    }

    predicate = predicates.get(log_type, predicates["all"])
    start_time = (datetime.now() - timedelta(hours=hours)).strftime("%Y-%m-%d %H:%M:%S")

    cmd = [
        "log", "show",
        "--predicate", predicate,
        "--start", start_time,
        "--style", "syslog",
        "--info",
    ]

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=30)
        output = stdout.decode("utf-8", errors="replace")

        if not output.strip():
            return f"# No {log_type} log entries found in the last {hours} hour(s)."

        # Limit to 500 lines to avoid overwhelming the analyzer
        lines = output.strip().splitlines()
        if len(lines) > 500:
            lines = lines[-500:]  # Most recent 500
        return "\n".join(lines)

    except asyncio.TimeoutError:
        logger.warning("log_show_timeout")
        return "# Log fetch timed out. Try reducing the time range."
    except FileNotFoundError:
        # `log` not available (Linux fallback)
        return await _read_linux_logs(log_type)


async def _read_linux_logs(log_type: str) -> str:
    """Fallback for Linux: read /var/log/auth.log or syslog."""
    paths = {
        "auth": ["/var/log/auth.log", "/var/log/secure"],
        "network": ["/var/log/syslog", "/var/log/messages"],
        "security": ["/var/log/auth.log", "/var/log/syslog"],
        "all": ["/var/log/auth.log", "/var/log/syslog"],
    }

    for path in paths.get(log_type, []):
        try:
            proc = await asyncio.create_subprocess_exec(
                "tail", "-n", "500", path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, _ = await proc.communicate()
            if stdout:
                return stdout.decode("utf-8", errors="replace")
        except Exception:
            continue

    return "# Could not read system logs. Try running the server with elevated permissions."
