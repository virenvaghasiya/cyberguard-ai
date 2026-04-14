"""
CyberGuard AI — macOS Firewall Manager (Phase 6).

Wraps the macOS `pfctl` packet filter to auto-block attacker IPs.

Requires the server to run with sudo, or for the pf anchor to be
pre-configured via:
    sudo python -m src.defense.setup_pf

How it works:
    - A named pf table <cyberguard_blocklist> holds all blocked IPs.
    - A pf rule drops all traffic from IPs in that table.
    - Adding/removing IPs is instant — no firewall reload needed.
    - If pfctl is unavailable (no sudo), falls back to a software-only
      blocklist that the API still tracks (manual mode).
"""

from __future__ import annotations

import asyncio
import ipaddress
import structlog

logger = structlog.get_logger()

BLOCK_TABLE = "cyberguard_blocklist"


def _validate_ip(ip: str) -> str:
    """Validate and normalise an IP address string. Raises ValueError on bad input."""
    try:
        return str(ipaddress.ip_address(ip))
    except ValueError:
        # Allow CIDR notation too
        return str(ipaddress.ip_network(ip, strict=False).network_address)


async def _run(cmd: list[str]) -> tuple[int, str, str]:
    """Run a shell command and return (returncode, stdout, stderr).
    Returns (-1, '', 'unavailable') if the binary is not found (e.g. Linux)."""
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
        return proc.returncode, stdout.decode().strip(), stderr.decode().strip()
    except FileNotFoundError:
        return -1, "", "unavailable"
    except asyncio.TimeoutError:
        return -1, "", "timeout"


async def is_pf_available() -> bool:
    """Return True if pfctl is available and the CyberGuard anchor is loaded."""
    rc, _, _ = await _run(["pfctl", "-t", BLOCK_TABLE, "-T", "show"])
    return rc == 0


async def block_ip(ip: str) -> bool:
    """
    Add an IP to the pf blocklist table.

    Returns True on success, False if pfctl is unavailable (no sudo).
    The block_store always records the block regardless.
    """
    try:
        validated = _validate_ip(ip)
    except ValueError:
        logger.warning("firewall_block_invalid_ip", ip=ip)
        return False

    rc, _, stderr = await _run(
        ["pfctl", "-t", BLOCK_TABLE, "-T", "add", validated]
    )
    if rc == 0:
        logger.info("firewall_ip_blocked", ip=validated)
        return True

    # pfctl returns 1 if IP already in table — that's fine
    if "already exists" in stderr or rc == 1:
        return True

    logger.warning("firewall_block_failed", ip=validated, stderr=stderr)
    return False


async def unblock_ip(ip: str) -> bool:
    """Remove an IP from the pf blocklist table."""
    try:
        validated = _validate_ip(ip)
    except ValueError:
        return False

    rc, _, stderr = await _run(
        ["pfctl", "-t", BLOCK_TABLE, "-T", "delete", validated]
    )
    if rc == 0:
        logger.info("firewall_ip_unblocked", ip=validated)
        return True

    logger.warning("firewall_unblock_failed", ip=validated, stderr=stderr)
    return False


async def list_blocked_ips() -> list[str]:
    """Return all IPs currently in the pf blocklist table."""
    rc, stdout, _ = await _run(["pfctl", "-t", BLOCK_TABLE, "-T", "show"])
    if rc != 0 or not stdout:
        return []
    return [line.strip() for line in stdout.splitlines() if line.strip()]


async def flush_all() -> bool:
    """Remove ALL IPs from the pf blocklist (emergency clear)."""
    rc, _, _ = await _run(["pfctl", "-t", BLOCK_TABLE, "-T", "flush"])
    if rc == 0:
        logger.info("firewall_flushed_all")
    return rc == 0
