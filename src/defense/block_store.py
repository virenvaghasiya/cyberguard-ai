"""
CyberGuard AI — Block List Store (Phase 6).

Persists blocked IPs in a SQLite database so blocks survive server
restarts and can be shown in the iPhone app with full history.

On startup, all active (non-expired) blocks are re-applied to pf.
A background task runs every 60 s to expire timed blocks.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path

import aiosqlite
import structlog

from src.defense import firewall

logger = structlog.get_logger()

DB_PATH = Path("data/blocklist.db")

# ── Schema ────────────────────────────────────────────────────────────────────

_CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS blocks (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ip           TEXT NOT NULL,
    reason       TEXT NOT NULL,
    attack_type  TEXT NOT NULL DEFAULT 'manual',
    severity     TEXT NOT NULL DEFAULT 'high',
    blocked_at   TEXT NOT NULL,
    expires_at   TEXT,
    unblocked_at TEXT,
    auto_block   INTEGER NOT NULL DEFAULT 1
);
"""

_CREATE_INDEX = """
CREATE INDEX IF NOT EXISTS idx_blocks_ip ON blocks(ip);
"""


# ── Helpers ───────────────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _expire_time(duration_seconds: int) -> str | None:
    if duration_seconds <= 0:
        return None  # permanent
    return (datetime.now(timezone.utc) + timedelta(seconds=duration_seconds)).isoformat()


def _is_active(row: dict) -> bool:
    if row["unblocked_at"]:
        return False
    if row["expires_at"] is None:
        return True
    return datetime.fromisoformat(row["expires_at"]) > datetime.now(timezone.utc)


@asynccontextmanager
async def _connect():
    """Async context manager that opens the blocklist DB with row_factory set."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    async with aiosqlite.connect(str(DB_PATH)) as db:
        db.row_factory = aiosqlite.Row
        yield db


# ── Public API ────────────────────────────────────────────────────────────────

async def init_db() -> None:
    """Create tables and re-apply active blocks to pf on startup."""
    async with _connect() as db:
        await db.execute(_CREATE_TABLE)
        await db.execute(_CREATE_INDEX)
        await db.commit()

    # Re-apply all still-active blocks to pf (survives server restarts)
    active = await list_active()
    reapplied = 0
    for entry in active:
        ok = await firewall.block_ip(entry["ip"])
        if ok:
            reapplied += 1
    if reapplied:
        logger.info("blocklist_reapplied_on_startup", count=reapplied)


async def add_block(
    ip: str,
    reason: str,
    attack_type: str = "manual",
    severity: str = "high",
    duration_seconds: int = 3600,
    auto_block: bool = True,
) -> dict:
    """
    Block an IP: record in DB + apply pf rule.

    Args:
        ip:               IP address to block
        reason:           Human-readable reason (shown in app)
        attack_type:      Category (brute_force, port_scan, malware, manual…)
        severity:         critical | high | medium
        duration_seconds: 0 = permanent, otherwise seconds until auto-unblock
        auto_block:       True = also apply pfctl rule

    Returns the created block record as a dict.
    """
    pf_ok = False
    if auto_block:
        pf_ok = await firewall.block_ip(ip)

    now = _now()
    expires = _expire_time(duration_seconds)

    async with _connect() as db:
        cursor = await db.execute(
            """
            INSERT INTO blocks (ip, reason, attack_type, severity,
                                blocked_at, expires_at, auto_block)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (ip, reason, attack_type, severity, now, expires, int(auto_block)),
        )
        await db.commit()
        row_id = cursor.lastrowid

    logger.info(
        "block_added",
        ip=ip, attack_type=attack_type, duration_seconds=duration_seconds,
        pf_applied=pf_ok,
    )

    return {
        "id": row_id,
        "ip": ip,
        "reason": reason,
        "attack_type": attack_type,
        "severity": severity,
        "blocked_at": now,
        "expires_at": expires,
        "unblocked_at": None,
        "pf_applied": pf_ok,
        "active": True,
    }


async def remove_block(ip: str) -> bool:
    """Unblock an IP: update DB + remove pf rule."""
    pf_ok = await firewall.unblock_ip(ip)
    now = _now()

    async with _connect() as db:
        await db.execute(
            "UPDATE blocks SET unblocked_at = ? WHERE ip = ? AND unblocked_at IS NULL",
            (now, ip),
        )
        await db.commit()

    logger.info("block_removed", ip=ip, pf_removed=pf_ok)
    return True


async def list_active() -> list[dict]:
    """Return all currently active (not expired, not manually unblocked) blocks."""
    async with _connect() as db:
        async with db.execute(
            "SELECT * FROM blocks WHERE unblocked_at IS NULL ORDER BY blocked_at DESC"
        ) as cursor:
            rows = await cursor.fetchall()

    now = datetime.now(timezone.utc)
    active = []
    for row in rows:
        d = dict(row)
        if d["expires_at"] and datetime.fromisoformat(d["expires_at"]) <= now:
            continue  # expired but not yet cleaned up
        d["active"] = True
        d["seconds_remaining"] = None
        if d["expires_at"]:
            remaining = (datetime.fromisoformat(d["expires_at"]) - now).total_seconds()
            d["seconds_remaining"] = max(0, int(remaining))
        active.append(d)

    return active


async def list_history(limit: int = 100) -> list[dict]:
    """Return full block/unblock history."""
    async with _connect() as db:
        async with db.execute(
            "SELECT * FROM blocks ORDER BY blocked_at DESC LIMIT ?",
            (limit,),
        ) as cursor:
            rows = await cursor.fetchall()
    return [dict(row) for row in rows]


async def is_blocked(ip: str) -> bool:
    """Return True if this IP is currently actively blocked."""
    active = await list_active()
    return any(entry["ip"] == ip for entry in active)


async def expire_old_blocks() -> int:
    """
    Remove pf rules for expired blocks and mark them in DB.
    Called by the background expiry task every 60 seconds.
    Returns number of blocks expired.
    """
    now = _now()
    expired_count = 0

    async with _connect() as db:
        async with db.execute(
            """
            SELECT ip FROM blocks
            WHERE unblocked_at IS NULL
              AND expires_at IS NOT NULL
              AND expires_at <= ?
            """,
            (now,),
        ) as cursor:
            rows = await cursor.fetchall()

        for row in rows:
            ip = row["ip"]
            await firewall.unblock_ip(ip)
            await db.execute(
                "UPDATE blocks SET unblocked_at = ? WHERE ip = ? AND unblocked_at IS NULL",
                (now, ip),
            )
            expired_count += 1
            logger.info("block_expired", ip=ip)

        if expired_count:
            await db.commit()

    return expired_count


async def run_expiry_loop() -> None:
    """Background task: expire old blocks every 60 seconds."""
    while True:
        await asyncio.sleep(60)
        try:
            expired = await expire_old_blocks()
            if expired:
                logger.info("expiry_loop_cleaned", count=expired)
        except Exception as e:
            logger.warning("expiry_loop_error", error=str(e))
