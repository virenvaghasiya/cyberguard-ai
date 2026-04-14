"""
CyberGuard AI — Auto-Response Rules Engine (Phase 9).

Watches the EventBus for threat events and fires configurable response
actions automatically — or queues them for confirmation if the rule is
set to manual mode.

Rule anatomy:
    name:          unique identifier
    condition:     dict describing what event to match
                   {attack_type, severity_gte, source, ...}
    actions:       list of action dicts
                   [{type: "block_ip", ...}, {type: "kill_process", ...},
                    {type: "push_notification", ...}, {type: "log", ...}]
    enabled:       bool — if False the rule is skipped
    auto:          bool — if True fire immediately; if False queue for
                   manual confirmation via /response/pending

Built-in default rules:
    - critical C2 → block IP + push
    - brute-force → block IP (1h) + push
    - crypto-miner process → kill process + push
    - SSH backdoor key added → push + log
    - malicious file → push + log

iOS push notifications use APNs HTTP/2 via aiohttp (no external lib needed).
Falls back to logging if APNs cert/key is not configured.
"""

from __future__ import annotations

import json
import os
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import structlog

from src.core.events import Event, EventBus, EventType, Severity

logger = structlog.get_logger()

RULES_PATH = Path("config/response_rules.json")
PENDING_PATH = Path("data/pending_actions.json")

# ── Severity ordering ─────────────────────────────────────────────────────────
_SEV_ORDER = {
    Severity.LOW: 0,
    Severity.MEDIUM: 1,
    Severity.HIGH: 2,
    Severity.CRITICAL: 3,
}

_STR_TO_SEV = {
    "low": Severity.LOW,
    "medium": Severity.MEDIUM,
    "high": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


# ── Default built-in rules ────────────────────────────────────────────────────

DEFAULT_RULES: list[dict] = [
    {
        "name": "block_c2_critical",
        "description": "Auto-block IP for confirmed C2 beacon (critical severity)",
        "enabled": True,
        "auto": True,
        "condition": {
            "attack_types": ["c2_beacon", "c2_connection", "known_malware_tool"],
            "severity_gte": "critical",
        },
        "actions": [
            {"type": "block_ip", "duration_hours": 24, "reason": "Auto-blocked: C2 beacon confirmed"},
            {"type": "push_notification", "title": "C2 Beacon Blocked", "body": "Malware C2 connection detected and IP blocked"},
        ],
    },
    {
        "name": "block_brute_force",
        "description": "Block IPs performing brute-force authentication attacks",
        "enabled": True,
        "auto": True,
        "condition": {
            "attack_types": ["brute_force", "credential_stuffing", "ssh_brute_force"],
            "severity_gte": "high",
        },
        "actions": [
            {"type": "block_ip", "duration_hours": 1, "reason": "Auto-blocked: brute force detected"},
            {"type": "push_notification", "title": "Brute Force Blocked", "body": "Brute force attack detected — attacker IP blocked for 1h"},
        ],
    },
    {
        "name": "kill_crypto_miner",
        "description": "Kill processes identified as crypto miners",
        "enabled": True,
        "auto": False,  # require manual confirmation — killing processes is destructive
        "condition": {
            "attack_types": ["crypto_miner"],
            "severity_gte": "high",
        },
        "actions": [
            {"type": "kill_process", "reason": "Crypto miner process detected"},
            {"type": "push_notification", "title": "Crypto Miner Detected", "body": "A crypto miner was found — confirm kill in CyberGuard"},
        ],
    },
    {
        "name": "alert_ssh_backdoor",
        "description": "Alert when SSH authorized_keys file is modified",
        "enabled": True,
        "auto": True,
        "condition": {
            "attack_types": ["ssh_backdoor"],
            "severity_gte": "critical",
        },
        "actions": [
            {"type": "push_notification", "title": "SSH Backdoor Alert", "body": "authorized_keys was modified — possible backdoor installed"},
            {"type": "log", "level": "critical", "message": "SSH backdoor key detected"},
        ],
    },
    {
        "name": "alert_persistence",
        "description": "Alert on new LaunchAgent/LaunchDaemon or cron persistence",
        "enabled": True,
        "auto": True,
        "condition": {
            "attack_types": ["persistence_launchagent", "persistence_cron"],
            "severity_gte": "high",
        },
        "actions": [
            {"type": "push_notification", "title": "Persistence Detected", "body": "New startup item added — possible malware persistence"},
            {"type": "log", "level": "warning", "message": "Persistence mechanism detected"},
        ],
    },
    {
        "name": "alert_malicious_file",
        "description": "Alert when a file matches malware hash or contains malicious script",
        "enabled": True,
        "auto": True,
        "condition": {
            "attack_types": ["malicious_file"],
            "severity_gte": "high",
        },
        "actions": [
            {"type": "push_notification", "title": "Malicious File Detected", "body": "A file matched malware signatures — check CyberGuard"},
            {"type": "log", "level": "critical", "message": "Malicious file found"},
        ],
    },
    {
        "name": "alert_dns_hijack",
        "description": "Alert on /etc/hosts or DNS configuration tampering",
        "enabled": True,
        "auto": True,
        "condition": {
            "attack_types": ["dns_hijacking"],
            "severity_gte": "high",
        },
        "actions": [
            {"type": "push_notification", "title": "DNS Hijack Detected", "body": "/etc/hosts was modified — DNS may be poisoned"},
            {"type": "log", "level": "critical", "message": "DNS hijacking detected"},
        ],
    },
    {
        "name": "alert_sqli_rce",
        "description": "Alert on confirmed SQL injection or RCE attack signature match",
        "enabled": True,
        "auto": True,
        "condition": {
            "attack_types": ["sql_injection", "remote_code_execution", "command_injection"],
            "severity_gte": "critical",
        },
        "actions": [
            {"type": "block_ip", "duration_hours": 12, "reason": "Auto-blocked: SQLi/RCE attack"},
            {"type": "push_notification", "title": "Web Attack Blocked", "body": "SQL injection / RCE attempt detected and source IP blocked"},
        ],
    },
]


# ── Rule loading / saving ─────────────────────────────────────────────────────

def _load_rules() -> list[dict]:
    if not RULES_PATH.exists():
        return DEFAULT_RULES[:]
    try:
        return json.loads(RULES_PATH.read_text())
    except (json.JSONDecodeError, OSError):
        return DEFAULT_RULES[:]


def _save_rules(rules: list[dict]) -> None:
    RULES_PATH.parent.mkdir(parents=True, exist_ok=True)
    RULES_PATH.write_text(json.dumps(rules, indent=2))


# ── Pending actions (manual confirmation queue) ───────────────────────────────

def _load_pending() -> list[dict]:
    if not PENDING_PATH.exists():
        return []
    try:
        return json.loads(PENDING_PATH.read_text())
    except (json.JSONDecodeError, OSError):
        return []


def _save_pending(pending: list[dict]) -> None:
    PENDING_PATH.parent.mkdir(parents=True, exist_ok=True)
    PENDING_PATH.write_text(json.dumps(pending, indent=2))


def _add_pending(action: dict) -> None:
    pending = _load_pending()
    action["id"] = f"{datetime.now(timezone.utc).timestamp():.0f}"
    action["queued_at"] = datetime.now(timezone.utc).isoformat()
    pending.append(action)
    _save_pending(pending)


def _remove_pending(action_id: str) -> dict | None:
    pending = _load_pending()
    for i, item in enumerate(pending):
        if item.get("id") == action_id:
            pending.pop(i)
            _save_pending(pending)
            return item
    return None


# ── Condition matching ────────────────────────────────────────────────────────

def _matches_condition(event: Event, condition: dict) -> bool:
    """Return True if the event satisfies all condition fields."""
    # attack_types: list of allowed types (OR match)
    allowed_types = condition.get("attack_types", [])
    if allowed_types:
        event_attack = event.data.get("attack_type", "")
        if not any(t == event_attack for t in allowed_types):
            return False

    # severity_gte: minimum severity
    sev_gte_str = condition.get("severity_gte", "")
    if sev_gte_str:
        min_sev = _STR_TO_SEV.get(sev_gte_str, Severity.LOW)
        if _SEV_ORDER.get(event.severity, 0) < _SEV_ORDER.get(min_sev, 0):
            return False

    # source: specific detector name
    source = condition.get("source", "")
    if source and event.source != source:
        return False

    return True


# ── iOS Push (APNs) ───────────────────────────────────────────────────────────

async def _send_push(title: str, body: str) -> bool:
    """
    Send an iOS push notification via APNs.
    Requires environment variables:
      APNS_DEVICE_TOKEN   — the device push token
      APNS_KEY_ID         — APNs auth key ID
      APNS_TEAM_ID        — Apple developer team ID
      APNS_BUNDLE_ID      — app bundle identifier
      APNS_PRIVATE_KEY    — path to .p8 private key file

    Silently logs and returns False if any are missing.
    """
    device_token = os.environ.get("APNS_DEVICE_TOKEN", "")
    key_id = os.environ.get("APNS_KEY_ID", "")
    team_id = os.environ.get("APNS_TEAM_ID", "")
    bundle_id = os.environ.get("APNS_BUNDLE_ID", "")
    key_path = os.environ.get("APNS_PRIVATE_KEY", "")

    if not all([device_token, key_id, team_id, bundle_id, key_path]):
        logger.debug("apns_not_configured_skipping_push")
        return False

    try:
        import jwt as pyjwt  # PyJWT
        from pathlib import Path as _P
        private_key = _P(key_path).read_text()
        now = int(datetime.now(timezone.utc).timestamp())
        token = pyjwt.encode(
            {"iss": team_id, "iat": now},
            private_key,
            algorithm="ES256",
            headers={"kid": key_id},
        )

        payload = json.dumps({
            "aps": {
                "alert": {"title": title, "body": body},
                "sound": "default",
                "badge": 1,
            }
        }).encode()

        import aiohttp
        url = f"https://api.push.apple.com/3/device/{device_token}"
        headers = {
            "authorization": f"bearer {token}",
            "apns-topic": bundle_id,
            "apns-push-type": "alert",
            "content-type": "application/json",
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=payload, headers=headers,
                                    timeout=aiohttp.ClientTimeout(total=10)) as resp:
                if resp.status == 200:
                    logger.info("push_sent", title=title)
                    return True
                logger.warning("push_failed", status=resp.status)
    except Exception as e:
        logger.warning("push_error", error=str(e))
    return False


# ── Action executor ───────────────────────────────────────────────────────────

async def _execute_action(action: dict, event: Event, pipeline: Any) -> dict:
    """Execute a single response action. Returns result dict."""
    action_type = action.get("type", "")
    now = datetime.now(timezone.utc).isoformat()
    result = {"type": action_type, "executed_at": now, "success": False}

    if action_type == "block_ip":
        ip = event.data.get("src_ip") or event.data.get("ip", "")
        if ip:
            try:
                from src.defense import block_store, firewall
                await block_store.add_block(
                    ip=ip,
                    reason=action.get("reason", "Auto-response rule"),
                    attack_type=event.data.get("attack_type", "unknown"),
                    severity=event.severity.value,
                    duration_hours=action.get("duration_hours", 24),
                )
                await firewall.block_ip(ip)
                result["success"] = True
                result["ip"] = ip
                logger.info("auto_blocked_ip", ip=ip, rule=action.get("reason", ""))
            except Exception as e:
                result["error"] = str(e)
        else:
            result["error"] = "No IP in event data"

    elif action_type == "kill_process":
        pid = event.data.get("pid")
        if pid and pipeline:
            pm = pipeline.get_detector("process_monitor")
            if pm:
                kill_result = await pm.kill_process(int(pid))
                result["success"] = kill_result.get("success", False)
                result["pid"] = pid
            else:
                result["error"] = "Process monitor not available"
        else:
            result["error"] = "No PID in event data"

    elif action_type == "push_notification":
        sent = await _send_push(
            title=action.get("title", "CyberGuard Alert"),
            body=action.get("body", event.data.get("attack_type", "Threat detected")),
        )
        result["success"] = sent
        result["push_sent"] = sent

    elif action_type == "log":
        level = action.get("level", "warning")
        msg = action.get("message", "Auto-response rule triggered")
        getattr(logger, level, logger.warning)(msg, event_data=event.data)
        result["success"] = True

    return result


# ── Rules Engine ──────────────────────────────────────────────────────────────

class RulesEngine:
    """
    Subscribes to all threat events and fires matching response rules.
    """

    def __init__(self, event_bus: EventBus, pipeline: Any = None) -> None:
        self.event_bus = event_bus
        self.pipeline = pipeline
        self._rules: list[dict] = _load_rules()
        self._execution_log: deque[dict] = deque(maxlen=500)

    def start(self) -> None:
        """Subscribe to threat events."""
        for et in (EventType.THREAT_CONFIRMED, EventType.ALERT_CREATED):
            self.event_bus.subscribe(et, self._on_event)
        logger.info("rules_engine_started", rules=len(self._rules))

    def stop(self) -> None:
        logger.info("rules_engine_stopped")

    async def _on_event(self, event: Event) -> None:
        """Called for every THREAT_CONFIRMED or ALERT_CREATED event."""
        for rule in self._rules:
            if not rule.get("enabled", True):
                continue
            if not _matches_condition(event, rule.get("condition", {})):
                continue

            now = datetime.now(timezone.utc).isoformat()
            log_entry = {
                "rule": rule["name"],
                "event_type": event.event_type.value,
                "attack_type": event.data.get("attack_type", ""),
                "severity": event.severity.value,
                "auto": rule.get("auto", True),
                "triggered_at": now,
                "actions": [],
            }

            if rule.get("auto", True):
                # Execute all actions immediately
                for action in rule.get("actions", []):
                    res = await _execute_action(action, event, self.pipeline)
                    log_entry["actions"].append(res)
                logger.info("rule_fired", rule=rule["name"], auto=True)
            else:
                # Queue for manual confirmation
                pending_item = {
                    "rule": rule["name"],
                    "description": rule.get("description", ""),
                    "event": {
                        "attack_type": event.data.get("attack_type", ""),
                        "severity": event.severity.value,
                        "data": event.data,
                    },
                    "actions": rule.get("actions", []),
                    "queued_at": now,
                }
                _add_pending(pending_item)
                # Still fire push notifications even in manual mode
                for action in rule.get("actions", []):
                    if action.get("type") == "push_notification":
                        await _execute_action(action, event, self.pipeline)
                logger.info("rule_queued_for_manual", rule=rule["name"])

            self._execution_log.appendleft(log_entry)

    # ── Public API ─────────────────────────────────────────────────────────

    def get_rules(self) -> list[dict]:
        return self._rules

    def get_rule(self, name: str) -> dict | None:
        return next((r for r in self._rules if r["name"] == name), None)

    def upsert_rule(self, rule: dict) -> bool:
        """Add or update a rule by name. Returns True if updated, False if added."""
        for i, r in enumerate(self._rules):
            if r["name"] == rule["name"]:
                self._rules[i] = rule
                _save_rules(self._rules)
                return True
        self._rules.append(rule)
        _save_rules(self._rules)
        return False

    def delete_rule(self, name: str) -> bool:
        before = len(self._rules)
        self._rules = [r for r in self._rules if r["name"] != name]
        if len(self._rules) < before:
            _save_rules(self._rules)
            return True
        return False

    def set_rule_enabled(self, name: str, enabled: bool) -> bool:
        for r in self._rules:
            if r["name"] == name:
                r["enabled"] = enabled
                _save_rules(self._rules)
                return True
        return False

    def get_execution_log(self, limit: int = 50) -> list[dict]:
        return list(self._execution_log)[:limit]

    def get_pending_actions(self) -> list[dict]:
        return _load_pending()

    async def confirm_action(self, action_id: str) -> dict:
        """Confirm and execute a pending manual action."""
        item = _remove_pending(action_id)
        if not item:
            return {"error": "Pending action not found", "id": action_id}

        results = []
        for action in item.get("actions", []):
            if action.get("type") == "push_notification":
                continue  # already sent when queued
            # Reconstruct a minimal event to pass to executor
            event_data = item.get("event", {})
            sev_str = event_data.get("severity", "high")
            fake_event = Event(
                event_type=EventType.THREAT_CONFIRMED,
                source="rules_engine",
                severity=_STR_TO_SEV.get(sev_str, Severity.HIGH),
                data=event_data.get("data", {}),
            )
            res = await _execute_action(action, fake_event, self.pipeline)
            results.append(res)

        return {"confirmed": True, "id": action_id, "results": results}

    def dismiss_action(self, action_id: str) -> bool:
        """Dismiss (discard) a pending action without executing it."""
        item = _remove_pending(action_id)
        return item is not None

    def reset_rules_to_default(self) -> int:
        """Restore all built-in rules, keeping any custom rules."""
        default_names = {r["name"] for r in DEFAULT_RULES}
        custom = [r for r in self._rules if r["name"] not in default_names]
        self._rules = DEFAULT_RULES[:] + custom
        _save_rules(self._rules)
        return len(self._rules)
