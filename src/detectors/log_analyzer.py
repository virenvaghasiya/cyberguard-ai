"""
Log Analyzer Detector.

Parses security-relevant log files and detects threat patterns using
rule-based analysis. Supports three log formats:

    - auth:   Linux auth.log / syslog (SSH, sudo, PAM events)
    - web:    Apache / Nginx access logs (HTTP scanning, bruteforce)
    - auto:   Auto-detect format from the first non-empty line

Detected threat categories:
    1. Brute Force        — repeated failed logins from one source
    2. Privilege Escalation — sudo/su usage, especially to root
    3. Root Login         — direct root SSH or console login
    4. Account Lockout    — PAM account locked messages
    5. Invalid Users      — SSH attempts with non-existent usernames
    6. Service Failure    — repeated service crash/restart messages
    7. Web Scanning       — high rate of 4xx errors from one IP
    8. Web Bruteforce     — repeated POST failures (login form hammering)

Rule-based rather than ML because log threat patterns are deterministic:
a brute force is N failures in T seconds — no model needed to name that.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

import structlog

from src.core.base_detector import BaseDetector
from src.core.events import Event, EventBus, EventType, Severity

logger = structlog.get_logger()

# ---------------------------------------------------------------------------
# Regex patterns for auth log parsing
# ---------------------------------------------------------------------------

# syslog prefix: "Apr 14 10:23:01 hostname sshd[1234]:"
_SYSLOG_PREFIX = re.compile(
    r"^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<service>\S+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.+)$"
)

# ISO timestamp prefix: "2024-01-15T10:23:01.000Z hostname sshd:"
_ISO_PREFIX = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"
    r"(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?\s+(?P<host>\S+)\s+(?P<service>\S+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<message>.+)$"
)

# Auth patterns
_FAILED_LOGIN = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.a-fA-F:]+)",
    re.IGNORECASE,
)
_INVALID_USER = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>[\d.a-fA-F:]+)",
    re.IGNORECASE,
)
_ACCEPTED_LOGIN = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.a-fA-F:]+)",
    re.IGNORECASE,
)
_ROOT_LOGIN = re.compile(
    r"(?:ROOT LOGIN|Accepted \S+ for root from (?P<ip>[\d.a-fA-F:]+))",
    re.IGNORECASE,
)
_SUDO_CMD = re.compile(
    r"(?P<user>\S+)\s*:\s*.*COMMAND=(?P<cmd>.+)$",
    re.IGNORECASE,
)
_SUDO_FAIL = re.compile(
    r"(?P<user>\S+)\s*:\s*.*authentication failure.*COMMAND=(?P<cmd>.+)$",
    re.IGNORECASE,
)
_SU_TO_ROOT = re.compile(
    r"Successful su for (?:root|0) by (?P<user>\S+)",
    re.IGNORECASE,
)
_ACCOUNT_LOCKED = re.compile(
    r"(?:account locked|user account locked|maximum.*attempts|pam_tally)",
    re.IGNORECASE,
)
_SERVICE_FAIL = re.compile(
    r"(?:Failed to start|service.*failed|segfault|core dumped|killed process)",
    re.IGNORECASE,
)
_CRON_EDIT = re.compile(
    r"(?:crontab|cron\.d|at\.allow|at\.deny)",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Regex for Apache / Nginx combined log format
# 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326
# ---------------------------------------------------------------------------
_WEB_LOG = re.compile(
    r'^(?P<ip>[\d.a-fA-F:]+)\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+(?P<status>\d{3})\s+(?P<size>\S+)'
)


class LogAnalyzer(BaseDetector):
    """
    Analyzes security log files for threat patterns.

    Accepts raw log text (a single string or list of lines) and returns
    a list of threat detections in the same format as other detectors.
    """

    def __init__(self, config: dict[str, Any], event_bus: EventBus) -> None:
        super().__init__(name="log_analyzer", config=config, event_bus=event_bus)

        cfg = config.get("log_analyzer", {})

        # Brute force: N failures within a sliding window
        self._brute_force_threshold = cfg.get("brute_force_threshold", 5)
        # Web scanning: N 4xx errors from one IP
        self._web_scan_threshold = cfg.get("web_scan_threshold", 20)
        # Sudo commands that always warrant attention
        self._sensitive_commands = set(cfg.get("sensitive_commands", [
            "passwd", "useradd", "userdel", "usermod", "visudo",
            "chmod", "chown", "rm -rf", "dd ", "mkfs", "fdisk",
            "iptables", "ufw", "systemctl", "service",
        ]))

    async def start(self) -> None:
        self._update_status(running=True)
        logger.info("log_analyzer_started")

    async def stop(self) -> None:
        self._update_status(running=False)
        logger.info("log_analyzer_stopped")

    async def analyze(self, data: Any) -> list[dict]:
        """
        Analyze log content for security threats.

        Args:
            data: Raw log text (str), list of log lines (list[str]),
                  or a dict with keys 'content' and optional 'log_type'
                  ('auth', 'web', or 'auto').

        Returns:
            List of threat detection dicts.
        """
        # --- Normalize input ---
        log_type = "auto"
        if isinstance(data, dict):
            raw = data.get("content", "")
            log_type = data.get("log_type", "auto")
        elif isinstance(data, list):
            raw = "\n".join(str(line) for line in data)
        else:
            raw = str(data)

        lines = [line for line in raw.splitlines() if line.strip()]
        if not lines:
            return []

        # --- Auto-detect format ---
        if log_type == "auto":
            log_type = self._detect_format(lines)

        # --- Parse and analyze ---
        if log_type == "web":
            findings = self._analyze_web_logs(lines)
        else:
            findings = self._analyze_auth_logs(lines)

        # --- Publish events and update status ---
        anomaly_count = len(findings)
        for finding in findings:
            await self.event_bus.publish(Event(
                event_type=EventType.ANOMALY_DETECTED,
                source=self.name,
                severity=finding["severity_enum"],
                data={
                    "detector": self.name,
                    "attack_type": finding["attack_type"],
                    **finding["details"],
                },
            ))

        self._update_status(
            events_processed=self._status.events_processed + len(lines),
            anomalies_detected=self._status.anomalies_detected + anomaly_count,
        )

        logger.info(
            "log_analysis_complete",
            lines_analyzed=len(lines),
            log_type=log_type,
            threats_found=anomaly_count,
        )

        return findings

    # -----------------------------------------------------------------------
    # Format detection
    # -----------------------------------------------------------------------

    def _detect_format(self, lines: list[str]) -> str:
        """Guess the log format from the first few non-empty lines."""
        sample = "\n".join(lines[:10])
        if _WEB_LOG.search(sample):
            return "web"
        if _SYSLOG_PREFIX.search(sample) or _ISO_PREFIX.search(sample):
            return "auth"
        # Fallback — try auth patterns anyway
        return "auth"

    # -----------------------------------------------------------------------
    # Auth log analysis
    # -----------------------------------------------------------------------

    def _analyze_auth_logs(self, lines: list[str]) -> list[dict]:
        """Parse auth/syslog lines and detect security events."""
        findings: list[dict] = []

        # Counters for aggregate detections
        failed_by_ip: dict[str, list[str]] = defaultdict(list)   # ip → [user, ...]
        failed_by_user: dict[str, int] = defaultdict(int)
        invalid_users_by_ip: dict[str, set] = defaultdict(set)
        sudo_cmds: list[dict] = []
        sudo_failures: list[dict] = []
        root_logins: list[str] = []
        account_lockouts: list[str] = []
        service_failures: list[str] = []
        cron_edits: list[str] = []

        for line in lines:
            msg = self._extract_message(line)
            if not msg:
                continue

            # Failed logins
            m = _FAILED_LOGIN.search(msg)
            if m:
                ip = m.group("ip")
                user = m.group("user")
                failed_by_ip[ip].append(user)
                failed_by_user[user] += 1
                continue

            # Invalid user attempts
            m = _INVALID_USER.search(msg)
            if m:
                ip = m.group("ip")
                user = m.group("user")
                invalid_users_by_ip[ip].add(user)
                continue

            # Root login
            m = _ROOT_LOGIN.search(msg)
            if m:
                ip = m.group("ip") if m.lastindex and "ip" in m.groupdict() else "unknown"
                root_logins.append(ip)
                continue

            # Sudo commands
            m = _SUDO_CMD.search(msg)
            if m and "sudo" in line.lower():
                sudo_cmds.append({"user": m.group("user"), "cmd": m.group("cmd").strip()})
                continue

            # Sudo failures
            m = _SUDO_FAIL.search(msg)
            if m:
                sudo_failures.append({"user": m.group("user"), "cmd": m.group("cmd").strip()})
                continue

            # Su to root
            m = _SU_TO_ROOT.search(msg)
            if m:
                sudo_cmds.append({"user": m.group("user"), "cmd": "su to root"})
                continue

            # Account lockout
            if _ACCOUNT_LOCKED.search(msg):
                account_lockouts.append(line.strip())
                continue

            # Service failures
            if _SERVICE_FAIL.search(msg):
                service_failures.append(line.strip())
                continue

            # Cron edits
            if _CRON_EDIT.search(msg):
                cron_edits.append(line.strip())
                continue

        # --- Aggregate: brute force by IP ---
        for ip, attempts in failed_by_ip.items():
            count = len(attempts)
            if count >= self._brute_force_threshold:
                unique_users = len(set(attempts))
                severity = Severity.CRITICAL if count >= 50 else (
                    Severity.HIGH if count >= 20 else Severity.MEDIUM
                )
                findings.append(self._make_finding(
                    attack_type="brute_force",
                    severity=severity,
                    confidence=min(1.0, count / 50),
                    details={
                        "source_ip": ip,
                        "failed_attempts": count,
                        "unique_usernames_tried": unique_users,
                        "description": f"Brute force: {count} failed logins from {ip}",
                    },
                ))

        # --- Invalid users by IP (credential stuffing / user enumeration) ---
        for ip, users in invalid_users_by_ip.items():
            count = len(users)
            if count >= 3:
                severity = Severity.HIGH if count >= 10 else Severity.MEDIUM
                findings.append(self._make_finding(
                    attack_type="user_enumeration",
                    severity=severity,
                    confidence=min(1.0, count / 20),
                    details={
                        "source_ip": ip,
                        "invalid_usernames_tried": count,
                        "usernames": list(users)[:10],
                        "description": f"User enumeration: {count} invalid usernames tried from {ip}",
                    },
                ))

        # --- Root logins ---
        if root_logins:
            severity = Severity.CRITICAL
            findings.append(self._make_finding(
                attack_type="root_login",
                severity=severity,
                confidence=1.0,
                details={
                    "login_count": len(root_logins),
                    "source_ips": list(set(root_logins)),
                    "description": f"Direct root login detected ({len(root_logins)} time(s))",
                },
            ))

        # --- Sudo sensitive commands ---
        sensitive_sudo = [
            c for c in sudo_cmds
            if any(s in c["cmd"] for s in self._sensitive_commands)
        ]
        if sensitive_sudo:
            severity = Severity.HIGH
            findings.append(self._make_finding(
                attack_type="privilege_escalation",
                severity=severity,
                confidence=0.8,
                details={
                    "command_count": len(sensitive_sudo),
                    "commands": [f"{c['user']}: {c['cmd']}" for c in sensitive_sudo[:5]],
                    "description": f"Sensitive sudo commands executed ({len(sensitive_sudo)} total)",
                },
            ))

        # --- Sudo failures (unauthorized escalation attempts) ---
        if sudo_failures:
            severity = Severity.HIGH if len(sudo_failures) >= 3 else Severity.MEDIUM
            findings.append(self._make_finding(
                attack_type="privilege_escalation_attempt",
                severity=severity,
                confidence=min(1.0, len(sudo_failures) / 5),
                details={
                    "failed_attempts": len(sudo_failures),
                    "users": list({c["user"] for c in sudo_failures}),
                    "description": f"Failed sudo attempts: {len(sudo_failures)} unauthorized escalation tries",
                },
            ))

        # --- Account lockouts ---
        if account_lockouts:
            severity = Severity.HIGH if len(account_lockouts) >= 3 else Severity.MEDIUM
            findings.append(self._make_finding(
                attack_type="account_lockout",
                severity=severity,
                confidence=0.9,
                details={
                    "lockout_count": len(account_lockouts),
                    "description": f"Account lockout(s) detected: {len(account_lockouts)} event(s)",
                },
            ))

        # --- Service failures ---
        if len(service_failures) >= 3:
            severity = Severity.MEDIUM
            findings.append(self._make_finding(
                attack_type="service_failure",
                severity=severity,
                confidence=min(1.0, len(service_failures) / 10),
                details={
                    "failure_count": len(service_failures),
                    "description": f"Repeated service failures: {len(service_failures)} events",
                },
            ))

        # --- Cron modifications ---
        if cron_edits:
            severity = Severity.MEDIUM
            findings.append(self._make_finding(
                attack_type="cron_modification",
                severity=severity,
                confidence=0.7,
                details={
                    "event_count": len(cron_edits),
                    "description": f"Cron/scheduled task modification detected ({len(cron_edits)} event(s))",
                },
            ))

        return findings

    # -----------------------------------------------------------------------
    # Web log analysis
    # -----------------------------------------------------------------------

    def _analyze_web_logs(self, lines: list[str]) -> list[dict]:
        """Parse Apache/Nginx combined log lines and detect attacks."""
        findings: list[dict] = []

        errors_by_ip: dict[str, int] = defaultdict(int)
        post_failures_by_ip: dict[str, int] = defaultdict(int)
        paths_by_ip: dict[str, set] = defaultdict(set)
        total_requests_by_ip: dict[str, int] = defaultdict(int)

        for line in lines:
            m = _WEB_LOG.match(line)
            if not m:
                continue

            ip = m.group("ip")
            method = m.group("method")
            path = m.group("path")
            status = int(m.group("status"))

            total_requests_by_ip[ip] += 1
            paths_by_ip[ip].add(path)

            if 400 <= status < 500:
                errors_by_ip[ip] += 1

            if method == "POST" and status in (401, 403):
                post_failures_by_ip[ip] += 1

        # --- Web scanning: high 4xx error rate ---
        for ip, error_count in errors_by_ip.items():
            if error_count >= self._web_scan_threshold:
                total = total_requests_by_ip[ip]
                error_rate = error_count / total if total else 0
                unique_paths = len(paths_by_ip[ip])
                severity = Severity.HIGH if error_count >= 100 else Severity.MEDIUM
                findings.append(self._make_finding(
                    attack_type="web_scanning",
                    severity=severity,
                    confidence=min(1.0, error_count / 100),
                    details={
                        "source_ip": ip,
                        "error_requests": error_count,
                        "total_requests": total,
                        "error_rate": round(error_rate, 3),
                        "unique_paths_probed": unique_paths,
                        "description": f"Web scanning from {ip}: {error_count} 4xx errors across {unique_paths} paths",
                    },
                ))

        # --- Web brute force: repeated POST failures ---
        for ip, fail_count in post_failures_by_ip.items():
            if fail_count >= 5:
                severity = Severity.HIGH if fail_count >= 20 else Severity.MEDIUM
                findings.append(self._make_finding(
                    attack_type="web_brute_force",
                    severity=severity,
                    confidence=min(1.0, fail_count / 20),
                    details={
                        "source_ip": ip,
                        "failed_post_requests": fail_count,
                        "description": f"Web brute force from {ip}: {fail_count} failed POST requests",
                    },
                ))

        return findings

    # -----------------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------------

    def _extract_message(self, line: str) -> str | None:
        """
        Extract the log message body from a syslog or ISO-format line.
        Falls back to returning the full line if no prefix matches.
        """
        m = _SYSLOG_PREFIX.match(line)
        if m:
            return m.group("message")
        m = _ISO_PREFIX.match(line)
        if m:
            return m.group("message")
        # No recognized prefix — treat whole line as message
        return line.strip()

    def _make_finding(
        self,
        attack_type: str,
        severity: Severity,
        confidence: float,
        details: dict,
    ) -> dict:
        """Build a standardized finding dict matching the detector contract."""
        return {
            "is_anomaly": True,
            "attack_type": attack_type,
            "confidence": round(confidence, 3),
            "severity": severity.value,
            "severity_enum": severity,
            "anomaly_score": -0.5 - (confidence * 0.5),
            "details": details,
        }
