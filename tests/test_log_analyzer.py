"""Tests for the Log Analyzer detector."""

import pytest
from src.core.events import EventBus, EventType, Event
from src.detectors.log_analyzer import LogAnalyzer


@pytest.fixture
def event_bus():
    return EventBus()


@pytest.fixture
def detector(event_bus):
    config = {
        "log_analyzer": {
            "brute_force_threshold": 5,
            "web_scan_threshold": 10,
            "sensitive_commands": ["passwd", "useradd", "visudo", "rm -rf"],
        }
    }
    return LogAnalyzer(config=config, event_bus=event_bus)


# ---------------------------------------------------------------------------
# Helpers — synthetic log builders
# ---------------------------------------------------------------------------

def _make_brute_force_log(ip="10.0.0.1", count=10, user="root"):
    """Simulate repeated SSH failed login attempts."""
    lines = []
    for i in range(count):
        lines.append(
            f"Apr 14 10:00:{i:02d} server sshd[1234]: "
            f"Failed password for {user} from {ip} port {40000 + i} ssh2"
        )
    return "\n".join(lines)


def _make_invalid_user_log(ip="10.0.0.2", count=5):
    """Simulate SSH invalid user enumeration."""
    lines = []
    users = [f"user{i}" for i in range(count)]
    for u in users:
        lines.append(
            f"Apr 14 10:01:00 server sshd[1235]: "
            f"Invalid user {u} from {ip} port 41000"
        )
    return "\n".join(lines)


def _make_root_login_log(ip="203.0.113.5"):
    return (
        f"Apr 14 10:02:00 server sshd[1236]: "
        f"Accepted password for root from {ip} port 22 ssh2"
    )


def _make_sudo_log(user="alice", cmd="/usr/bin/passwd bob"):
    return (
        f"Apr 14 10:03:00 server sudo[1237]: "
        f"{user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}"
    )


def _make_account_lockout_log():
    return (
        "Apr 14 10:04:00 server sshd[1238]: "
        "pam_tally2: user root, maximum 3 attempts exceeded"
    )


def _make_web_scan_log(ip="192.168.1.99", count=25):
    """Simulate an IP scanning many paths and getting 404s."""
    lines = []
    for i in range(count):
        lines.append(
            f'{ip} - - [14/Apr/2026:10:05:{i:02d} +0000] '
            f'"GET /admin/page{i} HTTP/1.1" 404 512'
        )
    return "\n".join(lines)


def _make_web_brute_force_log(ip="192.168.1.88", count=15):
    """Simulate repeated POST login failures."""
    lines = []
    for i in range(count):
        lines.append(
            f'{ip} - - [14/Apr/2026:10:06:{i:02d} +0000] '
            f'"POST /login HTTP/1.1" 401 128'
        )
    return "\n".join(lines)


def _make_clean_auth_log():
    """Normal auth log with just one successful login."""
    return (
        "Apr 14 10:07:00 server sshd[1239]: "
        "Accepted publickey for alice from 192.168.1.10 port 22 ssh2"
    )


def _make_clean_web_log():
    """Normal web traffic — all 200s, single IP."""
    lines = []
    for i in range(20):
        lines.append(
            f'10.0.0.10 - - [14/Apr/2026:10:08:{i:02d} +0000] '
            f'"GET /index.html HTTP/1.1" 200 2048'
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Auth log tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_detects_brute_force(detector):
    """Should flag repeated failed logins from one IP."""
    log = _make_brute_force_log(count=10)
    await detector.start()
    results = await detector.analyze(log)
    await detector.stop()

    attack_types = [r["attack_type"] for r in results]
    assert "brute_force" in attack_types

    bf = next(r for r in results if r["attack_type"] == "brute_force")
    assert bf["details"]["failed_attempts"] == 10
    assert bf["details"]["source_ip"] == "10.0.0.1"
    assert bf["confidence"] > 0


@pytest.mark.asyncio
async def test_brute_force_below_threshold_ignored(detector):
    """Fewer failures than threshold should not trigger brute force."""
    log = _make_brute_force_log(count=3)  # threshold is 5
    await detector.start()
    results = await detector.analyze(log)
    await detector.stop()

    attack_types = [r["attack_type"] for r in results]
    assert "brute_force" not in attack_types


@pytest.mark.asyncio
async def test_detects_user_enumeration(detector):
    """Should flag many invalid usernames from one IP."""
    log = _make_invalid_user_log(count=5)
    await detector.start()
    results = await detector.analyze(log)
    await detector.stop()

    attack_types = [r["attack_type"] for r in results]
    assert "user_enumeration" in attack_types


@pytest.mark.asyncio
async def test_detects_root_login(detector):
    """Direct root login should always be flagged as CRITICAL."""
    log = _make_root_login_log()
    await detector.start()
    results = await detector.analyze(log)
    await detector.stop()

    attack_types = [r["attack_type"] for r in results]
    assert "root_login" in attack_types

    root = next(r for r in results if r["attack_type"] == "root_login")
    assert root["severity"] == "critical"


@pytest.mark.asyncio
async def test_detects_privilege_escalation(detector):
    """Sensitive sudo commands should be flagged."""
    log = _make_sudo_log(cmd="/usr/bin/passwd bob")
    await detector.start()
    results = await detector.analyze(log)
    await detector.stop()

    attack_types = [r["attack_type"] for r in results]
    assert "privilege_escalation" in attack_types


@pytest.mark.asyncio
async def test_detects_account_lockout(detector):
    """PAM lockout messages should be flagged."""
    log = _make_account_lockout_log()
    await detector.start()
    results = await detector.analyze(log)
    await detector.stop()

    attack_types = [r["attack_type"] for r in results]
    assert "account_lockout" in attack_types


@pytest.mark.asyncio
async def test_clean_auth_log_no_alerts(detector):
    """Clean log with only a successful login should produce no alerts."""
    log = _make_clean_auth_log()
    await detector.start()
    results = await detector.analyze(log)
    await detector.stop()

    assert results == [], f"False positives on clean log: {[r['attack_type'] for r in results]}"


# ---------------------------------------------------------------------------
# Web log tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_detects_web_scanning(detector):
    """High 4xx error rate from one IP should be flagged."""
    log = _make_web_scan_log(count=25)
    await detector.start()
    results = await detector.analyze({"content": log, "log_type": "web"})
    await detector.stop()

    attack_types = [r["attack_type"] for r in results]
    assert "web_scanning" in attack_types

    scan = next(r for r in results if r["attack_type"] == "web_scanning")
    assert scan["details"]["source_ip"] == "192.168.1.99"
    assert scan["details"]["error_requests"] == 25


@pytest.mark.asyncio
async def test_detects_web_brute_force(detector):
    """Repeated POST 401/403 from one IP should be flagged."""
    log = _make_web_brute_force_log(count=15)
    await detector.start()
    results = await detector.analyze({"content": log, "log_type": "web"})
    await detector.stop()

    attack_types = [r["attack_type"] for r in results]
    assert "web_brute_force" in attack_types


@pytest.mark.asyncio
async def test_clean_web_log_no_alerts(detector):
    """Normal web traffic should produce no alerts."""
    log = _make_clean_web_log()
    await detector.start()
    results = await detector.analyze({"content": log, "log_type": "web"})
    await detector.stop()

    assert results == [], f"False positives on clean web log: {[r['attack_type'] for r in results]}"


# ---------------------------------------------------------------------------
# Format auto-detection
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_auto_detects_auth_format(detector):
    """Auto mode should correctly identify auth log format."""
    log = _make_brute_force_log(count=10)
    await detector.start()
    results = await detector.analyze({"content": log, "log_type": "auto"})
    await detector.stop()

    assert any(r["attack_type"] == "brute_force" for r in results)


@pytest.mark.asyncio
async def test_auto_detects_web_format(detector):
    """Auto mode should correctly identify web log format."""
    log = _make_web_scan_log(count=25)
    await detector.start()
    results = await detector.analyze({"content": log, "log_type": "auto"})
    await detector.stop()

    assert any(r["attack_type"] == "web_scanning" for r in results)


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_empty_input_returns_empty(detector):
    """Empty input should return no results without crashing."""
    await detector.start()
    results = await detector.analyze("")
    await detector.stop()

    assert results == []


@pytest.mark.asyncio
async def test_list_input_accepted(detector):
    """Accepts list of log lines as input."""
    lines = _make_brute_force_log(count=10).splitlines()
    await detector.start()
    results = await detector.analyze(lines)
    await detector.stop()

    assert any(r["attack_type"] == "brute_force" for r in results)


@pytest.mark.asyncio
async def test_publishes_events(detector, event_bus):
    """Each threat finding should publish an event to the bus."""
    collected = []

    async def handler(event: Event):
        collected.append(event)

    event_bus.subscribe(EventType.ANOMALY_DETECTED, handler)

    log = _make_brute_force_log(count=10)
    await detector.start()
    await detector.analyze(log)
    await detector.stop()

    assert len(collected) > 0
    assert collected[0].data["detector"] == "log_analyzer"


@pytest.mark.asyncio
async def test_detector_status_updated(detector):
    """Status counters should increment after analysis."""
    log = _make_brute_force_log(count=10)
    await detector.start()
    await detector.analyze(log)
    await detector.stop()

    status = detector.get_status()
    assert status.events_processed > 0
    assert status.anomalies_detected > 0


@pytest.mark.asyncio
async def test_result_structure(detector):
    """Every result must have the required fields."""
    log = _make_brute_force_log(count=10)
    await detector.start()
    results = await detector.analyze(log)
    await detector.stop()

    assert len(results) > 0
    for r in results:
        assert "is_anomaly" in r
        assert "attack_type" in r
        assert "confidence" in r
        assert "severity" in r
        assert "details" in r
        assert r["is_anomaly"] is True
        assert 0.0 <= r["confidence"] <= 1.0
