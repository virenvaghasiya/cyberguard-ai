"""Tests for the Vulnerability Scanner detector."""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch, MagicMock

import pytest

from src.core.events import EventBus, EventType, Event
from src.detectors.vuln_scanner import VulnerabilityScanner, KNOWN_SERVICES


@pytest.fixture
def event_bus():
    return EventBus()


@pytest.fixture
def detector(event_bus):
    config = {
        "vulnerability_scanner": {
            "timeout": 0.5,
            "max_concurrent": 10,
        }
    }
    return VulnerabilityScanner(config=config, event_bus=event_bus)


# ---------------------------------------------------------------------------
# Helpers — mock open_connection to avoid real network calls
# ---------------------------------------------------------------------------

def _mock_open_port(banner: bytes = b""):
    """Return an async mock that simulates an open port with a banner."""
    reader = AsyncMock()
    reader.read = AsyncMock(return_value=banner)

    writer = MagicMock()
    writer.write = MagicMock()
    writer.drain = AsyncMock()
    writer.close = MagicMock()
    writer.wait_closed = AsyncMock()

    async def fake_open_connection(host, port):
        return reader, writer

    return fake_open_connection


def _mock_closed_port():
    """Simulate a refused connection (port closed)."""
    async def fake_open_connection(host, port):
        raise ConnectionRefusedError()
    return fake_open_connection


def _mock_timeout_port():
    """Simulate a timed-out connection (port filtered)."""
    async def fake_open_connection(host, port):
        raise asyncio.TimeoutError()
    return fake_open_connection


# ---------------------------------------------------------------------------
# Lifecycle tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_start_stop(detector):
    """Detector should start and stop cleanly."""
    await detector.start()
    assert detector.get_status().running is True
    await detector.stop()
    assert detector.get_status().running is False


# ---------------------------------------------------------------------------
# Port scanning tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_detects_telnet_port(detector):
    """Open Telnet port (23) should be flagged as critical."""
    with patch("asyncio.open_connection", side_effect=_mock_open_port(b"")):
        await detector.start()
        results = await detector.analyze({"target": "127.0.0.1", "ports": [23]})
        await detector.stop()

    assert len(results) == 1
    assert results[0]["severity"] == "critical"
    assert "telnet" in results[0]["attack_type"].lower()
    assert results[0]["details"]["port"] == 23


@pytest.mark.asyncio
async def test_detects_redis_no_auth(detector):
    """Redis responding without auth should be flagged as critical."""
    redis_banner = b"+redis_version:7.0.0\r\n"
    with patch("asyncio.open_connection", side_effect=_mock_open_port(redis_banner)):
        await detector.start()
        results = await detector.analyze({"target": "127.0.0.1", "ports": [6379]})
        await detector.stop()

    assert len(results) == 1
    assert results[0]["severity"] == "critical"
    assert "anonymous" in results[0]["details"]["description"].lower() or \
           "authentication" in results[0]["details"]["description"].lower()


@pytest.mark.asyncio
async def test_detects_mysql_exposure(detector):
    """Open MySQL port should be flagged as high risk."""
    with patch("asyncio.open_connection", side_effect=_mock_open_port(b"MySQL 8.0")):
        await detector.start()
        results = await detector.analyze({"target": "127.0.0.1", "ports": [3306]})
        await detector.stop()

    assert len(results) == 1
    assert results[0]["severity"] in ("high", "critical")
    assert results[0]["details"]["port"] == 3306


@pytest.mark.asyncio
async def test_detects_outdated_openssh(detector):
    """Old OpenSSH version in banner should escalate severity."""
    old_banner = b"SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2"
    with patch("asyncio.open_connection", side_effect=_mock_open_port(old_banner)):
        await detector.start()
        results = await detector.analyze({"target": "127.0.0.1", "ports": [22]})
        await detector.stop()

    assert len(results) == 1
    assert results[0]["severity"] == "high"
    assert "outdated" in results[0]["details"]["description"].lower()


@pytest.mark.asyncio
async def test_closed_port_produces_no_finding(detector):
    """A closed port should produce no finding."""
    with patch("asyncio.open_connection", side_effect=_mock_closed_port()):
        await detector.start()
        results = await detector.analyze({"target": "127.0.0.1", "ports": [23]})
        await detector.stop()

    assert results == []


@pytest.mark.asyncio
async def test_filtered_port_produces_no_finding(detector):
    """A timed-out (filtered) port should produce no finding."""
    with patch("asyncio.open_connection", side_effect=_mock_timeout_port()):
        await detector.start()
        results = await detector.analyze({"target": "127.0.0.1", "ports": [23]})
        await detector.stop()

    assert results == []


@pytest.mark.asyncio
async def test_unknown_open_port_flagged_as_low(detector):
    """An open port not in the knowledge base should be flagged as LOW."""
    with patch("asyncio.open_connection", side_effect=_mock_open_port(b"")):
        await detector.start()
        # Port 19999 is not in KNOWN_SERVICES
        results = await detector.analyze({"target": "127.0.0.1", "ports": [19999]})
        await detector.stop()

    assert len(results) == 1
    assert results[0]["severity"] == "low"
    assert results[0]["attack_type"] == "unknown_open_port"


@pytest.mark.asyncio
async def test_multiple_ports_scanned(detector):
    """Multiple dangerous ports open should produce multiple findings."""
    open_ports = {23, 21, 3306}

    async def selective_open(host, port):
        if port in open_ports:
            reader = AsyncMock()
            reader.read = AsyncMock(return_value=b"")
            writer = MagicMock()
            writer.write = MagicMock()
            writer.drain = AsyncMock()
            writer.close = MagicMock()
            writer.wait_closed = AsyncMock()
            return reader, writer
        raise ConnectionRefusedError()

    with patch("asyncio.open_connection", side_effect=selective_open):
        await detector.start()
        results = await detector.analyze({
            "target": "127.0.0.1",
            "ports": [23, 21, 3306, 65432],
        })
        await detector.stop()

    assert len(results) == 3
    found_ports = {r["details"]["port"] for r in results}
    assert found_ports == open_ports


# ---------------------------------------------------------------------------
# Input handling tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_string_input_accepted(detector):
    """Plain IP string should work as input."""
    with patch("asyncio.open_connection", side_effect=_mock_open_port(b"")):
        await detector.start()
        results = await detector.analyze("127.0.0.1")
        await detector.stop()

    # Should scan default ports list and return findings for any open ones
    assert isinstance(results, list)


@pytest.mark.asyncio
async def test_invalid_input_returns_empty(detector):
    """Non-parseable input should return empty without crashing."""
    await detector.start()
    results = await detector.analyze(12345)
    await detector.stop()

    assert results == []


@pytest.mark.asyncio
async def test_cidr_range_resolves_hosts(detector):
    """CIDR /30 should resolve to 2 host addresses."""
    scanner = detector
    hosts = scanner._resolve_targets("192.168.1.4/30")
    assert hosts == ["192.168.1.5", "192.168.1.6"]


@pytest.mark.asyncio
async def test_large_cidr_rejected(detector):
    """CIDR ranges larger than /24 should be rejected for safety."""
    hosts = detector._resolve_targets("10.0.0.0/16")
    assert hosts == []


@pytest.mark.asyncio
async def test_hostname_resolved(detector):
    """Localhost hostname should resolve to an IP."""
    hosts = detector._resolve_targets("localhost")
    assert len(hosts) == 1
    assert hosts[0] in ("127.0.0.1", "::1")


# ---------------------------------------------------------------------------
# Event publishing tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_publishes_events_on_finding(detector, event_bus):
    """Each finding should publish an ANOMALY_DETECTED event."""
    collected = []

    async def handler(event: Event):
        collected.append(event)

    event_bus.subscribe(EventType.ANOMALY_DETECTED, handler)

    with patch("asyncio.open_connection", side_effect=_mock_open_port(b"")):
        await detector.start()
        await detector.analyze({"target": "127.0.0.1", "ports": [23]})
        await detector.stop()

    assert len(collected) == 1
    assert collected[0].data["detector"] == "vuln_scanner"
    assert collected[0].data["port"] == 23


# ---------------------------------------------------------------------------
# Result structure tests
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_result_has_required_fields(detector):
    """Every finding must contain the required fields."""
    with patch("asyncio.open_connection", side_effect=_mock_open_port(b"")):
        await detector.start()
        results = await detector.analyze({"target": "127.0.0.1", "ports": [23]})
        await detector.stop()

    assert len(results) == 1
    r = results[0]
    assert r["is_anomaly"] is True
    assert "attack_type" in r
    assert "confidence" in r
    assert "severity" in r
    assert "details" in r
    assert "host" in r["details"]
    assert "port" in r["details"]
    assert "description" in r["details"]
    assert "recommendation" in r["details"]
    assert 0.0 <= r["confidence"] <= 1.0


@pytest.mark.asyncio
async def test_status_updated_after_scan(detector):
    """events_processed should increment after a scan."""
    with patch("asyncio.open_connection", side_effect=_mock_closed_port()):
        await detector.start()
        await detector.analyze({"target": "127.0.0.1", "ports": [22, 23, 80]})
        await detector.stop()

    status = detector.get_status()
    assert status.events_processed == 3  # 3 ports scanned


# ---------------------------------------------------------------------------
# Knowledge base sanity checks (no async needed)
# ---------------------------------------------------------------------------

def test_known_services_not_empty():
    """Knowledge base must have entries."""
    assert len(KNOWN_SERVICES) > 10


def test_critical_ports_in_knowledge_base():
    """The most dangerous ports must be in the database."""
    assert 23 in KNOWN_SERVICES   # Telnet
    assert 2375 in KNOWN_SERVICES  # Docker API
    assert 512 in KNOWN_SERVICES   # rexec


def test_all_services_have_recommendation(detector):
    """Every known service should have a recommendation string."""
    for port, service in KNOWN_SERVICES.items():
        rec = detector._get_recommendation(port, service)
        assert isinstance(rec, str) and len(rec) > 0
