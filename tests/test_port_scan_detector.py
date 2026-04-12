"""Tests for the port scan detector."""

import pytest
import pandas as pd
from src.core.events import EventBus, EventType, Event
from src.detectors.port_scan_detector import PortScanDetector


@pytest.fixture
def event_bus():
    return EventBus()


@pytest.fixture
def detector(event_bus):
    config = {
        "port_scan_detector": {
            "min_unique_ports": 10,
            "max_avg_duration": 0.5,
            "max_avg_packets": 3,
            "min_flow_count": 8,
        }
    }
    return PortScanDetector(config=config, event_bus=event_bus)


def _make_scan_flows(src_ip="10.0.0.1", dst_ip="192.168.1.100", port_count=50):
    """Generate synthetic port scan flows."""
    return pd.DataFrame({
        "src_ip": [src_ip] * port_count,
        "dst_ip": [dst_ip] * port_count,
        "src_port": [50000 + i for i in range(port_count)],
        "dst_port": list(range(1, port_count + 1)),
        "protocol": [6] * port_count,
        "timestamp": [f"2025-01-01T00:00:{i * 0.01:.2f}" for i in range(port_count)],
        "duration": [0.001] * port_count,
        "packets": [1] * port_count,
        "bytes": [44] * port_count,
    })


def _make_normal_flows(count=50):
    """Generate normal-looking web traffic."""
    return pd.DataFrame({
        "src_ip": ["192.168.1.10"] * count,
        "dst_ip": ["203.0.113.50"] * count,
        "src_port": [50000 + i for i in range(count)],
        "dst_port": [443] * count,
        "protocol": [6] * count,
        "timestamp": [f"2025-01-01T00:0{i // 10}:{i % 10 * 5}" for i in range(count)],
        "duration": [2.5] * count,
        "packets": [50] * count,
        "bytes": [25000] * count,
    })


@pytest.mark.asyncio
async def test_detects_port_scan(detector):
    """Detector should flag obvious port scanning."""
    scan_flows = _make_scan_flows(port_count=50)
    await detector.start()
    results = await detector.analyze(scan_flows)
    await detector.stop()

    assert len(results) > 0, "Failed to detect port scan"
    assert results[0]["attack_type"] == "port_scan"
    assert results[0]["confidence"] > 0.5


@pytest.mark.asyncio
async def test_ignores_normal_traffic(detector):
    """Normal traffic to one port should not be flagged."""
    normal = _make_normal_flows(count=50)
    await detector.start()
    results = await detector.analyze(normal)
    await detector.stop()

    assert len(results) == 0, f"False positive: flagged normal traffic as scan"


@pytest.mark.asyncio
async def test_scan_type_classification(detector):
    """Sequential port scanning should be classified correctly."""
    scan_flows = _make_scan_flows(port_count=30)
    await detector.start()
    results = await detector.analyze(scan_flows)
    await detector.stop()

    assert len(results) > 0
    # Ports 1-30 in order should be classified as sequential or stealth_syn
    assert results[0]["scan_type"] in ["sequential", "stealth_syn"]


@pytest.mark.asyncio
async def test_publishes_events(detector, event_bus):
    """Scan detections should publish events to the bus."""
    collected = []

    async def handler(event: Event):
        collected.append(event)

    event_bus.subscribe(EventType.ANOMALY_DETECTED, handler)

    scan_flows = _make_scan_flows(port_count=30)
    await detector.start()
    await detector.analyze(scan_flows)
    await detector.stop()

    assert len(collected) > 0
    assert collected[0].data["attack_type"] == "port_scan"


@pytest.mark.asyncio
async def test_too_few_flows_ignored(detector):
    """Pairs with too few flows should not be flagged."""
    few_flows = _make_scan_flows(port_count=3)  # Below min_flow_count=8
    await detector.start()
    results = await detector.analyze(few_flows)
    await detector.stop()

    assert len(results) == 0
