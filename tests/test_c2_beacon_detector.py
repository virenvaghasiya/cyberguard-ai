"""Tests for the C2 beacon detector."""

import pytest
import pandas as pd
import numpy as np
from src.core.events import EventBus, EventType, Event
from src.detectors.c2_beacon_detector import C2BeaconDetector


@pytest.fixture
def event_bus():
    return EventBus()


@pytest.fixture
def detector(event_bus):
    config = {
        "c2_beacon_detector": {
            "min_flows": 5,
            "cv_threshold": 0.3,
            "fft_peak_threshold": 0.4,
            "payload_cv_threshold": 0.2,
        }
    }
    return C2BeaconDetector(config=config, event_bus=event_bus)


def _make_beacon_flows(
    src_ip="192.168.1.50",
    dst_ip="198.51.100.99",
    interval_seconds=60,
    count=20,
    jitter=0.0,
):
    """Generate synthetic C2 beacon flows with regular timing."""
    rng = np.random.default_rng(42)
    timestamps = []
    base = pd.Timestamp("2025-01-01 00:00:00")

    for i in range(count):
        jitter_offset = rng.uniform(-jitter, jitter) if jitter > 0 else 0
        ts = base + pd.Timedelta(seconds=i * interval_seconds + jitter_offset)
        timestamps.append(str(ts))

    return pd.DataFrame({
        "src_ip": [src_ip] * count,
        "dst_ip": [dst_ip] * count,
        "src_port": [50000 + i for i in range(count)],
        "dst_port": [443] * count,
        "protocol": [6] * count,
        "timestamp": timestamps,
        "duration": [1.0] * count,
        "packets": [5] * count,
        "bytes": [500] * count,  # Consistent payload
    })


def _make_bursty_traffic(count=30):
    """Generate normal bursty web traffic (irregular timing)."""
    rng = np.random.default_rng(99)
    timestamps = []
    base = pd.Timestamp("2025-01-01 00:00:00")
    current = 0.0

    for i in range(count):
        # Bursty: sometimes fast, sometimes slow
        gap = rng.exponential(scale=30.0)
        current += gap
        ts = base + pd.Timedelta(seconds=current)
        timestamps.append(ts.isoformat())

    return pd.DataFrame({
        "src_ip": ["192.168.1.10"] * count,
        "dst_ip": ["203.0.113.50"] * count,
        "src_port": [rng.integers(49152, 65535) for _ in range(count)],
        "dst_port": [443] * count,
        "protocol": [6] * count,
        "timestamp": timestamps,
        "duration": [rng.exponential(2.0) for _ in range(count)],
        "packets": [rng.integers(5, 200) for _ in range(count)],
        "bytes": [rng.integers(500, 50000) for _ in range(count)],
    })


@pytest.mark.asyncio
async def test_detects_regular_beacon(detector):
    """Perfectly periodic beacons should be detected."""
    beacon = _make_beacon_flows(interval_seconds=60, count=20, jitter=0.0)
    await detector.start()
    results = await detector.analyze(beacon)
    await detector.stop()

    assert len(results) > 0, "Failed to detect regular C2 beacon"
    assert results[0]["attack_type"] == "c2_beacon"
    assert results[0]["confidence"] > 0.5


@pytest.mark.asyncio
async def test_detects_beacon_with_jitter(detector):
    """Beacons with some timing jitter should still be detected."""
    beacon = _make_beacon_flows(interval_seconds=60, count=20, jitter=5.0)
    await detector.start()
    results = await detector.analyze(beacon)
    await detector.stop()

    assert len(results) > 0, "Failed to detect beacon with jitter"


@pytest.mark.asyncio
async def test_ignores_bursty_traffic(detector):
    """Normal bursty web traffic should not be flagged."""
    normal = _make_bursty_traffic(count=30)
    await detector.start()
    results = await detector.analyze(normal)
    await detector.stop()

    assert len(results) == 0, "False positive: flagged bursty traffic as beacon"


@pytest.mark.asyncio
async def test_beacon_interval_estimation(detector):
    """Detected beacon should correctly estimate the interval."""
    beacon = _make_beacon_flows(interval_seconds=120, count=15, jitter=0.0)
    await detector.start()
    results = await detector.analyze(beacon)
    await detector.stop()

    assert len(results) > 0
    estimated = results[0]["details"]["beacon_interval_seconds"]
    # Should be close to 120 seconds
    assert 100 < estimated < 140, f"Estimated interval {estimated}s, expected ~120s"


@pytest.mark.asyncio
async def test_publishes_events(detector, event_bus):
    """Beacon detections should publish events."""
    collected = []

    async def handler(event: Event):
        collected.append(event)

    event_bus.subscribe(EventType.ANOMALY_DETECTED, handler)

    beacon = _make_beacon_flows(interval_seconds=60, count=15)
    await detector.start()
    await detector.analyze(beacon)
    await detector.stop()

    assert len(collected) > 0
    assert collected[0].data["attack_type"] == "c2_beacon"


@pytest.mark.asyncio
async def test_too_few_flows_ignored(detector):
    """Pairs with fewer than min_flows should not be analyzed."""
    short = _make_beacon_flows(count=3)  # Below min_flows=5
    await detector.start()
    results = await detector.analyze(short)
    await detector.stop()

    assert len(results) == 0


@pytest.mark.asyncio
async def test_no_timestamps_returns_empty(detector):
    """Without timestamps, beacon detection should gracefully return empty."""
    df = pd.DataFrame({
        "src_ip": ["1.1.1.1"] * 10,
        "dst_ip": ["2.2.2.2"] * 10,
        "src_port": list(range(10)),
        "dst_port": [443] * 10,
        "protocol": [6] * 10,
        "duration": [1.0] * 10,
        "packets": [5] * 10,
        "bytes": [500] * 10,
    })
    await detector.start()
    results = await detector.analyze(df)
    await detector.stop()

    assert len(results) == 0
