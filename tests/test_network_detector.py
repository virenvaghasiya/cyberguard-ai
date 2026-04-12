"""Tests for the network anomaly detector."""

import pytest
from src.core.events import Event, EventBus, EventType
from src.detectors.network_detector import NetworkAnomalyDetector
from src.utils.sample_data import generate_sample_traffic


@pytest.fixture
def event_bus():
    return EventBus()


@pytest.fixture
def config():
    return {
        "network_detector": {
            "model": {
                "contamination": 0.05,
                "n_estimators": 100,
                "model_path": "/tmp/test_model.joblib",
            },
            "alerting": {
                "score_threshold": -0.3,
                "severity_mapping": {"high": -0.7, "medium": -0.5, "low": -0.3},
            },
        }
    }


@pytest.fixture
def detector(config, event_bus):
    return NetworkAnomalyDetector(config=config, event_bus=event_bus)


@pytest.mark.asyncio
async def test_detector_lifecycle(detector):
    """Detector should start and stop cleanly."""
    await detector.start()
    assert detector.get_status().running is True

    await detector.stop()
    assert detector.get_status().running is False


@pytest.mark.asyncio
async def test_detect_anomalies_in_synthetic_data(detector, event_bus):
    """Detector should find anomalies in synthetic data with injected attacks."""
    collected_events = []

    async def collector(event: Event):
        collected_events.append(event)

    event_bus.subscribe(EventType.ANOMALY_DETECTED, collector)

    await detector.start()

    # Generate data with known anomalies
    traffic = generate_sample_traffic(n_normal=2000, n_anomalous=100)
    results = await detector.analyze(traffic)

    await detector.stop()

    # We should have detected some anomalies
    anomalies = [r for r in results if r["is_anomaly"]]
    assert len(anomalies) > 0, "Detector found zero anomalies in data with injected attacks"

    # Events should have been published
    assert len(collected_events) > 0, "No anomaly events were published"

    # Status should reflect work done
    status = detector.get_status()
    assert status.events_processed == len(traffic)
    assert status.anomalies_detected == len(anomalies)


@pytest.mark.asyncio
async def test_anomaly_scores_are_valid(detector):
    """All results should have valid anomaly scores."""
    await detector.start()

    traffic = generate_sample_traffic(n_normal=500, n_anomalous=50)
    results = await detector.analyze(traffic)

    for r in results:
        assert "anomaly_score" in r
        assert isinstance(r["anomaly_score"], float)
        assert "is_anomaly" in r
        assert isinstance(r["is_anomaly"], bool)

    await detector.stop()


@pytest.mark.asyncio
async def test_severity_assignment(detector):
    """Anomalies should be assigned severity levels."""
    await detector.start()

    traffic = generate_sample_traffic(n_normal=1000, n_anomalous=100)
    results = await detector.analyze(traffic)

    anomalies = [r for r in results if r["is_anomaly"]]
    for a in anomalies:
        assert a["severity"] in ["high", "medium", "low"]

    await detector.stop()


@pytest.mark.asyncio
async def test_result_details(detector):
    """Each result should include flow details."""
    await detector.start()

    traffic = generate_sample_traffic(n_normal=100, n_anomalous=10)
    results = await detector.analyze(traffic)

    for r in results:
        assert "details" in r
        details = r["details"]
        assert "src_ip" in details
        assert "dst_ip" in details
        assert "dst_port" in details

    await detector.stop()


@pytest.mark.asyncio
async def test_empty_input(detector):
    """Empty input should return empty results without errors."""
    import pandas as pd

    await detector.start()
    results = await detector.analyze(pd.DataFrame())
    assert results == []
    await detector.stop()
