"""Tests for the phishing email detector."""

import pytest
from src.core.events import EventBus, EventType, Event
from src.detectors.phishing_detector import PhishingEmailDetector
from src.utils.sample_emails import generate_sample_emails


@pytest.fixture
def event_bus():
    return EventBus()


@pytest.fixture
def detector(event_bus):
    return PhishingEmailDetector(config={}, event_bus=event_bus)


def _phishing_email():
    """A clearly phishing email."""
    return {
        "subject": "Urgent: Your Account Has Been Suspended",
        "body": (
            "Dear Customer, we detected unusual activity. "
            "Your account will be suspended within 24 hours. "
            "Verify now: http://paypa1-verify.xyz/login "
            "Failure to respond will result in account closure."
        ),
        "sender_name": "PayPal Security",
        "sender_email": "security@paypa1-support.xyz",
        "reply_to": "reply@different-domain.com",
        "attachments": [],
    }


def _legitimate_email():
    """A clearly legitimate email."""
    return {
        "subject": "Team meeting notes",
        "body": "Hi team, here are the notes from today's standup. See you tomorrow.",
        "sender_name": "Alex Johnson",
        "sender_email": "alex@company.com",
        "reply_to": "",
        "attachments": [],
    }


@pytest.mark.asyncio
async def test_detects_phishing(detector):
    """Obvious phishing should be detected."""
    await detector.start()
    results = await detector.analyze([_phishing_email()])
    await detector.stop()

    assert len(results) == 1
    assert results[0]["is_phishing"] is True
    assert results[0]["phishing_score"] > 5.0


@pytest.mark.asyncio
async def test_passes_legitimate(detector):
    """Legitimate email should not be flagged."""
    await detector.start()
    results = await detector.analyze([_legitimate_email()])
    await detector.stop()

    assert len(results) == 1
    assert results[0]["is_phishing"] is False
    assert results[0]["phishing_score"] < 5.0


@pytest.mark.asyncio
async def test_batch_analysis(detector):
    """Should handle multiple emails in one call."""
    await detector.start()
    results = await detector.analyze([_phishing_email(), _legitimate_email()])
    await detector.stop()

    assert len(results) == 2
    assert results[0]["is_phishing"] is True
    assert results[1]["is_phishing"] is False


@pytest.mark.asyncio
async def test_single_email_input(detector):
    """Should accept a single email dict (not wrapped in list)."""
    await detector.start()
    results = await detector.analyze(_phishing_email())
    await detector.stop()

    assert len(results) == 1
    assert results[0]["is_phishing"] is True


@pytest.mark.asyncio
async def test_empty_input(detector):
    """Empty input should return empty results."""
    await detector.start()
    results = await detector.analyze([])
    await detector.stop()

    assert results == []


@pytest.mark.asyncio
async def test_severity_assignment(detector):
    """Phishing emails should be assigned severity levels."""
    await detector.start()
    results = await detector.analyze([_phishing_email()])
    await detector.stop()

    assert results[0]["severity"] in ["high", "medium", "low"]


@pytest.mark.asyncio
async def test_publishes_events(detector, event_bus):
    """Phishing detections should publish events."""
    collected = []

    async def handler(event: Event):
        collected.append(event)

    event_bus.subscribe(EventType.ANOMALY_DETECTED, handler)

    await detector.start()
    await detector.analyze([_phishing_email()])
    await detector.stop()

    assert len(collected) > 0
    assert collected[0].data["attack_type"] == "phishing"


@pytest.mark.asyncio
async def test_result_has_details(detector):
    """Results should include detailed information."""
    await detector.start()
    results = await detector.analyze([_phishing_email()])
    await detector.stop()

    r = results[0]
    assert "phishing_score" in r
    assert "confidence" in r
    assert "features" in r
    assert "details" in r
    assert "indicators" in r["details"]
    assert r["details"]["indicator_count"] > 0


@pytest.mark.asyncio
async def test_sample_emails_detection_rate(detector):
    """Detection rate on sample emails should be high with low false positives."""
    emails = generate_sample_emails()
    await detector.start()
    results = await detector.analyze(emails)
    await detector.stop()

    # Check phishing detection rate
    phishing_indices = [i for i, e in enumerate(emails) if e["label"] == "phishing"]
    detected = sum(1 for i in phishing_indices if results[i]["is_phishing"])
    detection_rate = detected / len(phishing_indices)
    assert detection_rate >= 0.8, f"Phishing detection rate too low: {detection_rate:.0%}"

    # Check false positive rate
    legit_indices = [i for i, e in enumerate(emails) if e["label"] == "legitimate"]
    false_positives = sum(1 for i in legit_indices if results[i]["is_phishing"])
    fp_rate = false_positives / len(legit_indices)
    assert fp_rate <= 0.2, f"False positive rate too high: {fp_rate:.0%}"


@pytest.mark.asyncio
async def test_detector_status(detector):
    """Detector should track status correctly."""
    await detector.start()
    assert detector.get_status().running is True

    await detector.analyze([_phishing_email(), _legitimate_email()])

    status = detector.get_status()
    assert status.events_processed == 2
    assert status.anomalies_detected >= 1

    await detector.stop()
    assert detector.get_status().running is False
