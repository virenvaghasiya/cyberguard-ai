"""Tests for the core event bus."""

import pytest
from src.core.events import Event, EventBus, EventType, Severity


@pytest.fixture
def event_bus():
    return EventBus()


@pytest.fixture
def sample_event():
    return Event(
        event_type=EventType.ANOMALY_DETECTED,
        source="test_detector",
        severity=Severity.HIGH,
        data={"src_ip": "192.168.1.100", "anomaly_score": -0.8},
    )


@pytest.mark.asyncio
async def test_publish_with_no_handlers(event_bus, sample_event):
    """Publishing to an event type with no subscribers should not raise."""
    await event_bus.publish(sample_event)


@pytest.mark.asyncio
async def test_subscribe_and_receive(event_bus, sample_event):
    """Subscribed handlers should receive published events."""
    received = []

    async def handler(event: Event):
        received.append(event)

    event_bus.subscribe(EventType.ANOMALY_DETECTED, handler)
    await event_bus.publish(sample_event)

    assert len(received) == 1
    assert received[0].event_id == sample_event.event_id
    assert received[0].data["src_ip"] == "192.168.1.100"


@pytest.mark.asyncio
async def test_multiple_handlers(event_bus, sample_event):
    """Multiple handlers on the same event type should all fire."""
    results = {"a": False, "b": False}

    async def handler_a(event):
        results["a"] = True

    async def handler_b(event):
        results["b"] = True

    event_bus.subscribe(EventType.ANOMALY_DETECTED, handler_a)
    event_bus.subscribe(EventType.ANOMALY_DETECTED, handler_b)
    await event_bus.publish(sample_event)

    assert results["a"] is True
    assert results["b"] is True


@pytest.mark.asyncio
async def test_handler_isolation(event_bus, sample_event):
    """A failing handler should not prevent other handlers from running."""
    second_ran = False

    async def bad_handler(event):
        raise ValueError("intentional failure")

    async def good_handler(event):
        nonlocal second_ran
        second_ran = True

    event_bus.subscribe(EventType.ANOMALY_DETECTED, bad_handler)
    event_bus.subscribe(EventType.ANOMALY_DETECTED, good_handler)
    await event_bus.publish(sample_event)

    assert second_ran is True


@pytest.mark.asyncio
async def test_unsubscribe(event_bus, sample_event):
    """Unsubscribed handlers should no longer receive events."""
    received = []

    async def handler(event):
        received.append(event)

    event_bus.subscribe(EventType.ANOMALY_DETECTED, handler)
    event_bus.unsubscribe(EventType.ANOMALY_DETECTED, handler)
    await event_bus.publish(sample_event)

    assert len(received) == 0


@pytest.mark.asyncio
async def test_event_log(event_bus, sample_event):
    """Recent events should be retrievable."""
    await event_bus.publish(sample_event)
    events = event_bus.get_recent_events(limit=10)

    assert len(events) == 1
    assert events[0]["event_type"] == "anomaly.detected"
    assert events[0]["severity"] == "high"


def test_event_to_dict(sample_event):
    """Event.to_dict() should produce a clean serializable dict."""
    d = sample_event.to_dict()
    assert d["event_type"] == "anomaly.detected"
    assert d["source"] == "test_detector"
    assert d["severity"] == "high"
    assert "event_id" in d
    assert "timestamp" in d
