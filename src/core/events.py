"""
Event bus for decoupled communication between CyberGuard modules.

Detectors publish events (threats, anomalies, status updates) and
other components (alert manager, response engine, API) subscribe to them.
This keeps modules independent — you can add or remove detectors
without touching the rest of the system.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Coroutine
from uuid import uuid4

import structlog

logger = structlog.get_logger()


class EventType(str, Enum):
    """All event types in the system."""
    ANOMALY_DETECTED = "anomaly.detected"
    THREAT_CONFIRMED = "threat.confirmed"
    ALERT_CREATED = "alert.created"
    ALERT_RESOLVED = "alert.resolved"
    SCAN_STARTED = "scan.started"
    SCAN_COMPLETED = "scan.completed"
    MODEL_UPDATED = "model.updated"
    SYSTEM_STATUS = "system.status"


class Severity(str, Enum):
    """Alert severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Event:
    """A single event flowing through the system."""
    event_type: EventType
    source: str                          # Which module produced this event
    data: dict[str, Any]                 # Event payload
    severity: Severity = Severity.INFO
    event_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> dict:
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "source": self.source,
            "severity": self.severity.value,
            "timestamp": self.timestamp.isoformat(),
            "data": self.data,
        }


# Type alias for event handler functions
EventHandler = Callable[[Event], Coroutine[Any, Any, None]]


class EventBus:
    """
    Async publish/subscribe event bus.

    Modules register handlers for specific event types. When an event
    is published, all matching handlers run concurrently.
    """

    def __init__(self) -> None:
        self._handlers: dict[EventType, list[EventHandler]] = defaultdict(list)
        self._event_log: list[Event] = []
        self._max_log_size = 10_000

    def subscribe(self, event_type: EventType, handler: EventHandler) -> None:
        """Register a handler for a specific event type."""
        self._handlers[event_type].append(handler)
        logger.debug("handler_subscribed", event_type=event_type.value, handler=handler.__name__)

    def unsubscribe(self, event_type: EventType, handler: EventHandler) -> None:
        """Remove a handler."""
        self._handlers[event_type] = [h for h in self._handlers[event_type] if h != handler]

    async def publish(self, event: Event) -> None:
        """
        Publish an event to all subscribed handlers.
        Handlers run concurrently. Failures in one handler don't block others.
        """
        self._record(event)
        handlers = self._handlers.get(event.event_type, [])

        if not handlers:
            logger.debug("event_no_handlers", event_type=event.event_type.value)
            return

        logger.info(
            "event_published",
            event_type=event.event_type.value,
            source=event.source,
            severity=event.severity.value,
            handler_count=len(handlers),
        )

        # Run all handlers concurrently, catch individual failures
        results = await asyncio.gather(
            *[self._safe_call(handler, event) for handler in handlers],
            return_exceptions=True,
        )

        for i, result in enumerate(results):
            if isinstance(result, Exception):
                logger.error(
                    "handler_failed",
                    handler=handlers[i].__name__,
                    error=str(result),
                )

    async def _safe_call(self, handler: EventHandler, event: Event) -> None:
        """Call a handler with error isolation."""
        try:
            await handler(event)
        except Exception as e:
            logger.error("handler_exception", handler=handler.__name__, error=str(e))
            raise

    def _record(self, event: Event) -> None:
        """Keep a bounded in-memory log of recent events."""
        self._event_log.append(event)
        if len(self._event_log) > self._max_log_size:
            self._event_log = self._event_log[-self._max_log_size:]

    def get_recent_events(self, limit: int = 100) -> list[dict]:
        """Return recent events for debugging or API responses."""
        return [e.to_dict() for e in self._event_log[-limit:]]
