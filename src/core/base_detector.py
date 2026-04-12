"""
Base class for all detection modules.

Every detector (network, log, phishing, vuln scanner) inherits from this.
It enforces a consistent interface so the pipeline manager can start, stop,
and query any detector without knowing its internals.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from src.core.events import EventBus


@dataclass
class DetectorStatus:
    """Runtime status of a detector."""
    name: str
    running: bool = False
    events_processed: int = 0
    anomalies_detected: int = 0
    last_run: datetime | None = None
    error: str | None = None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "running": self.running,
            "events_processed": self.events_processed,
            "anomalies_detected": self.anomalies_detected,
            "last_run": self.last_run.isoformat() if self.last_run else None,
            "error": self.error,
        }


class BaseDetector(ABC):
    """
    Abstract base for all CyberGuard detection modules.

    Subclasses must implement:
        - start(): Begin monitoring/detection
        - stop(): Clean shutdown
        - analyze(data): Run detection on a batch of data
        - get_status(): Return current operational status
    """

    def __init__(self, name: str, config: dict[str, Any], event_bus: EventBus) -> None:
        self.name = name
        self.config = config
        self.event_bus = event_bus
        self._status = DetectorStatus(name=name)

    @abstractmethod
    async def start(self) -> None:
        """Initialize and begin detection. Load models, open connections, etc."""
        ...

    @abstractmethod
    async def stop(self) -> None:
        """Graceful shutdown. Flush buffers, save state, close connections."""
        ...

    @abstractmethod
    async def analyze(self, data: Any) -> list[dict]:
        """
        Run detection on a batch of data.

        Returns a list of detection results, each containing at minimum:
            - anomaly_score: float
            - is_anomaly: bool
            - details: dict with detection-specific info
        """
        ...

    def get_status(self) -> DetectorStatus:
        """Return the detector's current operational status."""
        return self._status

    def _update_status(self, **kwargs) -> None:
        """Convenience method to update status fields."""
        for key, value in kwargs.items():
            if hasattr(self._status, key):
                setattr(self._status, key, value)
        self._status.last_run = datetime.now(timezone.utc)
