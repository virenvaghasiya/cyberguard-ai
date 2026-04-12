"""
Pipeline manager — orchestrates all active detection modules.

This is the central coordinator. It loads config, initializes detectors,
manages their lifecycle, and provides a single interface for the API layer.
"""

from __future__ import annotations

from typing import Any

import structlog
import yaml

from src.core.base_detector import BaseDetector
from src.core.events import EventBus

logger = structlog.get_logger()


class PipelineManager:
    """
    Manages the lifecycle and coordination of all detection modules.
    """

    def __init__(self, config_path: str = "config/default.yaml") -> None:
        self.config = self._load_config(config_path)
        self.event_bus = EventBus()
        self._detectors: dict[str, BaseDetector] = {}

    def _load_config(self, path: str) -> dict[str, Any]:
        """Load YAML configuration."""
        try:
            with open(path) as f:
                config = yaml.safe_load(f)
            logger.info("config_loaded", path=path)
            return config
        except FileNotFoundError:
            logger.warning("config_not_found", path=path, fallback="using defaults")
            return {}

    def register_detector(self, detector: BaseDetector) -> None:
        """Register a detector module with the pipeline."""
        self._detectors[detector.name] = detector
        logger.info("detector_registered", name=detector.name)

    async def start_all(self) -> None:
        """Start all registered detectors."""
        logger.info("pipeline_starting", detector_count=len(self._detectors))
        for name, detector in self._detectors.items():
            try:
                await detector.start()
                logger.info("detector_started", name=name)
            except Exception as e:
                logger.error("detector_start_failed", name=name, error=str(e))

    async def stop_all(self) -> None:
        """Gracefully stop all detectors."""
        logger.info("pipeline_stopping")
        for name, detector in self._detectors.items():
            try:
                await detector.stop()
                logger.info("detector_stopped", name=name)
            except Exception as e:
                logger.error("detector_stop_failed", name=name, error=str(e))

    def get_detector(self, name: str) -> BaseDetector | None:
        """Get a specific detector by name."""
        return self._detectors.get(name)

    def get_all_status(self) -> list[dict]:
        """Return status of all detectors."""
        return [d.get_status().to_dict() for d in self._detectors.values()]
