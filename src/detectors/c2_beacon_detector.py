"""
Command & Control (C2) Beacon Detector.

C2 beacons are the hardest thing to catch with basic anomaly detection because
each individual flow looks completely normal — small HTTPS request, standard
port, reasonable duration. Nothing unusual about a single beacon.

What gives C2 away is TIMING REGULARITY. Malware callbacks happen on a timer:
every 60 seconds, every 5 minutes, every hour. Even with jitter (randomized
delays), the underlying periodicity is detectable.

This detector uses two techniques:
1. Inter-arrival time analysis: Compute the standard deviation of time gaps
   between flows from the same source to the same destination. Low std dev
   relative to mean = suspicious regularity.
2. FFT-based periodicity detection: Apply a Fast Fourier Transform to the
   timing signal to find dominant frequencies. A strong peak at a single
   frequency means periodic behavior.

Normal traffic is bursty and irregular. Beacons are metronomic.
"""

from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd

import structlog

from src.core.base_detector import BaseDetector
from src.core.events import Event, EventBus, EventType, Severity

logger = structlog.get_logger()


class C2BeaconDetector(BaseDetector):
    """
    Detects C2 beacon patterns by analyzing timing regularity of flows.

    For each (src_ip, dst_ip) pair with enough flows, the detector:
    1. Computes inter-arrival times between consecutive flows
    2. Calculates the coefficient of variation (std/mean) — low CV = regular
    3. Runs FFT to detect dominant frequencies
    4. Checks for consistent payload sizes (beacons often send same data)
    5. Combines signals into a beacon confidence score
    """

    def __init__(self, config: dict[str, Any], event_bus: EventBus) -> None:
        super().__init__(name="c2_beacon_detector", config=config, event_bus=event_bus)

        beacon_config = config.get("c2_beacon_detector", {})

        # Minimum flows needed to detect periodicity
        self._min_flows = beacon_config.get("min_flows", 5)
        # Coefficient of variation threshold — below this is "too regular"
        self._cv_threshold = beacon_config.get("cv_threshold", 0.3)
        # FFT peak strength threshold
        self._fft_peak_threshold = beacon_config.get("fft_peak_threshold", 0.4)
        # Payload size consistency threshold (std/mean)
        self._payload_cv_threshold = beacon_config.get("payload_cv_threshold", 0.2)

    async def start(self) -> None:
        self._update_status(running=True)
        logger.info("c2_beacon_detector_started")

    async def stop(self) -> None:
        self._update_status(running=False)
        logger.info("c2_beacon_detector_stopped")

    async def analyze(self, data: Any) -> list[dict]:
        """
        Analyze flows for C2 beacon patterns.

        Groups flows by (src_ip, dst_ip) and checks timing regularity.
        """
        if isinstance(data, pd.DataFrame):
            df = data
        else:
            df = pd.read_csv(data)

        if df.empty or "src_ip" not in df.columns:
            return []

        # We need timestamps for timing analysis
        if "timestamp" not in df.columns:
            logger.warning("no_timestamps_for_beacon_detection")
            return []

        # Parse timestamps
        df = df.copy()
        df["_ts"] = pd.to_datetime(df["timestamp"], errors="coerce")
        df = df.dropna(subset=["_ts"])

        results = []
        anomaly_count = 0

        grouped = df.groupby(["src_ip", "dst_ip"])

        for (src_ip, dst_ip), group in grouped:
            if len(group) < self._min_flows:
                continue

            beacon_result = self._evaluate_pair(src_ip, dst_ip, group)
            if beacon_result is not None:
                anomaly_count += 1
                results.append(beacon_result)

                await self.event_bus.publish(Event(
                    event_type=EventType.ANOMALY_DETECTED,
                    source=self.name,
                    severity=beacon_result["severity_enum"],
                    data={
                        "detector": self.name,
                        "attack_type": "c2_beacon",
                        **beacon_result["details"],
                    },
                ))

        self._update_status(
            events_processed=self._status.events_processed + len(df),
            anomalies_detected=self._status.anomalies_detected + anomaly_count,
        )

        logger.info(
            "c2_beacon_analysis_complete",
            total_flows=len(df),
            pairs_analyzed=len(grouped),
            beacons_detected=anomaly_count,
        )

        return results

    def _evaluate_pair(
        self, src_ip: str, dst_ip: str, group: pd.DataFrame
    ) -> dict | None:
        """
        Evaluate a (src_ip, dst_ip) pair for beacon behavior.
        """
        # Sort by timestamp
        sorted_group = group.sort_values("_ts")
        timestamps = sorted_group["_ts"].values

        # Compute inter-arrival times in seconds
        iats = np.diff(timestamps.astype("int64")) / 1e9  # nanoseconds to seconds
        iats = iats[iats > 0]  # Drop zero/negative gaps

        if len(iats) < 3:
            return None

        # --- Signal 1: Timing regularity (coefficient of variation) ---
        iat_mean = np.mean(iats)
        iat_std = np.std(iats)
        cv = iat_std / iat_mean if iat_mean > 0 else float("inf")

        timing_score = max(0.0, 1.0 - (cv / self._cv_threshold)) if cv < self._cv_threshold else 0.0

        # --- Signal 2: FFT periodicity detection ---
        fft_score = self._fft_periodicity_score(iats)

        # --- Signal 3: Payload size consistency ---
        payload_score = 0.0
        if "bytes" in sorted_group.columns:
            byte_values = sorted_group["bytes"].values.astype(float)
            if np.mean(byte_values) > 0:
                payload_cv = np.std(byte_values) / np.mean(byte_values)
                if payload_cv < self._payload_cv_threshold:
                    payload_score = max(0.0, 1.0 - (payload_cv / self._payload_cv_threshold))

        # --- Signal 4: Consistent destination port ---
        port_consistency = 0.0
        if "dst_port" in sorted_group.columns:
            unique_ports = sorted_group["dst_port"].nunique()
            if unique_ports == 1:
                port_consistency = 1.0
            elif unique_ports <= 2:
                port_consistency = 0.5

        # --- Combined confidence ---
        confidence = (
            0.35 * timing_score
            + 0.30 * fft_score
            + 0.20 * payload_score
            + 0.15 * port_consistency
        )

        # Only flag if confidence is meaningful
        if confidence < 0.3:
            return None

        # Estimate the beacon interval
        beacon_interval = float(np.median(iats))

        # Severity based on confidence and how many beacons observed
        if confidence > 0.8 or len(iats) > 20:
            severity = Severity.HIGH
        elif confidence > 0.5:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        return {
            "is_anomaly": True,
            "attack_type": "c2_beacon",
            "confidence": round(confidence, 3),
            "severity": severity.value,
            "severity_enum": severity,
            "anomaly_score": -0.5 - (confidence * 0.5),
            "details": {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "flow_count": len(sorted_group),
                "beacon_interval_seconds": round(beacon_interval, 2),
                "timing_cv": round(cv, 4),
                "timing_score": round(timing_score, 3),
                "fft_score": round(fft_score, 3),
                "payload_consistency": round(payload_score, 3),
                "dst_port": int(sorted_group["dst_port"].mode().iloc[0]) if "dst_port" in sorted_group.columns else None,
            },
            "flow_indices": sorted_group.index.tolist(),
        }

    def _fft_periodicity_score(self, iats: np.ndarray) -> float:
        """
        Use Fast Fourier Transform to detect periodicity in inter-arrival times.

        Strong periodic signals produce a dominant peak in the frequency domain.
        We measure how much energy is concentrated in the top frequency vs
        the rest — a high ratio means strong periodicity.
        """
        if len(iats) < 4:
            return 0.0

        # Normalize the signal
        signal = iats - np.mean(iats)
        if np.std(signal) < 1e-10:
            # Near-zero variance = perfectly periodic
            return 1.0

        signal = signal / np.std(signal)

        # Compute FFT (skip DC component at index 0)
        fft_vals = np.abs(np.fft.rfft(signal))[1:]

        if len(fft_vals) == 0:
            return 0.0

        # Ratio of strongest frequency to total energy
        total_energy = np.sum(fft_vals)
        if total_energy < 1e-10:
            return 0.0

        peak_ratio = np.max(fft_vals) / total_energy

        # Normalize to 0-1 score
        score = min(1.0, peak_ratio / self._fft_peak_threshold)

        return round(score, 3)
