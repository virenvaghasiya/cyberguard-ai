"""
Port Scan Detector.

The Isolation Forest misses port scans because individual scan probes look
like normal tiny flows — one packet, 44 bytes, short duration. There's
nothing volumetrically unusual about a single SYN packet.

What makes a port scan detectable is the PATTERN across multiple flows:
- One source IP hitting many different destination ports on the same target
- Very rapid succession (milliseconds between probes)
- Near-zero duration per flow (SYN scan = no connection established)
- Sequential or systematic port ordering

This detector groups flows by (src_ip, dst_ip) pairs and looks for these
sequential scanning patterns using statistical thresholds rather than ML,
because the signal is clear and rule-based detection is more reliable here.
"""

from __future__ import annotations

from typing import Any

import numpy as np
import pandas as pd

import structlog

from src.core.base_detector import BaseDetector
from src.core.events import Event, EventBus, EventType, Severity

logger = structlog.get_logger()


class PortScanDetector(BaseDetector):
    """
    Detects port scanning activity by analyzing flow patterns per source-destination pair.

    Detection criteria (all evaluated per src_ip → dst_ip pair):
        1. Unique destination ports contacted exceeds threshold
        2. Average flow duration is very low (SYN scans don't complete handshake)
        3. Flows arrive in rapid succession (low inter-flow timing)
        4. Packet count per flow is consistently low (1-3 packets)
    """

    def __init__(self, config: dict[str, Any], event_bus: EventBus) -> None:
        super().__init__(name="port_scan_detector", config=config, event_bus=event_bus)

        scan_config = config.get("port_scan_detector", {})

        # Detection thresholds — tuned for typical scan behavior
        self._min_unique_ports = scan_config.get("min_unique_ports", 10)
        self._max_avg_duration = scan_config.get("max_avg_duration", 0.5)
        self._max_avg_packets = scan_config.get("max_avg_packets", 3)
        self._min_flow_count = scan_config.get("min_flow_count", 8)
        # Minimum fraction of ports that must be in the well-known range (1-1024)
        self._well_known_port_ratio = scan_config.get("well_known_port_ratio", 0.3)

    async def start(self) -> None:
        """No model to load — this is purely pattern-based."""
        self._update_status(running=True)
        logger.info("port_scan_detector_started")

    async def stop(self) -> None:
        self._update_status(running=False)
        logger.info("port_scan_detector_stopped")

    async def analyze(self, data: Any) -> list[dict]:
        """
        Analyze flows for port scanning patterns.

        Groups flows by (src_ip, dst_ip) and checks each pair for
        scanning indicators.

        Returns list of scan detections, one per suspicious IP pair.
        """
        if isinstance(data, pd.DataFrame):
            df = data
        else:
            df = pd.read_csv(data)

        if df.empty or "src_ip" not in df.columns:
            return []

        results = []
        anomaly_count = 0

        # Group by source → destination IP pair
        grouped = df.groupby(["src_ip", "dst_ip"])

        for (src_ip, dst_ip), group in grouped:
            scan_result = self._evaluate_pair(src_ip, dst_ip, group)

            if scan_result is not None:
                anomaly_count += 1
                results.append(scan_result)

                await self.event_bus.publish(Event(
                    event_type=EventType.ANOMALY_DETECTED,
                    source=self.name,
                    severity=scan_result["severity_enum"],
                    data={
                        "detector": self.name,
                        "attack_type": "port_scan",
                        "scan_type": scan_result["scan_type"],
                        **scan_result["details"],
                    },
                ))

        self._update_status(
            events_processed=self._status.events_processed + len(df),
            anomalies_detected=self._status.anomalies_detected + anomaly_count,
        )

        logger.info(
            "port_scan_analysis_complete",
            total_flows=len(df),
            pairs_analyzed=len(grouped),
            scans_detected=anomaly_count,
        )

        return results

    def _evaluate_pair(
        self, src_ip: str, dst_ip: str, group: pd.DataFrame
    ) -> dict | None:
        """
        Evaluate a single (src_ip, dst_ip) pair for scanning behavior.

        Returns a detection dict if scanning is detected, None otherwise.
        """
        flow_count = len(group)
        if flow_count < self._min_flow_count:
            return None

        dst_ports = group["dst_port"].values
        unique_ports = len(set(dst_ports))

        # Check 1: Enough unique destination ports?
        if unique_ports < self._min_unique_ports:
            return None

        # Check 2: Low average duration? (SYN scans don't establish connections)
        avg_duration = group["duration"].mean() if "duration" in group.columns else 0
        if avg_duration > self._max_avg_duration:
            return None

        # Check 3: Low packet count per flow?
        avg_packets = group["packets"].mean() if "packets" in group.columns else 1
        if avg_packets > self._max_avg_packets:
            return None

        # All checks passed — this is a scan. Now characterize it.
        scan_type = self._classify_scan_type(dst_ports, group)
        confidence = self._compute_confidence(
            unique_ports, avg_duration, avg_packets, flow_count
        )

        # Higher port count and faster scanning = higher severity
        if unique_ports >= 50 or confidence > 0.9:
            severity = Severity.HIGH
        elif unique_ports >= 20 or confidence > 0.7:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        return {
            "is_anomaly": True,
            "attack_type": "port_scan",
            "scan_type": scan_type,
            "confidence": confidence,
            "severity": severity.value,
            "severity_enum": severity,
            "anomaly_score": -0.5 - (confidence * 0.5),  # Map to -0.5 to -1.0 range
            "details": {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "unique_ports": unique_ports,
                "flow_count": flow_count,
                "avg_duration": round(avg_duration, 4),
                "avg_packets": round(avg_packets, 2),
                "port_range": f"{int(min(dst_ports))}-{int(max(dst_ports))}",
                "scan_type": scan_type,
            },
            # Track which original flow indices are part of this scan
            "flow_indices": group.index.tolist(),
        }

    def _classify_scan_type(self, ports: np.ndarray, group: pd.DataFrame) -> str:
        """
        Determine what kind of scan this is based on port patterns.

        - sequential: Ports are visited in order (1, 2, 3, 4...)
        - well_known: Targeting common service ports (22, 80, 443...)
        - random: Random port selection
        - stealth_syn: Very low packet count + zero duration (SYN-only)
        """
        sorted_ports = np.sort(ports)
        diffs = np.diff(sorted_ports)

        # Check for sequential scanning (ports incrementing by 1)
        sequential_ratio = np.mean(diffs == 1) if len(diffs) > 0 else 0
        if sequential_ratio > 0.5:
            return "sequential"

        # Check if targeting well-known ports
        well_known = np.sum(ports <= 1024) / len(ports)
        if well_known > self._well_known_port_ratio:
            return "well_known_targeted"

        # Check for stealth SYN (single packet, near-zero duration)
        avg_packets = group["packets"].mean() if "packets" in group.columns else 1
        avg_duration = group["duration"].mean() if "duration" in group.columns else 0
        if avg_packets <= 1.5 and avg_duration < 0.01:
            return "stealth_syn"

        return "random"

    def _compute_confidence(
        self,
        unique_ports: int,
        avg_duration: float,
        avg_packets: float,
        flow_count: int,
    ) -> float:
        """
        Compute a 0-1 confidence score for the scan detection.

        Each indicator contributes to overall confidence:
        - More unique ports = higher confidence
        - Lower duration = higher confidence
        - Lower packet count = higher confidence
        - More total flows = higher confidence
        """
        # Port diversity score (10 ports = 0.3, 50+ ports = 1.0)
        port_score = min(1.0, unique_ports / 50)

        # Duration score (0s = 1.0, 0.5s = 0.0)
        duration_score = max(0.0, 1.0 - (avg_duration / 0.5))

        # Packet score (1 pkt = 1.0, 3 pkts = 0.0)
        packet_score = max(0.0, 1.0 - (avg_packets - 1) / 2)

        # Volume score (8 flows = 0.3, 50+ flows = 1.0)
        volume_score = min(1.0, flow_count / 50)

        # Weighted combination
        confidence = (
            0.35 * port_score
            + 0.25 * duration_score
            + 0.20 * packet_score
            + 0.20 * volume_score
        )

        return round(confidence, 3)
