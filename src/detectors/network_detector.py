"""
Network Traffic Anomaly Detector.

This is the first active detection module in CyberGuard AI. It analyzes
network flow records and flags anomalous patterns using an Isolation Forest
model. The detector works in two modes:

1. Batch mode: Analyze a CSV/PCAP file of historical traffic
2. Live mode: Continuously monitor a network interface (future)

The Isolation Forest is a good starting point because:
- It's unsupervised — you don't need labeled attack data to get started
- It handles high-dimensional data well
- It's fast enough for near-real-time use
- It naturally assigns anomaly scores, which map cleanly to alert severity
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

import structlog

from src.core.base_detector import BaseDetector
from src.core.events import Event, EventBus, EventType, Severity
from src.detectors.network_features import extract_features_from_dataframe

logger = structlog.get_logger()


class NetworkAnomalyDetector(BaseDetector):
    """
    Detects anomalous network traffic patterns using Isolation Forest.

    Workflow:
        1. Load or train the anomaly detection model
        2. Receive network flow data (from file or live capture)
        3. Extract features from raw flows
        4. Score each flow with the model
        5. Flag anomalies and publish events to the event bus
    """

    def __init__(self, config: dict[str, Any], event_bus: EventBus) -> None:
        super().__init__(name="network_anomaly_detector", config=config, event_bus=event_bus)

        detector_config = config.get("network_detector", {})
        model_config = detector_config.get("model", {})
        alert_config = detector_config.get("alerting", {})

        # Model parameters
        self._contamination = model_config.get("contamination", 0.05)
        self._n_estimators = model_config.get("n_estimators", 200)
        self._model_path = Path(model_config.get("model_path", "data/models/network_anomaly_model.joblib"))

        # Alert thresholds
        self._score_threshold = alert_config.get("score_threshold", -0.3)
        self._severity_mapping = alert_config.get("severity_mapping", {
            "high": -0.7,
            "medium": -0.5,
            "low": -0.3,
        })

        self._model: IsolationForest | None = None
        self._scaler: StandardScaler = StandardScaler()
        self._is_trained = False

    async def start(self) -> None:
        """Load an existing model or prepare for training."""
        if self._model_path.exists():
            self._load_model()
        else:
            logger.info("no_existing_model", path=str(self._model_path))
            self._model = IsolationForest(
                contamination=self._contamination,
                n_estimators=self._n_estimators,
                random_state=42,
                n_jobs=-1,
            )
        self._update_status(running=True)

    async def stop(self) -> None:
        """Save model state and shut down."""
        if self._is_trained:
            self._save_model()
        self._update_status(running=False)

    async def analyze(self, data: Any) -> list[dict]:
        """
        Analyze network flow data for anomalies.

        Args:
            data: Either a pd.DataFrame of flow records, or a path to a CSV file.

        Returns:
            List of detection results with anomaly scores and details.
        """
        # Accept either a DataFrame or a file path
        if isinstance(data, (str, Path)):
            df = pd.read_csv(data)
            logger.info("loaded_traffic_file", path=str(data), rows=len(df))
        elif isinstance(data, pd.DataFrame):
            df = data
        else:
            raise ValueError(f"Expected DataFrame or file path, got {type(data)}")

        if df.empty:
            return []

        # Extract features
        features = extract_features_from_dataframe(df)

        # Train if we haven't yet (first run with new data)
        if not self._is_trained:
            await self._train(features)

        # Scale features using the fitted scaler
        scaled = self._scaler.transform(features)

        # Get anomaly scores — negative scores are more anomalous
        scores = self._model.score_samples(scaled)
        predictions = self._model.predict(scaled)  # 1 = normal, -1 = anomaly

        # Build results
        results = []
        anomaly_count = 0

        for i in range(len(df)):
            is_anomaly = bool(predictions[i] == -1)
            score = float(scores[i])
            severity = self._score_to_severity(score)

            result = {
                "index": i,
                "anomaly_score": score,
                "is_anomaly": is_anomaly,
                "severity": severity.value if is_anomaly else None,
                "details": {
                    "src_ip": df.iloc[i].get("src_ip", "unknown"),
                    "dst_ip": df.iloc[i].get("dst_ip", "unknown"),
                    "src_port": int(df.iloc[i].get("src_port", 0)),
                    "dst_port": int(df.iloc[i].get("dst_port", 0)),
                    "protocol": str(df.iloc[i].get("protocol", "unknown")),
                    "packets": int(df.iloc[i].get("packets", 0)),
                    "bytes": int(df.iloc[i].get("bytes", 0)),
                },
            }
            results.append(result)

            # Publish event for anomalies
            if is_anomaly:
                anomaly_count += 1
                await self.event_bus.publish(Event(
                    event_type=EventType.ANOMALY_DETECTED,
                    source=self.name,
                    severity=severity,
                    data={
                        "detector": self.name,
                        "anomaly_score": score,
                        **result["details"],
                    },
                ))

        self._update_status(
            events_processed=self._status.events_processed + len(df),
            anomalies_detected=self._status.anomalies_detected + anomaly_count,
        )

        logger.info(
            "analysis_complete",
            total_flows=len(df),
            anomalies=anomaly_count,
            anomaly_rate=f"{anomaly_count / len(df) * 100:.1f}%",
        )

        return results

    async def _train(self, features: pd.DataFrame) -> None:
        """Train the model on a set of feature vectors."""
        logger.info("training_model", samples=len(features))

        # Fit scaler and transform
        scaled = self._scaler.fit_transform(features)

        # Train the Isolation Forest
        self._model.fit(scaled)
        self._is_trained = True

        logger.info("model_trained", samples=len(features))

        # Save the trained model
        self._save_model()

        await self.event_bus.publish(Event(
            event_type=EventType.MODEL_UPDATED,
            source=self.name,
            data={"samples": len(features), "model_type": "isolation_forest"},
        ))

    def _score_to_severity(self, score: float) -> Severity:
        """Map anomaly score to alert severity."""
        if score <= self._severity_mapping.get("high", -0.7):
            return Severity.HIGH
        elif score <= self._severity_mapping.get("medium", -0.5):
            return Severity.MEDIUM
        else:
            return Severity.LOW

    def _save_model(self) -> None:
        """Persist model and scaler to disk."""
        self._model_path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(
            {"model": self._model, "scaler": self._scaler},
            self._model_path,
        )
        logger.info("model_saved", path=str(self._model_path))

    def _load_model(self) -> None:
        """Load a previously trained model."""
        data = joblib.load(self._model_path)
        self._model = data["model"]
        self._scaler = data["scaler"]
        self._is_trained = True
        logger.info("model_loaded", path=str(self._model_path))
