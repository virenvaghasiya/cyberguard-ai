"""
Network traffic feature extraction.

Transforms raw network flow records (from CSV, PCAP, or live capture)
into numerical feature vectors that the anomaly detection model can consume.

Each flow record becomes a row of features like packet rate, byte rate,
port entropy, protocol distribution, and timing characteristics. These
features are chosen because they're effective at distinguishing normal
traffic patterns from scanning, exfiltration, C2 beacons, and DDoS.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from scipy.stats import entropy

import structlog

logger = structlog.get_logger()

# The features we extract, in order. The model expects this exact ordering.
FEATURE_COLUMNS = [
    "flow_duration",
    "packet_count",
    "byte_count",
    "packets_per_second",
    "bytes_per_second",
    "src_port",
    "dst_port",
    "protocol_num",
    "src_port_entropy",
    "dst_port_entropy",
    "iat_mean",      # Inter-arrival time mean
    "iat_std",       # Inter-arrival time standard deviation
    "payload_ratio", # Ratio of payload bytes to total bytes
]


def extract_features_from_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    """
    Extract ML features from a DataFrame of network flow records.

    Expected input columns (flexible — we handle missing ones):
        - src_ip, dst_ip: Source and destination IP addresses
        - src_port, dst_port: Port numbers
        - protocol: Protocol number or name (TCP=6, UDP=17, ICMP=1)
        - timestamp: Flow start time
        - duration: Flow duration in seconds
        - packets: Packet count
        - bytes: Byte count

    Returns a DataFrame with one row per flow, columns = FEATURE_COLUMNS.
    """
    features = pd.DataFrame()

    # Duration — clamp to minimum 0.001s to avoid division by zero
    features["flow_duration"] = df.get("duration", pd.Series(0.0, index=df.index))
    features["flow_duration"] = features["flow_duration"].clip(lower=0.001)

    # Volume metrics
    features["packet_count"] = df.get("packets", pd.Series(0, index=df.index)).astype(float)
    features["byte_count"] = df.get("bytes", pd.Series(0, index=df.index)).astype(float)

    # Rate metrics — these are strong indicators of scanning and DDoS
    features["packets_per_second"] = features["packet_count"] / features["flow_duration"]
    features["bytes_per_second"] = features["byte_count"] / features["flow_duration"]

    # Port information (normalized to 0-1 range)
    features["src_port"] = df.get("src_port", pd.Series(0, index=df.index)).astype(float) / 65535
    features["dst_port"] = df.get("dst_port", pd.Series(0, index=df.index)).astype(float) / 65535

    # Protocol as numeric
    features["protocol_num"] = _normalize_protocol(df.get("protocol", pd.Series(6, index=df.index)))

    # Port entropy — measures how "spread out" the port usage is in the batch.
    # High entropy on destination ports = possible port scanning.
    features["src_port_entropy"] = _windowed_entropy(
        df.get("src_port", pd.Series(0, index=df.index))
    )
    features["dst_port_entropy"] = _windowed_entropy(
        df.get("dst_port", pd.Series(0, index=df.index))
    )

    # Inter-arrival time statistics (if timestamps are available)
    if "timestamp" in df.columns:
        iat = _compute_inter_arrival_times(df["timestamp"])
        features["iat_mean"] = iat["mean"]
        features["iat_std"] = iat["std"]
    else:
        features["iat_mean"] = 0.0
        features["iat_std"] = 0.0

    # Payload ratio — high ratio of payload to total can indicate data exfiltration
    if "payload_bytes" in df.columns:
        features["payload_ratio"] = (
            df["payload_bytes"].astype(float) / features["byte_count"].clip(lower=1)
        ).clip(0, 1)
    else:
        features["payload_ratio"] = 0.5  # Neutral default when not available

    # Fill any remaining NaN/inf values
    features = features.replace([np.inf, -np.inf], np.nan).fillna(0)

    logger.debug("features_extracted", shape=features.shape)
    return features[FEATURE_COLUMNS]


def _normalize_protocol(protocol_series: pd.Series) -> pd.Series:
    """Convert protocol names to numbers, then normalize."""
    protocol_map = {"tcp": 6, "udp": 17, "icmp": 1}

    def _to_num(val):
        if isinstance(val, (int, float)):
            return float(val)
        return float(protocol_map.get(str(val).lower(), 0))

    return protocol_series.apply(_to_num) / 255.0


def _windowed_entropy(port_series: pd.Series, window: int = 100) -> pd.Series:
    """
    Compute rolling entropy over port values.

    For each flow, we look at a window of recent port values and compute
    the Shannon entropy. This captures temporal patterns — a sudden shift
    to high-entropy port usage is suspicious.
    """
    result = pd.Series(0.0, index=port_series.index)

    for i in range(len(port_series)):
        start = max(0, i - window)
        window_data = port_series.iloc[start : i + 1]
        value_counts = window_data.value_counts(normalize=True)
        result.iloc[i] = entropy(value_counts) if len(value_counts) > 1 else 0.0

    return result


def _compute_inter_arrival_times(timestamps: pd.Series) -> pd.DataFrame:
    """Compute per-flow inter-arrival time statistics."""
    ts = pd.to_datetime(timestamps, errors="coerce")
    diffs = ts.diff().dt.total_seconds().fillna(0)

    return pd.DataFrame({
        "mean": diffs.rolling(window=50, min_periods=1).mean(),
        "std": diffs.rolling(window=50, min_periods=1).std().fillna(0),
    })
