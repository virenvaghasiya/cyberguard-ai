"""Tests for network traffic feature extraction."""

import numpy as np
import pandas as pd
import pytest

from src.detectors.network_features import (
    FEATURE_COLUMNS,
    extract_features_from_dataframe,
)


@pytest.fixture
def sample_flows():
    """Create a small DataFrame of synthetic flow records."""
    return pd.DataFrame({
        "src_ip": ["192.168.1.10", "192.168.1.20", "10.0.0.5"],
        "dst_ip": ["8.8.8.8", "203.0.113.50", "192.168.1.10"],
        "src_port": [52000, 53000, 54000],
        "dst_port": [443, 80, 22],
        "protocol": [6, 6, 17],
        "timestamp": [
            "2025-01-01T00:00:00",
            "2025-01-01T00:00:01",
            "2025-01-01T00:00:02",
        ],
        "duration": [1.5, 0.3, 5.0],
        "packets": [50, 10, 200],
        "bytes": [25000, 1500, 150000],
    })


def test_feature_shape(sample_flows):
    """Output should have one row per flow and the expected columns."""
    features = extract_features_from_dataframe(sample_flows)
    assert features.shape[0] == len(sample_flows)
    assert list(features.columns) == FEATURE_COLUMNS


def test_no_nans(sample_flows):
    """Features should never contain NaN values."""
    features = extract_features_from_dataframe(sample_flows)
    assert not features.isna().any().any(), "Features contain NaN values"


def test_no_infinities(sample_flows):
    """Features should never contain infinite values."""
    features = extract_features_from_dataframe(sample_flows)
    assert not np.isinf(features.values).any(), "Features contain infinite values"


def test_rate_computation(sample_flows):
    """Packets-per-second and bytes-per-second should be calculated correctly."""
    features = extract_features_from_dataframe(sample_flows)

    # First flow: 50 packets / 1.5 seconds = 33.33 pps
    assert abs(features.iloc[0]["packets_per_second"] - (50 / 1.5)) < 0.01


def test_zero_duration_handling():
    """Zero-duration flows should not cause division errors."""
    df = pd.DataFrame({
        "src_ip": ["192.168.1.1"],
        "dst_ip": ["10.0.0.1"],
        "src_port": [50000],
        "dst_port": [80],
        "protocol": [6],
        "duration": [0.0],  # Zero duration
        "packets": [100],
        "bytes": [5000],
    })
    features = extract_features_from_dataframe(df)
    assert not np.isinf(features.values).any()
    assert not features.isna().any().any()


def test_protocol_normalization():
    """Protocol names should be converted to normalized numbers."""
    df = pd.DataFrame({
        "src_ip": ["1.1.1.1", "2.2.2.2"],
        "dst_ip": ["3.3.3.3", "4.4.4.4"],
        "src_port": [50000, 50001],
        "dst_port": [80, 53],
        "protocol": ["tcp", "udp"],
        "duration": [1.0, 1.0],
        "packets": [10, 5],
        "bytes": [1000, 500],
    })
    features = extract_features_from_dataframe(df)
    # TCP=6/255, UDP=17/255
    assert abs(features.iloc[0]["protocol_num"] - 6 / 255) < 0.001
    assert abs(features.iloc[1]["protocol_num"] - 17 / 255) < 0.001


def test_empty_dataframe():
    """Empty input should return empty output with correct columns."""
    df = pd.DataFrame(columns=["src_ip", "dst_ip", "src_port", "dst_port", "protocol"])
    features = extract_features_from_dataframe(df)
    assert len(features) == 0
    assert list(features.columns) == FEATURE_COLUMNS
