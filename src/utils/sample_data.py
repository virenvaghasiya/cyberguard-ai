"""
Synthetic network traffic generator for testing and demos.

Generates realistic-looking network flow records with injected anomalies.
This gives you something to test against without needing real traffic captures.

The generator creates a mix of:
- Normal web browsing traffic (HTTP/HTTPS)
- DNS queries
- Internal service communication
- Injected anomalies: port scans, data exfiltration, C2 beacons, DDoS
"""

from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

import numpy as np
import pandas as pd

import structlog

logger = structlog.get_logger()


def generate_sample_traffic(
    n_normal: int = 5000,
    n_anomalous: int = 250,
    seed: int = 42,
) -> pd.DataFrame:
    """
    Generate synthetic network traffic with labeled anomalies.

    Args:
        n_normal: Number of normal flow records to generate.
        n_anomalous: Number of anomalous flow records to inject.
        seed: Random seed for reproducibility.

    Returns:
        DataFrame with columns: src_ip, dst_ip, src_port, dst_port,
        protocol, timestamp, duration, packets, bytes, label
    """
    rng = np.random.default_rng(seed)
    random.seed(seed)

    normal_flows = _generate_normal_traffic(n_normal, rng)
    anomalous_flows = _generate_anomalous_traffic(n_anomalous, rng)

    # Combine and shuffle
    df = pd.concat([normal_flows, anomalous_flows], ignore_index=True)
    df = df.sample(frac=1, random_state=seed).reset_index(drop=True)

    logger.info(
        "sample_traffic_generated",
        normal=n_normal,
        anomalous=n_anomalous,
        total=len(df),
    )

    return df


def _generate_normal_traffic(n: int, rng: np.random.Generator) -> pd.DataFrame:
    """Generate realistic normal traffic flows."""
    records = []
    base_time = datetime.now(timezone.utc) - timedelta(hours=1)

    # Internal network ranges
    internal_ips = [f"192.168.1.{i}" for i in range(1, 255)]
    dns_servers = ["8.8.8.8", "8.8.4.4", "1.1.1.1"]
    web_servers = [f"203.0.113.{i}" for i in range(1, 50)]

    for i in range(n):
        timestamp = base_time + timedelta(seconds=i * rng.exponential(0.5))
        traffic_type = rng.choice(["web", "dns", "internal"], p=[0.6, 0.15, 0.25])

        if traffic_type == "web":
            records.append({
                "src_ip": rng.choice(internal_ips),
                "dst_ip": rng.choice(web_servers),
                "src_port": int(rng.integers(49152, 65535)),
                "dst_port": rng.choice([80, 443, 443, 443, 8080]),  # HTTPS-heavy
                "protocol": 6,  # TCP
                "timestamp": timestamp.isoformat(),
                "duration": float(rng.exponential(2.0)),
                "packets": int(rng.integers(5, 200)),
                "bytes": int(rng.integers(500, 50000)),
                "label": "normal",
            })
        elif traffic_type == "dns":
            records.append({
                "src_ip": rng.choice(internal_ips),
                "dst_ip": rng.choice(dns_servers),
                "src_port": int(rng.integers(49152, 65535)),
                "dst_port": 53,
                "protocol": 17,  # UDP
                "timestamp": timestamp.isoformat(),
                "duration": float(rng.exponential(0.1)),
                "packets": int(rng.integers(1, 4)),
                "bytes": int(rng.integers(60, 512)),
                "label": "normal",
            })
        else:  # internal
            records.append({
                "src_ip": rng.choice(internal_ips),
                "dst_ip": rng.choice(internal_ips),
                "src_port": int(rng.integers(1024, 65535)),
                "dst_port": rng.choice([22, 3306, 5432, 6379, 8080, 8443]),
                "protocol": 6,
                "timestamp": timestamp.isoformat(),
                "duration": float(rng.exponential(5.0)),
                "packets": int(rng.integers(10, 500)),
                "bytes": int(rng.integers(1000, 100000)),
                "label": "normal",
            })

    return pd.DataFrame(records)


def _generate_anomalous_traffic(n: int, rng: np.random.Generator) -> pd.DataFrame:
    """
    Generate anomalous traffic flows across four attack categories.
    """
    records = []
    base_time = datetime.now(timezone.utc) - timedelta(hours=1)

    attack_types = ["port_scan", "exfiltration", "c2_beacon", "ddos"]
    per_type = n // len(attack_types)

    internal_ips = [f"192.168.1.{i}" for i in range(1, 255)]

    # --- Port Scan: One source hitting many ports on one target ---
    scanner_ip = rng.choice(internal_ips)
    target_ip = f"10.0.0.{rng.integers(1, 255)}"
    for i in range(per_type):
        records.append({
            "src_ip": scanner_ip,
            "dst_ip": target_ip,
            "src_port": int(rng.integers(49152, 65535)),
            "dst_port": int(rng.integers(1, 1024)),  # Scanning well-known ports
            "protocol": 6,
            "timestamp": (base_time + timedelta(seconds=i * 0.01)).isoformat(),  # Very fast
            "duration": 0.001,  # Near-zero duration = SYN scan
            "packets": 1,
            "bytes": 44,  # Single SYN packet
            "label": "port_scan",
        })

    # --- Data Exfiltration: Large outbound transfers to unusual IPs ---
    compromised_ip = rng.choice(internal_ips)
    for i in range(per_type):
        records.append({
            "src_ip": compromised_ip,
            "dst_ip": f"198.51.100.{rng.integers(1, 255)}",  # External IP
            "src_port": int(rng.integers(49152, 65535)),
            "dst_port": rng.choice([443, 8443, 4443]),  # Encrypted channels
            "protocol": 6,
            "timestamp": (base_time + timedelta(minutes=i * 2)).isoformat(),
            "duration": float(rng.uniform(30, 300)),  # Long sessions
            "packets": int(rng.integers(1000, 10000)),  # Heavy traffic
            "bytes": int(rng.integers(1_000_000, 50_000_000)),  # Large transfers
            "label": "exfiltration",
        })

    # --- C2 Beacon: Regular periodic callbacks to external server ---
    beacon_ip = rng.choice(internal_ips)
    c2_server = f"198.51.100.{rng.integers(1, 255)}"
    for i in range(per_type):
        records.append({
            "src_ip": beacon_ip,
            "dst_ip": c2_server,
            "src_port": int(rng.integers(49152, 65535)),
            "dst_port": 443,
            "protocol": 6,
            "timestamp": (base_time + timedelta(seconds=i * 60)).isoformat(),  # Exactly 60s apart
            "duration": float(rng.uniform(0.5, 2.0)),
            "packets": int(rng.integers(3, 10)),
            "bytes": int(rng.integers(200, 800)),  # Small, consistent payloads
            "label": "c2_beacon",
        })

    # --- DDoS: Massive packet floods from many sources to one target ---
    ddos_target = rng.choice(internal_ips)
    for i in range(per_type):
        records.append({
            "src_ip": f"{rng.integers(1,255)}.{rng.integers(0,255)}.{rng.integers(0,255)}.{rng.integers(1,255)}",
            "dst_ip": ddos_target,
            "src_port": int(rng.integers(1, 65535)),
            "dst_port": 80,
            "protocol": rng.choice([6, 17]),
            "timestamp": (base_time + timedelta(seconds=i * 0.001)).isoformat(),
            "duration": 0.001,
            "packets": int(rng.integers(100, 5000)),  # Huge packet counts
            "bytes": int(rng.integers(50000, 500000)),
            "label": "ddos",
        })

    return pd.DataFrame(records)
