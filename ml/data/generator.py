"""
Synthetic Network Flow Generator (Calibrated Behavioral Model)
=============================================================
Generates a reproducible, statistically grounded network-flow benchmark dataset
modeled after flow distributions observed in public network intrusion benchmarks
(e.g., CIC-IDS2017 / UNSW-NB15 flow telemetry characteristics).

Features realistic cross-class feature variance, borderline flows, and stochastic noise
to provide an academically defensible, non-trivial multi-class classification benchmark.
"""

from typing import Dict, Tuple
import numpy as np
import pandas as pd

TRAFFIC_CLASSES = [
    "BENIGN",
    "PORT_SCAN",
    "BRUTE_FORCE",
    "TRAFFIC_SPIKE",
    "SUSPICIOUS_TRANSFER",
]


def generate_synthetic_dataset(
    n_samples: int = 10000,
    random_seed: int = 42,
) -> pd.DataFrame:
    """
    Generate synthetic network flow samples with realistic statistical distributions
    and natural boundary overlap across classes.

    Parameters
    ----------
    n_samples : int
        Total number of flow records to generate.
    random_seed : int
        Seed for NumPy random generator for complete reproducibility.

    Returns
    -------
    pd.DataFrame
        DataFrame containing flow features and the target 'label' column.
    """
    rng = np.random.default_rng(seed=random_seed)

    # Class distribution targets (60% BENIGN, 10% each of 4 anomaly types)
    class_proportions: Dict[str, float] = {
        "BENIGN": 0.60,
        "PORT_SCAN": 0.10,
        "BRUTE_FORCE": 0.10,
        "TRAFFIC_SPIKE": 0.10,
        "SUSPICIOUS_TRANSFER": 0.10,
    }

    records = []

    for label, prop in class_proportions.items():
        count = int(n_samples * prop)

        if label == "BENIGN":
            # Normal HTTP/HTTPS, DNS, SSH, Database, Ephemeral traffic
            ports = rng.choice(
                [80, 443, 53, 22, 8080, 8443, 3306, 5432, 123, 8000],
                size=count,
                p=[0.38, 0.35, 0.08, 0.04, 0.04, 0.03, 0.03, 0.02, 0.01, 0.02],
            )
            # Duration: log-normal distribution with long-tailed connections (up to 90s)
            duration = rng.lognormal(mean=0.8, sigma=1.1, size=count).clip(0.01, 120.0)
            
            # Packet count: mixture of interactive (small) and transfer (large)
            is_large_transfer = rng.random(size=count) < 0.08
            base_packets = rng.integers(3, 140, size=count)
            large_packets = rng.integers(180, 2200, size=count)
            packet_count = np.where(is_large_transfer, large_packets, base_packets)
            
            avg_pkt_size = rng.normal(loc=680, scale=240, size=count).clip(54, 1500)
            byte_count = (packet_count * avg_pkt_size).astype(int)
            conn_rate = rng.gamma(shape=2.0, scale=1.8, size=count).clip(0.1, 32.0)

            # Realistic variance: multi-endpoint / CDN / DNS queries (up to 5 unique ports)
            unique_dst_ports = rng.choice([1, 2, 3, 4, 5], size=count, p=[0.92, 0.045, 0.02, 0.01, 0.005])

            # Realistic human typing errors: 96% zero, 3.2% 1 retry, 0.7% 2 retries, 0.1% 3 retries
            failed_auth_count = rng.choice([0, 1, 2, 3], size=count, p=[0.960, 0.032, 0.007, 0.001])

        elif label == "PORT_SCAN":
            # Fast sweeps (75%) and stealth scans (25%)
            is_stealth = rng.random(size=count) < 0.25
            ports = rng.integers(1, 65535, size=count)
            duration = np.where(
                is_stealth,
                rng.uniform(0.6, 5.0, size=count),
                rng.uniform(0.02, 1.8, size=count),
            )
            # Stealth scan probes 2-10 unique ports (overlaps with benign CDN/DNS on 2-4), fast sweeps probe 15-120
            stealth_ports = rng.integers(2, 11, size=count)
            fast_ports = rng.integers(15, 120, size=count)
            unique_dst_ports = np.where(is_stealth, stealth_ports, fast_ports)

            # In flow telemetry, total packets in a scan session equals sum of probe packets across ports (1-2 pkts/port)
            pkts_per_probe = rng.integers(1, 3, size=count)
            packet_count = (unique_dst_ports * pkts_per_probe).clip(1, 300)
            avg_pkt_size = rng.normal(loc=64, scale=18, size=count).clip(40, 180)
            byte_count = (packet_count * avg_pkt_size).astype(int)
            conn_rate = np.where(
                is_stealth,
                rng.uniform(2.5, 18.0, size=count),
                rng.uniform(32.0, 190.0, size=count),
            )
            failed_auth_count = rng.choice([0, 1], size=count, p=[0.97, 0.03])

        elif label == "BRUTE_FORCE":
            # Credential guessing bursts across auth ports
            ports = rng.choice([22, 3389, 8443, 8080, 21, 443], size=count, p=[0.42, 0.22, 0.16, 0.10, 0.05, 0.05])
            duration = rng.uniform(0.4, 8.0, size=count)
            packet_count = rng.integers(8, 110, size=count)
            avg_pkt_size = rng.normal(loc=320, scale=80, size=count).clip(100, 650)
            byte_count = (packet_count * avg_pkt_size).astype(int)
            conn_rate = rng.uniform(3.5, 45.0, size=count)
            unique_dst_ports = rng.choice([1, 2, 3], size=count, p=[0.88, 0.09, 0.03])

            # Brute force failure count: per-sample draws (low-volume 1-3 with high rate, high-volume 4-30)
            low_fails = rng.integers(1, 4, size=count)
            high_fails = rng.integers(4, 31, size=count)
            is_low_burst = rng.random(size=count) < 0.20
            failed_auth_count = np.where(is_low_burst, low_fails, high_fails)

        elif label == "TRAFFIC_SPIKE":
            # High-volume flooding / sudden load spike
            ports = rng.choice([80, 443, 53, 8080, 123], size=count, p=[0.36, 0.36, 0.14, 0.10, 0.04])
            duration = rng.uniform(0.8, 22.0, size=count)
            packet_count = rng.integers(350, 10500, size=count)
            avg_pkt_size = rng.normal(loc=840, scale=290, size=count).clip(280, 1500)
            byte_count = (packet_count * avg_pkt_size).astype(int)
            conn_rate = rng.uniform(18.0, 150.0, size=count)
            unique_dst_ports = rng.choice([1, 2, 3, 4], size=count, p=[0.72, 0.17, 0.08, 0.03])
            failed_auth_count = rng.choice([0, 1], size=count, p=[0.96, 0.04])

        elif label == "SUSPICIOUS_TRANSFER":
            # Prolonged high outbound data payload on sensitive ports (overlaps with large DB backup / TLS stream)
            ports = rng.choice([8443, 9000, 4444, 8000, 443, 9443], size=count, p=[0.30, 0.25, 0.20, 0.12, 0.08, 0.05])
            duration = rng.uniform(4.0, 280.0, size=count)
            packet_count = rng.integers(150, 3500, size=count)
            avg_pkt_size = rng.normal(loc=1280, scale=160, size=count).clip(750, 1500)
            byte_count = (packet_count * avg_pkt_size).astype(int)
            conn_rate = rng.uniform(0.3, 14.0, size=count)
            unique_dst_ports = rng.choice([1, 2, 3], size=count, p=[0.88, 0.09, 0.03])
            failed_auth_count = rng.choice([0, 1, 2], size=count, p=[0.85, 0.11, 0.04])

        else:
            raise ValueError(f"Unknown traffic class: {label}")

        # Derived rate features
        duration_safe = np.maximum(duration, 0.001)
        pkt_safe = np.maximum(packet_count, 1)
        bytes_per_sec = byte_count / duration_safe
        packets_per_sec = packet_count / duration_safe
        avg_packet_size = byte_count / pkt_safe

        df_class = pd.DataFrame(
            {
                "packet_count": packet_count,
                "byte_count": byte_count,
                "duration": np.round(duration, 4),
                "conn_rate": np.round(conn_rate, 2),
                "dst_port": ports,
                "unique_dst_ports": unique_dst_ports,
                "failed_auth_count": failed_auth_count,
                "bytes_per_sec": np.round(bytes_per_sec, 2),
                "packets_per_sec": np.round(packets_per_sec, 2),
                "avg_packet_size": np.round(avg_packet_size, 2),
                "label": label,
            }
        )
        records.append(df_class)

    # Concatenate and shuffle
    df = pd.concat(records, ignore_index=True)
    df = df.sample(frac=1.0, random_state=random_seed).reset_index(drop=True)
    return df


if __name__ == "__main__":
    data = generate_synthetic_dataset(n_samples=1000)
    print("Generated Calibrated Synthetic Dataset Sample:")
    print(data.head())
    print("\nClass distribution:")
    print(data["label"].value_counts())
