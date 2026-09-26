"""
Synthetic Network Flow Generator
================================
Generates a reproducible synthetic network-flow dataset designed to represent controlled
normal and anomalous patterns for an academic security gateway prototype.

Note:
This dataset is a synthetic simulation for prototype testing and development.
It does not represent real-world attack distributions.
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
    Generate synthetic network flow samples with realistic statistical distributions.

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

    # Class distribution targets (approximate: 60% BENIGN, 10% each of 4 anomaly types)
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
            # Normal HTTP/HTTPS, DNS, SSH traffic
            ports = rng.choice([80, 443, 53, 22, 8080], size=count, p=[0.45, 0.40, 0.08, 0.04, 0.03])
            duration = rng.exponential(scale=2.5, size=count) + 0.05
            packet_count = rng.integers(5, 80, size=count)
            avg_pkt_size = rng.normal(loc=650, scale=180, size=count).clip(64, 1500)
            byte_count = (packet_count * avg_pkt_size).astype(int)
            conn_rate = rng.gamma(shape=2.0, scale=1.5, size=count).clip(0.1, 15.0)
            unique_dst_ports = np.ones(count, dtype=int)
            failed_auth_count = np.zeros(count, dtype=int)

        elif label == "PORT_SCAN":
            # Fast probing across many unique destination ports, small packet footprints
            ports = rng.integers(1, 65535, size=count)
            duration = rng.uniform(0.01, 0.4, size=count)
            packet_count = rng.integers(1, 4, size=count)
            byte_count = packet_count * rng.integers(40, 90, size=count)
            conn_rate = rng.uniform(40.0, 200.0, size=count)
            unique_dst_ports = rng.integers(15, 120, size=count)
            failed_auth_count = np.zeros(count, dtype=int)

        elif label == "BRUTE_FORCE":
            # Rapid authentication attempts with repeated failure signatures
            ports = rng.choice([22, 8443, 3389, 21, 8080], size=count, p=[0.50, 0.20, 0.15, 0.10, 0.05])
            duration = rng.uniform(0.2, 5.0, size=count)
            packet_count = rng.integers(10, 60, size=count)
            byte_count = packet_count * rng.integers(150, 450, size=count)
            conn_rate = rng.uniform(8.0, 45.0, size=count)
            unique_dst_ports = rng.integers(1, 3, size=count)
            failed_auth_count = rng.integers(3, 25, size=count)

        elif label == "TRAFFIC_SPIKE":
            # High-volume flooding / bandwidth saturation patterns
            ports = rng.choice([80, 443, 53, 8080], size=count, p=[0.40, 0.40, 0.15, 0.05])
            duration = rng.uniform(1.0, 15.0, size=count)
            packet_count = rng.integers(800, 10000, size=count)
            avg_pkt_size = rng.uniform(500, 1450, size=count)
            byte_count = (packet_count * avg_pkt_size).astype(int)
            conn_rate = rng.uniform(25.0, 120.0, size=count)
            unique_dst_ports = rng.integers(1, 4, size=count)
            failed_auth_count = np.zeros(count, dtype=int)

        elif label == "SUSPICIOUS_TRANSFER":
            # Unusual high outbound data payload on non-standard/admin ports
            ports = rng.choice([8443, 9000, 4444, 443, 8000], size=count, p=[0.35, 0.25, 0.20, 0.10, 0.10])
            duration = rng.uniform(10.0, 240.0, size=count)
            packet_count = rng.integers(200, 2500, size=count)
            avg_pkt_size = rng.uniform(1200, 1500, size=count)  # High payload ratio
            byte_count = (packet_count * avg_pkt_size).astype(int)
            conn_rate = rng.uniform(0.5, 8.0, size=count)
            unique_dst_ports = np.ones(count, dtype=int)
            failed_auth_count = rng.choice([0, 1, 2], size=count, p=[0.85, 0.10, 0.05])

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
    print("Generated Synthetic Dataset Sample:")
    print(data.head())
    print("\nClass distribution:")
    print(data["label"].value_counts())
