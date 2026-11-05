"""
Feature Extractor and Input Validation
======================================
Defines network flow input schema and extracts structured numerical feature vectors
consistently for both model training and live inference.
"""

from typing import Any, Dict, List, Optional, Tuple, Union
import numpy as np
import pandas as pd
from pydantic import BaseModel, Field, field_validator

FEATURE_NAMES_V1 = [
    "packet_count",
    "byte_count",
    "duration",
    "conn_rate",
    "dst_port",
    "unique_dst_ports",
    "failed_auth_count",
    "bytes_per_sec",
    "packets_per_sec",
    "avg_packet_size",
]

# Production-grade V2 Feature Schema (9 features)
# failed_auth_count removed due to lack of genuine L3/L4 network observability
FEATURE_NAMES_V2 = [
    "packet_count",
    "byte_count",
    "duration",
    "conn_rate",
    "dst_port",
    "unique_dst_ports",
    "bytes_per_sec",
    "packets_per_sec",
    "avg_packet_size",
]

# Default alias for legacy/baseline compatibility
FEATURE_NAMES = FEATURE_NAMES_V1

Tuple_Features = Tuple[np.ndarray, Optional[np.ndarray]]


def calculate_conn_rate(
    packet_count: float,
    duration: float,
    host_connection_count: Optional[int] = None,
    window_seconds: Optional[float] = None,
) -> float:
    """
    Calculate mathematically defensible connection rate (connections/second).
    
    Shared calculation for both model training and live gateway inference:
    1. If stateful host connection history is available over a rolling window:
       conn_rate = host_connection_count / max(window_seconds, 0.1)
    2. For standalone single-flow records without prior host history:
       conn_rate = packet_count / max(duration, 0.01)
       
    Bounded cleanly within [0.1, 500.0] conns/sec to prevent division-by-zero artifacts.
    """
    if host_connection_count is not None and window_seconds is not None:
        span = max(float(window_seconds), 0.1)
        raw_rate = float(host_connection_count) / span
    else:
        dur_safe = max(float(duration), 0.01)
        raw_rate = float(packet_count) / dur_safe

    return float(np.clip(raw_rate, 0.1, 500.0))


class NetworkFlowInput(BaseModel):
    """
    Standard network flow schema for inference input.
    """

    packet_count: int = Field(default=1, ge=0, description="Total number of packets in the flow window")
    byte_count: int = Field(default=64, ge=0, description="Total payload bytes transferred in the flow")
    duration: float = Field(default=0.001, ge=0.0, description="Flow duration in seconds")
    conn_rate: float = Field(default=1.0, ge=0.0, description="Observed connection rate (connections per second)")
    dst_port: int = Field(default=80, ge=1, le=65535, description="Destination service port number")
    unique_dst_ports: int = Field(default=1, ge=1, description="Number of unique destination ports targeted")
    failed_auth_count: int = Field(default=0, ge=0, description="Number of observed failed authentication events")
    bytes_per_sec: Optional[float] = Field(default=None, ge=0.0, description="Throughput in bytes per second (auto-calculated if omitted)")
    packets_per_sec: Optional[float] = Field(default=None, ge=0.0, description="Packet rate in packets per second (auto-calculated if omitted)")
    avg_packet_size: Optional[float] = Field(default=None, ge=0.0, description="Average packet size (auto-calculated if omitted)")

    @field_validator("duration", "conn_rate", "bytes_per_sec", "packets_per_sec", "avg_packet_size")
    @classmethod
    def validate_finite_floats(cls, v: Optional[float]) -> Optional[float]:
        if v is None:
            return None
        if np.isnan(v) or np.isinf(v):
            raise ValueError("Float value must be finite and cannot be NaN or Inf.")
        return v


class FeatureExtractor:
    """
    Transforms structured flow records into standard numerical feature matrices.
    """

    @staticmethod
    def extract_from_flow(
        flow: NetworkFlowInput, schema: Optional[List[str]] = None
    ) -> np.ndarray:
        """
        Convert a single NetworkFlowInput into a 2D numpy array [1, n_features]
        according to the specified feature schema (defaults to FEATURE_NAMES_V1).
        """
        target_schema = schema if schema is not None else FEATURE_NAMES_V1
        duration_safe = max(flow.duration, 0.001)
        pkt_safe = max(flow.packet_count, 1)

        bytes_per_sec = (
            flow.bytes_per_sec
            if flow.bytes_per_sec is not None
            else flow.byte_count / duration_safe
        )
        packets_per_sec = (
            flow.packets_per_sec
            if flow.packets_per_sec is not None
            else flow.packet_count / duration_safe
        )
        avg_packet_size = (
            flow.avg_packet_size
            if flow.avg_packet_size is not None
            else flow.byte_count / pkt_safe
        )

        feature_map = {
            "packet_count": float(flow.packet_count),
            "byte_count": float(flow.byte_count),
            "duration": float(flow.duration),
            "conn_rate": float(flow.conn_rate),
            "dst_port": float(flow.dst_port),
            "unique_dst_ports": float(max(flow.unique_dst_ports, 1)),
            "failed_auth_count": float(max(flow.failed_auth_count, 0)),
            "bytes_per_sec": float(bytes_per_sec),
            "packets_per_sec": float(packets_per_sec),
            "avg_packet_size": float(avg_packet_size),
        }

        vector = [feature_map[name] for name in target_schema]
        return np.nan_to_num(np.array([vector], dtype=np.float64), nan=0.0, posinf=1e9, neginf=0.0)

    @staticmethod
    def extract_v2_from_flow(flow: NetworkFlowInput) -> np.ndarray:
        """Convenience method for extracting production-grade V2 9-feature vectors."""
        return FeatureExtractor.extract_from_flow(flow, schema=FEATURE_NAMES_V2)

    @staticmethod
    def extract_from_dict(d: Dict[str, Union[int, float]], schema: Optional[List[str]] = None) -> np.ndarray:
        """
        Validate dictionary via Pydantic model and extract feature vector.
        """
        flow = NetworkFlowInput(**d)
        return FeatureExtractor.extract_from_flow(flow, schema=schema)

    @staticmethod
    def extract_from_dataframe(df: pd.DataFrame, schema: Optional[List[str]] = None) -> Tuple_Features:
        """
        Extract feature matrix X and optional target array y from a DataFrame.
        """
        target_schema = schema if schema is not None else FEATURE_NAMES_V1
        for feature in target_schema:
            if feature not in df.columns:
                raise ValueError(f"Missing required feature column: {feature}")

        X = df[target_schema].to_numpy(dtype=np.float64)
        y = df["label"].to_numpy() if "label" in df.columns else None
        return X, y

