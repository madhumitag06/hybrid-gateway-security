"""
Feature Extractor and Input Validation
======================================
Defines network flow input schema and extracts structured numerical feature vectors
consistently for both model training and live inference.
"""

from typing import Dict, List, Optional, Union
import numpy as np
import pandas as pd
from pydantic import BaseModel, Field, field_validator

FEATURE_NAMES = [
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


class NetworkFlowInput(BaseModel):
    """
    Standard network flow schema for inference input.
    """

    packet_count: int = Field(..., ge=0, description="Total number of packets in the flow window")
    byte_count: int = Field(..., ge=0, description="Total payload bytes transferred in the flow")
    duration: float = Field(..., ge=0.0, description="Flow duration in seconds")
    conn_rate: float = Field(..., ge=0.0, description="Observed connection rate (connections per second)")
    dst_port: int = Field(..., ge=1, le=65535, description="Destination service port number")
    unique_dst_ports: int = Field(default=1, ge=1, description="Number of unique destination ports targeted")
    failed_auth_count: int = Field(default=0, ge=0, description="Number of observed failed authentication events")
    bytes_per_sec: Optional[float] = Field(default=None, ge=0.0, description="Throughput in bytes per second (auto-calculated if omitted)")
    packets_per_sec: Optional[float] = Field(default=None, ge=0.0, description="Packet rate in packets per second (auto-calculated if omitted)")
    avg_packet_size: Optional[float] = Field(default=None, ge=0.0, description="Average packet size (auto-calculated if omitted)")

    @field_validator("duration")
    @classmethod
    def validate_duration(cls, v: float) -> float:
        return float(v)


class FeatureExtractor:
    """
    Transforms structured flow records into standard numerical feature matrices.
    """

    @staticmethod
    def extract_from_flow(flow: NetworkFlowInput) -> np.ndarray:
        """
        Convert a single NetworkFlowInput into a 2D numpy array [1, n_features].
        """
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

        vector = [
            float(flow.packet_count),
            float(flow.byte_count),
            float(flow.duration),
            float(flow.conn_rate),
            float(flow.dst_port),
            float(flow.unique_dst_ports),
            float(flow.failed_auth_count),
            float(bytes_per_sec),
            float(packets_per_sec),
            float(avg_packet_size),
        ]
        return np.array([vector], dtype=np.float64)

    @staticmethod
    def extract_from_dict(d: Dict[str, Union[int, float]]) -> np.ndarray:
        """
        Validate dictionary via Pydantic model and extract feature vector.
        """
        flow = NetworkFlowInput(**d)
        return FeatureExtractor.extract_from_flow(flow)

    @staticmethod
    def extract_from_dataframe(df: pd.DataFrame) -> Tuple_Features:
        """
        Extract feature matrix X and optional target array y from a DataFrame.
        """
        for feature in FEATURE_NAMES:
            if feature not in df.columns:
                raise ValueError(f"Missing required feature column: {feature}")

        X = df[FEATURE_NAMES].to_numpy(dtype=np.float64)
        y = df["label"].to_numpy() if "label" in df.columns else None
        return X, y


Tuple_Features = tuple[np.ndarray, Optional[np.ndarray]]
