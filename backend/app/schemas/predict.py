"""
Prediction API Schemas
======================
Pydantic models for single and batch network flow inference requests and responses.
"""

from typing import Dict, List, Literal, Optional
from pydantic import BaseModel, Field

SeverityLevel = Literal["LOW", "MEDIUM", "HIGH"]
PolicyAction = Literal["Allow", "Monitor", "Restrict", "Block"]


class NetworkFlowRequest(BaseModel):
    """
    Input schema for network flow prediction requests.
    """

    packet_count: int = Field(..., ge=0, description="Total packet count in the flow window")
    byte_count: int = Field(..., ge=0, description="Total bytes transferred")
    duration: float = Field(..., ge=0.0, description="Duration in seconds")
    conn_rate: float = Field(..., ge=0.0, description="Connection rate (connections/second)")
    dst_port: int = Field(..., ge=1, le=65535, description="Destination service port")
    unique_dst_ports: int = Field(default=1, ge=1, description="Count of unique destination ports targeted")
    failed_auth_count: int = Field(default=0, ge=0, description="Count of failed authentication attempts")
    bytes_per_sec: Optional[float] = Field(default=None, ge=0.0, description="Throughput (bytes/sec)")
    packets_per_sec: Optional[float] = Field(default=None, ge=0.0, description="Packet rate (packets/sec)")
    avg_packet_size: Optional[float] = Field(default=None, ge=0.0, description="Average packet size (bytes)")
    source_ip: Optional[str] = Field(default="192.168.1.100", description="Source IP address")
    destination_ip: Optional[str] = Field(default="10.100.1.10", description="Destination IP address")
    persist: Optional[bool] = Field(default=True, description="Whether to persist this prediction into PostgreSQL")


class ContributingFeatureSchema(BaseModel):
    feature: str
    value: float
    deviation_z_score: float
    description: str


class PredictionResponse(BaseModel):
    """
    Output schema containing real model prediction results and transparent continuous risk score.
    """

    risk_score: int = Field(..., ge=0, le=100, description="Continuous risk score from 0 to 100")
    threat_level: SeverityLevel = Field(..., description="Categorical threat severity tier")
    attack_type: str = Field(..., description="Predicted traffic classification")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Class probability estimate for predicted class")
    action_recommendation: PolicyAction = Field(..., description="Recommended gateway policy action")
    is_anomaly: bool = Field(..., description="True if classified as non-benign traffic")
    class_probabilities: Dict[str, float] = Field(..., description="Class probability estimates from model")
    top_contributing_features: List[ContributingFeatureSchema] = Field(
        default_factory=list, description="Top anomalous feature indicators"
    )
    event_id: Optional[str] = Field(default=None, description="Persisted PostgreSQL security event identifier")


class BatchPredictionRequest(BaseModel):
    flows: List[NetworkFlowRequest] = Field(..., min_length=1, description="List of network flows to evaluate")


class BatchPredictionResponse(BaseModel):
    results: List[PredictionResponse] = Field(..., description="Ordered list of prediction results")
    total_evaluated: int
