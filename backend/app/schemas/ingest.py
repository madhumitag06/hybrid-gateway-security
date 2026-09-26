"""
Traffic Ingestion & Flow Capture Schemas
========================================
Pydantic models for PCAP upload, flow aggregation results, ingestion telemetry,
and sample PCAP management.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from backend.app.schemas.predict import PredictionResponse


class FlowFeatureSummary(BaseModel):
    """
    Summarized flow features extracted from aggregated packet batches.
    """
    flow_id: str
    source_ip: str
    destination_ip: str
    protocol: str
    dst_port: int
    packet_count: int
    byte_count: int
    duration: float
    conn_rate: float
    unique_dst_ports: int
    failed_auth_count: int = 0


class IngestedFlowResult(BaseModel):
    """
    Represents an extracted flow and its corresponding ML threat prediction.
    """
    flow_id: str
    flow_features: FlowFeatureSummary
    prediction: PredictionResponse
    persisted_event_id: Optional[str] = None


class IngestionMetrics(BaseModel):
    """
    Performance and diagnostic metrics for a traffic ingestion operation.
    """
    packets_read: int = Field(..., description="Total raw packets read from the source")
    packets_processed: int = Field(..., description="Total valid IP packets aggregated into flows")
    packets_skipped: int = Field(default=0, description="Packets skipped due to non-IP protocols or malformed headers")
    flows_generated: int = Field(..., description="Total distinct network flow sessions created")
    parse_duration_ms: float = Field(..., description="Wall-clock time spent parsing packets and aggregating flows (ms)")
    inference_duration_ms: float = Field(..., description="Wall-clock time spent on ML model inference (ms)")
    persist_duration_ms: float = Field(..., description="Wall-clock time spent persisting events to PostgreSQL (ms)")
    total_duration_ms: float = Field(..., description="Total end-to-end ingestion pipeline execution time (ms)")
    throughput_packets_per_sec: float = Field(..., description="Calculated packet processing throughput (packets/sec)")


class PcapIngestionResponse(BaseModel):
    """
    Full response returned after ingesting a PCAP file or sample trace.
    """
    source_type: str = Field(default="PCAP_INGESTION", description="Origin tag: PCAP_INGESTION, LIVE_CAPTURE, etc.")
    filename: str = Field(..., description="Name of the ingested file or scenario")
    file_size_bytes: int = Field(..., description="Size of the uploaded/processed file in bytes")
    is_demo: bool = Field(default=False, description="Whether this traffic is flagged as synthetic demo data")
    metrics: IngestionMetrics
    flows_evaluated: int = Field(..., description="Number of flows passed through ML inference")
    high_risk_flows_count: int = Field(..., description="Number of flows classified as HIGH or CRITICAL risk")
    results: List[IngestedFlowResult] = Field(default_factory=list, description="List of evaluated flow predictions")


class SamplePcapInfo(BaseModel):
    """
    Metadata for pre-packaged reproducible PCAP test fixtures.
    """
    sample_id: str
    name: str
    filename: str
    description: str
    packet_count: int
    expected_threat: str
    file_size_bytes: int


class IngestionStatusResponse(BaseModel):
    """
    Status of the traffic ingestion subsystem.
    """
    engine_status: str = "ONLINE"
    active_mode: str = "PCAP_INGESTION_PRIMARY"
    raw_socket_capture_supported: bool
    platform: str
    supported_formats: List[str] = ["pcap", "pcapng", "cap"]
    max_upload_size_mb: int = 15
    total_pcaps_ingested: int
    total_packets_processed: int
    total_flows_generated: int
