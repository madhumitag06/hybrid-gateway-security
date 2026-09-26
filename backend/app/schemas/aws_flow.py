"""
AWS VPC Flow Log Schemas
=========================
Pydantic schemas for parsing, validating, normalizing, and reporting
AWS VPC Flow Log telemetry.
"""

from typing import List, Literal, Optional
from pydantic import BaseModel, Field
from backend.app.schemas.predict import PredictionResponse
from backend.app.schemas.policy import PolicyDecision

TelemetrySourceType = Literal["AWS_VPC_FLOW_LOG", "AWS_VPC_FLOW_LOG_FIXTURE", "PCAP", "DEMO_SEED"]


class VpcFlowLogRecordSchema(BaseModel):
    """
    Standard AWS VPC Flow Log v2 Record representation.
    """
    version: int = 2
    account_id: str
    interface_id: str
    src_addr: str
    dst_addr: str
    src_port: int
    dst_port: int
    protocol: int
    packets: int
    bytes: int
    start: int
    end: int
    action: str  # "ACCEPT" or "REJECT"
    log_status: str  # "OK", "NODATA", "SKIPDATA"


class AwsVpcIngestionRequest(BaseModel):
    """
    Request payload for manual or direct API submission of VPC flow log data.
    """
    raw_log_content: Optional[str] = Field(
        default=None,
        description="Raw newline-delimited VPC Flow Log text (v2 space/tab delimited format)"
    )
    is_fixture: bool = Field(
        default=False,
        description="Must be set to True ONLY when submitting benchmark synthetic test fixtures."
    )
    persist: bool = Field(
        default=True,
        description="Whether to evaluate through PolicyEngine and persist events to PostgreSQL."
    )
    source_label: Optional[str] = Field(
        default=None,
        description="Optional provenance label describing the origin stream or file."
    )


class AwsVpcFlowItemResult(BaseModel):
    """
    Normalized flow evaluated through ML inference and PolicyEngine.
    """
    flow_id: str
    source_ip: str
    destination_ip: str
    source_zone: str
    destination_zone: str
    traffic_direction: str
    protocol_name: str
    dst_port: int
    packet_count: int
    byte_count: int
    duration: float
    conn_rate: float
    unique_dst_ports: int
    failed_auth_count: int = Field(
        default=0,
        description="Strictly 0 for VPC Flow Logs. Flow logs do not contain L7 authentication data."
    )
    interface_id: Optional[str] = None
    account_id: Optional[str] = None
    prediction: PredictionResponse
    policy_decision: Optional[PolicyDecision] = None
    persisted_event_id: Optional[str] = None


class AwsVpcIngestionResponse(BaseModel):
    """
    Summary and detailed telemetry results for an ingested VPC Flow Log batch.
    """
    telemetry_source: TelemetrySourceType
    source_label: str
    is_fixture: bool
    total_records_parsed: int
    total_flows_aggregated: int
    high_risk_flows_count: int
    parse_duration_ms: float
    inference_duration_ms: float
    total_duration_ms: float
    results: List[AwsVpcFlowItemResult] = Field(default_factory=list)


class AwsVpcSampleFixtureInfo(BaseModel):
    """
    Metadata for reproducible offline AWS VPC Flow Log benchmark scenarios.
    """
    sample_id: str
    name: str
    filename: str
    description: str
    record_count: int
    expected_threat: str
    file_size_bytes: int
    telemetry_source: str = "AWS_VPC_FLOW_LOG_FIXTURE"
