"""
Cloud Telemetry Schemas
=======================
Defines canonical network flow representation across AWS, GCP, Azure, and Docker Lab,
guaranteeing exact mathematical compatibility with the gateway's 9-feature ML pipeline.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional, Union
from pydantic import BaseModel, Field, model_validator
from backend.app.cloud.schemas.cloud_account import CloudProviderType
from backend.app.schemas.predict import PredictionResponse


class CanonicalFlowRecord(BaseModel):
    """
    Standardized internal network flow record derived from cloud provider logs.
    Guarantees strict 9-feature mathematical parity.
    """
    flow_id: str
    provider: CloudProviderType
    account_id: str = "default"
    region: str = "global"
    src_ip: str = ""
    dst_ip: str = ""
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    src_port: int = 0
    dst_port: int = 80
    protocol: str = "TCP"
    protocol_number: int = 6
    protocol_num: Optional[int] = None
    packet_count: int = 1
    byte_count: int = 64
    duration: float = 1.0
    duration_seconds: Optional[float] = None
    conn_rate: float = 1.0
    bytes_per_sec: float = 64.0
    packets_per_sec: float = 1.0
    avg_packet_size: float = 64.0
    unique_dst_ports: int = 1
    start_time: int = 0
    end_time: int = 0
    action: str = "ACCEPT"  # ACCEPT, REJECT, ALLOW, DENY
    log_status: str = "OK"
    flow_direction: str = "CROSS_ZONE"
    interface_id: Optional[str] = None
    resource_id: Optional[str] = None
    vpc_id: Optional[str] = None
    timestamp: Optional[datetime] = None
    raw_payload: Optional[Dict[str, Any]] = None
    raw_format: str = "CANONICAL"
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="before")
    @classmethod
    def sync_canonical_fields(cls, values: Any) -> Any:
        if isinstance(values, dict):
            # Sync IP addresses
            src = values.get("src_ip") or values.get("source_ip", "")
            dst = values.get("dst_ip") or values.get("destination_ip", "")
            values["src_ip"] = src
            values["source_ip"] = src
            values["dst_ip"] = dst
            values["destination_ip"] = dst

            # Sync duration
            dur = values.get("duration") or values.get("duration_seconds", 1.0)
            values["duration"] = max(float(dur), 0.001)
            values["duration_seconds"] = values["duration"]

            # Sync protocol number
            pnum = values.get("protocol_number") or values.get("protocol_num", 6)
            values["protocol_number"] = int(pnum)
            values["protocol_num"] = int(pnum)

            # Sync region default
            if not values.get("region"):
                values["region"] = "global"

            # Sync resource_id / interface_id
            if values.get("resource_id") and not values.get("interface_id"):
                values["interface_id"] = values["resource_id"]
            elif values.get("interface_id") and not values.get("resource_id"):
                values["resource_id"] = values["interface_id"]

            # Timestamp default
            if not values.get("timestamp"):
                values["timestamp"] = datetime.now(timezone.utc)
        return values


class CloudFlowItemResult(BaseModel):
    flow_id: str
    provider: str = "MULTI_CLOUD"
    account_id: str = "default"
    src_ip: str = ""
    dst_ip: str = ""
    dst_port: int = 80
    protocol: str = "TCP"
    flow_direction: str = "CROSS_ZONE"
    packet_count: int = 1
    byte_count: int = 64
    duration_seconds: float = 1.0
    conn_rate: float = 1.0
    unique_dst_ports: int = 1
    risk_score: float = 0.0
    threat_level: str = "LOW"
    attack_type: str = "Benign"
    policy_action: str = "ALLOW"
    enforcement_status: Optional[str] = None
    event_id: Optional[str] = None
    canonical_flow: Optional[CanonicalFlowRecord] = None
    source_zone: Optional[str] = None
    destination_zone: Optional[str] = None
    traffic_direction: Optional[str] = None
    features_used: Optional[List[str]] = None
    flow_features: Optional[Dict[str, Any]] = None
    prediction: Optional[PredictionResponse] = None
    persisted_event_id: Optional[str] = None


class TelemetryNormalizationReport(BaseModel):
    features_extracted: List[str]
    schema_version: str = "v2_canonical"
    failed_auth_synthesized: bool = False
    timestamp_provenance: bool = True
    direction_classified: bool = True


class CloudTelemetryBatchRequest(BaseModel):
    provider: CloudProviderType
    account_id: str = "default"
    region: Optional[str] = None
    records: List[Any] = Field(default_factory=list)
    raw_records: Optional[List[str]] = Field(None, description="Raw log lines or JSON strings")
    json_payload: Optional[Dict[str, Any]] = Field(None, description="Parsed structured JSON log batch")
    persist_events: bool = True
    persist: Optional[bool] = None

    @model_validator(mode="before")
    @classmethod
    def sync_batch_fields(cls, values: Any) -> Any:
        if isinstance(values, dict):
            if "raw_records" in values and values["raw_records"] and not values.get("records"):
                values["records"] = values["raw_records"]
            if "persist" in values and "persist_events" not in values:
                values["persist_events"] = values["persist"]
        return values


class CloudTelemetryBatchResponse(BaseModel):
    status: str = "SUCCESS"
    provider: str
    account_id: str
    records_received: int
    records_parsed: int
    records_aggregated: int
    high_risk_flows_detected: int
    flows_accepted: int
    flows_dropped: int
    parsing_duration_ms: float
    inference_duration_ms: float
    flows: List[CloudFlowItemResult]
    normalization_report: TelemetryNormalizationReport
