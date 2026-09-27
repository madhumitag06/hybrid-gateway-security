"""
Dashboard & Security Event API Schemas
======================================
Pydantic models for the dashboard summary, security events query/filtering,
audit histories, traffic time-series, response timelines, notifications,
unified search, system profiles, AI copilot briefings, and policy action responses.
"""

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field

FrontendSeverity = Literal["low", "medium", "high", "critical"]
PolicyAction = Literal["Allow", "Monitor", "Restrict", "Block"]
EventStatus = Literal["Applied", "Monitoring", "Allowed", "Simulated", "Pending"]


class SecurityEventSchema(BaseModel):
    id: str
    time: str
    event: str
    source: str
    destination: str
    risk: int = Field(..., ge=0, le=100)
    severity: FrontendSeverity
    action: PolicyAction
    status: EventStatus
    description: str
    attack_type: Optional[str] = None
    confidence: Optional[float] = None
    is_anomaly: Optional[bool] = None
    is_demo: Optional[bool] = False


class SecurityEventDetailSchema(SecurityEventSchema):
    flow_features: Dict[str, Any] = Field(default_factory=dict)
    class_probabilities: Dict[str, float] = Field(default_factory=dict)
    top_contributing_features: List[Dict[str, Any]] = Field(default_factory=list)
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


class EventListResponseSchema(BaseModel):
    events: List[SecurityEventSchema]
    total: int
    limit: int
    offset: int


class PolicyAuditLogSchema(BaseModel):
    id: int
    event_id: str
    requested_action: PolicyAction
    previous_action: Optional[str] = None
    resulting_status: EventStatus
    actor: str
    timestamp: datetime


class EventHistoryResponseSchema(BaseModel):
    event_id: str
    history: List[PolicyAuditLogSchema]


class RiskReasonSchema(BaseModel):
    label: str
    value: int
    tone: Literal["red", "orange", "yellow", "blue"]


class TrafficPointSchema(BaseModel):
    time_label: str
    timestamp: Optional[datetime] = None
    inbound_val: float = 0.0  # Normalized flow volume / record count
    outbound_val: float = 0.0
    flow_count: int = 0
    total_packets: int = 0
    total_bytes: int = 0
    anomaly_count: int = 0
    anomaly_note: Optional[str] = None


class TimelineStepSchema(BaseModel):
    id: Optional[str] = None
    time: str
    title: str
    sub: str
    icon: str
    action: Optional[str] = "Monitor"
    status: Optional[str] = "Applied"


class KeyMetricsSchema(BaseModel):
    detection_rate: str = "98.5%"
    detection_note: str = "Holdout Benchmark (N=200)"
    false_positives: str = "0.0%"
    fp_note: str = "Holdout Validation Suite"
    ml_latency: str = "1.8 ms (Inference)"
    latency_note: str = "SHAP Explainer: ~20.6 ms"
    active_policies: int = 0
    policies_note: str = "In-memory sandbox filter"


class NotificationItemSchema(BaseModel):
    id: str
    event_id: str
    title: str
    source: str
    destination: str
    risk: int
    severity: str
    attack_type: str
    time: str
    is_read: bool = False


class DashboardDataSchema(BaseModel):
    riskScore: int = Field(..., ge=0, le=100)
    riskState: PolicyAction
    activeFlows: int  # Maintained for backward compatibility (Evaluated Event Count)
    evaluatedEventsCount: int = 0  # Explicit truthful event count
    events: List[SecurityEventSchema]
    reasons: List[RiskReasonSchema]
    modelStatus: str = "Trained RandomForestClassifier active (Phase 1)"
    isSimulatedFlowBuffer: bool = False
    databaseBackend: str = "PostgreSQL (Persistent Storage)"

    # Operational Telemetry & Latency Reconciliation
    processUptime: str = "Operational"
    uptimeSeconds: int = 0
    processStartTimeUtc: Optional[str] = None
    inferenceLatency: str = "1.8 ms (Model Inference)"
    pipelineLatency: str = "22.4 ms (End-to-End with SHAP)"
    avgLatency: str = "1.8 ms"
    connectionHealth: str = "Healthy"
    connectionNote: str = "FastAPI ↔ PostgreSQL ↔ RandomForest"
    timeRange: str = "Last 24 hours"
    trafficVolumeUnit: str = "Recorded Flow Telemetry Volume (Events / Time Bucket)"
    trafficPoints: List[TrafficPointSchema] = Field(default_factory=list)
    timeline: List[TimelineStepSchema] = Field(default_factory=list)
    keyMetrics: KeyMetricsSchema = Field(default_factory=KeyMetricsSchema)
    notifications: List[NotificationItemSchema] = Field(default_factory=list)
    unreadNotificationsCount: int = 0


class PolicyActionRequest(BaseModel):
    action: PolicyAction
    actor: Optional[str] = "analyst"


class PolicyActionResponse(BaseModel):
    eventId: str
    action: PolicyAction
    status: EventStatus
    message: str
    timestamp: Optional[datetime] = None


class SearchResultItemSchema(BaseModel):
    id: str
    result_type: Literal["EVENT", "RULE", "TOPOLOGY"]
    title: str
    subtitle: str
    badge: str
    risk_score: Optional[int] = None
    target: Optional[str] = None
    action: Optional[str] = None


class SearchResultsSchema(BaseModel):
    query: str
    total_matches: int
    results: List[SearchResultItemSchema]


class SystemProfileSchema(BaseModel):
    username: str = "secops_admin"
    full_name: str = "SecOps Local Console"
    role: str = "Gateway Administrator (Local Unauthenticated Console Session)"
    organization: str = "Hybrid Security Gateway"
    auth_status: str = "Unconfigured (Local Prototype Environment)"
    active_mode: str = "DRY_RUN"
    is_safety_active: bool = True
    supported_environments: List[Dict[str, str]] = Field(default_factory=list)
    uptime_seconds: int = 0
    uptime_formatted: str = "Process Running"
    process_start_time: str = ""
    database_status: str = "Connected (PostgreSQL on port 5434)"
    ml_model_status: str = "Online (RandomForestClassifier)"


class AICopilotBriefingResponse(BaseModel):
    event_id: str
    provider: str
    model: str
    is_llm_generated: bool
    executive_summary: str
    threat_narrative: str
    remediation_steps: List[str]
    disclaimer: str
