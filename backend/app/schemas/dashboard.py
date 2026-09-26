"""
Dashboard & Security Event API Schemas
======================================
Pydantic models for the dashboard summary, security events query/filtering,
audit histories, and policy action responses.
"""

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field

FrontendSeverity = Literal["low", "medium", "high", "critical"]
PolicyAction = Literal["Allow", "Monitor", "Restrict", "Block"]
EventStatus = Literal["Applied", "Monitoring", "Allowed"]


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


class DashboardDataSchema(BaseModel):
    riskScore: int = Field(..., ge=0, le=100)
    riskState: PolicyAction
    activeFlows: int
    events: List[SecurityEventSchema]
    reasons: List[RiskReasonSchema]
    modelStatus: str = "Trained RandomForestClassifier active (Phase 1)"
    isSimulatedFlowBuffer: bool = False  # Now PostgreSQL backed
    databaseBackend: str = "PostgreSQL (Persistent Storage)"


class PolicyActionRequest(BaseModel):
    action: PolicyAction
    actor: Optional[str] = "analyst"


class PolicyActionResponse(BaseModel):
    eventId: str
    action: PolicyAction
    status: EventStatus
    message: str
    timestamp: Optional[datetime] = None
