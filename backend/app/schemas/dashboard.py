"""
Dashboard API Schemas
=====================
Pydantic models for the dashboard summary, security events, and policy action endpoints.
"""

from typing import List, Literal, Optional
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
    modelStatus: str = "Trained RandomForestClassifier active"
    isSimulatedFlowBuffer: bool = True  # Explicit disclaimer until live packet capture is implemented


class PolicyActionRequest(BaseModel):
    action: PolicyAction


class PolicyActionResponse(BaseModel):
    eventId: str
    action: PolicyAction
    status: EventStatus
    message: str
