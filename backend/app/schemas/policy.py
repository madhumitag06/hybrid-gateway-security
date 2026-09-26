"""
Policy Engine & Enforcement API Schemas
=======================================
Pydantic schemas for structured policy decisions, active containment rules,
lifecycle management, and Static vs. Adaptive policy comparison.
"""

from datetime import datetime
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field

PolicyActionType = Literal["Allow", "Monitor", "Restrict", "Block"]
EnforcementStatusType = Literal["ACTIVE", "SIMULATED", "EXPIRED", "REVOKED", "FAILED"]
EnforcementModeType = Literal["DRY_RUN", "SANDBOX"]


class PolicyDecision(BaseModel):
    """
    Context-aware security policy decision computed by the PolicyEngine.
    """
    decision_id: str
    event_id: Optional[str] = None
    target_ip: str
    target_port: Optional[int] = None
    protocol: Optional[str] = "TCP"
    policy_action: PolicyActionType
    enforcement_required: bool
    confidence: float
    threat_level: str
    attack_type: str
    risk_score: int
    rule_name: str
    reason: str
    suggested_ttl_seconds: int = 300


class ActiveEnforcementRule(BaseModel):
    """
    Represents an active containment rule managed by the EnforcementAdapter.
    """
    rule_id: str
    event_id: Optional[str] = None
    target_ip: str
    target_port: Optional[int] = None
    protocol: Optional[str] = "ANY"
    action: PolicyActionType
    status: EnforcementStatusType
    mode: EnforcementModeType
    reason: str
    ttl_seconds: int
    expires_at: datetime
    remaining_ttl_seconds: int
    created_at: datetime
    revoked_at: Optional[datetime] = None
    revoked_by: Optional[str] = None


class EnforcementConfigSchema(BaseModel):
    """
    Global configuration state for policy enforcement.
    """
    active_mode: EnforcementModeType
    default_ttl_seconds: int
    management_allowlist: List[str]
    total_active_rules: int


class EnforcementConfigUpdate(BaseModel):
    """
    Update request for enforcement configuration.
    """
    active_mode: Optional[EnforcementModeType] = None
    default_ttl_seconds: Optional[int] = Field(None, ge=10, le=86400)
    management_allowlist: Optional[List[str]] = None


class PolicyComparisonResult(BaseModel):
    """
    Objective side-by-side comparison between Static Baseline and Adaptive AI Policy.
    """
    flow_id: str
    target_ip: str
    dst_port: int
    static_decision: PolicyActionType
    static_rule_matched: Optional[str]
    adaptive_decision: PolicyActionType
    adaptive_risk_score: int
    adaptive_confidence: float
    decision_divergence: bool
    divergence_rationale: str


class RevokeRuleRequest(BaseModel):
    actor: Optional[str] = "analyst"
    reason: Optional[str] = "Manual policy rollback requested by analyst"


class RevokeRuleResponse(BaseModel):
    rule_id: str
    target_ip: str
    status: str
    message: str
    timestamp: datetime
