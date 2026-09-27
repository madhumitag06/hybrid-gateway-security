"""
Policy & Enforcement API Router (v1)
====================================
Provides REST endpoints for active containment rule queries, manual rollbacks/revocations,
mode toggling (DRY_RUN / SANDBOX), and Static vs. Adaptive policy comparisons.
"""

from datetime import datetime, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.config import settings
from backend.app.db.session import get_db
from backend.app.repositories.enforcement_repo import EnforcementRepository
from backend.app.repositories.policy_audit_repo import PolicyAuditRepository
from backend.app.schemas.policy import (
    ActiveEnforcementRule,
    EnforcementConfigSchema,
    EnforcementConfigUpdate,
    PolicyAuditLogSchema,
    PolicyComparisonResult,
    PolicyDecision,
    RevokeRuleRequest,
    RevokeRuleResponse,
)
from backend.app.schemas.predict import NetworkFlowRequest, PredictionResponse
from backend.app.services.enforcement_service import EnforcementService
from backend.app.services.ml_service import MLService
from backend.app.services.policy_engine import PolicyEngine
from backend.app.services.static_policy_engine import StaticPolicyEngine

router = APIRouter(tags=["Policy & Enforcement"])


@router.get(
    "/v1/enforcement/rules",
    response_model=List[ActiveEnforcementRule],
    summary="List active and historical containment rules",
    description="Returns all active, expired, or revoked containment rules from PostgreSQL with calculated remaining TTLs.",
)
def list_enforcement_rules(
    status_filter: Optional[str] = Query(None, description="Filter by status: ACTIVE, EXPIRED, REVOKED, SIMULATED"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
) -> List[ActiveEnforcementRule]:
    repo = EnforcementRepository(db)
    repo.prune_expired_rules()
    rules_models, _ = repo.list_all_rules(limit=limit, offset=offset, status_filter=status_filter)

    now = datetime.now(timezone.utc)
    results: List[ActiveEnforcementRule] = []

    for r in rules_models:
        rem_ttl = max(int((r.expires_at - now).total_seconds()), 0) if r.status == "ACTIVE" else 0
        results.append(
            ActiveEnforcementRule(
                rule_id=r.id,
                event_id=r.event_id,
                target_ip=r.target_ip,
                target_port=r.target_port,
                protocol=r.protocol or "ANY",
                action=r.action,  # type: ignore
                status=r.status,  # type: ignore
                mode=r.mode,  # type: ignore
                reason=r.reason,
                ttl_seconds=r.ttl_seconds,
                expires_at=r.expires_at,
                remaining_ttl_seconds=rem_ttl,
                created_at=r.created_at,
                revoked_at=r.revoked_at,
                revoked_by=r.revoked_by,
            )
        )

    return results


@router.post(
    "/v1/enforcement/rules/{rule_id}/revoke",
    response_model=RevokeRuleResponse,
    summary="Manually revoke active containment rule",
    description="Rolls back active containment for a target host and logs the action in the immutable audit ledger.",
)
def revoke_containment_rule(
    rule_id: str,
    request: RevokeRuleRequest = RevokeRuleRequest(),
    db: Session = Depends(get_db),
) -> RevokeRuleResponse:
    repo = EnforcementRepository(db)
    rule = repo.get_by_id(rule_id)
    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Containment rule '{rule_id}' not found.",
        )

    success, msg = EnforcementService.revoke_rule(
        rule_id=rule_id, db=db, actor=request.actor or "analyst"
    )
    if not success:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=msg)

    return RevokeRuleResponse(
        rule_id=rule_id,
        target_ip=rule.target_ip,
        status="REVOKED",
        message=msg,
        timestamp=datetime.now(timezone.utc),
    )


@router.get(
    "/v1/enforcement/config",
    response_model=EnforcementConfigSchema,
    summary="Get active enforcement configuration",
    description="Returns current operating mode (DRY_RUN vs SANDBOX), management allowlist, and active rule counts.",
)
def get_enforcement_config(db: Session = Depends(get_db)) -> EnforcementConfigSchema:
    repo = EnforcementRepository(db)
    active_count = len(repo.list_active_rules())
    return EnforcementConfigSchema(
        active_mode=EnforcementService.get_mode(),  # type: ignore
        default_ttl_seconds=settings.default_rule_ttl_seconds,
        management_allowlist=settings.management_allowlist,
        total_active_rules=active_count,
    )


@router.put(
    "/v1/enforcement/config",
    response_model=EnforcementConfigSchema,
    summary="Update enforcement configuration",
    description="Switch between DRY_RUN and SANDBOX modes or update management allowlist.",
)
def update_enforcement_config(
    update: EnforcementConfigUpdate,
    db: Session = Depends(get_db),
) -> EnforcementConfigSchema:
    if update.active_mode:
        EnforcementService.set_mode(update.active_mode)
    if update.default_ttl_seconds:
        settings.default_rule_ttl_seconds = update.default_ttl_seconds
    if update.management_allowlist is not None:
        settings.management_allowlist = update.management_allowlist

    return get_enforcement_config(db=db)


@router.post(
    "/v1/policies/evaluate",
    response_model=PolicyDecision,
    summary="Evaluate adaptive policy for a flow",
    description="Passes a flow through ThreatPredictor and evaluates context-aware policy decisions.",
)
def evaluate_flow_policy(
    flow_request: NetworkFlowRequest,
) -> PolicyDecision:
    pred: PredictionResponse = MLService.predict(flow_request)
    source_ip = flow_request.source_ip or "192.168.1.100"
    destination_ip = flow_request.destination_ip or "10.100.1.10"

    return PolicyEngine.evaluate(
        prediction=pred,
        source_ip=source_ip,
        destination_ip=destination_ip,
        dst_port=flow_request.dst_port,
        protocol="TCP",
    )


@router.post(
    "/v1/policies/compare",
    response_model=PolicyComparisonResult,
    summary="Compare Static Baseline vs. Adaptive AI Policy",
    description="Evaluates a flow through both Static Baseline and Adaptive AI Policy engines to report neutral decision divergences.",
)
def compare_policies(
    flow_request: NetworkFlowRequest,
) -> PolicyComparisonResult:
    source_ip = flow_request.source_ip or "192.168.1.100"
    destination_ip = flow_request.destination_ip or "10.100.1.10"

    pred: PredictionResponse = MLService.predict(flow_request)
    adaptive_decision = PolicyEngine.evaluate(
        prediction=pred,
        source_ip=source_ip,
        destination_ip=destination_ip,
        dst_port=flow_request.dst_port,
        protocol="TCP",
    )

    return StaticPolicyEngine.compare_with_adaptive(
        flow=flow_request,
        source_ip=source_ip,
        dst_port=flow_request.dst_port,
        adaptive_decision=adaptive_decision,
        flow_id=f"flow-cmp-{flow_request.dst_port}",
    )


@router.get(
    "/v1/enforcement/audit",
    response_model=List[PolicyAuditLogSchema],
    summary="Get recent policy audit logs",
    description="Returns chronological audit history of policy actions and rollbacks recorded in PostgreSQL.",
)
def get_policy_audit_logs(
    limit: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
) -> List[PolicyAuditLogSchema]:
    repo = PolicyAuditRepository(db)
    logs = repo.get_recent_logs(limit=limit)
    return [
        PolicyAuditLogSchema(
            id=log.id,
            timestamp=log.timestamp,
            event_id=log.event_id,
            requested_action=log.requested_action,
            previous_action=log.previous_action,
            resulting_status=log.resulting_status,
            actor=log.actor,
        )
        for log in logs
    ]

