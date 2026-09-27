"""
Security Events API Router (v1)
===============================
Provides historical querying, filtering, pagination, and audit logs for PostgreSQL-persisted events.
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session
from backend.app.db.session import get_db
from backend.app.repositories.policy_audit_repo import PolicyAuditRepository
from backend.app.repositories.security_event_repo import SecurityEventRepository
from backend.app.schemas.analytics import EventExplanationResponse
from backend.app.schemas.dashboard import (
    EventHistoryResponseSchema,
    EventListResponseSchema,
    PolicyAuditLogSchema,
    SecurityEventDetailSchema,
    SecurityEventSchema,
)

router = APIRouter(prefix="/v1/events", tags=["Security Events"])


def _map_event_to_schema(e) -> SecurityEventSchema:
    time_str = e.timestamp.strftime("%H:%M:%S") if e.timestamp else "00:00:00"
    severity_map = {"LOW": "low", "MEDIUM": "medium", "HIGH": "high"}
    severity = severity_map.get(e.threat_level, "medium")
    if e.risk_score >= 85:
        severity = "critical"

    return SecurityEventSchema(
        id=e.id,
        time=time_str,
        event=f"{e.attack_type.replace('_', ' ').title()} Detected" if e.is_anomaly else "Normal Network Traffic",
        source=e.source_ip,
        destination=e.destination_ip,
        risk=e.risk_score,
        severity=severity,
        action=e.current_policy_action,
        status=e.status,
        description=e.description,
        attack_type=e.attack_type,
        confidence=e.confidence,
        is_anomaly=e.is_anomaly,
        is_demo=e.is_demo,
    )


@router.get(
    "",
    response_model=EventListResponseSchema,
    summary="Query persisted security events",
    description="Retrieve historical security events from PostgreSQL with flexible multi-attribute filtering and pagination.",
)
def list_events(
    threat_level: Optional[str] = Query(None, description="Filter by threat level: LOW, MEDIUM, HIGH"),
    attack_type: Optional[str] = Query(None, description="Filter by attack type: BENIGN, PORT_SCAN, BRUTE_FORCE, etc."),
    action: Optional[str] = Query(None, description="Filter by active policy action: Allow, Monitor, Restrict, Block"),
    min_risk: Optional[int] = Query(None, ge=0, le=100, description="Minimum risk score threshold"),
    max_risk: Optional[int] = Query(None, ge=0, le=100, description="Maximum risk score threshold"),
    is_anomaly: Optional[bool] = Query(None, description="Filter by anomaly flag"),
    search: Optional[str] = Query(None, description="Search term matching IP, event ID, or description"),
    limit: int = Query(50, ge=1, le=500, description="Page limit"),
    offset: int = Query(0, ge=0, description="Page offset"),
    db: Session = Depends(get_db),
) -> EventListResponseSchema:
    repo = SecurityEventRepository(db)
    events, total = repo.list_events(
        limit=limit,
        offset=offset,
        threat_level=threat_level,
        attack_type=attack_type,
        action=action,
        min_risk=min_risk,
        max_risk=max_risk,
        is_anomaly=is_anomaly,
        search=search,
    )
    return EventListResponseSchema(
        events=[_map_event_to_schema(e) for e in events],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{event_id}",
    response_model=SecurityEventDetailSchema,
    summary="Get security event details",
    description="Fetch full record details including raw flow vectors and class probability estimates from PostgreSQL.",
)
def get_event_detail(
    event_id: str,
    db: Session = Depends(get_db),
) -> SecurityEventDetailSchema:
    repo = SecurityEventRepository(db)
    event = repo.get_by_id(event_id)
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security event '{event_id}' not found in database.",
        )

    base_schema = _map_event_to_schema(event)
    return SecurityEventDetailSchema(
        **base_schema.model_dump(),
        flow_features=event.flow_features or {},
        class_probabilities=event.class_probabilities or {},
        top_contributing_features=event.top_contributing_features or [],
        created_at=event.created_at,
        updated_at=event.updated_at,
    )


@router.get(
    "/{event_id}/history",
    response_model=EventHistoryResponseSchema,
    summary="Get policy audit history for event",
    description="Fetch immutable chronological ledger of policy modifications made to this incident.",
)
def get_event_history(
    event_id: str,
    db: Session = Depends(get_db),
) -> EventHistoryResponseSchema:
    repo = SecurityEventRepository(db)
    if not repo.get_by_id(event_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security event '{event_id}' not found.",
        )

    audit_repo = PolicyAuditRepository(db)
    history = audit_repo.get_history_for_event(event_id)

    return EventHistoryResponseSchema(
        event_id=event_id,
        history=[
            PolicyAuditLogSchema(
                id=h.id,
                event_id=h.event_id,
                requested_action=h.requested_action,
                previous_action=h.previous_action,
                resulting_status=h.resulting_status,
                actor=h.actor,
                timestamp=h.timestamp,
            )
            for h in history
        ],
    )


@router.get(
    "/{event_id}/explanation",
    response_model=EventExplanationResponse,
    summary="Get Detailed SHAP Feature Attribution for Event",
    description="Returns full 10-feature Shapley waterfall values, base prior probabilities, baseline deviations, and policy reasoning for an incident.",
)
def get_event_explanation(
    event_id: str,
    db: Session = Depends(get_db),
) -> EventExplanationResponse:
    repo = SecurityEventRepository(db)
    event = repo.get_by_id(event_id)
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Security event '{event_id}' not found in database.",
        )

    from backend.app.schemas.analytics import DetailedFeatureAttribution, PolicyReasoningTrace
    from backend.app.schemas.predict import PredictionResponse
    from backend.app.services.explainability_service import ExplainabilityService
    from backend.app.services.policy_engine import PolicyEngine
    from ml.features.extractor import NetworkFlowInput

    ff = event.flow_features or {}
    flow_obj = NetworkFlowInput(
        packet_count=int(ff.get("packet_count", 1)),
        byte_count=int(ff.get("byte_count", 64)),
        duration=float(ff.get("duration", 0.1)),
        conn_rate=float(ff.get("conn_rate", 1.0)),
        dst_port=int(ff.get("dst_port", 80)),
        unique_dst_ports=int(ff.get("unique_dst_ports", 1)),
        failed_auth_count=int(ff.get("failed_auth_count", 0)),
        bytes_per_sec=ff.get("bytes_per_sec"),
        packets_per_sec=ff.get("packets_per_sec"),
        avg_packet_size=ff.get("avg_packet_size"),
    )

    pred = PredictionResponse(
        attack_type=event.attack_type,
        confidence=event.confidence,
        risk_score=event.risk_score,
        threat_level=event.threat_level,
        action_recommendation=event.action_recommendation,
        is_anomaly=event.is_anomaly,
        class_probabilities=event.class_probabilities or {},
        top_contributing_features=[],
    )

    policy_dec = PolicyEngine.evaluate(
        prediction=pred,
        source_ip=event.source_ip,
        destination_ip=event.destination_ip,
        dst_port=int(ff.get("dst_port", 80)),
        protocol="TCP",
        event_id=event.id,
    )

    explain_svc = ExplainabilityService.get_instance()
    full_explanation = explain_svc.get_full_explanation(
        flow_input=flow_obj,
        predicted_class=event.attack_type,
        risk_score=event.risk_score,
        confidence=event.confidence,
        policy_action=event.current_policy_action,
        policy_rule_name=policy_dec.rule_name,
        enforcement_status=event.status,
    )

    telem_src = ff.get("telemetry_source")
    if not telem_src:
        telem_src = "DEMO_SEED" if event.is_demo else "PCAP_FIXTURE"

    return EventExplanationResponse(
        event_id=event.id,
        timestamp=event.timestamp,
        source_ip=event.source_ip,
        destination_ip=event.destination_ip,
        telemetry_source=telem_src,
        attack_type=event.attack_type,
        confidence=event.confidence,
        risk_score=event.risk_score,
        threat_level=event.threat_level,  # type: ignore
        expected_base_probability=full_explanation["expected_base_probability"],
        all_base_values=full_explanation["all_base_values"],
        feature_attributions=[
            DetailedFeatureAttribution(**fa)
            for fa in full_explanation["feature_attributions"]
        ],
        top_positive_contributors=[
            DetailedFeatureAttribution(**fa)
            for fa in full_explanation["top_positive_contributors"]
        ],
        top_mitigating_contributors=[
            DetailedFeatureAttribution(**fa)
            for fa in full_explanation["top_mitigating_contributors"]
        ],
        policy_reasoning=PolicyReasoningTrace(
            enacted_policy_action=event.current_policy_action,  # type: ignore
            policy_rule_name=policy_dec.rule_name,
            enforcement_status=event.status,
            is_confidence_gated=(policy_dec.rule_name == "CONFIDENCE_GATING_MONITOR"),
            is_allowlisted=(policy_dec.rule_name == "MANAGEMENT_ALLOWLIST_PROTECTION"),
        ),
        disclaimer=full_explanation["disclaimer"],
    )


