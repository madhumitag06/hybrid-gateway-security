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
