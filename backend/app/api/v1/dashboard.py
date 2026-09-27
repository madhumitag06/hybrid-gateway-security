"""
Dashboard API Router (v1)
=========================
Serves aggregated dashboard metrics from PostgreSQL, time-filtered metrics,
unified search, persistent notification management, AI copilot briefings,
system identity profiles, and persists policy action updates.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Path, Query
from sqlalchemy.orm import Session
from backend.app.db.session import get_db
from backend.app.schemas.dashboard import (
    AICopilotBriefingResponse,
    DashboardDataSchema,
    NotificationItemSchema,
    PolicyActionRequest,
    PolicyActionResponse,
    SearchResultsSchema,
    SystemProfileSchema,
)
from backend.app.services.dashboard_service import DashboardService
from backend.app.services.llm.service import LLMService

router = APIRouter(tags=["Dashboard"])


@router.get(
    "/dashboard",
    response_model=DashboardDataSchema,
    summary="Get aggregated security dashboard metrics",
    description="Returns gateway risk state, evaluated event count, security events, dynamic traffic time series, response timeline, and top risk explanations derived dynamically from PostgreSQL-persisted events.",
)
@router.get("/v1/dashboard", response_model=DashboardDataSchema, include_in_schema=False)
def get_dashboard(
    time_range: Optional[str] = Query(None, alias="range", description="Time filter: '1h', '24h', '7d', '30d', 'all'"),
    db: Session = Depends(get_db),
) -> DashboardDataSchema:
    return DashboardService.get_dashboard_data(db=db, time_range=time_range)


@router.get(
    "/search",
    response_model=SearchResultsSchema,
    summary="Unified Gateway Search",
    description="Searches across PostgreSQL security events and active containment rules matching IP, event ID, attack type, or policy action.",
)
@router.get("/v1/search", response_model=SearchResultsSchema, include_in_schema=False)
def search_gateway(
    q: str = Query(..., min_length=1, description="Search query term (IP, event ID, domain, attack type, rule)"),
    db: Session = Depends(get_db),
) -> SearchResultsSchema:
    return DashboardService.search_gateway(db=db, query=q)


@router.get(
    "/system/profile",
    response_model=SystemProfileSchema,
    summary="Get System Profile & Security Analyst Identity",
    description="Returns console profile identity, active execution environments, process uptime metrics, and safety guardrail statuses.",
)
@router.get("/v1/system/profile", response_model=SystemProfileSchema, include_in_schema=False)
def get_system_profile(db: Session = Depends(get_db)) -> SystemProfileSchema:
    return DashboardService.get_system_profile(db=db)


@router.get(
    "/system/ai-status",
    summary="Get Security Analyst AI Copilot Status",
    description="Returns the configured LLM provider (none, groq, openai), model identifier, and active advisory role.",
)
@router.get("/v1/system/ai-status", include_in_schema=False)
def get_ai_status() -> Dict[str, Any]:
    return LLMService.get_instance().get_status()


@router.post(
    "/events/{event_id}/ai-briefing",
    response_model=AICopilotBriefingResponse,
    summary="Generate AI Copilot Incident Briefing",
    description="Synthesizes an advisory executive incident briefing and actionable remediation advice grounded in RandomForest classification and SHAP feature attributions.",
)
@router.post("/v1/events/{event_id}/ai-briefing", response_model=AICopilotBriefingResponse, include_in_schema=False)
def get_event_ai_briefing(
    event_id: str = Path(..., description="ID of the security event to analyze"),
    db: Session = Depends(get_db),
) -> AICopilotBriefingResponse:
    return DashboardService.generate_ai_briefing(db=db, event_id=event_id)


@router.post(
    "/notifications/{event_id}/read",
    summary="Mark security notification as read",
    description="Persists read status for a high-risk security incident notification into PostgreSQL.",
)
@router.post("/v1/notifications/{event_id}/read", include_in_schema=False)
def mark_notification_read(
    event_id: str = Path(...),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    success = DashboardService.mark_notification_read(db=db, event_id=event_id)
    return {"event_id": event_id, "is_read": True, "success": success}


@router.post(
    "/notifications/read-all",
    summary="Mark all security notifications as read",
    description="Marks all high-risk incident notifications as read in PostgreSQL.",
)
@router.post("/v1/notifications/read-all", include_in_schema=False)
def mark_all_notifications_read(
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    count = DashboardService.mark_all_notifications_read(db=db)
    return {"marked_read_count": count, "success": True}


@router.get(
    "/notifications",
    response_model=List[NotificationItemSchema],
    summary="List security alert notifications",
    description="Returns list of high-risk / anomalous security event notifications with persistent read states.",
)
@router.get("/v1/notifications", response_model=List[NotificationItemSchema], include_in_schema=False)
def list_notifications(
    db: Session = Depends(get_db),
) -> List[NotificationItemSchema]:
    data = DashboardService.get_dashboard_data(db=db, time_range="30d")
    return data.notifications


@router.post(
    "/events/{event_id}/action",
    response_model=PolicyActionResponse,
    summary="Update policy action for security event",
    description="Applies and logs a gateway policy action ('Monitor', 'Restrict', 'Block') to PostgreSQL.",
)
@router.post("/v1/events/{event_id}/action", response_model=PolicyActionResponse, include_in_schema=False)
def update_event_action(
    event_id: str = Path(..., description="ID of the security event to update"),
    request: PolicyActionRequest = ...,
    db: Session = Depends(get_db),
) -> PolicyActionResponse:
    return DashboardService.apply_policy_action(
        db=db,
        event_id=event_id,
        action=request.action,
        actor=request.actor or "analyst",
    )
