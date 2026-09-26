"""
Dashboard API Router (v1)
=========================
Serves aggregated dashboard metrics and accepts policy action updates.
"""

from fastapi import APIRouter, Path
from backend.app.schemas.dashboard import (
    DashboardDataSchema,
    PolicyActionRequest,
    PolicyActionResponse,
)
from backend.app.services.dashboard_service import DashboardService

router = APIRouter(tags=["Dashboard"])


@router.get(
    "/dashboard",
    response_model=DashboardDataSchema,
    summary="Get aggregated security dashboard metrics",
    description="Returns gateway risk state, active flow count, security events, and top risk explanations derived dynamically from the ML model.",
)
@router.get("/v1/dashboard", response_model=DashboardDataSchema, include_in_schema=False)
def get_dashboard() -> DashboardDataSchema:
    return DashboardService.get_dashboard_data()


@router.post(
    "/events/{event_id}/action",
    response_model=PolicyActionResponse,
    summary="Update policy action for security event",
    description="Applies a gateway policy action ('Monitor', 'Restrict', 'Block') to an incident event.",
)
@router.post("/v1/events/{event_id}/action", response_model=PolicyActionResponse, include_in_schema=False)
def update_event_action(
    event_id: str = Path(..., description="ID of the security event to update"),
    request: PolicyActionRequest = ...,
) -> PolicyActionResponse:
    return DashboardService.apply_policy_action(event_id=event_id, action=request.action)
