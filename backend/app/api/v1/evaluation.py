"""
Evaluation & Benchmarking REST API Router
=========================================
Exposes endpoints to run controlled benchmark suites, list scenario suites,
and export empirical evaluation reports in JSON or CSV format.
"""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session

from backend.app.db.session import get_db
from backend.app.schemas.evaluation import (
    EvaluationRunRequest,
    EvaluationRunResponse,
    EvaluationSuiteInfo,
)
from backend.app.services.evaluation.comparative_service import ComparativeEvaluationService

router = APIRouter(prefix="/evaluation", tags=["Evaluation & Benchmarking"])


@router.get(
    "/suites",
    response_model=List[EvaluationSuiteInfo],
    summary="List available benchmark scenario suites",
    description="Returns predefined benchmark scenario suites with their default sample counts and descriptions.",
)
def list_suites() -> List[EvaluationSuiteInfo]:
    return ComparativeEvaluationService.list_suites()


@router.post(
    "/run",
    response_model=EvaluationRunResponse,
    summary="Execute comparative evaluation benchmark",
    description="Runs dual evaluation across Adaptive AI and Traditional Static Policy Baseline on ground-truth labeled scenarios.",
)
def run_evaluation(
    req: EvaluationRunRequest,
    db: Session = Depends(get_db),
) -> EvaluationRunResponse:
    if req.sample_count < 10 or req.sample_count > 500:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Sample count must be between 10 and 500 (received {req.sample_count}).",
        )

    valid_suites = [s.suite_name for s in ComparativeEvaluationService.list_suites()]
    if req.suite_name not in valid_suites:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid suite_name '{req.suite_name}'. Allowed suites: {valid_suites}",
        )

    return ComparativeEvaluationService.run_evaluation(request=req, db=db)


@router.get(
    "/export",
    summary="Export latest evaluation benchmark report",
    description="Generates an exportable evaluation benchmark report in JSON or CSV format.",
)
def export_evaluation(
    suite_name: str = Query("FULL_BENCHMARK", description="Scenario suite name"),
    sample_count: int = Query(200, ge=10, le=500, description="Sample count"),
    export_format: str = Query("json", description="Export format: 'json' or 'csv'"),
    db: Session = Depends(get_db),
) -> Response:
    req = EvaluationRunRequest(
        suite_name=suite_name,  # type: ignore
        sample_count=sample_count,
        include_shap=False,
        persist_events=False,
    )
    result = ComparativeEvaluationService.run_evaluation(req, db=db)

    if export_format.lower() == "csv":
        csv_content = ComparativeEvaluationService.export_report_csv(result)
        return Response(
            content=csv_content,
            media_type="text/csv",
            headers={
                "Content-Disposition": f"attachment; filename=gateway_evaluation_{suite_name.lower()}.csv"
            },
        )
    else:
        json_content = result.model_dump_json(indent=2)
        return Response(
            content=json_content,
            media_type="application/json",
            headers={
                "Content-Disposition": f"attachment; filename=gateway_evaluation_{suite_name.lower()}.json"
            },
        )
