"""
Hybrid Cloud & AWS Telemetry REST API Endpoints
================================================
Endpoints for hybrid network zone topology, AWS VPC Flow Log ingestion,
benchmark sample execution, and cloud telemetry status.
"""

from typing import Any, Dict, List
from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile, status
from sqlalchemy.orm import Session

from backend.app.db.session import get_db
from backend.app.schemas.aws_flow import (
    AwsVpcIngestionRequest,
    AwsVpcIngestionResponse,
    AwsVpcSampleFixtureInfo,
)
from backend.app.services.aws_sample_fixtures import (
    AWS_FIXTURE_DIR,
    ensure_aws_sample_fixtures,
)
from backend.app.services.aws_telemetry_client import AwsTelemetryClient
from backend.app.services.aws_vpc_flow_parser import AwsVpcFlowParser
from backend.app.services.hybrid_topology import (
    HybridTopologySummary,
    NetworkZoneClassifier,
)

router = APIRouter(prefix="/hybrid", tags=["Hybrid Cloud & AWS Telemetry"])


@router.get(
    "/topology",
    response_model=HybridTopologySummary,
    summary="Get Hybrid Network Topology Configuration",
    description="Returns configured On-Premises and AWS VPC CIDR ranges and cloud security boundaries.",
)
def get_hybrid_topology() -> HybridTopologySummary:
    return NetworkZoneClassifier.get_topology_summary()


@router.get(
    "/telemetry-status",
    response_model=Dict[str, Any],
    summary="Get AWS Telemetry Ingestion Status",
    description="Reports whether AWS integration is in offline fixture mode or read-only CloudWatch/S3 mode.",
)
def get_telemetry_status() -> Dict[str, Any]:
    return AwsTelemetryClient.get_status()


@router.get(
    "/lab-status",
    response_model=Dict[str, Any],
    summary="Get Virtual Hybrid-Cloud Lab & Telemetry Status",
    description="Returns configured hybrid lab topology, real PCAP/VPC ingestion counters, persisted event statistics, and enforcement state.",
)
def get_hybrid_lab_status(db: Session = Depends(get_db)) -> Dict[str, Any]:
    from sqlalchemy import func
    from backend.app.config import settings
    from backend.app.models.security_event import SecurityEventModel
    from backend.app.repositories.enforcement_repo import EnforcementRepository
    from backend.app.services.enforcement_service import EnforcementService
    from backend.app.services.ingestion_service import IngestionService
    from backend.app.services.ml_service import MLService

    topo = NetworkZoneClassifier.get_topology_summary()
    ingest_status = IngestionService.get_status()
    enforce_repo = EnforcementRepository(db)
    enforce_repo.prune_expired_rules()
    active_rules = enforce_repo.list_active_rules()

    total_events = db.query(func.count(SecurityEventModel.id)).scalar() or 0
    high_risk_events = (
        db.query(func.count(SecurityEventModel.id))
        .filter(SecurityEventModel.risk_score >= 70)
        .scalar()
        or 0
    )

    return {
        "environment_type": "SIMULATED_DOCKER_HYBRID_CLOUD",
        "topology": topo.model_dump(),
        "gateway_intelligence": {
            "ml_model_loaded": MLService.is_loaded(),
            "model_type": "RandomForestClassifier",
            "shap_explainer": "Conditional TreeExplainer (threshold >= 50)",
            "enforcement_mode": EnforcementService.get_mode(),
            "lab_data_plane_enforcement_opt_in": getattr(settings, "lab_enforcement_enabled", False),
            "active_containment_rules_count": len(active_rules),
        },
        "telemetry_counters": {
            "total_pcaps_ingested": ingest_status.total_pcaps_ingested,
            "total_packets_processed": ingest_status.total_packets_processed,
            "total_flows_generated": ingest_status.total_flows_generated,
            "persisted_security_events": total_events,
            "high_risk_events": high_risk_events,
            "pcap_max_evaluated_flows": settings.pcap_max_evaluated_flows,
            "pcap_max_response_flows": settings.pcap_max_response_flows,
        },
        "provenance_distinction": {
            "topology_source": "CONFIGURED_HYBRID_TOPOLOGY",
            "cloud_representation": "SIMULATED_AWS_VPC_ENVIRONMENT (10.20.10.0/24)",
            "onprem_representation": "ISOLATED_PRIVATE_ENVIRONMENT (10.10.10.0/24)",
            "transit_gateway": "DEDICATED_LINUX_ROUTER (lab-router: 10.10.10.2 <-> 10.20.10.2)",
            "host_network_isolation": "STRICT_DOCKER_BRIDGE_ISOLATION (Zero Windows Host Firewall/Route Changes)",
        },
    }


@router.get(
    "/samples",
    response_model=List[AwsVpcSampleFixtureInfo],
    summary="List Benchmark AWS VPC Flow Log Fixtures",
    description="Returns metadata for pre-packaged reproducible AWS VPC Flow Log benchmark test scenarios.",
)
def list_sample_fixtures() -> List[AwsVpcSampleFixtureInfo]:
    return ensure_aws_sample_fixtures()


@router.post(
    "/ingest-vpc-logs",
    response_model=AwsVpcIngestionResponse,
    summary="Ingest AWS VPC Flow Logs (Direct Text or File)",
    description="Parses AWS VPC Flow Logs, performs ML threat prediction and PolicyEngine evaluation, and persists events to PostgreSQL.",
)
def ingest_vpc_flow_logs(
    payload: AwsVpcIngestionRequest,
    db: Session = Depends(get_db),
) -> AwsVpcIngestionResponse:
    if not payload.raw_log_content or not payload.raw_log_content.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No VPC flow log content provided in request payload.",
        )

    label = payload.source_label or ("vpc_fixture_input" if payload.is_fixture else "vpc_flow_log_upload")

    return AwsVpcFlowParser.ingest_vpc_flow_records(
        raw_content=payload.raw_log_content,
        is_fixture=payload.is_fixture,
        source_label=label,
        persist=payload.persist,
        db=db,
    )


@router.post(
    "/upload-vpc-file",
    response_model=AwsVpcIngestionResponse,
    summary="Upload and Ingest AWS VPC Flow Log File (.log, .txt, .tsv)",
    description="Uploads a VPC flow log file for immediate parsing, ML inference, and PostgreSQL persistence.",
)
async def upload_vpc_log_file(
    file: UploadFile = File(..., description="VPC flow log text file"),
    is_fixture: bool = Form(default=False, description="Whether this is a synthetic benchmark fixture"),
    persist: bool = Form(default=True, description="Whether to store security events in PostgreSQL"),
    db: Session = Depends(get_db),
) -> AwsVpcIngestionResponse:
    if not file.filename:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing filename.",
        )

    content_bytes = await file.read()
    if not content_bytes:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Uploaded file is empty (0 bytes).",
        )

    try:
        raw_text = content_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Uploaded file is not valid UTF-8 text.",
        )

    return AwsVpcFlowParser.ingest_vpc_flow_records(
        raw_content=raw_text,
        is_fixture=is_fixture,
        source_label=file.filename,
        persist=persist,
        db=db,
    )


@router.post(
    "/samples/{sample_id}/ingest",
    response_model=AwsVpcIngestionResponse,
    summary="Ingest Benchmark AWS VPC Flow Log Fixture",
    description="Loads a built-in benchmark fixture, normalizes flow records, and evaluates events via ML and PolicyEngine.",
)
def ingest_sample_fixture(
    sample_id: str,
    persist: bool = True,
    db: Session = Depends(get_db),
) -> AwsVpcIngestionResponse:
    samples = ensure_aws_sample_fixtures()
    target_sample = next((s for s in samples if s.sample_id == sample_id), None)
    if not target_sample:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Sample fixture '{sample_id}' not found.",
        )

    file_path = AWS_FIXTURE_DIR / target_sample.filename
    if not file_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Fixture file '{target_sample.filename}' missing from disk.",
        )

    raw_text = file_path.read_text(encoding="utf-8")

    return AwsVpcFlowParser.ingest_vpc_flow_records(
        raw_content=raw_text,
        is_fixture=True,  # Built-in samples are strictly fixtures
        source_label=target_sample.filename,
        persist=persist,
        db=db,
    )


@router.get(
    "/scenarios",
    response_model=List[Dict[str, Any]],
    summary="List Hybrid-Cloud Traffic Generation Scenarios",
    description="Returns metadata for the 6 real cross-network traffic scenarios available in the virtual hybrid lab.",
)
def list_hybrid_scenarios() -> List[Dict[str, Any]]:
    from backend.app.services.hybrid_traffic_service import HybridTrafficService
    return HybridTrafficService.list_scenarios()


@router.post(
    "/scenarios/{scenario_id}/run",
    response_model=Dict[str, Any],
    summary="Trigger Hybrid-Cloud Network Traffic Scenario",
    description="Dispatches a real cross-boundary traffic generation scenario to the traffic-generator container and reports execution results.",
)
def run_hybrid_scenario(scenario_id: str) -> Dict[str, Any]:
    from backend.app.services.hybrid_traffic_service import HybridTrafficService
    try:
        return HybridTrafficService.run_scenario(scenario_id)
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))
    except Exception as ex:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(ex))


@router.get(
    "/infrastructure/health",
    response_model=Dict[str, Any],
    summary="Get Hybrid Lab 13-Container Infrastructure Health",
    description="Probes the lab-router agent, database connection, and returns verified status of all 13 Docker services.",
)
def get_infrastructure_health() -> Dict[str, Any]:
    from backend.app.services.hybrid_traffic_service import HybridTrafficService
    return HybridTrafficService.get_infrastructure_health()
