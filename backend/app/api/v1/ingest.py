"""
Traffic Ingestion API Router (v1)
=================================
Handles PCAP file uploads, sample PCAP fixture ingestion, and ingestion subsystem telemetry.
"""

import os
from pathlib import Path
import shutil
import tempfile
from typing import List, Optional
from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile, status
from sqlalchemy.orm import Session

from backend.app.db.session import get_db
from backend.app.schemas.ingest import (
    IngestionStatusResponse,
    PcapIngestionResponse,
    SamplePcapInfo,
)
from backend.app.services.ingestion_service import IngestionService

router = APIRouter(prefix="/v1/ingest", tags=["Traffic Ingestion"])

MAX_UPLOAD_SIZE_BYTES = 15 * 1024 * 1024  # 15 MB limit
ALLOWED_EXTENSIONS = {".pcap", ".pcapng", ".cap"}


@router.get(
    "/status",
    response_model=IngestionStatusResponse,
    summary="Get traffic ingestion engine status",
    description="Returns operational status, cumulative counters, and platform capture support details.",
)
def get_ingestion_status() -> IngestionStatusResponse:
    return IngestionService.get_status()


@router.get(
    "/samples",
    response_model=List[SamplePcapInfo],
    summary="List available sample PCAP test fixtures",
    description="Returns metadata for pre-packaged reproducible PCAP captures for demonstrations and tests.",
)
def list_sample_pcaps() -> List[SamplePcapInfo]:
    return IngestionService.list_samples()


@router.post(
    "/samples/{sample_filename}",
    response_model=PcapIngestionResponse,
    summary="Ingest a built-in sample PCAP fixture",
    description="Parses, aggregates, evaluates, and optionally persists flows from a verified demonstration PCAP fixture.",
)
def ingest_sample_pcap(
    sample_filename: str,
    persist: bool = Query(True, description="Whether to persist evaluated flow events into PostgreSQL"),
    db: Session = Depends(get_db),
) -> PcapIngestionResponse:
    target_path = IngestionService.get_sample_path(sample_filename)
    return IngestionService.ingest_pcap_file(
        filepath=target_path,
        filename=sample_filename,
        persist=persist,
        db=db,
    )


@router.post(
    "/pcap",
    response_model=PcapIngestionResponse,
    summary="Upload and ingest a PCAP / PCAPNG capture file",
    description="Accepts a raw PCAP or PCAPNG capture file, parses IP packets, aggregates bidirectional flows, runs Phase 1 ML threat prediction, and optionally persists results to PostgreSQL.",
)
async def upload_and_ingest_pcap(
    file: UploadFile = File(..., description="PCAP or PCAPNG network trace file"),
    persist: bool = Form(True, description="Whether to persist evaluated flows into PostgreSQL"),
    db: Session = Depends(get_db),
) -> PcapIngestionResponse:
    filename = file.filename or "uploaded_capture.pcap"
    ext = Path(filename).suffix.lower()

    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid file extension '{ext}'. Allowed extensions: {sorted(list(ALLOWED_EXTENSIONS))}",
        )

    # Isolated temporary file with strict cleanup
    temp_dir = Path(tempfile.mkdtemp(prefix="gateway_pcap_"))
    safe_filename = Path(filename).name
    temp_file_path = temp_dir / safe_filename

    try:
        bytes_read = 0
        with open(temp_file_path, "wb") as buffer:
            while chunk := await file.read(64 * 1024):  # 64 KB chunks
                bytes_read += len(chunk)
                if bytes_read > MAX_UPLOAD_SIZE_BYTES:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"Uploaded file exceeds maximum allowed size of {MAX_UPLOAD_SIZE_BYTES // (1024 * 1024)} MB.",
                    )
                buffer.write(chunk)

        if bytes_read == 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Uploaded PCAP file is empty (0 bytes).",
            )

        response = IngestionService.ingest_pcap_file(
            filepath=temp_file_path,
            filename=safe_filename,
            persist=persist,
            db=db,
        )
        return response

    finally:
        # Guarantee removal of temporary files
        try:
            if temp_file_path.exists():
                temp_file_path.unlink()
            if temp_dir.exists():
                shutil.rmtree(temp_dir, ignore_errors=True)
        except Exception:
            pass
