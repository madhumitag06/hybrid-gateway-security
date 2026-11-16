"""
Hybrid-Cloud Telemetry Sensor & Ingestion Adapter
=================================================
Connects the virtual hybrid-cloud telemetry plane (`/var/lib/hybrid-lab/telemetry`)
to the existing FastAPI Adaptive AI Security Gateway (`http://gateway-api:8000`):

  1. Enforces bounded PCAP storage and rotation.
  2. Tracks processed PCAPs using SHA-256 persistent ledger (`IngestionLedger`).
  3. Uploads captured PCAP files to `POST /api/v1/ingest/pcap`.
  4. Generates AWS VPC Flow Logs v2-compatible simulation records from captured lab
     traffic and submits them to `POST /api/v1/hybrid/ingest-vpc-logs` with
     `is_fixture=True` (truthfully labeled as simulated telemetry).
  5. Guarantees idempotent startup scanning and avoids duplicate processing.
"""

import argparse
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import sys
import time
from typing import Any, Dict, List, Optional
import urllib.error
import urllib.request
import uuid

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("telemetry_sensor")

SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
sys.path.insert(0, str(SCRIPT_DIR / "capture"))
sys.path.insert(0, str(SCRIPT_DIR / "flowlog-generator"))

from ingestion_ledger import IngestionLedger  # type: ignore
from pcap_rotator import enforce_capture_bounds, trigger_router_capture  # type: ignore
from vpc_flowlog_exporter import convert_pcap_to_simulated_vpc_flow_logs  # type: ignore

TELEMETRY_ROOT = Path(os.getenv("LAB_TELEMETRY_DIR", "/var/lib/hybrid-lab/telemetry"))
PCAP_DIR = TELEMETRY_ROOT / "pcaps"
FLOWLOG_DIR = TELEMETRY_ROOT / "flowlogs"
META_DIR = TELEMETRY_ROOT / "metadata"
GATEWAY_API_URL = os.getenv("GATEWAY_API_URL", "http://gateway-api:8000").rstrip("/")


def upload_pcap_to_gateway(pcap_path: Path, persist: bool = True) -> Dict[str, Any]:
    """
    Uploads a PCAP file via multipart/form-data to the existing gateway ingestion API
    (`POST /api/v1/ingest/pcap`).
    """
    boundary = f"----HybridGatewayBoundary{uuid.uuid4().hex}"
    pcap_bytes = pcap_path.read_bytes()

    body_parts = [
        f"--{boundary}\r\n".encode("utf-8"),
        f'Content-Disposition: form-data; name="file"; filename="{pcap_path.name}"\r\n'.encode("utf-8"),
        b"Content-Type: application/vnd.tcpdump.pcap\r\n\r\n",
        pcap_bytes,
        b"\r\n",
        f"--{boundary}\r\n".encode("utf-8"),
        b'Content-Disposition: form-data; name="persist"\r\n\r\n',
        ("true" if persist else "false").encode("utf-8"),
        b"\r\n",
        f"--{boundary}--\r\n".encode("utf-8"),
    ]
    body = b"".join(body_parts)

    headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
    service_key = os.getenv("GATEWAY_SERVICE_KEY", "").strip()
    if service_key:
        headers["X-Service-Token"] = service_key

    req = urllib.request.Request(
        f"{GATEWAY_API_URL}/api/v1/ingest/pcap",
        data=body,
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def ingest_simulated_vpc_flowlogs_to_gateway(
    raw_content: str,
    source_label: str,
    persist: bool = True,
) -> Dict[str, Any]:
    """
    Submits AWS VPC Flow Logs-compatible simulation records to `POST /api/v1/hybrid/ingest-vpc-logs`
    with `is_fixture=True` so they are truthfully recorded as simulated VPC telemetry.
    """
    payload = json.dumps(
        {
            "raw_log_content": raw_content,
            "is_fixture": True,
            "persist": persist,
            "source_label": source_label,
        }
    ).encode("utf-8")

    headers = {"Content-Type": "application/json"}
    service_key = os.getenv("GATEWAY_SERVICE_KEY", "").strip()
    if service_key:
        headers["X-Service-Token"] = service_key

    req = urllib.request.Request(
        f"{GATEWAY_API_URL}/api/v1/hybrid/ingest-vpc-logs",
        data=payload,
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def process_and_ingest_pcap(
    pcap_path: Path,
    include_vpc_flowlogs: bool = True,
    persist: bool = True,
    ledger: Optional[IngestionLedger] = None,
) -> Dict[str, Any]:
    """
    Safely ingests a PCAP file and optionally generates simulated AWS VPC flow logs.
    Tracks state in the persistent IngestionLedger:
      - Validates deduplication and idempotency.
      - Acquires concurrency lock.
      - Marks IN_PROGRESS.
      - Uploads and evaluates via Gateway API.
      - Marks COMPLETED on success, or FAILED on error.
    """
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    # Enforce volume bounds
    rotation_info = enforce_capture_bounds(PCAP_DIR, META_DIR)

    sha256_hash: Optional[str] = None
    if ledger is not None:
        should, reason, sha256_hash = ledger.should_ingest(pcap_path)
        if not should:
            logger.info(f"[IDEMPOTENT_SKIP] {pcap_path.name} (SHA-256: {sha256_hash[:12] if sha256_hash else 'n/a'}): {reason}")
            existing_entry = ledger.get_entry(pcap_path.name)
            return existing_entry.get("summary") or {
                "pcap_file": pcap_path.name,
                "status": "SKIPPED_DUPLICATE",
                "reason": reason,
                "sha256": sha256_hash,
            }

        if not ledger.acquire_processing(pcap_path.name):
            logger.info(f"[CONCURRENCY_LOCKED] {pcap_path.name} is currently being processed by another worker. Skipping.")
            return {
                "pcap_file": pcap_path.name,
                "status": "SKIPPED_LOCKED",
            }

        ledger.mark_in_progress(pcap_path, sha256_hash or "")

    try:
        logger.info(f"[INGEST_START] Uploading PCAP {pcap_path.name} (SHA-256: {sha256_hash[:12] if sha256_hash else 'calculating'}...) to Gateway API")
        pcap_res = upload_pcap_to_gateway(pcap_path, persist=persist)

        vpc_res: Optional[Dict[str, Any]] = None
        flowlog_meta: Optional[Dict[str, Any]] = None

        if include_vpc_flowlogs:
            flowlog_meta = convert_pcap_to_simulated_vpc_flow_logs(pcap_path, FLOWLOG_DIR)
            if flowlog_meta["records_generated"] > 0:
                vpc_res = ingest_simulated_vpc_flowlogs_to_gateway(
                    raw_content=flowlog_meta["raw_content"],
                    source_label=flowlog_meta["flowlog_filename"],
                    persist=persist,
                )

        summary = {
            "pcap_file": pcap_path.name,
            "sha256": sha256_hash,
            "pcap_ingestion": {
                "packets_processed": pcap_res.get("metrics", {}).get("packets_processed"),
                "flows_generated": pcap_res.get("flows_generated"),
                "flows_evaluated": pcap_res.get("flows_evaluated"),
                "events_persisted": pcap_res.get("events_persisted"),
                "high_risk_flows_count": pcap_res.get("high_risk_flows_count"),
                "top_results": [
                    {
                        "flow_id": r.get("flow_id"),
                        "source_ip": r.get("flow_features", {}).get("source_ip"),
                        "destination_ip": r.get("flow_features", {}).get("destination_ip"),
                        "dst_port": r.get("flow_features", {}).get("dst_port"),
                        "attack_type": r.get("prediction", {}).get("attack_type"),
                        "risk_score": r.get("prediction", {}).get("risk_score"),
                        "confidence": r.get("prediction", {}).get("confidence"),
                        "action_recommendation": r.get("prediction", {}).get("action_recommendation"),
                        "persisted_event_id": r.get("persisted_event_id"),
                    }
                    for r in pcap_res.get("results", [])[:5]
                ],
            },
            "simulated_vpc_flowlog_ingestion": {
                "flowlog_file": flowlog_meta["flowlog_filename"] if flowlog_meta else None,
                "records_generated": flowlog_meta["records_generated"] if flowlog_meta else 0,
                "total_flows_aggregated": vpc_res.get("total_flows_aggregated") if vpc_res else 0,
                "high_risk_flows_count": vpc_res.get("high_risk_flows_count") if vpc_res else 0,
                "telemetry_source": vpc_res.get("telemetry_source") if vpc_res else "AWS_VPC_FLOW_LOG_FIXTURE",
            },
            "storage_rotation": rotation_info,
            "ingested_at_utc": datetime.now(timezone.utc).isoformat(),
        }

        if ledger is not None and sha256_hash:
            ledger.mark_completed(pcap_path, sha256_hash, summary)
            logger.info(
                f"[INGEST_SUCCESS] {pcap_path.name}: "
                f"flows={summary['pcap_ingestion']['flows_evaluated']}, "
                f"events_persisted={summary['pcap_ingestion']['events_persisted']}"
            )

        return summary

    except Exception as exc:
        if ledger is not None and sha256_hash:
            ledger.mark_failed(pcap_path, sha256_hash, str(exc))
            logger.error(f"[INGEST_FAILURE] {pcap_path.name} (SHA-256: {sha256_hash[:12]}): {exc}")
        raise exc

    finally:
        if ledger is not None:
            ledger.release_processing(pcap_path.name)


def run_startup_scan(ledger: IngestionLedger, include_vpc_logs: bool = True, persist: bool = True) -> List[Dict[str, Any]]:
    """
    Executes a deterministic, idempotent startup scan across all existing PCAPs in the
    telemetry directory. Skips already-ingested files and processes only new or modified PCAPs.
    """
    logger.info(f"[+] Executing idempotent startup scan on {PCAP_DIR}...")
    scan_results = []
    pcap_files = sorted(PCAP_DIR.glob("*.pcap*"), key=lambda p: p.name)

    for pcap_f in pcap_files:
        should, reason, sha = ledger.should_ingest(pcap_f)
        if not should:
            logger.info(f"[IDEMPOTENT_SKIP] {pcap_f.name} (SHA-256: {sha[:12] if sha else 'n/a'}): {reason}")
            continue

        try:
            summary = process_and_ingest_pcap(
                pcap_f,
                include_vpc_flowlogs=include_vpc_logs,
                persist=persist,
                ledger=ledger,
            )
            scan_results.append(summary)
        except Exception as err:
            logger.warning(f"[!] Startup scan warning for {pcap_f.name}: {err}")

    logger.info(f"[+] Startup scan completed. Ingested {len(scan_results)} new/modified PCAPs out of {len(pcap_files)} total.")
    return scan_results


def main() -> None:
    parser = argparse.ArgumentParser(description="Hybrid Lab Telemetry Sensor & Ingestion CLI")
    parser.add_argument("--daemon", action="store_true", help="Run in background sensor watch mode")
    parser.add_argument("--capture-router", type=str, help="Trigger bounded tcpdump on lab-router for scenario name")
    parser.add_argument("--duration", type=int, default=8, help="Capture duration in seconds (bounded 1..30)")
    parser.add_argument("--max-packets", type=int, default=500, help="Maximum packets to capture (bounded 10..2500)")
    parser.add_argument("--ingest-pcap", type=str, help="Filename or path of PCAP in telemetry volume to ingest")
    parser.add_argument("--ingest-latest", action="store_true", help="Ingest the most recent PCAP in /var/lib/hybrid-lab/telemetry/pcaps")
    parser.add_argument("--ingest-all", action="store_true", help="Ingest all scenario PCAPs in /var/lib/hybrid-lab/telemetry/pcaps")
    parser.add_argument("--no-vpc-logs", action="store_true", help="Skip simulated VPC flow log generation/ingestion")
    parser.add_argument("--force", action="store_true", help="Force re-ingestion regardless of ledger status")
    args = parser.parse_args()

    PCAP_DIR.mkdir(parents=True, exist_ok=True)
    FLOWLOG_DIR.mkdir(parents=True, exist_ok=True)
    META_DIR.mkdir(parents=True, exist_ok=True)

    ledger_path = META_DIR / "pcap_ingestion_ledger.json"
    ledger = IngestionLedger(ledger_path)

    if args.capture_router:
        cap_meta = trigger_router_capture(
            scenario=args.capture_router,
            max_packets=args.max_packets,
            duration_seconds=args.duration,
        )
        print(json.dumps(cap_meta, indent=2))
        return

    if args.ingest_pcap:
        cand = Path(args.ingest_pcap)
        if not cand.is_absolute():
            cand = PCAP_DIR / cand.name
        use_ledger = None if args.force else ledger
        res = process_and_ingest_pcap(cand, include_vpc_flowlogs=not args.no_vpc_logs, ledger=use_ledger)
        print(json.dumps(res, indent=2))
        return

    if args.ingest_latest:
        files = sorted(PCAP_DIR.glob("*.pcap*"), key=lambda f: f.stat().st_mtime, reverse=True)
        if not files:
            raise SystemExit("No PCAP files found in /var/lib/hybrid-lab/telemetry/pcaps")
        use_ledger = None if args.force else ledger
        res = process_and_ingest_pcap(files[0], include_vpc_flowlogs=not args.no_vpc_logs, ledger=use_ledger)
        print(json.dumps(res, indent=2))
        return

    if args.ingest_all:
        files = sorted(PCAP_DIR.glob("*.pcap*"), key=lambda f: f.name)
        all_results = []
        for f in files:
            use_ledger = None if args.force else ledger
            all_results.append(process_and_ingest_pcap(f, include_vpc_flowlogs=not args.no_vpc_logs, ledger=use_ledger))
        print(json.dumps({"ingested_count": len(all_results), "summaries": all_results}, indent=2))
        return

    if args.daemon:
        auto_ingest = os.getenv("AUTO_INGEST_ENABLED", "true").strip().lower() in ("1", "true", "yes")
        logger.info(
            f"[+] Telemetry sensor watching {PCAP_DIR} "
            f"(Gateway API: {GATEWAY_API_URL}, auto_ingest={auto_ingest})"
        )

        # Step 1: Idempotent startup scan
        if auto_ingest:
            run_startup_scan(ledger, include_vpc_logs=not args.no_vpc_logs, persist=True)

        # Step 2: Continuous watcher loop with persistent deduplication
        while True:
            try:
                enforce_capture_bounds(PCAP_DIR, META_DIR)
                if auto_ingest:
                    for pcap_f in sorted(PCAP_DIR.glob("*.pcap*"), key=lambda p: p.name):
                        should, reason, sha = ledger.should_ingest(pcap_f)
                        if not should:
                            continue

                        try:
                            summary = process_and_ingest_pcap(
                                pcap_f,
                                include_vpc_flowlogs=not args.no_vpc_logs,
                                persist=True,
                                ledger=ledger,
                            )
                            logger.info(
                                f"[+] Auto-ingested {pcap_f.name}: "
                                f"flows={summary['pcap_ingestion']['flows_evaluated']}, "
                                f"events_persisted={summary['pcap_ingestion']['events_persisted']}"
                            )
                        except Exception as ingest_err:
                            logger.warning(f"[!] Auto-ingest warning for {pcap_f.name}: {ingest_err}")
            except Exception as loop_err:
                logger.warning(f"[!] Telemetry loop warning: {loop_err}")
            time.sleep(5.0)


if __name__ == "__main__":
    main()
