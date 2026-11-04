"""
Hybrid-Cloud Telemetry Sensor & Ingestion Adapter
=================================================
Connects the virtual hybrid-cloud telemetry plane (`/var/lib/hybrid-lab/telemetry`)
to the existing FastAPI Adaptive AI Security Gateway (`http://gateway-api:8000`):

  1. Enforces bounded PCAP storage and rotation.
  2. Uploads captured PCAP files to `POST /api/v1/ingest/pcap`.
  3. Generates AWS VPC Flow Logs v2-compatible simulation records from captured lab
     traffic and submits them to `POST /api/v1/hybrid/ingest-vpc-logs` with
     `is_fixture=True` (truthfully labeled as simulated telemetry).
"""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import time
from typing import Any, Dict, Optional
import urllib.error
import urllib.request
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parent / "capture"))
sys.path.insert(0, str(Path(__file__).resolve().parent / "flowlog-generator"))

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

    req = urllib.request.Request(
        f"{GATEWAY_API_URL}/api/v1/ingest/pcap",
        data=body,
        headers={"Content-Type": f"multipart/form-data; boundary={boundary}"},
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

    req = urllib.request.Request(
        f"{GATEWAY_API_URL}/api/v1/hybrid/ingest-vpc-logs",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def process_and_ingest_pcap(
    pcap_path: Path,
    include_vpc_flowlogs: bool = True,
    persist: bool = True,
) -> Dict[str, Any]:
    if not pcap_path.exists():
        raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

    rotation_info = enforce_capture_bounds(PCAP_DIR, META_DIR)
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
    return summary


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
    args = parser.parse_args()

    PCAP_DIR.mkdir(parents=True, exist_ok=True)
    FLOWLOG_DIR.mkdir(parents=True, exist_ok=True)
    META_DIR.mkdir(parents=True, exist_ok=True)

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
        res = process_and_ingest_pcap(cand, include_vpc_flowlogs=not args.no_vpc_logs)
        print(json.dumps(res, indent=2))
        return

    if args.ingest_latest:
        files = sorted(PCAP_DIR.glob("*.pcap*"), key=lambda f: f.stat().st_mtime, reverse=True)
        if not files:
            raise SystemExit("No PCAP files found in /var/lib/hybrid-lab/telemetry/pcaps")
        res = process_and_ingest_pcap(files[0], include_vpc_flowlogs=not args.no_vpc_logs)
        print(json.dumps(res, indent=2))
        return

    if args.ingest_all:
        files = sorted(PCAP_DIR.glob("*.pcap*"), key=lambda f: f.name)
        all_results = []
        for f in files:
            all_results.append(process_and_ingest_pcap(f, include_vpc_flowlogs=not args.no_vpc_logs))
        print(json.dumps({"ingested_count": len(all_results), "summaries": all_results}, indent=2))
        return

    if args.daemon:
        auto_ingest = os.getenv("AUTO_INGEST_ENABLED", "true").strip().lower() in ("1", "true", "yes")
        seen_mtime_ns: Dict[str, int] = {}
        print(
            f"[+] Telemetry sensor watching {PCAP_DIR} "
            f"(Gateway API: {GATEWAY_API_URL}, auto_ingest={auto_ingest})"
        )
        while True:
            try:
                enforce_capture_bounds(PCAP_DIR, META_DIR)
                if auto_ingest:
                    for pcap_f in sorted(PCAP_DIR.glob("*.pcap*"), key=lambda p: p.name):
                        try:
                            stat = pcap_f.stat()
                            if stat.st_size > 24 and seen_mtime_ns.get(pcap_f.name) != stat.st_mtime_ns:
                                summary = process_and_ingest_pcap(
                                    pcap_f,
                                    include_vpc_flowlogs=not args.no_vpc_logs,
                                    persist=True,
                                )
                                seen_mtime_ns[pcap_f.name] = stat.st_mtime_ns
                                print(
                                    f"[+] Auto-ingested {pcap_f.name}: "
                                    f"flows={summary['pcap_ingestion']['flows_evaluated']}, "
                                    f"events_persisted={summary['pcap_ingestion']['events_persisted']}"
                                )
                        except Exception as ingest_err:
                            print(f"[!] Auto-ingest warning for {pcap_f.name}: {ingest_err}")
            except Exception as loop_err:
                print(f"[!] Telemetry loop warning: {loop_err}")
            time.sleep(5.0)


if __name__ == "__main__":
    main()

