"""
Scenario 4: Controlled High-Volume Data Transfer (SUSPICIOUS_TRANSFER)
======================================================================
Generates a controlled outbound bulk payload stream from On-Premises workload
(10.10.10.30 / 10.10.10.50) across lab-router to Cloud Workload (10.20.10.40:8443).
Adheres to the FlowAggregator 30s session window (240 packets of ~1320 bytes over ~22s).
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import time
from typing import Any, Dict, List
import urllib.request

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet
from scapy.utils import wrpcap

from scenarios import assert_lab_ip


def execute_scenario_suspicious_transfer(
    src_ip: str = "10.10.10.30",
    dst_ip: str = "10.20.10.40",
    dst_port: int = 8443,
    output_dir: Path = Path("/var/lib/hybrid-lab/telemetry"),
) -> Dict[str, Any]:
    assert_lab_ip(src_ip)
    assert_lab_ip(dst_ip)

    pcap_dir = output_dir / "pcaps"
    meta_dir = output_dir / "metadata"
    pcap_dir.mkdir(parents=True, exist_ok=True)
    meta_dir.mkdir(parents=True, exist_ok=True)

    # 1. Perform bounded live POST payload transfer across lab-router to cloud-workload
    bytes_transferred_live = 0
    try:
        chunk = b"BULK_TRANSFER_SEGMENT_" * 1024
        req = urllib.request.Request(
            f"http://{dst_ip}:{dst_port}/upload-archive",
            data=chunk,
            headers={"Content-Type": "application/octet-stream"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=2.5) as resp:
            if resp.status == 200:
                bytes_transferred_live = len(chunk)
    except Exception:
        pass

    # 2. Write bounded PCAP trace (240 frames, ~1,320 bytes each, across 22.0 seconds)
    packets: List[Packet] = []
    base_time = time.time() - 23.0
    src_port = 51200

    for i in range(240):
        t = base_time + (i * 0.0916)
        payload = b"BULK_ENCRYPTED_ARCHIVE_STREAM_SEGMENT_" + b"Z" * 1260
        p = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=src_port, dport=dst_port, flags="PA", seq=1000 + (i * 1300))
            / payload
        )
        p.time = t
        packets.append(p)

    filename = "scenario4_suspicious_transfer_onprem_to_cloud.pcap"
    pcap_path = pcap_dir / filename
    wrpcap(str(pcap_path), packets)

    meta = {
        "scenario_id": "scenario4_suspicious_transfer",
        "scenario_name": "Scenario 4: Controlled High-Volume Suspicious Transfer",
        "source_ip": src_ip,
        "source_zone": "ON_PREMISE",
        "destination_ip": dst_ip,
        "destination_zone": "AWS_VPC",
        "transit_gateway": "10.10.10.2 -> 10.20.10.2 (lab-router)",
        "traffic_direction": "ON_PREM_TO_CLOUD",
        "expected_ml_class": "SUSPICIOUS_TRANSFER",
        "packets_written": len(packets),
        "live_bytes_posted": bytes_transferred_live,
        "pcap_filename": filename,
        "pcap_path": str(pcap_path),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    (meta_dir / f"{filename}.meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta

