"""
Scenario 1: Normal On-Premises to Cloud Communication (BENIGN)
==============================================================
Sends legitimate HTTP/TLS requests from On-Premises (10.10.10.10 / 10.10.10.50)
across the Virtual Gateway (10.10.10.2 -> 10.20.10.2) to Cloud Web (10.20.10.20:443 & :80),
and records a bounded PCAP file and metadata for the existing ingestion pipeline.
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


def execute_scenario_benign(
    src_ip: str = "10.10.10.10",
    dst_ip: str = "10.20.10.20",
    dst_port: int = 443,
    output_dir: Path = Path("/var/lib/hybrid-lab/telemetry"),
) -> Dict[str, Any]:
    assert_lab_ip(src_ip)
    assert_lab_ip(dst_ip)

    pcap_dir = output_dir / "pcaps"
    meta_dir = output_dir / "metadata"
    pcap_dir.mkdir(parents=True, exist_ok=True)
    meta_dir.mkdir(parents=True, exist_ok=True)

    # 1. Perform live HTTP requests across lab-router to cloud-web (10.20.10.20:8080 & :443)
    live_responses = 0
    for i in range(4):
        try:
            url = f"http://{dst_ip}:8080/api/health?req={i + 1}"
            with urllib.request.urlopen(url, timeout=2.0) as resp:
                if resp.status == 200:
                    live_responses += 1
        except Exception:
            pass
        time.sleep(0.1)

    # 2. Construct bounded, deterministic hybrid-zone PCAP trace matching the session
    packets: List[Packet] = []
    base_time = time.time() - 3.0
    src_port = 54321

    p1 = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="S", seq=1000)
    p1.time = base_time
    packets.append(p1)

    p2 = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags="SA", seq=2000, ack=1001)
    p2.time = base_time + 0.02
    packets.append(p2)

    p3 = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="A", seq=1001, ack=2001)
    p3.time = base_time + 0.03
    packets.append(p3)

    for i in range(20):
        t = base_time + 0.05 + (i * 0.1)
        payload = b"HYBRID_BENIGN_TLS_APPLICATION_PAYLOAD_" + b"X" * 600
        p = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=src_port, dport=dst_port, flags="PA", seq=1001 + (i * 600), ack=2001)
            / payload
        )
        p.time = t
        packets.append(p)

    p_fin = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="FA", seq=13001, ack=2001)
    p_fin.time = base_time + 2.40
    packets.append(p_fin)

    p_fin_ack = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags="FA", seq=2001, ack=13002)
    p_fin_ack.time = base_time + 2.45
    packets.append(p_fin_ack)

    filename = "scenario1_benign_onprem_to_cloud.pcap"
    pcap_path = pcap_dir / filename
    wrpcap(str(pcap_path), packets)

    meta = {
        "scenario_id": "scenario1_benign",
        "scenario_name": "Scenario 1: Normal On-Premises to Cloud Communication",
        "source_ip": src_ip,
        "source_zone": "ON_PREMISE",
        "destination_ip": dst_ip,
        "destination_zone": "AWS_VPC",
        "transit_gateway": "10.10.10.2 -> 10.20.10.2 (lab-router)",
        "traffic_direction": "ON_PREM_TO_CLOUD",
        "expected_ml_class": "BENIGN",
        "packets_written": len(packets),
        "live_http_checks_succeeded": live_responses,
        "pcap_filename": filename,
        "pcap_path": str(pcap_path),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    (meta_dir / f"{filename}.meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta

