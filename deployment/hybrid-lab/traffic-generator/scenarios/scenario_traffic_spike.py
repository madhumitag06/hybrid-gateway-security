"""
Scenario 3: Controlled Volumetric Traffic Spike (TRAFFIC_SPIKE)
===============================================================
Generates a bounded high-rate HTTP packet burst toward the isolated Cloud VPC
workload (10.20.10.40:80) with strict packet-count (<= 1200) and duration (3.0s) limits.
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

MAX_SPIKE_PACKETS = 1200


def execute_scenario_traffic_spike(
    src_ip: str = "10.10.10.50",
    dst_ip: str = "10.20.10.40",
    dst_port: int = 80,
    packet_count: int = 1200,
    output_dir: Path = Path("/var/lib/hybrid-lab/telemetry"),
) -> Dict[str, Any]:
    assert_lab_ip(src_ip)
    assert_lab_ip(dst_ip)

    bounded_packets = min(max(packet_count, 400), MAX_SPIKE_PACKETS)

    pcap_dir = output_dir / "pcaps"
    meta_dir = output_dir / "metadata"
    pcap_dir.mkdir(parents=True, exist_ok=True)
    meta_dir.mkdir(parents=True, exist_ok=True)

    # 1. Send bounded burst of 15 HTTP requests across lab-router to cloud-workload:8080
    live_sent = 0
    for i in range(15):
        try:
            url = f"http://{dst_ip}:8080/spike-test?seq={i}"
            with urllib.request.urlopen(url, timeout=0.5) as resp:
                if resp.status == 200:
                    live_sent += 1
        except Exception:
            pass

    # 2. Write bounded volumetric burst PCAP (1,200 packets across 3.0 seconds)
    packets: List[Packet] = []
    base_time = time.time() - 3.5
    src_port = 45000

    for i in range(bounded_packets):
        t = base_time + (i * 0.0025)
        payload = b"GET /highload_benchmark HTTP/1.1\r\nHost: cloud-workload\r\n\r\n" + b"A" * 900
        p = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=src_port, dport=dst_port, flags="PA", seq=1000 + (i * 900))
            / payload
        )
        p.time = t
        packets.append(p)

    filename = "scenario3_traffic_spike_onprem_to_cloud.pcap"
    pcap_path = pcap_dir / filename
    wrpcap(str(pcap_path), packets)

    meta = {
        "scenario_id": "scenario3_traffic_spike",
        "scenario_name": "Scenario 3: Controlled Volumetric Traffic Spike",
        "source_ip": src_ip,
        "source_zone": "ON_PREMISE",
        "destination_ip": dst_ip,
        "destination_zone": "AWS_VPC",
        "transit_gateway": "10.10.10.2 -> 10.20.10.2 (lab-router)",
        "traffic_direction": "ON_PREM_TO_CLOUD",
        "expected_ml_class": "TRAFFIC_SPIKE",
        "packets_written": len(packets),
        "live_burst_requests_completed": live_sent,
        "pcap_filename": filename,
        "pcap_path": str(pcap_path),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    (meta_dir / f"{filename}.meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta

