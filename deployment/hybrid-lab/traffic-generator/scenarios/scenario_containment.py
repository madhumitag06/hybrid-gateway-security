"""
Scenario 5: Blocked or Restricted Cross-Boundary Communication
==============================================================
Generates high-risk cross-gateway probing traffic from 10.10.10.50 toward
Cloud Database (10.20.10.30:5432) and Cloud Workload (10.20.10.40:445),
triggering a deterministic PolicyEngine Block/Restrict decision, audit ledger entry,
and (when optional lab enforcement is opted-in) isolated lab-router packet filtering.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import socket
import time
from typing import Any, Dict, List

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet
from scapy.utils import wrpcap

from scenarios import assert_lab_ip


def execute_scenario_containment(
    src_ip: str = "10.10.10.50",
    dst_ip: str = "10.20.10.30",
    output_dir: Path = Path("/var/lib/hybrid-lab/telemetry"),
) -> Dict[str, Any]:
    assert_lab_ip(src_ip)
    assert_lab_ip(dst_ip)

    pcap_dir = output_dir / "pcaps"
    meta_dir = output_dir / "metadata"
    pcap_dir.mkdir(parents=True, exist_ok=True)
    meta_dir.mkdir(parents=True, exist_ok=True)

    sensitive_ports = [
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
        1433, 1521, 3306, 3389, 5432, 5900, 6379, 8000, 8080, 8443, 9000, 9200, 27017,
    ]

    # 1. Test initial connectivity across lab-router to cloud-db (10.20.10.30:5432)
    initial_probe_reachable = False
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.5)
    try:
        initial_probe_reachable = s.connect_ex((dst_ip, 5432)) == 0
    except Exception:
        pass
    finally:
        s.close()

    # 2. Generate high-risk multi-port sweep PCAP targeting sensitive cloud DB/admin ports
    packets: List[Packet] = []
    base_time = time.time() - 1.0
    src_port_base = 55000

    for idx, dport in enumerate(sensitive_ports):
        t = base_time + (idx * 0.004)
        p_syn = IP(src=src_ip, dst=dst_ip) / TCP(
            sport=src_port_base + idx, dport=dport, flags="S", seq=9000 + idx
        )
        p_syn.time = t
        packets.append(p_syn)

        p_rst = IP(src=dst_ip, dst=src_ip) / TCP(
            sport=dport, dport=src_port_base + idx, flags="RA", seq=0, ack=9001 + idx
        )
        p_rst.time = t + 0.001
        packets.append(p_rst)

    filename = "scenario5_blocked_restricted_containment.pcap"
    pcap_path = pcap_dir / filename
    wrpcap(str(pcap_path), packets)

    meta = {
        "scenario_id": "scenario5_containment",
        "scenario_name": "Scenario 5: Blocked or Restricted Cross-Boundary Communication",
        "source_ip": src_ip,
        "source_zone": "ON_PREMISE",
        "destination_ip": dst_ip,
        "destination_zone": "AWS_VPC",
        "transit_gateway": "10.10.10.2 -> 10.20.10.2 (lab-router)",
        "traffic_direction": "ON_PREM_TO_CLOUD",
        "expected_ml_class": "PORT_SCAN",
        "expected_policy_action": "Block",
        "expected_policy_rule": "RECON_PORT_SCAN_QUARANTINE",
        "initial_cloud_db_reachable": initial_probe_reachable,
        "packets_written": len(packets),
        "pcap_filename": filename,
        "pcap_path": str(pcap_path),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    (meta_dir / f"{filename}.meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta

