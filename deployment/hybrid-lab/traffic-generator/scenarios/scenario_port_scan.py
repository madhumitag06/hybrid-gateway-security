"""
Scenario 2: Controlled Reconnaissance Port Scanning (PORT_SCAN)
===============================================================
Probes a bounded, configurable list of 25 service ports from the On-Premises
scanner (10.10.10.50) across lab-router (10.10.10.2 -> 10.20.10.2) targeting ONLY
the isolated Cloud VPC test workload (10.20.10.40).
"""

from datetime import datetime, timezone
import json
from pathlib import Path
import socket
import time
from typing import Any, Dict, List, Optional

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet
from scapy.utils import wrpcap

from scenarios import assert_lab_ip

DEFAULT_SCAN_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 3306, 3389, 5432, 5900, 8000, 8080, 8443, 8888, 9000,
]


def execute_scenario_port_scan(
    src_ip: str = "10.10.10.50",
    dst_ip: str = "10.20.10.40",
    target_ports: Optional[List[int]] = None,
    output_dir: Path = Path("/var/lib/hybrid-lab/telemetry"),
) -> Dict[str, Any]:
    assert_lab_ip(src_ip)
    assert_lab_ip(dst_ip)

    # Bound maximum scanned ports to 50 for safety
    ports = (target_ports or DEFAULT_SCAN_PORTS)[:50]

    pcap_dir = output_dir / "pcaps"
    meta_dir = output_dir / "metadata"
    pcap_dir.mkdir(parents=True, exist_ok=True)
    meta_dir.mkdir(parents=True, exist_ok=True)

    # 1. Execute bounded TCP connect probes across lab-router to cloud-workload
    open_ports: List[int] = []
    for dport in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.15)
        try:
            if s.connect_ex((dst_ip, dport)) == 0:
                open_ports.append(dport)
        except Exception:
            pass
        finally:
            s.close()

    # 2. Write bounded PCAP trace of the 25-port SYN reconnaissance sweep
    packets: List[Packet] = []
    base_time = time.time() - 1.0
    src_port_base = 49152

    for idx, dport in enumerate(ports):
        t = base_time + (idx * 0.005)
        p_syn = IP(src=src_ip, dst=dst_ip) / TCP(
            sport=src_port_base + idx, dport=dport, flags="S", seq=5000 + idx
        )
        p_syn.time = t
        packets.append(p_syn)

        reply_flags = "SA" if dport in open_ports else "RA"
        p_rep = IP(src=dst_ip, dst=src_ip) / TCP(
            sport=dport, dport=src_port_base + idx, flags=reply_flags, seq=0, ack=5001 + idx
        )
        p_rep.time = t + 0.001
        packets.append(p_rep)

    filename = "scenario2_port_scan_onprem_to_cloud.pcap"
    pcap_path = pcap_dir / filename
    wrpcap(str(pcap_path), packets)

    meta = {
        "scenario_id": "scenario2_port_scan",
        "scenario_name": "Scenario 2: Controlled Cross-Gateway Port Scanning",
        "source_ip": src_ip,
        "source_zone": "ON_PREMISE",
        "destination_ip": dst_ip,
        "destination_zone": "AWS_VPC",
        "transit_gateway": "10.10.10.2 -> 10.20.10.2 (lab-router)",
        "traffic_direction": "ON_PREM_TO_CLOUD",
        "ports_probed_count": len(ports),
        "open_ports_detected": open_ports,
        "expected_ml_class": "PORT_SCAN",
        "packets_written": len(packets),
        "pcap_filename": filename,
        "pcap_path": str(pcap_path),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    (meta_dir / f"{filename}.meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta

