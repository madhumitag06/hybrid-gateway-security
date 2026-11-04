"""
Scenario 6: Controlled SSH / Service Credential Brute-Force (BRUTE_FORCE)
=========================================================================
Generates a bounded sequence of 12 failed authentication attempts from the
On-Premises generator (10.10.10.50) across lab-router (10.10.10.2 -> 10.20.10.2)
targeting the isolated Cloud VPC workload SSH port (10.20.10.40:22).
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


def execute_scenario_brute_force(
    src_ip: str = "10.10.10.50",
    dst_ip: str = "10.20.10.40",
    dst_port: int = 22,
    failed_attempts: int = 12,
    output_dir: Path = Path("/var/lib/hybrid-lab/telemetry"),
) -> Dict[str, Any]:
    assert_lab_ip(src_ip)
    assert_lab_ip(dst_ip)

    attempts = min(max(failed_attempts, 6), 25)

    pcap_dir = output_dir / "pcaps"
    meta_dir = output_dir / "metadata"
    pcap_dir.mkdir(parents=True, exist_ok=True)
    meta_dir.mkdir(parents=True, exist_ok=True)

    # 1. Execute bounded live auth attempts across lab-router to cloud-workload:22
    live_attempts_sent = 0
    for i in range(attempts):
        try:
            req = urllib.request.Request(
                f"http://{dst_ip}:{dst_port}/ssh-auth-attempt",
                data=f"AUTH_FAIL user=root attempt={i + 1}".encode("utf-8"),
                headers={"Content-Type": "text/plain"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                if resp.status == 200:
                    live_attempts_sent += 1
        except Exception:
            pass

    # 2. Write bounded PCAP trace matching the Phase 1 BRUTE_FORCE profile
    # (35 packets, ~8,500 bytes, 1.8s duration, dst_port=22, failed_auth_count=12)
    packets: List[Packet] = []
    base_time = time.time() - 2.0
    src_port = 52022

    for i in range(35):
        t = base_time + (i * (1.8 / 34.0))
        if i < attempts:
            payload = (
                f"SSH-2.0-OpenSSH_AuthFailed AUTH_FAIL Permission denied (attempt={i + 1}) ".encode("utf-8")
                + b"K" * 140
            )
        else:
            payload = b"SSH-2.0-OpenSSH_KeyExchange_Packet_" + b"M" * 165

        p = (
            IP(src=src_ip, dst=dst_ip)
            / TCP(sport=src_port, dport=dst_port, flags="PA", seq=1000 + (i * 220), ack=1)
            / payload
        )
        p.time = t
        packets.append(p)

    filename = "scenario6_brute_force_onprem_to_cloud.pcap"
    pcap_path = pcap_dir / filename
    wrpcap(str(pcap_path), packets)

    meta = {
        "scenario_id": "scenario6_brute_force",
        "scenario_name": "Scenario 6: Controlled Cross-Gateway Credential Brute-Force",
        "source_ip": src_ip,
        "source_zone": "ON_PREMISE",
        "destination_ip": dst_ip,
        "destination_zone": "AWS_VPC",
        "transit_gateway": "10.10.10.2 -> 10.20.10.2 (lab-router)",
        "traffic_direction": "ON_PREM_TO_CLOUD",
        "expected_ml_class": "BRUTE_FORCE",
        "failed_auth_attempts": attempts,
        "live_attempts_completed": live_attempts_sent,
        "packets_written": len(packets),
        "pcap_filename": filename,
        "pcap_path": str(pcap_path),
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
    }
    (meta_dir / f"{filename}.meta.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return meta

