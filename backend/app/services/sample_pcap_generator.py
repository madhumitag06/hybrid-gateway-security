"""
Sample PCAP Fixture Generator
=============================
Generates small, self-contained, deterministic PCAP files using Scapy for testing
and reproducible dashboard demonstration without external downloads.
"""

from pathlib import Path
import time
from typing import List

from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Packet
from scapy.utils import wrpcap

from backend.app.schemas.ingest import SamplePcapInfo

SAMPLE_DIR = Path(__file__).resolve().parent.parent / "data" / "sample_pcaps"


def generate_benign_https_pcap(filepath: Path) -> int:
    """
    Generates a standard TLS/HTTPS session to port 443.
    """
    packets: List[Packet] = []
    base_time = 1710000000.0  # Stable epoch timestamp
    src_ip = "192.168.1.50"
    dst_ip = "10.100.0.1"
    src_port = 54321
    dst_port = 443

    # TCP 3-way Handshake
    p1 = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="S", seq=1000)
    p1.time = base_time
    packets.append(p1)

    p2 = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags="SA", seq=2000, ack=1001)
    p2.time = base_time + 0.02
    packets.append(p2)

    p3 = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="A", seq=1001, ack=2001)
    p3.time = base_time + 0.03
    packets.append(p3)

    # TLS Client Hello & Application Data (simulated payload packets)
    for i in range(20):
        t = base_time + 0.05 + (i * 0.1)
        payload = b"TLS_SIMULATED_RECORD_ENCRYPTED_PAYLOAD_" + b"X" * 600
        p = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="PA", seq=1001 + (i * 600), ack=2001) / payload
        p.time = t
        packets.append(p)

    # TCP Teardown (FIN/ACK)
    p_fin = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="FA", seq=13001, ack=2001)
    p_fin.time = base_time + 2.4
    packets.append(p_fin)

    p_fin_ack = IP(src=dst_ip, dst=src_ip) / TCP(sport=dst_port, dport=src_port, flags="FA", seq=2001, ack=13002)
    p_fin_ack.time = base_time + 2.45
    packets.append(p_fin_ack)

    filepath.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(filepath), packets)
    return len(packets)


def generate_port_scan_pcap(filepath: Path) -> int:
    """
    Generates a rapid SYN scan across multiple destination ports from a single source.
    """
    packets: List[Packet] = []
    base_time = 1710000010.0
    src_ip = "192.168.1.77"
    dst_ip = "10.100.4.12"
    src_port = 49152

    target_ports = [
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995,
        1433, 1521, 3306, 3389, 5432, 5900, 8000, 8080, 8443, 8888, 9000,
    ]

    for idx, dport in enumerate(target_ports):
        t = base_time + (idx * 0.005)
        # SYN Probe
        p_syn = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port + idx, dport=dport, flags="S", seq=5000 + idx)
        p_syn.time = t
        packets.append(p_syn)

        # RST/ACK Response from closed ports
        p_rst = IP(src=dst_ip, dst=src_ip) / TCP(sport=dport, dport=src_port + idx, flags="RA", seq=0, ack=5001 + idx)
        p_rst.time = t + 0.001
        packets.append(p_rst)

    filepath.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(filepath), packets)
    return len(packets)


def generate_traffic_spike_pcap(filepath: Path) -> int:
    """
    Generates a high-rate packet burst towards port 80 (volumetric saturation pattern).
    """
    packets: List[Packet] = []
    base_time = 1710000020.0
    src_ip = "198.51.100.9"
    dst_ip = "10.100.1.44"
    src_port = 45000
    dst_port = 80

    for i in range(1200):
        t = base_time + (i * 0.0025)  # 1200 packets across 3.0 seconds
        payload = b"GET /highload_benchmark HTTP/1.1\r\nHost: target\r\n\r\n" + b"A" * 900
        p = IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port, flags="PA", seq=1000 + (i * 900)) / payload
        p.time = t
        packets.append(p)

    filepath.parent.mkdir(parents=True, exist_ok=True)
    wrpcap(str(filepath), packets)
    return len(packets)


def ensure_sample_pcaps() -> List[SamplePcapInfo]:
    """
    Ensures baseline demonstration PCAPs exist on disk and returns their metadata.
    """
    SAMPLE_DIR.mkdir(parents=True, exist_ok=True)

    samples = [
        {
            "sample_id": "sample-benign-web",
            "name": "Benign HTTPS Session",
            "filename": "benign_web.pcap",
            "description": "Standard TLS/HTTPS handshake and payload exchange adhering to normal flow distributions.",
            "generator": generate_benign_https_pcap,
            "expected_threat": "BENIGN",
        },
        {
            "sample_id": "sample-port-scan",
            "name": "Reconnaissance Port Scan",
            "filename": "port_scan.pcap",
            "description": "Rapid SYN scan probing 25+ distinct service ports in under 0.2 seconds.",
            "generator": generate_port_scan_pcap,
            "expected_threat": "PORT_SCAN",
        },
        {
            "sample_id": "sample-traffic-spike",
            "name": "Volumetric Traffic Burst",
            "filename": "traffic_spike.pcap",
            "description": "High-frequency packet stream generating sudden throughput surge towards HTTP web services.",
            "generator": generate_traffic_spike_pcap,
            "expected_threat": "TRAFFIC_SPIKE",
        },
    ]

    results: List[SamplePcapInfo] = []

    for s in samples:
        target_path = SAMPLE_DIR / s["filename"]
        if not target_path.exists() or target_path.stat().st_size == 0:
            pkt_count = s["generator"](target_path)
        else:
            # Quick stat estimation
            pkt_count = 25

        size_bytes = target_path.stat().st_size if target_path.exists() else 0

        results.append(
            SamplePcapInfo(
                sample_id=s["sample_id"],
                name=s["name"],
                filename=s["filename"],
                description=s["description"],
                packet_count=pkt_count,
                expected_threat=s["expected_threat"],
                file_size_bytes=size_bytes,
            )
        )

    return results
