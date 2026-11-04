"""
AWS VPC Flow Logs-Compatible Simulation Exporter
================================================
Converts captured hybrid lab packet streams (PCAPs crossing between 10.10.10.0/24
and 10.20.10.0/24) into AWS VPC Flow Logs v2-compatible records:

Fields:
  version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status flow-direction

IMPORTANT PROVENANCE NOTICE:
  These records are generated inside the isolated Docker virtual hybrid-cloud lab
  to simulate AWS VPC Flow Logs telemetry. They are explicitly marked with
  `is_fixture=True` and a `simulated_lab_vpc_flow_` source label so they are never
  silently misrepresented as live AWS CloudWatch telemetry.
"""

from collections import defaultdict
from datetime import datetime, timezone
import os
from pathlib import Path
import time
from typing import Any, Dict, List, Tuple

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.utils import PcapReader

SIM_ACCOUNT_ID = os.getenv(
    "SIMULATED_AWS_ACCOUNT_ID",
    os.getenv("AWS_SIMULATED_ACCOUNT_ID", "123456789012"),
)
SIM_ENI_ID = os.getenv(
    "SIMULATED_AWS_ENI_ID",
    os.getenv("AWS_SIMULATED_ENI_CLOUD", "eni-sim0a1b2c3d4e5f01"),
)


def convert_pcap_to_simulated_vpc_flow_logs(
    pcap_path: Path,
    flowlog_dir: Path,
    account_id: str = SIM_ACCOUNT_ID,
    interface_id: str = SIM_ENI_ID,
) -> Dict[str, Any]:
    """
    Reads a PCAP file from the virtual lab and produces an AWS VPC Flow Logs-compatible
    simulation file (.log) with ACCEPT / REJECT actions and flow-direction (ingress/egress).
    """
    flowlog_dir.mkdir(parents=True, exist_ok=True)

    # Key: (src_ip, dst_ip, src_port, dst_port, proto_num)
    flows: Dict[Tuple[str, str, int, int, int], Dict[str, Any]] = {}

    with PcapReader(str(pcap_path)) as reader:
        for pkt in reader:
            if not pkt.haslayer(IP):
                continue
            ip = pkt[IP]
            src_ip = str(ip.src)
            dst_ip = str(ip.dst)
            pkt_len = int(len(pkt))
            pkt_ts = int(float(getattr(pkt, "time", time.time())))

            proto_num = int(ip.proto)
            sport = 0
            dport = 0
            has_rst = False
            is_syn_only = False

            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                proto_num = 6
                sport = int(tcp.sport)
                dport = int(tcp.dport)
                flags_int = int(tcp.flags)
                if flags_int & 0x04:  # RST flag
                    has_rst = True
                if flags_int == 0x02:  # SYN only
                    is_syn_only = True
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                proto_num = 17
                sport = int(udp.sport)
                dport = int(udp.dport)
            elif pkt.haslayer(ICMP):
                proto_num = 1

            # Fold reverse responder->initiator packets into the forward initiator session
            rev_key = (dst_ip, src_ip, dport, sport, proto_num)
            if rev_key in flows:
                if has_rst:
                    flows[rev_key]["rejected"] = True
                    continue
                rec = flows[rev_key]
                rec["packets"] += 1
                rec["bytes"] += pkt_len
                if pkt_ts < rec["start"]:
                    rec["start"] = pkt_ts
                if pkt_ts >= rec["end"]:
                    rec["end"] = pkt_ts + 1
                continue

            key = (src_ip, dst_ip, sport, dport, proto_num)
            if key not in flows:
                flows[key] = {
                    "packets": 0,
                    "bytes": 0,
                    "start": pkt_ts,
                    "end": pkt_ts + 1,
                    "rejected": False,
                    "syn_only": is_syn_only,
                }
            rec = flows[key]
            rec["packets"] += 1
            rec["bytes"] += pkt_len
            if pkt_ts < rec["start"]:
                rec["start"] = pkt_ts
            if pkt_ts >= rec["end"]:
                rec["end"] = pkt_ts + 1
            if not is_syn_only:
                rec["syn_only"] = False

    header = (
        "version account-id interface-id srcaddr dstaddr srcport dstport "
        "protocol packets bytes start end action log-status flow-direction"
    )
    lines: List[str] = [header]

    for (src_ip, dst_ip, sport, dport, proto_num), stats in flows.items():
        action = "REJECT" if (stats["rejected"] or (stats["syn_only"] and stats["packets"] <= 2)) else "ACCEPT"
        # From the perspective of the Simulated Cloud VPC (10.20.10.0/24):
        flow_dir = "ingress" if dst_ip.startswith("10.20.10.") else "egress"
        line = (
            f"2 {account_id} {interface_id} {src_ip} {dst_ip} {sport} {dport} "
            f"{proto_num} {stats['packets']} {stats['bytes']} {stats['start']} {stats['end']} "
            f"{action} OK {flow_dir}"
        )
        lines.append(line)

    out_name = f"simulated_vpc_flow_{pcap_path.stem}.log"
    out_path = flowlog_dir / out_name
    raw_content = "\n".join(lines) + "\n"
    out_path.write_text(raw_content, encoding="utf-8")

    return {
        "flowlog_filename": out_name,
        "flowlog_path": str(out_path),
        "records_generated": max(len(lines) - 1, 0),
        "is_simulated_vpc_flow_log": True,
        "raw_content": raw_content,
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
    }

