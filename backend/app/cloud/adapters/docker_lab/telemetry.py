"""
Docker Lab Telemetry Provider
Ingests local simulated PCAP and router forwarding telemetry into CanonicalFlowRecord format.
"""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional, Union

try:
    from backend.app.cloud.interfaces.telemetry import BaseTelemetryProvider
    from backend.app.cloud.schemas.cloud_telemetry import CanonicalFlowRecord
except ImportError:
    from app.cloud.interfaces.telemetry import BaseTelemetryProvider
    from app.cloud.schemas.cloud_telemetry import CanonicalFlowRecord

logger = logging.getLogger(__name__)


class DockerLabTelemetryProvider(BaseTelemetryProvider):
    """Docker Lab network telemetry provider."""

    def __init__(self, lab_id: str = "docker-hybrid-lab-01"):
        super().__init__(provider_name="DOCKER_LAB", account_id=lab_id)

    def fetch_flow_records(
        self,
        since: Optional[datetime] = None,
        limit: int = 100,
        filter_params: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        now_ts = int(datetime.now(timezone.utc).timestamp())
        sample_logs = [
            {"src_ip": "10.10.10.15", "dst_ip": "10.20.10.2", "src_port": 50123, "dst_port": 80, "protocol": "TCP", "packets": 40, "bytes": 32000, "duration": 1.2},
            {"src_ip": "10.10.10.99", "dst_ip": "10.20.10.2", "src_port": 58900, "dst_port": 22, "protocol": "TCP", "packets": 15, "bytes": 1200, "duration": 2.5},
            {"src_ip": "10.20.10.15", "dst_ip": "10.10.10.2", "src_port": 44321, "dst_port": 443, "protocol": "TCP", "packets": 80, "bytes": 74000, "duration": 0.8},
        ]
        return sample_logs[:limit]

    def parse_raw_log_record(
        self, raw_record: Union[str, Dict[str, Any]]
    ) -> Optional[CanonicalFlowRecord]:
        rec: Dict[str, Any] = {}
        if isinstance(raw_record, dict):
            rec = raw_record
        elif isinstance(raw_record, str):
            # Try comma or space-separated
            tokens = raw_record.strip().split()
            if len(tokens) >= 5:
                rec = {
                    "src_ip": tokens[0],
                    "dst_ip": tokens[1],
                    "src_port": int(tokens[2]) if tokens[2].isdigit() else 0,
                    "dst_port": int(tokens[3]) if tokens[3].isdigit() else 80,
                    "protocol": tokens[4],
                }

        if not rec or "src_ip" not in rec or "dst_ip" not in rec:
            return None

        src_ip = rec["src_ip"]
        dst_ip = rec["dst_ip"]
        src_port = int(rec.get("src_port", 0))
        dst_port = int(rec.get("dst_port", 80))
        protocol = str(rec.get("protocol", "TCP")).upper()
        proto_num = 6 if protocol == "TCP" else (17 if protocol == "UDP" else 1)

        packet_count = int(rec.get("packets", rec.get("packet_count", 1)))
        byte_count = int(rec.get("bytes", rec.get("byte_count", 64)))
        duration = max(float(rec.get("duration", 1.0)), 0.1)

        conn_rate = float(packet_count) / duration
        bytes_per_sec = float(byte_count) / duration
        packets_per_sec = conn_rate
        avg_packet_size = float(byte_count) / float(max(packet_count, 1))

        ts = datetime.now(timezone.utc)

        flow_direction = "CROSS_ZONE"
        if src_ip.startswith("10.10.") and dst_ip.startswith("10.20."):
            flow_direction = "CROSS_ZONE"
        elif src_ip.startswith("10.10.") and dst_ip.startswith("10.10."):
            flow_direction = "INTERNAL"
        elif src_ip.startswith("10.20.") and dst_ip.startswith("10.20."):
            flow_direction = "INTERNAL"

        return CanonicalFlowRecord(
            flow_id=f"docker-lab-{int(ts.timestamp())}-{src_ip}:{src_port}->{dst_ip}:{dst_port}",
            provider="DOCKER_LAB",
            account_id=self.account_id,
            region="local",
            resource_id="hybrid-lab-router",
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol,
            protocol_number=proto_num,
            packet_count=packet_count,
            byte_count=byte_count,
            duration=duration,
            conn_rate=conn_rate,
            bytes_per_sec=bytes_per_sec,
            packets_per_sec=packets_per_sec,
            avg_packet_size=avg_packet_size,
            unique_dst_ports=1,
            action="ACCEPT",
            log_status="OK",
            flow_direction=flow_direction,
            timestamp=ts,
            raw_payload=rec,
        )

