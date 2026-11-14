"""
GCP Telemetry Provider
Ingests and parses Google Cloud VPC Flow Logs from Cloud Logging JSON format into CanonicalFlowRecord format.
"""

from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, List, Optional, Union

try:
    from backend.app.cloud.interfaces.telemetry import BaseTelemetryProvider
    from backend.app.cloud.schemas.cloud_telemetry import CanonicalFlowRecord
except ImportError:
    from app.cloud.interfaces.telemetry import BaseTelemetryProvider
    from app.cloud.schemas.cloud_telemetry import CanonicalFlowRecord

logger = logging.getLogger(__name__)

IP_PROTOCOLS = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
    58: "ICMPv6",
}


class GcpTelemetryProvider(BaseTelemetryProvider):
    """GCP Cloud Logging VPC Flow Log telemetry ingestion provider."""

    def __init__(self, project_id: str = "gcp-builders-hub-prod", region: str = "us-central1"):
        super().__init__(provider_name="GCP", account_id=project_id)
        self.project_id = project_id
        self.region = region

    def fetch_flow_records(
        self,
        since: Optional[datetime] = None,
        limit: int = 100,
        filter_params: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Fetch flow logs from Google Cloud Logging if google-cloud-logging available,
        or return mock GCP VPC flow logs.
        """
        try:
            from google.cloud import logging as gcp_logging
            client = gcp_logging.Client(project=self.project_id)
            log_filter = filter_params.get("filter") if filter_params else 'logName:"logs/compute.googleapis.com%2Fvpc_flows"'
            entries = client.list_entries(filter_=log_filter, max_results=limit)
            return [e.to_api_repr() for e in entries]
        except Exception:
            pass

        # Deterministic GCP flow logs for offline test/verification
        now_iso = datetime.now(timezone.utc).isoformat()
        sample_entries = [
            {
                "insertId": "gcp-flow-001",
                "jsonPayload": {
                    "connection": {
                        "src_ip": "10.40.10.15",
                        "dest_ip": "10.40.10.2",
                        "src_port": 49152,
                        "dest_port": 443,
                        "protocol": 6,
                    },
                    "bytes_sent": "25000",
                    "packets_sent": "30",
                    "start_time": now_iso,
                    "end_time": now_iso,
                    "reporter": "SRC",
                    "rule_details": {"action": "ALLOW"},
                },
                "resource": {
                    "type": "gce_subnetwork",
                    "labels": {
                        "project_id": self.project_id,
                        "subnetwork_name": "hybrid-gcp-subnet-uscentral1",
                    },
                },
                "timestamp": now_iso,
            },
            {
                "insertId": "gcp-flow-002",
                "jsonPayload": {
                    "connection": {
                        "src_ip": "198.51.100.77",
                        "dest_ip": "10.40.10.2",
                        "src_port": 53200,
                        "dest_port": 22,
                        "protocol": 6,
                    },
                    "bytes_sent": "1480",
                    "packets_sent": "18",
                    "start_time": now_iso,
                    "end_time": now_iso,
                    "reporter": "DEST",
                    "rule_details": {"action": "DENY"},
                },
                "resource": {
                    "type": "gce_subnetwork",
                    "labels": {
                        "project_id": self.project_id,
                        "subnetwork_name": "hybrid-gcp-subnet-uscentral1",
                    },
                },
                "timestamp": now_iso,
            },
        ]
        return sample_entries[:limit]

    def parse_raw_log_record(
        self, raw_record: Union[str, Dict[str, Any]]
    ) -> Optional[CanonicalFlowRecord]:
        """
        Parses a GCP VPC Flow Log JSON entry into CanonicalFlowRecord format.
        """
        entry: Dict[str, Any] = {}
        if isinstance(raw_record, str):
            try:
                entry = json.loads(raw_record)
            except json.JSONDecodeError:
                return None
        elif isinstance(raw_record, dict):
            entry = raw_record

        if not entry:
            return None

        payload = entry.get("jsonPayload")
        if not payload or not isinstance(payload, dict):
            # Might be flat dictionary
            payload = entry

        conn = payload.get("connection", {})
        if not conn:
            return None

        src_ip = conn.get("src_ip")
        dst_ip = conn.get("dest_ip") or conn.get("dst_ip")
        if not src_ip or not dst_ip:
            return None

        src_port = int(conn.get("src_port", 0))
        dst_port = int(conn.get("dest_port", 0))
        proto_num = int(conn.get("protocol", 6))
        protocol_name = IP_PROTOCOLS.get(proto_num, str(proto_num))

        packet_count = int(payload.get("packets_sent", 1))
        byte_count = int(payload.get("bytes_sent", 64))

        # Parse start and end time
        start_time_raw = payload.get("start_time")
        end_time_raw = payload.get("end_time")
        duration = 1.0

        ts = datetime.now(timezone.utc)
        if start_time_raw:
            try:
                # Handle ISO timestamps with Z or offset
                clean_start = str(start_time_raw).replace("Z", "+00:00")
                ts = datetime.fromisoformat(clean_start)
                if end_time_raw:
                    clean_end = str(end_time_raw).replace("Z", "+00:00")
                    end_dt = datetime.fromisoformat(clean_end)
                    duration = max((end_dt - ts).total_seconds(), 0.1)
            except Exception:
                duration = 1.0

        conn_rate = float(packet_count) / duration
        bytes_per_sec = float(byte_count) / duration
        packets_per_sec = conn_rate
        avg_packet_size = float(byte_count) / float(max(packet_count, 1))

        rule_details = payload.get("rule_details", {})
        action = rule_details.get("action", "ALLOW").upper() if isinstance(rule_details, dict) else "ALLOW"

        resource_labels = entry.get("resource", {}).get("labels", {})
        resource_id = resource_labels.get("subnetwork_name", "gcp-subnet")
        insert_id = entry.get("insertId", f"gcp-{int(ts.timestamp())}")

        flow_direction = "CROSS_ZONE"
        if src_ip.startswith("10.40.") and dst_ip.startswith("10.40."):
            flow_direction = "INTERNAL"
        elif dst_ip.startswith("10.40."):
            flow_direction = "INGRESS"
        elif src_ip.startswith("10.40."):
            flow_direction = "EGRESS"

        return CanonicalFlowRecord(
            flow_id=f"gcp-{insert_id}-{src_ip}:{src_port}->{dst_ip}:{dst_port}",
            provider="GCP",
            account_id=self.project_id,
            region=self.region,
            resource_id=resource_id,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=protocol_name,
            protocol_number=proto_num,
            packet_count=packet_count,
            byte_count=byte_count,
            duration=duration,
            conn_rate=conn_rate,
            bytes_per_sec=bytes_per_sec,
            packets_per_sec=packets_per_sec,
            avg_packet_size=avg_packet_size,
            unique_dst_ports=1,
            action=action,
            log_status="OK",
            flow_direction=flow_direction,
            timestamp=ts,
            raw_payload=entry,
        )

