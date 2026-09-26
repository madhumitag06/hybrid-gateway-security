"""
AWS VPC Flow Log Parser & Ingestion Engine
===========================================
Parses AWS VPC Flow Logs (Version 2 standard format), aggregates flow records into
canonical sessions, computes ML feature vectors with strict provenance, evaluates
threats via ThreatPredictor and PolicyEngine, and persists security events to PostgreSQL.
"""

from collections import defaultdict
from datetime import datetime, timezone
import time
from typing import Dict, List, Optional, Tuple
from sqlalchemy.orm import Session

from backend.app.models.security_event import SecurityEventModel
from backend.app.repositories.security_event_repo import SecurityEventRepository
from backend.app.schemas.aws_flow import (
    AwsVpcFlowItemResult,
    AwsVpcIngestionResponse,
    TelemetrySourceType,
    VpcFlowLogRecordSchema,
)
from backend.app.schemas.predict import NetworkFlowRequest, PredictionResponse
from backend.app.services.dashboard_service import DashboardService
from backend.app.services.enforcement_service import EnforcementService
from backend.app.services.hybrid_topology import NetworkZoneClassifier
from backend.app.services.ml_service import MLService
from backend.app.services.policy_engine import PolicyEngine


class AggregatedVpcFlow:
    """
    Internal accumulator for aggregating multiple VPC flow log records sharing a session key.
    """
    def __init__(self, src_ip: str, dst_ip: str, protocol: int):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.protocol = protocol
        self.ports_targeted: set[int] = set()
        self.primary_dst_port: int = 80
        self.total_packets: int = 0
        self.total_bytes: int = 0
        self.min_start: Optional[int] = None
        self.max_end: Optional[int] = None
        self.interface_id: Optional[str] = None
        self.account_id: Optional[str] = None
        self.record_count: int = 0

    def add_record(self, rec: VpcFlowLogRecordSchema) -> None:
        self.total_packets += rec.packets
        self.total_bytes += rec.bytes
        self.ports_targeted.add(rec.dst_port)
        self.primary_dst_port = rec.dst_port  # Keeps recent/primary port
        self.interface_id = rec.interface_id
        self.account_id = rec.account_id
        self.record_count += 1

        if self.min_start is None or rec.start < self.min_start:
            self.min_start = rec.start
        if self.max_end is None or rec.end > self.max_end:
            self.max_end = rec.end

    @property
    def duration_seconds(self) -> float:
        if self.min_start is not None and self.max_end is not None:
            return max(float(self.max_end - self.min_start), 0.1)
        return 1.0

    @property
    def conn_rate(self) -> float:
        return float(self.total_packets) / self.duration_seconds

    @property
    def unique_dst_ports(self) -> int:
        return len(self.ports_targeted)


class AwsVpcFlowParser:
    """
    Standard parser and ingestion processor for AWS VPC Flow Log telemetry.
    """

    PROTOCOL_MAP = {
        6: "TCP",
        17: "UDP",
        1: "ICMP",
        58: "ICMPv6",
    }

    @classmethod
    def parse_raw_log_line(cls, line: str) -> Optional[VpcFlowLogRecordSchema]:
        """
        Parses a single whitespace-delimited v2 VPC Flow Log line.
        Returns None if header, comment, or NODATA/SKIPDATA record.
        """
        parts = line.strip().split()
        if not parts or len(parts) < 14:
            return None

        # Check for header row
        if parts[0].lower() in ["version", "#version"]:
            return None

        # Standard field positions in AWS default v2 format:
        # 0: version (2)
        # 1: account-id
        # 2: interface-id
        # 3: srcaddr
        # 4: dstaddr
        # 5: srcport
        # 6: dstport
        # 7: protocol
        # 8: packets
        # 9: bytes
        # 10: start
        # 11: end
        # 12: action
        # 13: log-status
        try:
            version = int(parts[0])
            account_id = parts[1]
            interface_id = parts[2]
            srcaddr = parts[3]
            dstaddr = parts[4]

            # Handle '-' placeholders for NODATA records
            if srcaddr == "-" or dstaddr == "-":
                return None

            srcport = int(parts[5]) if parts[5] != "-" else 0
            dstport = int(parts[6]) if parts[6] != "-" else 0
            protocol = int(parts[7]) if parts[7] != "-" else 6
            packets = int(parts[8]) if parts[8] != "-" else 0
            bytes_transferred = int(parts[9]) if parts[9] != "-" else 0
            start_ts = int(parts[10]) if parts[10] != "-" else int(time.time())
            end_ts = int(parts[11]) if parts[11] != "-" else start_ts + 1
            action = parts[12]
            log_status = parts[13]

            if log_status != "OK":
                return None

            return VpcFlowLogRecordSchema(
                version=version,
                account_id=account_id,
                interface_id=interface_id,
                src_addr=srcaddr,
                dst_addr=dstaddr,
                src_port=srcport,
                dst_port=dstport,
                protocol=protocol,
                packets=packets,
                bytes=bytes_transferred,
                start=start_ts,
                end=end_ts,
                action=action,
                log_status=log_status,
            )
        except (ValueError, IndexError):
            return None

    @classmethod
    def ingest_vpc_flow_records(
        cls,
        raw_content: str,
        is_fixture: bool = False,
        source_label: str = "vpc_flow_logs",
        persist: bool = True,
        db: Optional[Session] = None,
    ) -> AwsVpcIngestionResponse:
        """
        Parses multi-line VPC flow logs, aggregates into flow sessions, executes ML inference,
        evaluates PolicyEngine decisions, and persists security events.
        """
        start_time = time.perf_counter()
        lines = raw_content.strip().splitlines()
        parsed_records: List[VpcFlowLogRecordSchema] = []

        for line in lines:
            rec = cls.parse_raw_log_line(line)
            if rec:
                parsed_records.append(rec)

        parse_dur_ms = (time.perf_counter() - start_time) * 1000.0

        # Step 2: Aggregate by (src_ip, dst_ip, protocol)
        session_map: Dict[Tuple[str, str, int], AggregatedVpcFlow] = {}
        for r in parsed_records:
            key = (r.src_addr, r.dst_addr, r.protocol)
            if key not in session_map:
                session_map[key] = AggregatedVpcFlow(r.src_addr, r.dst_addr, r.protocol)
            session_map[key].add_record(r)

        # Step 3: ML Inference & Policy Engine Execution
        inf_start = time.perf_counter()
        results: List[AwsVpcFlowItemResult] = []
        high_risk_count = 0

        telemetry_source: TelemetrySourceType = (
            "AWS_VPC_FLOW_LOG_FIXTURE" if is_fixture else "AWS_VPC_FLOW_LOG"
        )

        for idx, (key, session) in enumerate(session_map.items()):
            flow_id = f"aws-flw-{idx + 1:04d}"
            src_zone = NetworkZoneClassifier.classify_ip(session.src_ip)
            dst_zone = NetworkZoneClassifier.classify_ip(session.dst_ip)
            direction = NetworkZoneClassifier.classify_direction(session.src_ip, session.dst_ip)
            proto_name = cls.PROTOCOL_MAP.get(session.protocol, f"PROTO_{session.protocol}")

            # Strict Provenance Feature Construction:
            # - OBSERVED: packet_count, byte_count, dst_port, interface_id, account_id
            # - DERIVED: duration, conn_rate, unique_dst_ports
            # - UNAVAILABLE: failed_auth_count = 0 (Strictly 0 for VPC flow logs)
            flow_req = NetworkFlowRequest(
                packet_count=session.total_packets,
                byte_count=session.total_bytes,
                duration=session.duration_seconds,
                conn_rate=session.conn_rate,
                dst_port=session.primary_dst_port,
                unique_dst_ports=session.unique_dst_ports,
                failed_auth_count=0,  # Factual, not inferred
            )

            # 1. ML Threat Inference
            prediction: PredictionResponse = MLService.predict(flow_req)
            if prediction.threat_level in ["HIGH", "CRITICAL"] or prediction.risk_score >= 70:
                high_risk_count += 1

            # 2. Context-Aware Policy Decision
            policy_decision = PolicyEngine.evaluate(
                prediction=prediction,
                source_ip=session.src_ip,
                destination_ip=session.dst_ip,
                dst_port=session.primary_dst_port,
                protocol=proto_name,
            )

            # 3. Controlled Active Containment via Phase 5 Enforcement
            persisted_event_id: Optional[str] = None

            if persist and db is not None:
                import uuid
                event_id = f"evt-aws-{int(time.time())}-{uuid.uuid4().hex[:6]}"
                enforce_res, _ = EnforcementService.execute_decision(
                    decision=policy_decision,
                    db=db,
                    actor="aws_vpc_ingestion_pipeline",
                )

                # Determine final event status
                if enforce_res.status in ["ACTIVE", "SIMULATED"]:
                    final_status = (
                        "Applied"
                        if policy_decision.policy_action in ["Restrict", "Block"]
                        else "Monitoring"
                    )
                else:
                    final_status = (
                        "Allowed" if policy_decision.policy_action == "Allow" else "Monitoring"
                    )

                event_model = SecurityEventModel(
                    id=event_id,
                    timestamp=datetime.now(timezone.utc),
                    source_ip=session.src_ip,
                    destination_ip=session.dst_ip,
                    attack_type=prediction.attack_type,
                    risk_score=prediction.risk_score,
                    threat_level=prediction.threat_level,
                    confidence=prediction.confidence,
                    action_recommendation=prediction.action_recommendation,
                    current_policy_action=policy_decision.policy_action,
                    status=final_status,
                    description=f"AWS VPC Flow Ingestion: {policy_decision.reason}",
                    is_anomaly=prediction.is_anomaly,
                    is_demo=is_fixture,
                    flow_features={
                        "telemetry_source": telemetry_source,
                        "source_zone": src_zone,
                        "destination_zone": dst_zone,
                        "traffic_direction": direction,
                        "interface_id": session.interface_id,
                        "account_id": session.account_id,
                        "packet_count": session.total_packets,
                        "byte_count": session.total_bytes,
                        "duration": session.duration_seconds,
                        "conn_rate": session.conn_rate,
                        "dst_port": session.primary_dst_port,
                        "unique_dst_ports": session.unique_dst_ports,
                        "failed_auth_count": 0,
                    },
                    class_probabilities=prediction.class_probabilities,
                    top_contributing_features=[
                        f.model_dump() for f in prediction.top_contributing_features
                    ],
                )

                repo = SecurityEventRepository(db)
                repo.create(event_model)
                persisted_event_id = event_id

            results.append(
                AwsVpcFlowItemResult(
                    flow_id=flow_id,
                    source_ip=session.src_ip,
                    destination_ip=session.dst_ip,
                    source_zone=src_zone,
                    destination_zone=dst_zone,
                    traffic_direction=direction,
                    protocol_name=proto_name,
                    dst_port=session.primary_dst_port,
                    packet_count=session.total_packets,
                    byte_count=session.total_bytes,
                    duration=session.duration_seconds,
                    conn_rate=session.conn_rate,
                    unique_dst_ports=session.unique_dst_ports,
                    failed_auth_count=0,
                    interface_id=session.interface_id,
                    account_id=session.account_id,
                    prediction=prediction,
                    policy_decision=policy_decision,
                    persisted_event_id=persisted_event_id,
                )
            )

        inf_dur_ms = (time.perf_counter() - inf_start) * 1000.0
        total_dur_ms = (time.perf_counter() - start_time) * 1000.0

        return AwsVpcIngestionResponse(
            telemetry_source=telemetry_source,
            source_label=source_label,
            is_fixture=is_fixture,
            total_records_parsed=len(parsed_records),
            total_flows_aggregated=len(session_map),
            high_risk_flows_count=high_risk_count,
            parse_duration_ms=round(parse_dur_ms, 2),
            inference_duration_ms=round(inf_dur_ms, 2),
            total_duration_ms=round(total_dur_ms, 2),
            results=results,
        )
