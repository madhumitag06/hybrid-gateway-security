"""
Network Flow Aggregator
=======================
Aggregates individual L3/L4 IP packets into bidirectional network flow sessions
using canonical 5-tuple keys and sliding time windows. Extracts exact feature
representations compatible with the Phase 1 ML pipeline (NetworkFlowInput).
"""

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
from typing import Dict, List, Optional, Set, Tuple
from ml.features.extractor import NetworkFlowInput


@dataclass
class PacketRecord:
    """
    Internal representation of a parsed network packet.
    """
    timestamp: float          # Epoch timestamp in seconds
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str             # "TCP", "UDP", "ICMP", "OTHER"
    length_bytes: int         # Total wire length
    tcp_flags: Optional[int] = None


@dataclass
class FlowSession:
    """
    State of an active bidirectional network flow session.
    """
    initiator_ip: str
    responder_ip: str
    initiator_port: int
    responder_port: int
    protocol: str
    first_seen: float
    last_seen: float
    packet_count: int = 0
    byte_count: int = 0
    packets: List[PacketRecord] = field(default_factory=list)

    @property
    def duration(self) -> float:
        return max(self.last_seen - self.first_seen, 0.001)


class FlowAggregator:
    """
    Aggregates packet streams into structured flow records.
    
    Session Identification:
      Canonical bidirectional key: (min(ep1, ep2), max(ep1, ep2), protocol)
      where ep = (ip, port).
      The endpoint sending the first packet is designated as the initiator (source_ip),
      and the target is the responder (destination_ip, dst_port).
    """

    def __init__(
        self,
        inactivity_timeout: float = 10.0,
        max_flow_duration: float = 30.0,
    ):
        self.inactivity_timeout = inactivity_timeout
        self.max_flow_duration = max_flow_duration
        self.active_sessions: Dict[Tuple, FlowSession] = {}
        self.completed_flows: List[FlowSession] = []
        # Per-source host tracking for scan detection and conn_rate
        self.host_target_ports: Dict[str, Set[int]] = defaultdict(set)
        self.host_connection_timestamps: Dict[str, List[float]] = defaultdict(list)

    @staticmethod
    def _make_canonical_key(src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: str) -> Tuple:
        ep1 = (src_ip, src_port)
        ep2 = (dst_ip, dst_port)
        if ep1 <= ep2:
            return (ep1, ep2, protocol)
        return (ep2, ep1, protocol)

    def add_packet(self, packet: PacketRecord) -> Optional[FlowSession]:
        """
        Process a single packet, update active session state, and return completed session
        if a timeout or duration boundary was reached.
        """
        key = self._make_canonical_key(
            packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port, packet.protocol
        )

        # Track destination ports targeted by the source IP for port-scan detection
        self.host_target_ports[packet.src_ip].add(packet.dst_port)
        self.host_connection_timestamps[packet.src_ip].append(packet.timestamp)

        flushed_session: Optional[FlowSession] = None

        if key in self.active_sessions:
            session = self.active_sessions[key]
            # Check for inactivity or maximum session duration expiration
            if (packet.timestamp - session.last_seen > self.inactivity_timeout) or (
                packet.timestamp - session.first_seen > self.max_flow_duration
            ):
                flushed_session = session
                self.completed_flows.append(session)
                # Start new session
                session = FlowSession(
                    initiator_ip=packet.src_ip,
                    responder_ip=packet.dst_ip,
                    initiator_port=packet.src_port,
                    responder_port=packet.dst_port,
                    protocol=packet.protocol,
                    first_seen=packet.timestamp,
                    last_seen=packet.timestamp,
                    packet_count=1,
                    byte_count=packet.length_bytes,
                    packets=[packet],
                )
                self.active_sessions[key] = session
            else:
                session.packet_count += 1
                session.byte_count += packet.length_bytes
                session.last_seen = packet.timestamp
                session.packets.append(packet)
        else:
            session = FlowSession(
                initiator_ip=packet.src_ip,
                responder_ip=packet.dst_ip,
                initiator_port=packet.src_port,
                responder_port=packet.dst_port,
                protocol=packet.protocol,
                first_seen=packet.timestamp,
                last_seen=packet.timestamp,
                packet_count=1,
                byte_count=packet.length_bytes,
                packets=[packet],
            )
            self.active_sessions[key] = session

        return flushed_session

    def flush_all(self) -> List[FlowSession]:
        """
        Flush all remaining active sessions into the completed list and return them.
        """
        for session in self.active_sessions.values():
            self.completed_flows.append(session)
        self.active_sessions.clear()
        return self.completed_flows

    def extract_features(self, session: FlowSession) -> Tuple[NetworkFlowInput, str, str]:
        """
        Convert a FlowSession into a Phase 1 NetworkFlowInput along with (source_ip, destination_ip).
        
        Features:
          - packet_count: Total packets in flow
          - byte_count: Total bytes transferred
          - duration: Seconds between first and last packet
          - conn_rate: Flows/packets initiated per second from source IP
          - dst_port: Target service port on responder
          - unique_dst_ports: Number of distinct destination ports targeted by initiator
          - failed_auth_count: 0 (conservative; encrypted or unobservable without L7 auth stream)
        """
        source_ip = session.initiator_ip
        destination_ip = session.responder_ip
        dst_port = session.responder_port

        # Calculate unique destination ports targeted by this initiator
        unique_ports = len(self.host_target_ports.get(source_ip, {dst_port}))
        unique_ports = max(unique_ports, 1)

        # Calculate connection rate (flow initiation frequency within window)
        timestamps = self.host_connection_timestamps.get(source_ip, [session.first_seen])
        if len(timestamps) > 1:
            time_span = max(timestamps[-1] - timestamps[0], 0.1)
            conn_rate = round(len(timestamps) / time_span, 2)
        else:
            conn_rate = round(session.packet_count / max(session.duration, 0.1), 2)

        # Bound values safely within expected physical boundaries
        packet_count = max(session.packet_count, 1)
        byte_count = max(session.byte_count, 1)
        duration = max(round(session.duration, 4), 0.001)
        safe_dst_port = max(min(dst_port, 65535), 1)

        flow_input = NetworkFlowInput(
            packet_count=packet_count,
            byte_count=byte_count,
            duration=duration,
            conn_rate=float(conn_rate),
            dst_port=safe_dst_port,
            unique_dst_ports=unique_ports,
            failed_auth_count=0,  # Honest limitation: default to 0 for L3/L4 captures
        )

        return flow_input, source_ip, destination_ip
