"""
Network Flow Aggregator
=======================
Aggregates individual L3/L4 IP packets into bidirectional network flow sessions
using canonical 5-tuple keys and sliding time windows. Extracts exact feature
representations compatible with the Phase 1 ML pipeline (NetworkFlowInput).
"""

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import threading
import time
from typing import Deque, Dict, List, Optional, Set, Tuple
from ml.features.extractor import NetworkFlowInput, calculate_conn_rate


class HostPortTracker:
    """
    Thread-safe, memory-bounded, rolling 60-second window tracker
    for unique destination ports and connection frequency per source host.
    """

    def __init__(self, window_seconds: float = 60.0, max_hosts: int = 10000):
        self.window_seconds = window_seconds
        self.max_hosts = max_hosts
        self.lock = threading.RLock()
        # Mapping: src_ip -> deque of (timestamp, dst_port)
        self.host_ports: Dict[str, Deque[Tuple[float, int]]] = defaultdict(deque)
        # Mapping: src_ip -> deque of timestamp (for conn_rate calculation)
        self.host_timestamps: Dict[str, Deque[float]] = defaultdict(deque)
        # Mapping: src_ip -> last_seen_timestamp (for LRU eviction)
        self.host_last_seen: Dict[str, float] = {}

    def record_destination_port(
        self, src_ip: str, dst_port: int, timestamp: Optional[float] = None
    ) -> None:
        ts = float(timestamp) if timestamp is not None else time.time()
        with self.lock:
            # Memory bounded host eviction
            if len(self.host_last_seen) >= self.max_hosts and src_ip not in self.host_last_seen:
                oldest_host = min(self.host_last_seen, key=self.host_last_seen.get)
                del self.host_last_seen[oldest_host]
                if oldest_host in self.host_ports:
                    del self.host_ports[oldest_host]
                if oldest_host in self.host_timestamps:
                    del self.host_timestamps[oldest_host]

            self.host_last_seen[src_ip] = ts
            self.host_ports[src_ip].append((ts, int(dst_port)))
            self.host_timestamps[src_ip].append(ts)
            self._expire_host_entries(src_ip, ts)

    def get_unique_dst_ports(
        self, src_ip: str, current_time: Optional[float] = None
    ) -> int:
        ts = float(current_time) if current_time is not None else time.time()
        with self.lock:
            if src_ip not in self.host_ports:
                return 1
            self._expire_host_entries(src_ip, ts)
            q = self.host_ports[src_ip]
            if not q:
                return 1
            return max(1, len({port for _, port in q}))

    def get_connection_rate(
        self, src_ip: str, packet_count: int, duration: float, current_time: Optional[float] = None
    ) -> float:
        ts = float(current_time) if current_time is not None else time.time()
        with self.lock:
            if src_ip not in self.host_timestamps:
                return calculate_conn_rate(packet_count=packet_count, duration=duration)
            self._expire_host_entries(src_ip, ts)
            q = self.host_timestamps[src_ip]
            if len(q) > 1:
                window_span = max(q[-1] - q[0], 0.1)
                return calculate_conn_rate(
                    packet_count=packet_count,
                    duration=duration,
                    host_connection_count=len(q),
                    window_seconds=window_span,
                )
            return calculate_conn_rate(packet_count=packet_count, duration=duration)

    def _expire_host_entries(self, src_ip: str, current_time: float) -> None:
        cutoff = current_time - self.window_seconds
        q_ports = self.host_ports.get(src_ip)
        if q_ports:
            while q_ports and q_ports[0][0] < cutoff:
                q_ports.popleft()

        q_times = self.host_timestamps.get(src_ip)
        if q_times:
            while q_times and q_times[0] < cutoff:
                q_times.popleft()


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
    is_auth_failure: bool = False


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
    failed_auth_count: int = 0
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
        port_scan_window_seconds: float = 60.0,
    ):
        self.inactivity_timeout = inactivity_timeout
        self.max_flow_duration = max_flow_duration
        self.active_sessions: Dict[Tuple, FlowSession] = {}
        self.completed_flows: List[FlowSession] = []
        # Production-grade 60-second rolling window host port & rate tracker
        self.host_tracker = HostPortTracker(window_seconds=port_scan_window_seconds)

    @property
    def host_target_ports(self) -> Dict[str, Set[int]]:
        """Backwards-compatible view of active destination ports per host."""
        with self.host_tracker.lock:
            result = {}
            for host, q in self.host_tracker.host_ports.items():
                ports = {p for _, p in q}
                if ports:
                    result[host] = ports
            return result

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

        flushed_session: Optional[FlowSession] = None

        if key in self.active_sessions:
            session = self.active_sessions[key]
            # Track destination port only when packet is from initiator to responder (prevents reverse pollution)
            if packet.src_ip == session.initiator_ip:
                self.host_tracker.record_destination_port(packet.src_ip, packet.dst_port, packet.timestamp)

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
                    failed_auth_count=1 if packet.is_auth_failure else 0,
                    packets=[packet],
                )
                self.active_sessions[key] = session
            else:
                session.packet_count += 1
                session.byte_count += packet.length_bytes
                if packet.is_auth_failure:
                    session.failed_auth_count += 1
                session.last_seen = packet.timestamp
                session.packets.append(packet)
        else:
            # First packet of a new session: packet.src_ip is designated initiator
            self.host_tracker.record_destination_port(packet.src_ip, packet.dst_port, packet.timestamp)
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
                failed_auth_count=1 if packet.is_auth_failure else 0,
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
        Convert a FlowSession into a NetworkFlowInput along with (source_ip, destination_ip).
        """
        source_ip = session.initiator_ip
        destination_ip = session.responder_ip
        dst_port = session.responder_port

        # Calculate unique destination ports targeted by initiator within 60s rolling window
        unique_ports = self.host_tracker.get_unique_dst_ports(
            source_ip, current_time=session.last_seen
        )

        # Calculate connection rate using unified defensible formula
        conn_rate = self.host_tracker.get_connection_rate(
            source_ip,
            packet_count=session.packet_count,
            duration=session.duration,
            current_time=session.last_seen,
        )

        # Bound values safely within expected physical boundaries
        packet_count = max(session.packet_count, 1)
        byte_count = max(session.byte_count, 1)
        duration = max(round(session.duration, 4), 0.001)
        safe_dst_port = max(min(dst_port, 65535), 1)

        flow_input = NetworkFlowInput(
            packet_count=packet_count,
            byte_count=byte_count,
            duration=duration,
            conn_rate=round(float(conn_rate), 2),
            dst_port=safe_dst_port,
            unique_dst_ports=int(unique_ports),
            failed_auth_count=max(session.failed_auth_count, 0),
        )

        return flow_input, source_ip, destination_ip
