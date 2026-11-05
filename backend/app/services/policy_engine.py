"""
Adaptive Policy Decision Engine
===============================
Evaluates machine learning threat predictions in operational context (management allowlists,
confidence thresholds, attack-specific graduated policies) to produce deterministic,
structured policy decisions.
"""

from collections import defaultdict, deque
from datetime import datetime, timezone
import ipaddress
import threading
import time
from typing import Deque, Dict, List, Optional
import uuid

from backend.app.config import settings
from backend.app.schemas.policy import PolicyDecision
from backend.app.schemas.predict import PredictionResponse


class SSHProbeTracker:
    """
    Thread-safe, memory-bounded, rolling-window tracker for observable SSH connection bursts.
    Detects repeated failed/short probes without requiring plaintext authentication payloads.
    """

    def __init__(self, window_seconds: float = 60.0, max_hosts: int = 5000):
        self.window_seconds = window_seconds
        self.max_hosts = max_hosts
        self.lock = threading.RLock()
        self.host_probes: Dict[str, Deque[float]] = defaultdict(deque)
        self.host_last_seen: Dict[str, float] = {}

    def record_ssh_attempt(
        self,
        source_ip: str,
        byte_count: Optional[int] = None,
        timestamp: Optional[float] = None,
    ) -> int:
        ts = float(timestamp) if timestamp is not None else time.time()
        with self.lock:
            # If byte_count indicates an established large session (>25KB), do not treat as failed probe
            max_bytes = getattr(settings, "ssh_max_bytes_per_probe", 10000)
            if byte_count is not None and byte_count > max_bytes:
                # Legitimate large transfer / interactive session; do not count toward probe burst
                return self.get_probe_count(source_ip, current_time=ts)

            if len(self.host_last_seen) >= self.max_hosts and source_ip not in self.host_last_seen:
                oldest = min(self.host_last_seen, key=self.host_last_seen.get)
                del self.host_last_seen[oldest]
                if oldest in self.host_probes:
                    del self.host_probes[oldest]

            self.host_last_seen[source_ip] = ts
            q = self.host_probes[source_ip]
            q.append(ts)
            self._expire(source_ip, ts)
            return len(q)

    def get_probe_count(
        self, source_ip: str, current_time: Optional[float] = None
    ) -> int:
        ts = float(current_time) if current_time is not None else time.time()
        with self.lock:
            if source_ip not in self.host_probes:
                return 0
            self._expire(source_ip, ts)
            return len(self.host_probes[source_ip])

    def reset_host(self, source_ip: str) -> None:
        with self.lock:
            if source_ip in self.host_probes:
                del self.host_probes[source_ip]
            if source_ip in self.host_last_seen:
                del self.host_last_seen[source_ip]

    def _expire(self, source_ip: str, current_time: float) -> None:
        q = self.host_probes.get(source_ip)
        if not q:
            return
        cutoff = current_time - self.window_seconds
        while q and q[0] < cutoff:
            q.popleft()


class PolicyEngine:
    """
    Decouples ML threat detection from security policy enforcement decisions.
    """

    ssh_tracker = SSHProbeTracker(
        window_seconds=getattr(settings, "ssh_burst_window_seconds", 60.0)
    )

    @classmethod
    def is_ip_allowlisted(cls, ip_str: str, allowlist: Optional[List[str]] = None) -> bool:
        """
        Check if an IP address belongs to any protected CIDR block.
        """
        cidrs = allowlist if allowlist is not None else settings.management_allowlist
        try:
            target = ipaddress.ip_address(ip_str.strip())
            for cidr in cidrs:
                network = ipaddress.ip_network(cidr.strip(), strict=False)
                if target in network:
                    return True
        except ValueError:
            pass
        return False

    @classmethod
    def evaluate(
        cls,
        prediction: PredictionResponse,
        source_ip: str,
        destination_ip: str,
        dst_port: int,
        protocol: str = "TCP",
        event_id: Optional[str] = None,
        custom_allowlist: Optional[List[str]] = None,
        byte_count: Optional[int] = None,
    ) -> PolicyDecision:
        """
        Evaluate context-aware security policy for an evaluated network flow.
        """
        decision_id = f"dec-{uuid.uuid4().hex[:8]}"

        # 1. Management Allowlist Check (Highest Precedence)
        if cls.is_ip_allowlisted(source_ip, custom_allowlist):
            return PolicyDecision(
                decision_id=decision_id,
                event_id=event_id,
                target_ip=source_ip,
                target_port=dst_port,
                protocol=protocol,
                policy_action="Allow",
                enforcement_required=False,
                confidence=prediction.confidence,
                threat_level=prediction.threat_level,
                attack_type=prediction.attack_type,
                risk_score=prediction.risk_score,
                rule_name="MANAGEMENT_ALLOWLIST_PROTECTION",
                reason=f"Source IP {source_ip} matches protected management allowlist CIDR; enforcement bypassed.",
                suggested_ttl_seconds=0,
            )

        # 2. Confidence Gating Check
        # If prediction confidence is low (< 0.60) on a non-benign flow, downgrade to observational Monitoring
        if prediction.confidence < 0.60 and prediction.threat_level != "LOW":
            return PolicyDecision(
                decision_id=decision_id,
                event_id=event_id,
                target_ip=source_ip,
                target_port=dst_port,
                protocol=protocol,
                policy_action="Monitor",
                enforcement_required=False,
                confidence=prediction.confidence,
                threat_level=prediction.threat_level,
                attack_type=prediction.attack_type,
                risk_score=prediction.risk_score,
                rule_name="CONFIDENCE_GATING_MONITOR",
                reason=f"Threat confidence ({prediction.confidence * 100:.1f}%) is below operating threshold (60%); placed in observation mode.",
                suggested_ttl_seconds=180,
            )

        # 3. Observable SSH Brute-Force Safeguard Check
        is_ssh_target = (dst_port in (22, 2222))
        ssh_safeguard_active = getattr(settings, "ssh_safeguard_enabled", True) and is_ssh_target

        threat_level = prediction.threat_level.upper()
        attack_type = prediction.attack_type.upper()

        if ssh_safeguard_active:
            flow_bytes = byte_count if byte_count is not None else getattr(prediction, "byte_count", None)
            probe_count = cls.ssh_tracker.record_ssh_attempt(source_ip, byte_count=flow_bytes)

            block_thresh = getattr(settings, "ssh_block_burst_threshold", 12)
            restrict_thresh = getattr(settings, "ssh_restrict_burst_threshold", 6)
            monitor_thresh = getattr(settings, "ssh_monitor_burst_threshold", 3)

            # If ML did not flag this as high-severity brute force (e.g. zero L7 auth telemetry),
            # evaluate observable connection burst thresholds:
            if threat_level != "HIGH" and attack_type != "BRUTE_FORCE":
                if probe_count >= block_thresh:
                    return PolicyDecision(
                        decision_id=decision_id,
                        event_id=event_id,
                        target_ip=source_ip,
                        target_port=None,
                        protocol="ANY",
                        policy_action="Block",
                        enforcement_required=True,
                        confidence=0.95,
                        threat_level="HIGH",
                        attack_type="BRUTE_FORCE",
                        risk_score=90,
                        rule_name="OBSERVABLE_SSH_BURST_BLOCK",
                        reason=f"Observable SSH credential stuffing burst: {probe_count} attempts in {cls.ssh_tracker.window_seconds:.0f}s from {source_ip}; quarantined host.",
                        suggested_ttl_seconds=600,
                    )
                elif probe_count >= restrict_thresh:
                    return PolicyDecision(
                        decision_id=decision_id,
                        event_id=event_id,
                        target_ip=source_ip,
                        target_port=dst_port,
                        protocol=protocol,
                        policy_action="Restrict",
                        enforcement_required=True,
                        confidence=0.85,
                        threat_level="MEDIUM",
                        attack_type="BRUTE_FORCE",
                        risk_score=65,
                        rule_name="OBSERVABLE_SSH_BURST_RESTRICT",
                        reason=f"Elevated SSH probe burst: {probe_count} attempts in {cls.ssh_tracker.window_seconds:.0f}s from {source_ip}; restricted port {dst_port}.",
                        suggested_ttl_seconds=300,
                    )
                elif probe_count >= monitor_thresh:
                    return PolicyDecision(
                        decision_id=decision_id,
                        event_id=event_id,
                        target_ip=source_ip,
                        target_port=dst_port,
                        protocol=protocol,
                        policy_action="Monitor",
                        enforcement_required=False,
                        confidence=0.70,
                        threat_level="MEDIUM",
                        attack_type="BRUTE_FORCE",
                        risk_score=45,
                        rule_name="OBSERVABLE_SSH_BURST_MONITOR",
                        reason=f"Repeated SSH connection attempts: {probe_count} probes in {cls.ssh_tracker.window_seconds:.0f}s from {source_ip}; placed in observation mode.",
                        suggested_ttl_seconds=180,
                    )

        # 4. Graduated Threat Level Mapping

        if threat_level == "LOW" or attack_type == "BENIGN":
            return PolicyDecision(
                decision_id=decision_id,
                event_id=event_id,
                target_ip=source_ip,
                target_port=dst_port,
                protocol=protocol,
                policy_action="Allow",
                enforcement_required=False,
                confidence=prediction.confidence,
                threat_level="LOW",
                attack_type="BENIGN",
                risk_score=prediction.risk_score,
                rule_name="BASELINE_TRAFFIC_ALLOW",
                reason="Traffic profile conforms to baseline distributions; no policy restriction required.",
                suggested_ttl_seconds=0,
            )

        elif threat_level == "MEDIUM":
            return PolicyDecision(
                decision_id=decision_id,
                event_id=event_id,
                target_ip=source_ip,
                target_port=dst_port,
                protocol=protocol,
                policy_action="Restrict",
                enforcement_required=True,
                confidence=prediction.confidence,
                threat_level="MEDIUM",
                attack_type=prediction.attack_type,
                risk_score=prediction.risk_score,
                rule_name="GRADUATED_SERVICE_RESTRICTION",
                reason=f"Medium risk anomaly ({prediction.attack_type}) detected. Applying targeted port/rate restriction on port {dst_port}.",
                suggested_ttl_seconds=180,
            )

        else:  # HIGH / CRITICAL
            if attack_type == "PORT_SCAN":
                return PolicyDecision(
                    decision_id=decision_id,
                    event_id=event_id,
                    target_ip=source_ip,
                    target_port=None,
                    protocol="ANY",
                    policy_action="Block",
                    enforcement_required=True,
                    confidence=prediction.confidence,
                    threat_level="HIGH",
                    attack_type=attack_type,
                    risk_score=prediction.risk_score,
                    rule_name="RECON_PORT_SCAN_QUARANTINE",
                    reason=f"Multi-port scanning reconnaissance detected from {source_ip}. Quarantining host.",
                    suggested_ttl_seconds=300,
                )
            elif attack_type == "BRUTE_FORCE":
                return PolicyDecision(
                    decision_id=decision_id,
                    event_id=event_id,
                    target_ip=source_ip,
                    target_port=None,
                    protocol="ANY",
                    policy_action="Block",
                    enforcement_required=True,
                    confidence=prediction.confidence,
                    threat_level="HIGH",
                    attack_type=attack_type,
                    risk_score=prediction.risk_score,
                    rule_name="BRUTE_FORCE_AUTHENTICATION_QUARANTINE",
                    reason=f"Authentication attack signature detected on port {dst_port} from {source_ip}. Quarantining host.",
                    suggested_ttl_seconds=600,
                )
            elif attack_type == "TRAFFIC_SPIKE":
                return PolicyDecision(
                    decision_id=decision_id,
                    event_id=event_id,
                    target_ip=source_ip,
                    target_port=dst_port,
                    protocol=protocol,
                    policy_action="Restrict",
                    enforcement_required=True,
                    confidence=prediction.confidence,
                    threat_level="HIGH",
                    attack_type=attack_type,
                    risk_score=prediction.risk_score,
                    rule_name="VOLUMETRIC_SPIKE_RATE_LIMIT",
                    reason=f"High volumetric throughput surge detected from {source_ip}. Applying rate-limit restriction.",
                    suggested_ttl_seconds=300,
                )
            else:
                return PolicyDecision(
                    decision_id=decision_id,
                    event_id=event_id,
                    target_ip=source_ip,
                    target_port=None,
                    protocol="ANY",
                    policy_action="Block",
                    enforcement_required=True,
                    confidence=prediction.confidence,
                    threat_level="HIGH",
                    attack_type=attack_type,
                    risk_score=prediction.risk_score,
                    rule_name="HIGH_RISK_ANOMALY_QUARANTINE",
                    reason=f"High risk anomaly ({prediction.attack_type}) exceeding critical threshold (score={prediction.risk_score}).",
                    suggested_ttl_seconds=300,
                )
