"""
Adaptive Policy Decision Engine
===============================
Evaluates machine learning threat predictions in operational context (management allowlists,
confidence thresholds, attack-specific graduated policies) to produce deterministic,
structured policy decisions.
"""

from datetime import datetime, timezone
import ipaddress
from typing import List, Optional
import uuid

from backend.app.config import settings
from backend.app.schemas.policy import PolicyDecision
from backend.app.schemas.predict import PredictionResponse


class PolicyEngine:
    """
    Decouples ML threat detection from security policy enforcement decisions.
    """

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

        # 3. Graduated Threat Level Mapping
        threat_level = prediction.threat_level.upper()
        attack_type = prediction.attack_type.upper()

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
                    target_port=dst_port,
                    protocol=protocol,
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
                    target_port=dst_port,
                    protocol=protocol,
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
                    target_port=dst_port,
                    protocol=protocol,
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
