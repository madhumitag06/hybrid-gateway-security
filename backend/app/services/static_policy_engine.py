"""
Static Policy Engine (Baseline Reference)
=========================================
Implements traditional deterministic, rule-based security policy logic
for direct objective comparison against the Adaptive AI Policy Engine.
"""

from typing import List, Optional, Set
from backend.app.schemas.policy import PolicyComparisonResult, PolicyDecision
from backend.app.schemas.predict import NetworkFlowRequest, PredictionResponse


class StaticPolicyEngine:
    """
    Evaluates flows strictly against fixed, predefined static rules.
    """
    PROHIBITED_PORTS: Set[int] = {21, 23, 135, 139, 445}
    KNOWN_MALICIOUS_IPS: Set[str] = {"203.0.113.100", "198.51.100.200"}
    PACKET_COUNT_THRESHOLD: int = 2000
    CONN_RATE_THRESHOLD: float = 100.0

    @classmethod
    def evaluate(
        cls,
        flow: NetworkFlowRequest,
        source_ip: str,
        dst_port: int,
    ) -> tuple[str, Optional[str]]:
        """
        Evaluate flow using static heuristic rules.
        Returns: (static_action: 'Allow' | 'Block', rule_matched: Optional[str])
        """
        if source_ip in cls.KNOWN_MALICIOUS_IPS:
            return "Block", "STATIC_IP_BLACKLIST"

        if dst_port in cls.PROHIBITED_PORTS:
            return "Block", f"PROHIBITED_DESTINATION_PORT_{dst_port}"

        if flow.packet_count > cls.PACKET_COUNT_THRESHOLD:
            return "Block", f"STATIC_VOLUMETRIC_LIMIT_EXCEEDED (>{cls.PACKET_COUNT_THRESHOLD} pkts)"

        if flow.conn_rate > cls.CONN_RATE_THRESHOLD:
            return "Block", f"STATIC_CONNECTION_RATE_LIMIT_EXCEEDED (>{cls.CONN_RATE_THRESHOLD} conn/s)"

        return "Allow", None

    @classmethod
    def compare_with_adaptive(
        cls,
        flow: NetworkFlowRequest,
        source_ip: str,
        dst_port: int,
        adaptive_decision: PolicyDecision,
        flow_id: str = "flow-cmp",
    ) -> PolicyComparisonResult:
        """
        Compare static baseline decision with adaptive AI decision and return neutral divergence analysis.
        """
        static_action, static_rule = cls.evaluate(flow, source_ip, dst_port)
        adaptive_action = adaptive_decision.policy_action

        # Check for decision divergence
        divergence = static_action.upper() != adaptive_action.upper()

        if not divergence:
            rationale = f"Both engines aligned on '{adaptive_action}' action."
        else:
            if static_action == "Allow" and adaptive_action in ["Restrict", "Block"]:
                rationale = (
                    f"Adaptive Engine identified '{adaptive_decision.attack_type}' threat (Risk: {adaptive_decision.risk_score}, "
                    f"Conf: {adaptive_decision.confidence * 100:.0f}%) via multi-feature correlation, whereas Static Engine allowed "
                    f"the traffic because thresholds (port={dst_port}, pkts={flow.packet_count}) were not exceeded."
                )
            elif static_action == "Block" and adaptive_action in ["Allow", "Monitor"]:
                rationale = (
                    f"Static Engine triggered rule '{static_rule}' based on rigid parameter check, while Adaptive Engine "
                    f"evaluated benign contextual distributions (Risk: {adaptive_decision.risk_score})."
                )
            else:
                rationale = f"Decision difference: Static ({static_action}) vs Adaptive ({adaptive_action})."

        return PolicyComparisonResult(
            flow_id=flow_id,
            target_ip=source_ip,
            dst_port=dst_port,
            static_decision=static_action,  # type: ignore
            static_rule_matched=static_rule,
            adaptive_decision=adaptive_action,
            adaptive_risk_score=adaptive_decision.risk_score,
            adaptive_confidence=adaptive_decision.confidence,
            decision_divergence=divergence,
            divergence_rationale=rationale,
        )
