"""
Dashboard Aggregation Service
==============================
Evaluates gateway network flows through the real ML Service to dynamically construct
dashboard metrics, security events, explainable risk reasons, and handle policy actions.

Note:
Flow records represent simulated gateway observation buffers for prototype demonstration
until live packet ingestion (eBPF/pcap) is implemented in subsequent phases.
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional
from backend.app.schemas.dashboard import (
    DashboardDataSchema,
    PolicyAction,
    PolicyActionResponse,
    RiskReasonSchema,
    SecurityEventSchema,
)
from backend.app.schemas.predict import NetworkFlowRequest, PredictionResponse
from backend.app.services.ml_service import MLService


# Initial sample flow scenarios evaluated by the ML model on startup
INITIAL_FLOW_SCENARIOS = [
    {
        "id": "evt-1001",
        "time": "14:32:07",
        "source": "192.168.1.77",
        "destination": "10.100.4.12",
        "flow": NetworkFlowRequest(
            packet_count=2,
            byte_count=120,
            duration=0.08,
            conn_rate=120.0,
            dst_port=8443,
            unique_dst_ports=75,
            failed_auth_count=0,
        ),
        "override_action": None,
    },
    {
        "id": "evt-1002",
        "time": "14:28:15",
        "source": "203.0.113.24",
        "destination": "10.100.2.18",
        "flow": NetworkFlowRequest(
            packet_count=35,
            byte_count=8500,
            duration=1.8,
            conn_rate=18.0,
            dst_port=22,
            unique_dst_ports=1,
            failed_auth_count=12,
        ),
        "override_action": None,
    },
    {
        "id": "evt-1003",
        "time": "14:12:41",
        "source": "198.51.100.9",
        "destination": "10.100.1.44",
        "flow": NetworkFlowRequest(
            packet_count=4500,
            byte_count=4500000,
            duration=4.0,
            conn_rate=60.0,
            dst_port=80,
            unique_dst_ports=1,
            failed_auth_count=0,
        ),
        "override_action": None,
    },
    {
        "id": "evt-1004",
        "time": "13:47:22",
        "source": "192.0.2.56",
        "destination": "10.100.3.20",
        "flow": NetworkFlowRequest(
            packet_count=8,
            byte_count=600,
            duration=0.8,
            conn_rate=15.0,
            dst_port=8080,
            unique_dst_ports=5,
            failed_auth_count=0,
        ),
        "override_action": None,
    },
    {
        "id": "evt-1005",
        "time": "11:03:11",
        "source": "192.168.1.101",
        "destination": "10.100.4.12",
        "flow": NetworkFlowRequest(
            packet_count=1200,
            byte_count=1600000,
            duration=120.0,
            conn_rate=3.0,
            dst_port=8443,
            unique_dst_ports=1,
            failed_auth_count=0,
        ),
        "override_action": None,
    },
    {
        "id": "evt-1006",
        "time": "10:45:00",
        "source": "192.168.1.50",
        "destination": "10.100.0.1",
        "flow": NetworkFlowRequest(
            packet_count=25,
            byte_count=15000,
            duration=2.5,
            conn_rate=2.0,
            dst_port=443,
            unique_dst_ports=1,
            failed_auth_count=0,
        ),
        "override_action": None,
    },
]


class DashboardService:
    _events_state: Dict[str, Dict] = {e["id"]: dict(e) for e in INITIAL_FLOW_SCENARIOS}

    @classmethod
    def get_dashboard_data(cls) -> DashboardDataSchema:
        """
        Evaluate all current flow scenarios through the real ML Service and build dashboard telemetry.
        """
        events: List[SecurityEventSchema] = []
        max_risk = 0
        risk_sum = 0
        reasons_counter: Dict[str, int] = {}

        for item in cls._events_state.values():
            flow_req: NetworkFlowRequest = item["flow"]
            pred: PredictionResponse = MLService.predict(flow_req)

            # Map ML prediction into event fields
            risk = pred.risk_score
            max_risk = max(max_risk, risk)
            risk_sum += risk

            if risk >= 85:
                severity = "critical"
            elif risk >= 70:
                severity = "high"
            elif risk >= 40:
                severity = "medium"
            else:
                severity = "low"

            effective_action = item["override_action"] or pred.action_recommendation
            status = "Applied" if effective_action in ["Restrict", "Block"] else ("Monitoring" if effective_action == "Monitor" else "Allowed")

            # Construct human-readable description with ML rationale
            if pred.is_anomaly:
                feat_reasons = ", ".join([f"{c.feature} ({c.value})" for c in pred.top_contributing_features[:2]])
                desc = f"Classified as {pred.attack_type} with confidence {pred.confidence * 100:.1f}%. Key deviations: {feat_reasons}."
            else:
                desc = "Standard baseline network activity adhering to normal flow distributions."

            event_title = f"{pred.attack_type.replace('_', ' ').title()} Detected" if pred.is_anomaly else "Normal Network Traffic"

            events.append(
                SecurityEventSchema(
                    id=item["id"],
                    time=item["time"],
                    event=event_title,
                    source=item["source"],
                    destination=item["destination"],
                    risk=risk,
                    severity=severity,
                    action=effective_action,
                    status=status,
                    description=desc,
                    attack_type=pred.attack_type,
                    confidence=pred.confidence,
                )
            )

            # Aggregate contributing features for Explainable AI card
            for cf in pred.top_contributing_features:
                reasons_counter[cf.feature] = reasons_counter.get(cf.feature, 0) + int(abs(cf.deviation_z_score) * 5)

        # Calculate overall Gateway Risk State
        overall_risk = int(max_risk * 0.7 + (risk_sum / max(len(events), 1)) * 0.3)
        overall_risk = min(max(overall_risk, 0), 100)

        if overall_risk >= 70:
            risk_state: PolicyAction = "Restrict"
        elif overall_risk >= 40:
            risk_state: PolicyAction = "Monitor"
        else:
            risk_state: PolicyAction = "Allow"

        # Format top risk reasons for dashboard XAI panel
        reasons_list: List[RiskReasonSchema] = []
        feature_labels = {
            "unique_dst_ports": "Port Scan / Probing Activity",
            "conn_rate": "Traffic Frequency Spike",
            "failed_auth_count": "Failed Authentication Burst",
            "byte_count": "Unusual Data Transfer Volume",
            "dst_port": "Non-Standard / Admin Port Access",
            "avg_packet_size": "Abnormal Payload Ratio",
        }

        tone_map = {
            "unique_dst_ports": "red",
            "conn_rate": "orange",
            "failed_auth_count": "yellow",
            "byte_count": "blue",
            "dst_port": "red",
            "avg_packet_size": "blue",
        }

        for feat, count in sorted(reasons_counter.items(), key=lambda x: x[1], reverse=True)[:5]:
            reasons_list.append(
                RiskReasonSchema(
                    label=feature_labels.get(feat, feat),
                    value=min(max(count, 5), 100),
                    tone=tone_map.get(feat, "blue"),
                )
            )

        if not reasons_list:
            reasons_list.append(RiskReasonSchema(label="Baseline Traffic Activity", value=10, tone="blue"))

        return DashboardDataSchema(
            riskScore=overall_risk,
            riskState=risk_state,
            activeFlows=247,
            events=events,
            reasons=reasons_list,
            modelStatus="Trained RandomForestClassifier active (Phase 1)",
            isSimulatedFlowBuffer=True,
        )

    @classmethod
    def apply_policy_action(cls, event_id: str, action: PolicyAction) -> PolicyActionResponse:
        """
        Update the policy action for a specific security event.
        """
        if event_id not in cls._events_state:
            # Fallback creation if custom event
            cls._events_state[event_id] = {
                "id": event_id,
                "time": datetime.now(timezone.utc).strftime("%H:%M:%S"),
                "source": "192.168.1.100",
                "destination": "10.100.1.1",
                "flow": NetworkFlowRequest(
                    packet_count=10,
                    byte_count=5000,
                    duration=1.0,
                    conn_rate=5.0,
                    dst_port=443,
                ),
                "override_action": action,
            }
        else:
            cls._events_state[event_id]["override_action"] = action

        status = "Applied" if action in ["Restrict", "Block"] else ("Monitoring" if action == "Monitor" else "Allowed")
        return PolicyActionResponse(
            eventId=event_id,
            action=action,
            status=status,
            message=f"Policy action '{action}' successfully updated for event '{event_id}'.",
        )
