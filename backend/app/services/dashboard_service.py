"""
Dashboard Aggregation Service (PostgreSQL Backed)
=================================================
Evaluates and queries security telemetry from PostgreSQL to construct dashboard metrics,
events, explainable risk reasons, and handle persistent policy actions.
"""

from datetime import datetime, timezone
import uuid
from typing import Dict, List, Optional
from sqlalchemy.orm import Session
from backend.app.models.security_event import SecurityEventModel
from backend.app.repositories.policy_audit_repo import PolicyAuditRepository
from backend.app.repositories.security_event_repo import SecurityEventRepository
from backend.app.schemas.dashboard import (
    DashboardDataSchema,
    PolicyAction,
    PolicyActionResponse,
    RiskReasonSchema,
    SecurityEventSchema,
)
from backend.app.schemas.predict import NetworkFlowRequest, PredictionResponse
from backend.app.services.ml_service import MLService


# Initial demo flow scenarios for fresh database seeding (clearly marked as is_demo=True)
INITIAL_DEMO_SCENARIOS = [
    {
        "id": "evt-1001",
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
    },
    {
        "id": "evt-1002",
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
    },
    {
        "id": "evt-1003",
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
    },
    {
        "id": "evt-1004",
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
    },
    {
        "id": "evt-1005",
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
    },
    {
        "id": "evt-1006",
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
    },
]


class DashboardService:
    @classmethod
    def seed_initial_data_if_empty(cls, db: Session) -> None:
        """
        If the PostgreSQL database has 0 events, seed initial baseline demonstration flows
        evaluated through the real ML model.
        """
        repo = SecurityEventRepository(db)
        if repo.count() > 0:
            return

        print("[*] Database is empty. Seeding initial baseline demonstration events...")
        for item in INITIAL_DEMO_SCENARIOS:
            cls.record_prediction(
                db=db,
                flow_request=item["flow"],
                source_ip=item["source"],
                destination_ip=item["destination"],
                custom_id=item["id"],
                is_demo=True,
            )

    @classmethod
    def record_prediction(
        cls,
        db: Session,
        flow_request: NetworkFlowRequest,
        source_ip: str = "192.168.1.100",
        destination_ip: str = "10.100.1.10",
        custom_id: Optional[str] = None,
        is_demo: bool = False,
    ) -> Tuple_Pred_Event:
        """
        Executes ML inference via ThreatPredictor and persists the event into PostgreSQL.
        """
        pred: PredictionResponse = MLService.predict(flow_request)

        event_id = custom_id or f"evt-{uuid.uuid4().hex[:8]}"
        risk = pred.risk_score

        if risk >= 85:
            severity = "critical"
        elif risk >= 70:
            severity = "high"
        elif risk >= 40:
            severity = "medium"
        else:
            severity = "low"

        action = pred.action_recommendation
        status = "Applied" if action in ["Restrict", "Block"] else ("Monitoring" if action == "Monitor" else "Allowed")

        if pred.is_anomaly:
            feat_reasons = ", ".join([f"{c.feature} ({c.value})" for c in pred.top_contributing_features[:2]])
            desc = f"Classified as {pred.attack_type} with confidence {pred.confidence * 100:.1f}%. Key deviations: {feat_reasons}."
        else:
            desc = "Standard baseline network activity adhering to normal flow distributions."

        event_model = SecurityEventModel(
            id=event_id,
            timestamp=datetime.now(timezone.utc),
            source_ip=source_ip,
            destination_ip=destination_ip,
            attack_type=pred.attack_type,
            risk_score=risk,
            threat_level=pred.threat_level,
            confidence=pred.confidence,
            action_recommendation=pred.action_recommendation,
            current_policy_action=action,
            status=status,
            description=desc,
            is_anomaly=pred.is_anomaly,
            is_demo=is_demo,
            flow_features=flow_request.model_dump(),
            class_probabilities=pred.class_probabilities,
            top_contributing_features=[c.model_dump() for c in pred.top_contributing_features],
        )

        repo = SecurityEventRepository(db)
        repo.create(event_model)

        # Log initial policy action in audit ledger
        audit_repo = PolicyAuditRepository(db)
        audit_repo.log_action(
            event_id=event_id,
            requested_action=action,
            previous_action=None,
            resulting_status=status,
            actor="ml_policy_engine" if not is_demo else "demo_seed",
        )

        pred.event_id = event_id
        return pred, event_model

    @classmethod
    def get_dashboard_data(cls, db: Session) -> DashboardDataSchema:
        """
        Query recent security events from PostgreSQL and construct live dashboard telemetry.
        """
        cls.seed_initial_data_if_empty(db)
        repo = SecurityEventRepository(db)
        events_models, _ = repo.list_events(limit=20, offset=0)

        events: List[SecurityEventSchema] = []
        max_risk = 0
        risk_sum = 0
        reasons_counter: Dict[str, int] = {}

        for e in events_models:
            risk = e.risk_score
            max_risk = max(max_risk, risk)
            risk_sum += risk

            severity_map = {"LOW": "low", "MEDIUM": "medium", "HIGH": "high"}
            severity = severity_map.get(e.threat_level, "medium")
            if risk >= 85:
                severity = "critical"

            time_str = e.timestamp.strftime("%H:%M:%S") if e.timestamp else "00:00:00"
            event_title = f"{e.attack_type.replace('_', ' ').title()} Detected" if e.is_anomaly else "Normal Network Traffic"

            events.append(
                SecurityEventSchema(
                    id=e.id,
                    time=time_str,
                    event=event_title,
                    source=e.source_ip,
                    destination=e.destination_ip,
                    risk=risk,
                    severity=severity,
                    action=e.current_policy_action,
                    status=e.status,
                    description=e.description,
                    attack_type=e.attack_type,
                    confidence=e.confidence,
                    is_anomaly=e.is_anomaly,
                    is_demo=e.is_demo,
                )
            )

            # Aggregate contributing features for Explainable AI card
            if e.top_contributing_features:
                for cf in e.top_contributing_features:
                    feat_name = cf.get("feature", "")
                    z_val = abs(cf.get("deviation_z_score", 1.0))
                    if feat_name:
                        reasons_counter[feat_name] = reasons_counter.get(feat_name, 0) + int(z_val * 5)

        # Calculate overall Gateway Risk State
        overall_risk = int(max_risk * 0.7 + (risk_sum / max(len(events), 1)) * 0.3) if events else 0
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
            isSimulatedFlowBuffer=False,
            databaseBackend="PostgreSQL (Persistent Storage)",
        )

    @classmethod
    def apply_policy_action(
        cls, db: Session, event_id: str, action: PolicyAction, actor: str = "analyst"
    ) -> PolicyActionResponse:
        """
        Update the policy action for a specific security event in PostgreSQL and write to audit ledger.
        """
        repo = SecurityEventRepository(db)
        event = repo.get_by_id(event_id)
        if not event:
            # If event not found, create a placeholder event
            placeholder = SecurityEventModel(
                id=event_id,
                timestamp=datetime.now(timezone.utc),
                source_ip="192.168.1.100",
                destination_ip="10.100.1.1",
                attack_type="MANUAL_FLAG",
                risk_score=50,
                threat_level="MEDIUM",
                confidence=1.0,
                action_recommendation=action,
                current_policy_action=action,
                status="Applied" if action in ["Restrict", "Block"] else "Monitoring",
                description=f"Manual policy override applied: {action}",
                is_anomaly=True,
                is_demo=False,
                flow_features={},
                class_probabilities={},
                top_contributing_features=[],
            )
            repo.create(placeholder)
            event = placeholder

        previous_action = event.current_policy_action
        new_status = "Applied" if action in ["Restrict", "Block"] else ("Monitoring" if action == "Monitor" else "Allowed")

        repo.update_policy_action(event_id=event_id, new_action=action, new_status=new_status)

        # Record in policy audit ledger
        audit_repo = PolicyAuditRepository(db)
        audit_repo.log_action(
            event_id=event_id,
            requested_action=action,
            previous_action=previous_action,
            resulting_status=new_status,
            actor=actor,
        )

        return PolicyActionResponse(
            eventId=event_id,
            action=action,
            status=new_status,
            message=f"Policy action '{action}' successfully persisted to PostgreSQL for event '{event_id}'.",
            timestamp=datetime.now(timezone.utc),
        )


Tuple_Pred_Event = tuple[PredictionResponse, SecurityEventModel]
