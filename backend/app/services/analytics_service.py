"""
Security Analytics Aggregation Service
=======================================
Aggregates historical telemetry distributions from PostgreSQL including risk score
histograms, attack-type distributions, zone transit matrices, provenance ledgers,
and global feature sensitivity rankings.
"""

from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List
from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.app.models.active_enforcement import ActiveEnforcementModel
from backend.app.models.security_event import SecurityEventModel
from backend.app.repositories.enforcement_repo import EnforcementRepository
from backend.app.schemas.analytics import (
    AnalyticsHistogramBin,
    AnalyticsSummaryResponse,
    AttackTypeDistribution,
    GlobalFeatureSensitivity,
    PolicyDecisionDistribution,
    TelemetryProvenanceDistribution,
    ZoneTrafficDistribution,
)
from ml.features.extractor import FEATURE_NAMES

HISTOGRAM_BUCKETS = [
    ("0-19", 0, 19),
    ("20-39", 20, 39),
    ("40-59", 40, 59),
    ("60-79", 60, 79),
    ("80-100", 80, 100),
]


class AnalyticsService:

    @classmethod
    def get_summary(cls, db: Session) -> AnalyticsSummaryResponse:
        """
        Calculates aggregate security analytics directly from persisted PostgreSQL records.
        """
        total_events = db.query(func.count(SecurityEventModel.id)).scalar() or 0

        # Query all events for in-depth breakdown (or paginate if large)
        events: List[SecurityEventModel] = db.query(SecurityEventModel).all()

        # 1. Analytics Histogram Buckets (0-19, 20-39, 40-59, 60-79, 80-100)
        bucket_counts = {label: 0 for label, _, _ in HISTOGRAM_BUCKETS}
        attack_counts: Dict[str, int] = defaultdict(int)
        zone_counts: Dict[str, int] = defaultdict(int)
        provenance_counts: Dict[str, int] = defaultdict(int)
        action_counts: Dict[str, int] = defaultdict(int)
        feature_shap_sums: Dict[str, float] = defaultdict(float)
        feature_shap_counts: Dict[str, int] = defaultdict(int)

        real_count = 0
        fixture_demo_count = 0

        for e in events:
            score = e.risk_score
            for label, min_val, max_val in HISTOGRAM_BUCKETS:
                if min_val <= score <= max_val:
                    bucket_counts[label] += 1
                    break

            attack_counts[e.attack_type] += 1
            action_counts[e.current_policy_action] += 1

            # Extract provenance from flow_features JSON
            ff = e.flow_features or {}
            telem_src = ff.get("telemetry_source")
            if not telem_src:
                if e.is_demo:
                    telem_src = "DEMO_SEED"
                elif "aws" in e.id.lower():
                    telem_src = "AWS_VPC_FLOW_LOG_FIXTURE"
                else:
                    telem_src = "PCAP_FIXTURE"
            elif telem_src == "PCAP":
                telem_src = "PCAP_FIXTURE"

            is_real = telem_src in ["AWS_VPC_FLOW_LOG", "LIVE_PCAP_STREAM", "LIVE_NETWORK_STREAM"]
            provenance_counts[telem_src] += 1

            if is_real:
                real_count += 1
            else:
                fixture_demo_count += 1

            direction = ff.get("traffic_direction") or ("INTRA_CLOUD" if "aws" in e.id.lower() else "ON_PREM_TO_CLOUD")
            zone_counts[direction] += 1

            # Aggregate feature attributions
            top_feats = e.top_contributing_features or []
            for tf in top_feats:
                feat = tf.get("feature")
                sv = tf.get("shap_value")
                if feat and sv is not None:
                    feature_shap_sums[feat] += abs(float(sv))
                    feature_shap_counts[feat] += 1

        # Calculate percentages
        total_float = float(total_events) if total_events > 0 else 1.0

        histogram_res = [
            AnalyticsHistogramBin(
                bin_label=label,
                min_score=min_v,
                max_score=max_v,
                count=bucket_counts[label],
                percentage=round((bucket_counts[label] / total_float) * 100.0, 1),
            )
            for label, min_v, max_v in HISTOGRAM_BUCKETS
        ]

        attack_res = [
            AttackTypeDistribution(
                attack_type=atk,
                count=cnt,
                percentage=round((cnt / total_float) * 100.0, 1),
            )
            for atk, cnt in sorted(attack_counts.items(), key=lambda x: x[1], reverse=True)
        ]

        zone_res = [
            ZoneTrafficDistribution(
                traffic_direction=zd,
                count=cnt,
                percentage=round((cnt / total_float) * 100.0, 1),
            )
            for zd, cnt in sorted(zone_counts.items(), key=lambda x: x[1], reverse=True)
        ]

        provenance_res = [
            TelemetryProvenanceDistribution(
                telemetry_source=ts,
                count=cnt,
                percentage=round((cnt / total_float) * 100.0, 1),
                is_real_telemetry=ts in ["AWS_VPC_FLOW_LOG", "LIVE_PCAP_STREAM", "LIVE_NETWORK_STREAM"],
            )
            for ts, cnt in sorted(provenance_counts.items(), key=lambda x: x[1], reverse=True)
        ]

        policy_res = [
            PolicyDecisionDistribution(
                policy_action=act,  # type: ignore
                count=cnt,
                percentage=round((cnt / total_float) * 100.0, 1),
            )
            for act, cnt in sorted(action_counts.items(), key=lambda x: x[1], reverse=True)
        ]

        # Calculate mean absolute SHAP for global sensitivity ranking
        feature_sensitivities: List[GlobalFeatureSensitivity] = []
        for feat in FEATURE_NAMES:
            c = feature_shap_counts.get(feat, 0)
            s = feature_shap_sums.get(feat, 0.0)
            mean_abs = (s / float(c)) if c > 0 else 0.0
            feature_sensitivities.append((feat, mean_abs))

        feature_sensitivities.sort(key=lambda x: x[1], reverse=True)

        sensitivity_res = [
            GlobalFeatureSensitivity(
                feature=feat,
                mean_abs_shap=round(float(val), 4),
                importance_rank=rank + 1,
            )
            for rank, (feat, val) in enumerate(feature_sensitivities)
        ]

        # Count active containment rules in sandbox
        enforce_repo = EnforcementRepository(db)
        active_rules = enforce_repo.list_active_rules()

        return AnalyticsSummaryResponse(
            total_events_evaluated=total_events,
            real_telemetry_events=real_count,
            fixture_demo_events=fixture_demo_count,
            active_sandbox_rules_count=len(active_rules),
            histogram_buckets=histogram_res,
            attack_type_distribution=attack_res,
            zone_traffic_distribution=zone_res,
            telemetry_provenance_distribution=provenance_res,
            policy_decision_distribution=policy_res,
            top_sensitive_features=sensitivity_res,
            generated_at_utc=datetime.now(timezone.utc),
        )
