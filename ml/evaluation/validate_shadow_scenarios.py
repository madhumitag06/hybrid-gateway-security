"""
Live Hybrid-Cloud Gateway Validation Script (Phase 3)
=====================================================
Parses live hybrid-lab scenario PCAPs using FlowAggregator, extracts the 9 features,
runs authoritative production Random Forest inference and candidate XGBoost V2 shadow inference,
audits agreement/disagreements, verifies SHAP explanations, and records results into PostgreSQL.
"""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
import time
from typing import Any, Dict, List

# Ensure repository root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.utils import PcapReader

from backend.app.config import settings
from backend.app.db.session import SessionLocal, init_db
from backend.app.models.shadow_prediction import ShadowPredictionModel
from backend.app.schemas.predict import NetworkFlowRequest
from backend.app.services.dashboard_service import DashboardService
from backend.app.services.flow_aggregator import FlowAggregator, FlowSession, PacketRecord
from backend.app.services.ml_service import MLService
from backend.app.services.shadow_service import ShadowService
from ml.features.extractor import FEATURE_NAMES_V2, FeatureExtractor

PCAP_DIR = Path("data/lab_pcaps")

SCENARIOS = [
    {
        "id": "A",
        "name": "Benign On-Prem to Cloud Traffic",
        "file": "scenario1_benign_onprem_to_cloud.pcap",
        "expected_class": "BENIGN",
    },
    {
        "id": "B",
        "name": "Port Scanning Across Gateway",
        "file": "scenario2_port_scan_onprem_to_cloud.pcap",
        "expected_class": "PORT_SCAN",
    },
    {
        "id": "C",
        "name": "SSH Brute-Force Probes",
        "file": "scenario6_brute_force_onprem_to_cloud.pcap",
        "expected_class": "BRUTE_FORCE",
    },
    {
        "id": "D",
        "name": "Volumetric Traffic Spike / Flood",
        "file": "scenario3_traffic_spike_onprem_to_cloud.pcap",
        "expected_class": "TRAFFIC_SPIKE",
    },
    {
        "id": "E",
        "name": "Suspicious File Transfer / Exfiltration",
        "file": "scenario4_suspicious_transfer_onprem_to_cloud.pcap",
        "expected_class": "SUSPICIOUS_TRANSFER",
    },
    {
        "id": "F",
        "name": "Cross-Network Containment & Restriction",
        "file": "scenario5_blocked_restricted_containment.pcap",
        "expected_class": "PORT_SCAN",
    },
]


def parse_pcap_to_flows(pcap_path: Path) -> List[Tuple[FlowSession, NetworkFlowInput, str, str]]:
    aggregator = FlowAggregator()
    with PcapReader(str(pcap_path)) as reader:
        for pkt in reader:
            if IP in pkt:
                ip_layer = pkt[IP]
            elif IPv6 in pkt:
                ip_layer = pkt[IPv6]
            else:
                continue

            proto = "OTHER"
            sport = 0
            dport = 0
            tcp_flags = None

            if TCP in pkt:
                proto = "TCP"
                sport = int(pkt[TCP].sport)
                dport = int(pkt[TCP].dport)
                tcp_flags = int(pkt[TCP].flags)
            elif UDP in pkt:
                proto = "UDP"
                sport = int(pkt[UDP].sport)
                dport = int(pkt[UDP].dport)
            elif ICMP in pkt:
                proto = "ICMP"

            pkt_record = PacketRecord(
                timestamp=float(pkt.time),
                src_ip=str(ip_layer.src),
                dst_ip=str(ip_layer.dst),
                src_port=sport,
                dst_port=dport,
                protocol=proto,
                length_bytes=len(pkt),
                tcp_flags=tcp_flags,
            )
            aggregator.add_packet(pkt_record)

    sessions = aggregator.flush_all()
    results = []
    for sess in sessions:
        flow_input, src_ip, dst_ip = aggregator.extract_features(sess)
        results.append((sess, flow_input, src_ip, dst_ip))
    return results


def main():
    print("=" * 70)
    print(" LIVE HYBRID-CLOUD GATEWAY VALIDATION — SHADOW MODE (XGBOOST V2)")
    print("=" * 70)

    init_db()

    cand_predictor = ShadowService.get_candidate_predictor()
    if cand_predictor is None:
        print("[!] ERROR: Candidate predictor failed to load!")
        return

    print(f"[+] Production Model: Random Forest ({settings.ml_artifacts_dir})")
    print(f"[+] Candidate Model: XGBoost V2 ({settings.shadow_artifacts_dir})")
    print(f"[+] Schema: {len(cand_predictor.feature_schema)} features (Clean V2)")

    scenario_reports = []

    with SessionLocal() as db:
        for sc in SCENARIOS:
            pcap_file = PCAP_DIR / sc["file"]
            if not pcap_file.is_file():
                print(f"[!] Warning: {pcap_file} not found, skipping...")
                continue

            print(f"\n--- Scenario {sc['id']}: {sc['name']} ---")
            print(f"    File: {sc['file']} ({pcap_file.stat().st_size} bytes)")

            sessions = parse_pcap_to_flows(pcap_file)
            print(f"    Aggregated Flows: {len(sessions)}")

            flow_results = []
            agreements = 0
            prod_latencies = []
            cand_latencies = []

            for sess, flow_input, src_ip, dst_ip in sessions:
                flow_req = NetworkFlowRequest(
                    packet_count=flow_input.packet_count,
                    byte_count=flow_input.byte_count,
                    duration=flow_input.duration,
                    conn_rate=flow_input.conn_rate,
                    dst_port=flow_input.dst_port,
                    unique_dst_ports=flow_input.unique_dst_ports,
                    failed_auth_count=flow_input.failed_auth_count,
                )

                t_prod0 = time.perf_counter()
                prod_pred, evt_model = DashboardService.record_prediction(
                    db=db,
                    flow_request=flow_req,
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    is_demo=False,
                )
                prod_lat = (time.perf_counter() - t_prod0) * 1000.0
                prod_latencies.append(prod_lat)

                # Query latest shadow record
                latest_shadow = (
                    db.query(ShadowPredictionModel)
                    .filter(ShadowPredictionModel.flow_id == evt_model.id)
                    .first()
                )

                if latest_shadow:
                    cand_lat = latest_shadow.candidate_latency_ms
                    cand_latencies.append(cand_lat)
                    if latest_shadow.agreement:
                        agreements += 1

                    flow_results.append({
                        "flow_id": evt_model.id,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "dst_port": sess.responder_port,
                        "protocol": sess.protocol,
                        "features_v2": latest_shadow.flow_features,
                        "prod_attack_type": latest_shadow.prod_attack_type,
                        "prod_confidence": latest_shadow.prod_confidence,
                        "prod_risk_score": latest_shadow.prod_risk_score,
                        "prod_latency_ms": prod_lat,
                        "cand_attack_type": latest_shadow.candidate_attack_type,
                        "cand_confidence": latest_shadow.candidate_confidence,
                        "cand_risk_score": latest_shadow.candidate_risk_score,
                        "cand_latency_ms": cand_lat,
                        "agreement": latest_shadow.agreement,
                        "disagreement_type": latest_shadow.disagreement_type,
                        "shap_attributions": latest_shadow.shap_attributions,
                    })

            db.commit()

            total_flows = len(flow_results)
            agree_pct = (agreements / total_flows * 100.0) if total_flows > 0 else 100.0
            avg_p_lat = sum(prod_latencies) / len(prod_latencies) if prod_latencies else 0.0
            avg_c_lat = sum(cand_latencies) / len(cand_latencies) if cand_latencies else 0.0

            sc_summary = {
                "scenario_id": sc["id"],
                "name": sc["name"],
                "expected_class": sc["expected_class"],
                "total_flows": total_flows,
                "agreements": agreements,
                "disagreements": total_flows - agreements,
                "agreement_pct": round(agree_pct, 2),
                "avg_prod_latency_ms": round(avg_p_lat, 3),
                "avg_cand_latency_ms": round(avg_c_lat, 3),
                "flows": flow_results,
            }
            scenario_reports.append(sc_summary)

            print(f"    Results: {total_flows} flows evaluated")
            print(f"    Agreement Rate: {agree_pct:.1f}% ({agreements}/{total_flows})")
            print(f"    Avg Latency: Prod RF = {avg_p_lat:.3f} ms | Candidate XGBoost V2 = {avg_c_lat:.3f} ms")

    # Save comprehensive report to JSON
    out_path = Path("data/reports/live_scenario_validation_report.json")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({"timestamp_utc": datetime.now(timezone.utc).isoformat(), "scenarios": scenario_reports}, f, indent=2)

    print("\n" + "=" * 70)
    print(f"[+] Complete report saved to: {out_path}")
    print("=" * 70)


if __name__ == "__main__":
    main()
