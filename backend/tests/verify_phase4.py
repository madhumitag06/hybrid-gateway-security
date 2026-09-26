"""
Phase 4 End-to-End Persistence and Verification Script
"""
import sys
from sqlalchemy import select
from backend.app.db.session import SessionLocal
from backend.app.models.security_event import SecurityEventModel
from backend.app.models.policy_audit_log import PolicyAuditLogModel
from backend.app.services.ingestion_service import IngestionService
from backend.app.services.sample_pcap_generator import SAMPLE_DIR

def run_verification():
    print("=" * 60)
    print("PHASE 4 END-TO-END VERIFICATION")
    print("=" * 60)

    with SessionLocal() as db:
        # 1. Ingest port scan sample with persistence enabled
        port_scan_pcap = SAMPLE_DIR / "port_scan.pcap"
        print(f"[*] Ingesting {port_scan_pcap.name} with persist=True...")
        res = IngestionService.ingest_pcap_file(
            filepath=port_scan_pcap,
            filename="port_scan.pcap",
            persist=True,
            db=db,
        )
        db.commit()

        print(f"[+] Ingestion complete: {res.metrics.packets_processed} pkts parsed, {res.flows_evaluated} flows evaluated, {res.high_risk_flows_count} high risk.")
        print(f"    Parse time: {res.metrics.parse_duration_ms} ms | ML time: {res.metrics.inference_duration_ms} ms | DB Persist: {res.metrics.persist_duration_ms} ms")
        print(f"    Throughput: {res.metrics.throughput_packets_per_sec} packets/sec")

        first_flow = res.results[0]
        event_id = first_flow.persisted_event_id
        print(f"[+] Persisted Event ID: {event_id}")

        # 2. Query PostgreSQL directly to verify record
        stmt = select(SecurityEventModel).where(SecurityEventModel.id == event_id)
        persisted_event = db.scalar(stmt)
        assert persisted_event is not None, "Event not found in PostgreSQL!"
        print(f"[+] Direct DB Query Verified:")
        print(f"    - Event ID: {persisted_event.id}")
        print(f"    - Source IP: {persisted_event.source_ip}")
        print(f"    - Destination IP: {persisted_event.destination_ip}")
        print(f"    - Attack Type: {persisted_event.attack_type}")
        print(f"    - Risk Score: {persisted_event.risk_score}")
        print(f"    - Threat Level: {persisted_event.threat_level}")
        print(f"    - Policy Action: {persisted_event.current_policy_action}")
        print(f"    - is_demo: {persisted_event.is_demo} (Expected: False)")
        print(f"    - is_anomaly: {persisted_event.is_anomaly}")

        assert persisted_event.is_demo is False, "PCAP ingested events must have is_demo=False!"
        assert persisted_event.risk_score >= 70, "Port scan flow should have high risk score!"

        # 3. Check audit log
        audit_stmt = select(PolicyAuditLogModel).where(PolicyAuditLogModel.event_id == event_id)
        logs = db.scalars(audit_stmt).all()
        print(f"[+] Audit Logs found for event: {len(logs)}")
        for l in logs:
            print(f"    - [{l.timestamp}] Action: {l.requested_action}, Status: {l.resulting_status}, Actor: {l.actor}")

    print("\n[SUCCESS] Phase 4 Verification Passed Perfectly!")

if __name__ == "__main__":
    run_verification()
