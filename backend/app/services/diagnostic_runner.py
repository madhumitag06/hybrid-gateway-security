import os

from backend.app.cloud.adapters.aws.identity import AwsIdentityProvider
from backend.app.cloud.adapters.aws.telemetry import AwsTelemetryProvider
from backend.app.services.aws_vpc_flow_parser import AwsVpcFlowParser
from backend.app.services.ml_service import MLService
from backend.app.services.policy_engine import PolicyEngine

id_prov = AwsIdentityProvider()
session, diag = id_prov.get_boto3_session()
print(f"STS AssumeRole Status: {diag.get('status')}")

tel_prov = AwsTelemetryProvider(account_id="698766075180", region="ap-southeast-2", identity_provider=id_prov)
raw_events, chk = tel_prov.fetch_from_cloudwatch_logs(
    session=session,
    log_group="/aws/vpc/flowlogs/ap-southeast-2-default",
    limit=50
)
print(f"Retrieved events from CloudWatch: {len(raw_events)}")
if raw_events:
    lines = [e["message"] for e in raw_events if "message" in e]
    raw_text = "\n".join(lines)
    resp = AwsVpcFlowParser.ingest_vpc_flow_records(raw_text, persist=False)
    flows = resp.results
    print(f"Evaluated flows: {len(flows)}")
    print("\n" + "=" * 110)
    print("LIVE AWS VPC FLOW LOGS DIAGNOSTIC REPORT (Account: 698766075180, Region: ap-southeast-2)")
    print("=" * 110)
    for idx, f in enumerate(flows[:10], 1):
        pred = f.prediction
        policy = f.policy_decision
        probs = pred.class_probabilities
        print(f"Record #{idx}:")
        print(f"  Flow ID               : {f.flow_id} ({f.source_ip} -> {f.destination_ip}:{f.dst_port} {f.protocol_name})")
        print(f"  Extracted Features    : packet_count={f.packet_count}, byte_count={f.byte_count}, duration={f.duration:.3f}s, unique_dst_ports={f.unique_dst_ports}, conn_rate={f.conn_rate:.2f}")
        print(f"  Class Probabilities   : BENIGN={probs.get('BENIGN', 0):.4f}, PORT_SCAN={probs.get('PORT_SCAN', 0):.4f}, BRUTE_FORCE={probs.get('BRUTE_FORCE', 0):.4f}, TRAFFIC_SPIKE={probs.get('TRAFFIC_SPIKE', 0):.4f}, SUSPICIOUS_TRANSFER={probs.get('SUSPICIOUS_TRANSFER', 0):.4f}")
        print(f"  Predicted Class       : {pred.attack_type}")
        print(f"  Continuous Risk Score : {pred.risk_score} / 100 ({pred.threat_level})")
        print(f"  Deterministic Policy  : {policy.policy_action} (Rule: {policy.rule_name})")
        print("-" * 110)
