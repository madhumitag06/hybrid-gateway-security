export type Severity = 'low' | 'medium' | 'high' | 'critical'
export type PolicyAction = 'Allow' | 'Monitor' | 'Restrict' | 'Block'
export type ThreatLevel = 'LOW' | 'MEDIUM' | 'HIGH'
export type NetworkZone = 'ON_PREMISE' | 'AWS_VPC' | 'INTERNET'
export type TrafficDirection =
  | 'ON_PREM_TO_CLOUD'
  | 'CLOUD_TO_ON_PREM'
  | 'INTRA_CLOUD'
  | 'INTRA_ON_PREM'
  | 'INGRESS_EXTERNAL'
  | 'EGRESS_EXTERNAL'
  | 'EXTERNAL_TO_EXTERNAL'
export type TelemetrySourceType = 'AWS_VPC_FLOW_LOG' | 'AWS_VPC_FLOW_LOG_FIXTURE' | 'PCAP' | 'DEMO_SEED'

export interface SecurityEvent {
  id: string
  time: string
  event: string
  source: string
  destination: string
  risk: number
  severity: Severity
  action: PolicyAction
  status: 'Applied' | 'Monitoring' | 'Allowed' | 'Simulated' | 'Pending'
  description: string
  attack_type?: string
  confidence?: number
  source_zone?: NetworkZone
  destination_zone?: NetworkZone
  traffic_direction?: TrafficDirection
  telemetry_source?: TelemetrySourceType
}

export interface RiskReason {
  label: string
  value: number
  tone: string
}

export interface DashboardData {
  riskScore: number
  riskState: PolicyAction
  activeFlows: number
  events: SecurityEvent[]
  reasons: RiskReason[]
  modelStatus?: string
  isSimulatedFlowBuffer?: boolean
}

export interface FlowPredictionRequest {
  packet_count: number
  byte_count: number
  duration: number
  conn_rate: number
  dst_port: number
  unique_dst_ports?: number
  failed_auth_count?: number
  bytes_per_sec?: number
  packets_per_sec?: number
  avg_packet_size?: number
}

export interface ContributingFeature {
  feature: string
  value: number
  deviation_z_score: number
  description: string
  shap_value?: number
  contribution_direction?: 'INCREASES_RISK' | 'DECREASES_RISK' | 'NEUTRAL'
}

export interface FlowPredictionResponse {
  risk_score: number
  threat_level: ThreatLevel
  attack_type: string
  confidence: number
  action_recommendation: PolicyAction
  is_anomaly: boolean
  class_probabilities: Record<string, number>
  top_contributing_features: ContributingFeature[]
}

export interface BackendHealth {
  status: string
  app_name: string
  version: string
  model_loaded: boolean
  model_type: string
  model_features: string[]
  classes: string[]
  timestamp_utc: string
}

export interface SamplePcapInfo {
  sample_id: string
  name: string
  filename: string
  description: string
  packet_count: number
  expected_threat: string
  file_size_bytes: number
}

export interface FlowFeatureSummary {
  flow_id: string
  source_ip: string
  destination_ip: string
  protocol: string
  dst_port: number
  packet_count: number
  byte_count: number
  duration: number
  conn_rate: number
  unique_dst_ports: number
  failed_auth_count: number
}

export interface IngestedFlowResult {
  flow_id: string
  flow_features: FlowFeatureSummary
  prediction: FlowPredictionResponse
  persisted_event_id?: string
}

export interface IngestionMetrics {
  packets_read: number
  packets_processed: number
  packets_skipped: number
  flows_generated: number
  parse_duration_ms: number
  inference_duration_ms: number
  persist_duration_ms: number
  total_duration_ms: number
  throughput_packets_per_sec: number
}

export interface PcapIngestionResponse {
  source_type: string
  filename: string
  file_size_bytes: number
  is_demo: boolean
  metrics: IngestionMetrics
  flows_evaluated: number
  high_risk_flows_count: number
  results: IngestedFlowResult[]
}

export interface IngestionStatusResponse {
  engine_status: string
  active_mode: string
  raw_socket_capture_supported: boolean
  platform: string
  supported_formats: string[]
  max_upload_size_mb: number
  total_pcaps_ingested: number
  total_packets_processed: number
  total_flows_generated: number
}

export type EnforcementMode = 'DRY_RUN' | 'SANDBOX'
export type EnforcementStatus = 'ACTIVE' | 'SIMULATED' | 'EXPIRED' | 'REVOKED' | 'FAILED'

export interface PolicyDecision {
  decision_id: string
  event_id?: string
  target_ip: string
  target_port?: number
  protocol?: string
  policy_action: PolicyAction
  enforcement_required: boolean
  confidence: number
  threat_level: string
  attack_type: string
  risk_score: number
  rule_name: string
  reason: string
  suggested_ttl_seconds: number
}

export interface ActiveEnforcementRule {
  rule_id: string
  event_id?: string
  target_ip: string
  target_port?: number
  protocol?: string
  action: PolicyAction
  status: EnforcementStatus
  mode: EnforcementMode
  reason: string
  ttl_seconds: number
  expires_at: string
  remaining_ttl_seconds: number
  created_at: string
  revoked_at?: string
  revoked_by?: string
}

export interface EnforcementConfig {
  active_mode: EnforcementMode
  default_ttl_seconds: number
  management_allowlist: string[]
  total_active_rules: number
}

export interface PolicyComparisonResult {
  flow_id: string
  target_ip: string
  dst_port: number
  static_decision: PolicyAction
  static_rule_matched?: string
  adaptive_decision: PolicyAction
  adaptive_risk_score: number
  adaptive_confidence: number
  decision_divergence: boolean
  divergence_rationale: string
}

export interface HybridTopologySummary {
  on_prem_cidrs: string[]
  aws_vpc_cidrs: string[]
  aws_region: string
  telemetry_mode: string
  is_cloud_read_only: boolean
  cloud_firewall_modification_enabled: boolean
}

export interface AwsVpcSampleFixtureInfo {
  sample_id: string
  name: string
  filename: string
  description: string
  record_count: number
  expected_threat: string
  file_size_bytes: number
  telemetry_source: string
}

export interface AwsVpcFlowItemResult {
  flow_id: string
  source_ip: string
  destination_ip: string
  source_zone: NetworkZone
  destination_zone: NetworkZone
  traffic_direction: TrafficDirection
  protocol_name: string
  dst_port: number
  packet_count: number
  byte_count: number
  duration: number
  conn_rate: number
  unique_dst_ports: number
  failed_auth_count: number
  interface_id?: string
  account_id?: string
  prediction: FlowPredictionResponse
  policy_decision?: PolicyDecision
  persisted_event_id?: string
}

export interface AwsVpcIngestionResponse {
  telemetry_source: TelemetrySourceType
  source_label: string
  is_fixture: boolean
  total_records_parsed: number
  total_flows_aggregated: number
  high_risk_flows_count: number
  parse_duration_ms: number
  inference_duration_ms: number
  total_duration_ms: number
  results: AwsVpcFlowItemResult[]
}

// Phase 7: Analytics & Explainability Types

export interface AnalyticsHistogramBin {
  bin_label: string
  min_score: number
  max_score: number
  count: number
  percentage: number
}

export interface AttackTypeDistribution {
  attack_type: string
  count: number
  percentage: number
}

export interface ZoneTrafficDistribution {
  traffic_direction: string
  count: number
  percentage: number
}

export interface TelemetryProvenanceDistribution {
  telemetry_source: string
  count: number
  percentage: number
  is_real_telemetry: boolean
}

export interface PolicyDecisionDistribution {
  policy_action: PolicyAction
  count: number
  percentage: number
}

export interface GlobalFeatureSensitivity {
  feature: string
  mean_abs_shap: number
  importance_rank: number
}

export interface AnalyticsSummaryResponse {
  total_events_evaluated: number
  real_telemetry_events: number
  fixture_demo_events: number
  active_sandbox_rules_count: number
  histogram_buckets: AnalyticsHistogramBin[]
  attack_type_distribution: AttackTypeDistribution[]
  zone_traffic_distribution: ZoneTrafficDistribution[]
  telemetry_provenance_distribution: TelemetryProvenanceDistribution[]
  policy_decision_distribution: PolicyDecisionDistribution[]
  top_sensitive_features: GlobalFeatureSensitivity[]
  generated_at_utc: string
}

export interface DetailedFeatureAttribution {
  feature: string
  value: number
  shap_value: number
  contribution_direction: string
  description: string
  deviation_z_score?: number
}

export interface PolicyReasoningTrace {
  enacted_policy_action: PolicyAction
  policy_rule_name: string
  enforcement_status: string
  is_confidence_gated: boolean
  is_allowlisted: boolean
}

export interface EventExplanationResponse {
  event_id: string
  timestamp: string
  source_ip: string
  destination_ip: string
  telemetry_source: string
  attack_type: string
  confidence: number
  risk_score: number
  threat_level: ThreatLevel
  expected_base_probability: number
  all_base_values: Record<string, number>
  feature_attributions: DetailedFeatureAttribution[]
  top_positive_contributors: DetailedFeatureAttribution[]
  top_mitigating_contributors: DetailedFeatureAttribution[]
  policy_reasoning: PolicyReasoningTrace
  disclaimer: string
}

export interface FlowExplanationResponse {
  attack_type: string
  confidence: number
  risk_score: number
  threat_level: ThreatLevel
  action_recommendation: PolicyAction
  enacted_policy_decision: PolicyAction
  policy_rule_name: string
  expected_base_probability: number
  feature_attributions: DetailedFeatureAttribution[]
  top_positive_contributors: DetailedFeatureAttribution[]
  top_mitigating_contributors: DetailedFeatureAttribution[]
  disclaimer: string
}


