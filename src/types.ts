export type Severity = 'low' | 'medium' | 'high' | 'critical'
export type PolicyAction = 'Allow' | 'Monitor' | 'Restrict' | 'Block'
export type ThreatLevel = 'LOW' | 'MEDIUM' | 'HIGH'

export interface SecurityEvent {
  id: string
  time: string
  event: string
  source: string
  destination: string
  risk: number
  severity: Severity
  action: PolicyAction
  status: 'Applied' | 'Monitoring' | 'Allowed'
  description: string
  attack_type?: string
  confidence?: number
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

