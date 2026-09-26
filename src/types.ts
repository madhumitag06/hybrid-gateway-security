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

