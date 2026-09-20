export type Severity = 'low' | 'medium' | 'high' | 'critical'
export type PolicyAction = 'Allow' | 'Monitor' | 'Restrict' | 'Block'

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
}

export interface RiskReason { label: string; value: number; tone: string }
export interface DashboardData {
  riskScore: number
  riskState: PolicyAction
  activeFlows: number
  events: SecurityEvent[]
  reasons: RiskReason[]
}
