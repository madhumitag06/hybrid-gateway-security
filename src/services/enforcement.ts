/**
 * Policy & Enforcement API Client Service
 * =======================================
 * Handles active containment mode, rule listing, manual revocation,
 * and static vs. adaptive policy comparison.
 */

import { request } from './api'
import type {
  ActiveEnforcementRule,
  EnforcementConfig,
  FlowPredictionRequest,
  PolicyAuditLog,
  PolicyComparisonResult,
  PolicyDecision,
} from '../types'

export async function getEnforcementConfig(): Promise<EnforcementConfig> {
  return request<EnforcementConfig>('v1/enforcement/config')
}

export async function updateEnforcementMode(mode: 'DRY_RUN' | 'SANDBOX'): Promise<EnforcementConfig> {
  return request<EnforcementConfig>('v1/enforcement/config', {
    method: 'PUT',
    body: JSON.stringify({ active_mode: mode }),
  })
}

export async function listEnforcementRules(
  statusFilter?: string
): Promise<ActiveEnforcementRule[]> {
  const endpoint = statusFilter
    ? `v1/enforcement/rules?status_filter=${encodeURIComponent(statusFilter)}`
    : 'v1/enforcement/rules'
  return request<ActiveEnforcementRule[]>(endpoint)
}

export async function revokeEnforcementRule(
  ruleId: string,
  actor: string = 'SecOps Console'
): Promise<{ rule_id: string; status: string; message: string }> {
  return request<{ rule_id: string; status: string; message: string }>(
    `v1/enforcement/rules/${encodeURIComponent(ruleId)}/revoke`,
    {
      method: 'POST',
      body: JSON.stringify({ actor, reason: 'Manual containment revocation by analyst' }),
    }
  )
}

export async function getPolicyAuditLogs(limit: number = 50): Promise<PolicyAuditLog[]> {
  return request<PolicyAuditLog[]>(`v1/enforcement/audit?limit=${limit}`)
}

export async function evaluateFlowPolicy(
  flow: FlowPredictionRequest
): Promise<PolicyDecision> {
  return request<PolicyDecision>('v1/policies/evaluate', {
    method: 'POST',
    body: JSON.stringify(flow),
  })
}

export async function comparePolicies(
  flow: FlowPredictionRequest
): Promise<PolicyComparisonResult> {
  return request<PolicyComparisonResult>('v1/policies/compare', {
    method: 'POST',
    body: JSON.stringify(flow),
  })
}
