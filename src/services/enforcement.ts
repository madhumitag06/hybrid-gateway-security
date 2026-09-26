/**
 * Policy & Enforcement API Client Service
 */

import type {
  ActiveEnforcementRule,
  EnforcementConfig,
  FlowPredictionRequest,
  PolicyComparisonResult,
  PolicyDecision,
} from '../types'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'

export async function getEnforcementConfig(): Promise<EnforcementConfig> {
  const response = await fetch(`${API_BASE_URL}/api/v1/enforcement/config`)
  if (!response.ok) {
    throw new Error(`Failed to fetch enforcement config (${response.status})`)
  }
  return response.json()
}

export async function updateEnforcementMode(mode: 'DRY_RUN' | 'SANDBOX'): Promise<EnforcementConfig> {
  const response = await fetch(`${API_BASE_URL}/api/v1/enforcement/config`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ active_mode: mode }),
  })
  if (!response.ok) {
    throw new Error(`Failed to update enforcement mode (${response.status})`)
  }
  return response.json()
}

export async function listEnforcementRules(
  statusFilter?: string
): Promise<ActiveEnforcementRule[]> {
  const url = statusFilter
    ? `${API_BASE_URL}/api/v1/enforcement/rules?status_filter=${statusFilter}`
    : `${API_BASE_URL}/api/v1/enforcement/rules`
  const response = await fetch(url)
  if (!response.ok) {
    throw new Error(`Failed to list enforcement rules (${response.status})`)
  }
  return response.json()
}

export async function revokeEnforcementRule(
  ruleId: string,
  actor: string = 'analyst'
): Promise<{ rule_id: string; status: string; message: string }> {
  const response = await fetch(
    `${API_BASE_URL}/api/v1/enforcement/rules/${encodeURIComponent(ruleId)}/revoke`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ actor, reason: 'Analyst rollback request' }),
    }
  )
  if (!response.ok) {
    const err = await response.json().catch(() => ({}))
    throw new Error(err.detail || `Failed to revoke rule (${response.status})`)
  }
  return response.json()
}

export async function evaluateFlowPolicy(
  flow: FlowPredictionRequest
): Promise<PolicyDecision> {
  const response = await fetch(`${API_BASE_URL}/api/v1/policies/evaluate`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(flow),
  })
  if (!response.ok) {
    throw new Error(`Failed to evaluate policy (${response.status})`)
  }
  return response.json()
}

export async function comparePolicies(
  flow: FlowPredictionRequest
): Promise<PolicyComparisonResult> {
  const response = await fetch(`${API_BASE_URL}/api/v1/policies/compare`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(flow),
  })
  if (!response.ok) {
    throw new Error(`Failed to compare policies (${response.status})`)
  }
  return response.json()
}
