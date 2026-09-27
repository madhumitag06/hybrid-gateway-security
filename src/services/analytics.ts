/**
 * Security Analytics & Explainability API Client
 * ===============================================
 * Client functions for fetching historical analytics distributions,
 * detailed SHAP feature attributions, and policy decision traces.
 */

import type {
  AnalyticsSummaryResponse,
  EventExplanationResponse,
  FlowExplanationResponse,
  FlowPredictionRequest,
} from '../types'

const API_BASE = '/api/v1'

export async function getAnalyticsSummary(): Promise<AnalyticsSummaryResponse> {
  const response = await fetch(`${API_BASE}/analytics/summary`)
  if (!response.ok) {
    throw new Error(`Failed to fetch analytics summary: ${response.statusText}`)
  }
  return response.json()
}

export async function getEventExplanation(
  eventId: string
): Promise<EventExplanationResponse> {
  const response = await fetch(`${API_BASE}/events/${eventId}/explanation`)
  if (!response.ok) {
    const err = await response.json().catch(() => ({}))
    throw new Error(err.detail || `Failed to fetch explanation for event ${eventId}`)
  }
  return response.json()
}

export async function explainFlow(
  flow: FlowPredictionRequest,
  customAllowlist?: string[]
): Promise<FlowExplanationResponse> {
  const response = await fetch(`${API_BASE}/analytics/explain-flow`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      flow,
      custom_allowlist: customAllowlist,
    }),
  })
  if (!response.ok) {
    const err = await response.json().catch(() => ({}))
    throw new Error(err.detail || `Failed to explain flow vector: ${response.statusText}`)
  }
  return response.json()
}
