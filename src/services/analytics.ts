/**
 * Security Analytics & Explainability API Client
 * ===============================================
 * Client functions for fetching historical analytics distributions,
 * detailed SHAP feature attributions, and policy decision traces.
 */

import { request } from './api'
import type {
  AnalyticsSummaryResponse,
  EventExplanationResponse,
  FlowExplanationResponse,
  FlowPredictionRequest,
} from '../types'

export async function getAnalyticsSummary(): Promise<AnalyticsSummaryResponse> {
  return request<AnalyticsSummaryResponse>('v1/analytics/summary')
}

export async function getEventExplanation(
  eventId: string
): Promise<EventExplanationResponse> {
  return request<EventExplanationResponse>(`v1/events/${encodeURIComponent(eventId)}/explanation`)
}

export async function explainFlow(
  flow: FlowPredictionRequest,
  customAllowlist?: string[]
): Promise<FlowExplanationResponse> {
  return request<FlowExplanationResponse>('v1/analytics/explain-flow', {
    method: 'POST',
    body: JSON.stringify({
      flow,
      custom_allowlist: customAllowlist,
    }),
  })
}
