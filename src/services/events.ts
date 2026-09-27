/**
 * Security Events API Client Service
 * ==================================
 * Provides filtered querying, pagination, and detailed retrieval of
 * PostgreSQL-persisted security events.
 */

import { request } from './api'
import type { EventListResponseSchema, SecurityEventDetailSchema } from '../types'

export interface EventFilterParams {
  threat_level?: string
  attack_type?: string
  action?: string
  min_risk?: number
  max_risk?: number
  is_anomaly?: boolean
  search?: string
  limit?: number
  offset?: number
}

export async function listSecurityEvents(
  params: EventFilterParams = {}
): Promise<EventListResponseSchema> {
  const query = new URLSearchParams()
  if (params.threat_level) query.set('threat_level', params.threat_level)
  if (params.attack_type) query.set('attack_type', params.attack_type)
  if (params.action) query.set('action', params.action)
  if (params.min_risk !== undefined) query.set('min_risk', String(params.min_risk))
  if (params.max_risk !== undefined) query.set('max_risk', String(params.max_risk))
  if (params.is_anomaly !== undefined) query.set('is_anomaly', String(params.is_anomaly))
  if (params.search) query.set('search', params.search)
  if (params.limit) query.set('limit', String(params.limit))
  if (params.offset) query.set('offset', String(params.offset))

  const queryString = query.toString()
  const endpoint = queryString ? `v1/events?${queryString}` : 'v1/events'
  return request<EventListResponseSchema>(endpoint)
}

export async function getSecurityEventDetail(
  eventId: string
): Promise<SecurityEventDetailSchema> {
  return request<SecurityEventDetailSchema>(`v1/events/${encodeURIComponent(eventId)}`)
}
