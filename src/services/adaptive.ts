/**
 * Adaptive ML Learning & Feedback Client Service
 * ================================================
 */

import { request } from './api'

export interface AdaptiveTelemetry {
  total_ingested_pcaps: number
  total_extracted_flows: number
  verified_feedback_count: number
  unverified_flow_count: number
  excluded_flow_count: number
  verified_class_distribution: Record<string, number>
  training_threshold_min_samples: number
  is_retraining_eligible: boolean
  active_model_version: string
  standby_model_version: string | null
  latest_candidate_run: any | null
}

export interface FeedbackRecord {
  id: string
  ingestion_id: string | null
  flow_id: string
  timestamp: string
  source_ip: string
  destination_ip: string
  dst_port: number
  protocol: string
  flow_features: Record<string, any>
  predicted_class: string
  prediction_confidence: number
  model_version: string
  verified_label: string | null
  feedback_status: 'UNVERIFIED' | 'CONFIRMED' | 'CORRECTED' | 'EXCLUDED'
  reviewed_by: string | null
  reviewed_at: string | null
  notes: string | null
  is_training_eligible: boolean
}

export async function getAdaptiveTelemetry(): Promise<AdaptiveTelemetry> {
  return request<AdaptiveTelemetry>('v1/adaptive/telemetry')
}

export async function listFeedbacks(
  page: number = 1,
  pageSize: number = 25,
  statusFilter?: string
): Promise<{ total: number; page: number; page_size: number; records: FeedbackRecord[] }> {
  const query = statusFilter ? `?page=${page}&page_size=${pageSize}&status_filter=${statusFilter}` : `?page=${page}&page_size=${pageSize}`
  return request<{ total: number; page: number; page_size: number; records: FeedbackRecord[] }>(`v1/adaptive/feedbacks${query}`)
}

export async function submitFlowFeedback(
  feedbackId: string,
  action: 'CONFIRM' | 'CORRECT' | 'EXCLUDE' | 'RESET',
  verifiedLabel?: string,
  notes?: string
): Promise<FeedbackRecord> {
  return request<FeedbackRecord>('v1/adaptive/feedback', {
    method: 'POST',
    body: JSON.stringify({
      feedback_id: feedbackId,
      action,
      verified_label: verifiedLabel,
      reviewer: 'admin',
      notes,
    }),
  })
}

export async function prepareTrainingDataset(minSamples: number = 5): Promise<any> {
  return request<any>(`v1/adaptive/dataset/prepare?min_samples=${minSamples}`, {
    method: 'POST',
  })
}

export async function triggerRetraining(candidateVersion?: string): Promise<any> {
  return request<any>('v1/adaptive/train', {
    method: 'POST',
    body: JSON.stringify({ candidate_version: candidateVersion, created_by: 'admin' }),
  })
}

export async function listTrainingRuns(limit: number = 20): Promise<any[]> {
  return request<any[]>(`v1/adaptive/runs?limit=${limit}`)
}

export async function approveCandidatePromotion(runId: string): Promise<any> {
  return request<any>('v1/adaptive/promote', {
    method: 'POST',
    body: JSON.stringify({ run_id: runId, approved_by: 'admin' }),
  })
}

export async function rollbackAdaptiveModel(reason?: string): Promise<any> {
  return request<any>('v1/adaptive/rollback', {
    method: 'POST',
    body: JSON.stringify({ reason: reason || 'Administrator rollback' }),
  })
}

