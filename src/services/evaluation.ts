/**
 * Evaluation & Benchmarking API Client
 * =====================================
 * Communicates with backend endpoints for running controlled benchmarks and exporting reports.
 */

import { getApiUrl, request } from './api'
import type { EvaluationRunResponse, EvaluationSuiteInfo } from '../types'

export async function fetchEvaluationSuites(): Promise<EvaluationSuiteInfo[]> {
  return request<EvaluationSuiteInfo[]>('v1/evaluation/suites')
}

export async function runEvaluation(
  suiteName: string = 'FULL_BENCHMARK',
  sampleCount: number = 200,
  includeShap: boolean = true
): Promise<EvaluationRunResponse> {
  return request<EvaluationRunResponse>('v1/evaluation/run', {
    method: 'POST',
    body: JSON.stringify({
      suite_name: suiteName,
      sample_count: sampleCount,
      include_shap: includeShap,
      persist_events: false,
    }),
  })
}

export function getExportUrl(
  suiteName: string = 'FULL_BENCHMARK',
  sampleCount: number = 200,
  format: 'json' | 'csv' = 'json'
): string {
  return getApiUrl(
    `v1/evaluation/export?suite_name=${encodeURIComponent(
      suiteName
    )}&sample_count=${sampleCount}&export_format=${format}`
  )
}

export interface ShadowComparisonResponse {
  candidate_status: {
    status: string
    shadow_mode_enabled: boolean
    candidate_model: string
    candidate_version: string
    feature_schema_version: string
    feature_count: number
    features: string[]
    classes: string[]
    artifacts_dir: string
    enforcement_authority: string
    error?: string
  }
  summary: {
    total_evaluated: number
    agreement_count: number
    disagreement_count: number
    agreement_rate_pct: number
    avg_prod_latency_ms: number
    avg_candidate_latency_ms: number
  }
  disagreements_by_type: Record<string, number>
  candidate_distribution: Record<string, number>
  recent_comparisons: Array<{
    id: string
    flow_id: string
    timestamp: string
    source_ip: string
    destination_ip: string
    dst_port: number
    protocol: string
    prod_attack_type: string
    prod_confidence: number
    prod_risk_score: number
    prod_latency_ms: number
    candidate_attack_type: string
    candidate_confidence: number
    candidate_risk_score: number
    candidate_latency_ms: number
    agreement: boolean
    disagreement_type: string | null
    shap_attributions: Array<{
      feature: string
      value: number
      shap_value: number
      contribution_direction: string
      description: string
    }>
  }>
}

export async function fetchShadowComparison(limit: number = 25): Promise<ShadowComparisonResponse> {
  return request<ShadowComparisonResponse>(`v1/shadow/comparison?limit=${limit}`)
}
