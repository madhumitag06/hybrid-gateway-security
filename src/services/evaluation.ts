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
