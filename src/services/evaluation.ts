/**
 * Evaluation & Benchmarking API Client
 * =====================================
 * Communicates with backend endpoints for running controlled benchmarks and exporting reports.
 */

import type { EvaluationRunResponse, EvaluationSuiteInfo } from '../types'

const API_BASE = '/api'

export async function fetchEvaluationSuites(): Promise<EvaluationSuiteInfo[]> {
  const resp = await fetch(`${API_BASE}/v1/evaluation/suites`)
  if (!resp.ok) {
    throw new Error(`Failed to fetch evaluation suites: HTTP ${resp.status}`)
  }
  return resp.json()
}

export async function runEvaluation(
  suiteName: string = 'FULL_BENCHMARK',
  sampleCount: number = 200,
  includeShap: boolean = true
): Promise<EvaluationRunResponse> {
  const resp = await fetch(`${API_BASE}/v1/evaluation/run`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      suite_name: suiteName,
      sample_count: sampleCount,
      include_shap: includeShap,
      persist_events: false,
    }),
  })

  if (!resp.ok) {
    const errorBody = await resp.text()
    throw new Error(`Evaluation run failed: HTTP ${resp.status} - ${errorBody}`)
  }

  return resp.json()
}

export function getExportUrl(
  suiteName: string = 'FULL_BENCHMARK',
  sampleCount: number = 200,
  format: 'json' | 'csv' = 'json'
): string {
  return `${API_BASE}/v1/evaluation/export?suite_name=${encodeURIComponent(
    suiteName
  )}&sample_count=${sampleCount}&export_format=${format}`
}
