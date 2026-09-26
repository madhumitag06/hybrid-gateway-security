/**
 * Hybrid Cloud & AWS Telemetry Service
 * =====================================
 * API client methods for querying hybrid network topology,
 * listing benchmark VPC flow log fixtures, and ingesting AWS VPC flow logs.
 */

import type {
  AwsVpcIngestionResponse,
  AwsVpcSampleFixtureInfo,
  HybridTopologySummary,
} from '../types'

const API_BASE = '/api/v1/hybrid'

export async function getHybridTopology(): Promise<HybridTopologySummary> {
  const response = await fetch(`${API_BASE}/topology`)
  if (!response.ok) {
    throw new Error(`Failed to fetch hybrid topology: ${response.statusText}`)
  }
  return response.json()
}

export async function getAwsVpcSamples(): Promise<AwsVpcSampleFixtureInfo[]> {
  const response = await fetch(`${API_BASE}/samples`)
  if (!response.ok) {
    throw new Error(`Failed to list AWS VPC sample fixtures: ${response.statusText}`)
  }
  return response.json()
}

export async function ingestAwsVpcSample(sampleId: string, persist: boolean = true): Promise<AwsVpcIngestionResponse> {
  const response = await fetch(`${API_BASE}/samples/${sampleId}/ingest?persist=${persist}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
  })
  if (!response.ok) {
    const err = await response.json().catch(() => ({}))
    throw new Error(err.detail || `Failed to ingest AWS VPC sample: ${response.statusText}`)
  }
  return response.json()
}

export async function ingestRawVpcLogs(
  rawContent: string,
  isFixture: boolean = false,
  sourceLabel?: string
): Promise<AwsVpcIngestionResponse> {
  const response = await fetch(`${API_BASE}/ingest-vpc-logs`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      raw_log_content: rawContent,
      is_fixture: isFixture,
      persist: true,
      source_label: sourceLabel,
    }),
  })
  if (!response.ok) {
    const err = await response.json().catch(() => ({}))
    throw new Error(err.detail || `Failed to ingest VPC logs: ${response.statusText}`)
  }
  return response.json()
}
