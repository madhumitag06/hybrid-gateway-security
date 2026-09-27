/**
 * Hybrid Cloud & AWS Telemetry Service
 * =====================================
 * API client methods for querying hybrid network topology,
 * listing benchmark VPC flow log fixtures, and ingesting AWS VPC flow logs.
 */

import { request } from './api'
import type {
  AwsVpcIngestionResponse,
  AwsVpcSampleFixtureInfo,
  HybridTopologySummary,
} from '../types'

export async function getHybridTopology(): Promise<HybridTopologySummary> {
  return request<HybridTopologySummary>('v1/hybrid/topology')
}

export async function getAwsVpcSamples(): Promise<AwsVpcSampleFixtureInfo[]> {
  return request<AwsVpcSampleFixtureInfo[]>('v1/hybrid/samples')
}

export async function ingestAwsVpcSample(
  sampleId: string,
  persist: boolean = true
): Promise<AwsVpcIngestionResponse> {
  return request<AwsVpcIngestionResponse>(
    `v1/hybrid/samples/${encodeURIComponent(sampleId)}/ingest?persist=${persist}`,
    {
      method: 'POST',
    }
  )
}

export async function ingestRawVpcLogs(
  rawContent: string,
  isFixture: boolean = false,
  sourceLabel?: string
): Promise<AwsVpcIngestionResponse> {
  return request<AwsVpcIngestionResponse>('v1/hybrid/ingest-vpc-logs', {
    method: 'POST',
    body: JSON.stringify({
      raw_log_content: rawContent,
      is_fixture: isFixture,
      persist: true,
      source_label: sourceLabel,
    }),
  })
}
