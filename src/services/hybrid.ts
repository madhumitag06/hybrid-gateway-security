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

export interface HybridScenarioInfo {
  id: string
  name: string
  category: string
  source_ip: string
  source_name: string
  destination_ip: string
  destination_name: string
  port: string | number
  protocol: string
  packets: number
  expected_action: string
  description: string
}

export interface ScenarioRunResult {
  run_id: string
  scenario: string
  status: string
  duration_ms: number
  output?: any
  message?: string
  timestamp: string
}

export interface InfrastructureHealthResponse {
  overall_status: string
  containers_count: number
  healthy_containers: number
  router: {
    url: string
    status: string
    ip_forward_active: boolean
    interfaces: Record<string, string>
  }
  database: {
    engine: string
    status: string
    pool_size: number
  }
  ml_engine: {
    model_type: string
    artifacts_dir: string
    shap_threshold: number
  }
  containers: Array<{
    name: string
    role: string
    zone: string
    ip: string
    status: string
    health: string
  }>
  checked_at: string
}

export async function getHybridScenarios(): Promise<HybridScenarioInfo[]> {
  return request<HybridScenarioInfo[]>('v1/hybrid/scenarios')
}

export async function runHybridScenario(scenarioId: string): Promise<ScenarioRunResult> {
  return request<ScenarioRunResult>(`v1/hybrid/scenarios/${encodeURIComponent(scenarioId)}/run`, {
    method: 'POST',
  })
}

export async function getInfrastructureHealth(): Promise<InfrastructureHealthResponse> {
  return request<InfrastructureHealthResponse>('v1/hybrid/infrastructure/health')
}

export async function getHybridLabStatus(): Promise<any> {
  return request<any>('v1/hybrid/lab-status')
}
