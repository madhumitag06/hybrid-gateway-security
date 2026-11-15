/**
 * Multi-Cloud Management & Telemetry Service
 * ==========================================
 * Connects frontend dashboard with FastAPI multi-cloud endpoints:
 * accounts, health probes, resource inventory, and canonical flow telemetry.
 */

import { request } from './api'

export interface CloudProviderInfo {
  id: string
  name: string
  auth_methods: string[]
  telemetry_types: string[]
  enforcement_mechanisms: string[]
}

export interface CloudAccountStatus {
  account_id: string
  provider: 'AWS' | 'GCP' | 'AZURE' | 'DOCKER_LAB'
  account_name: string
  region: string
  status: 'NOT_CONFIGURED' | 'CONFIGURED' | 'CONNECTED' | 'DEGRADED' | 'ERROR'
  enabled: boolean
  enforcement_enabled: boolean
  latency_ms?: number
  error_message?: string
  last_checked_at?: string
}

export interface CloudResource {
  id?: string
  resource_id: string
  account_id: string
  provider: string
  resource_type: string
  name: string
  cidr_block?: string
  region: string
  zone?: string
  vpc_id?: string
  parent_resource_id?: string
  state: string
  tags?: Record<string, string>
}

export interface CloudInventorySummary {
  total_vpcs: number
  total_subnets: number
  total_security_groups: number
  total_gateways: number
  by_provider: Record<string, number>
}

export interface MultiCloudHealthResponse {
  overall_status: 'HEALTHY' | 'DEGRADED' | 'CRITICAL' | 'NOT_CONFIGURED'
  checked_at: string
  multi_cloud_ready: boolean
  providers: Record<
    string,
    {
      provider: string
      healthy: boolean
      status: string
      region: string
      account_id?: string
      role?: string
      arn?: string
      telemetry_ready: boolean
      enforcement_ready: boolean
      checked_at: string
    }
  >
}

export interface CloudTelemetryBatchResponse {
  status: string
  provider: string
  account_id: string
  records_received: number
  records_parsed: number
  records_aggregated: number
  high_risk_flows_detected: number
  flows_accepted: number
  flows_dropped: number
  parsing_duration_ms: number
  inference_duration_ms: number
  flows: Array<{
    flow_id: string
    src_ip: string
    dst_ip: string
    dst_port: number
    protocol: string
    flow_direction: string
    packet_count: number
    byte_count: number
    conn_rate: number
    risk_score: number
    threat_level: string
    attack_type: string
    policy_action: string
  }>
  normalization_report: {
    features_extracted: string[]
    schema_version: string
    failed_auth_synthesized: boolean
    timestamp_provenance: boolean
    direction_classified: boolean
  }
}

export const cloudService = {
  async getProviders(): Promise<{ providers: CloudProviderInfo[] }> {
    return request<{ providers: CloudProviderInfo[] }>('/cloud/providers')
  },

  async getAccounts(provider?: string): Promise<CloudAccountStatus[]> {
    const query = provider ? `?provider=${encodeURIComponent(provider)}` : ''
    return request<CloudAccountStatus[]>(`/cloud/accounts${query}`)
  },

  async testConnection(provider: string, config?: any): Promise<any> {
    return request<any>(`/cloud/accounts/${provider}/test-connection`, {
      method: 'POST',
      body: JSON.stringify(config || {}),
    })
  },

  async getResources(provider?: string, resourceType?: string, syncLive?: boolean): Promise<CloudResource[]> {
    const params = new URLSearchParams()
    if (provider) params.set('provider', provider)
    if (resourceType) params.set('resource_type', resourceType)
    if (syncLive) params.set('sync_live', 'true')
    const qs = params.toString() ? `?${params.toString()}` : ''
    return request<CloudResource[]>(`/cloud/resources${qs}`)
  },

  async getInventorySummary(): Promise<CloudInventorySummary> {
    return request<CloudInventorySummary>('/cloud/inventory/summary')
  },

  async getHealth(): Promise<MultiCloudHealthResponse> {
    return request<MultiCloudHealthResponse>('/cloud/health')
  },

  async ingestTelemetry(batch: {
    provider: string
    account_id: string
    region?: string
    records: any[]
    persist_events?: boolean
  }): Promise<CloudTelemetryBatchResponse> {
    return request<CloudTelemetryBatchResponse>('/cloud/telemetry/ingest', {
      method: 'POST',
      body: JSON.stringify(batch),
    })
  },

  async discoverAwsResources(region?: string): Promise<any> {
    const qs = region ? `?region=${encodeURIComponent(region)}` : ''
    return request<any>(`/cloud/accounts/AWS/discover${qs}`, {
      method: 'POST',
    })
  },

  async getAwsFlowLogs(region?: string): Promise<any> {
    const qs = region ? `?region=${encodeURIComponent(region)}` : ''
    return request<any>(`/cloud/accounts/AWS/flow-logs${qs}`)
  },

  async pollAwsTelemetry(options?: {
    limit?: number
    log_group?: string
    s3_bucket?: string
    mock_fallback?: boolean
  }): Promise<CloudTelemetryBatchResponse> {
    const params = new URLSearchParams()
    if (options?.limit) params.set('limit', String(options.limit))
    if (options?.log_group) params.set('log_group', options.log_group)
    if (options?.s3_bucket) params.set('s3_bucket', options.s3_bucket)
    if (options?.mock_fallback) params.set('mock_fallback', 'true')
    const qs = params.toString() ? `?${params.toString()}` : ''
    return request<CloudTelemetryBatchResponse>(`/cloud/accounts/AWS/poll-telemetry${qs}`, {
      method: 'POST',
    })
  },

  async getAwsTelemetryStatus(): Promise<any> {
    return request<any>('/cloud/accounts/AWS/telemetry-status')
  },

  async getAwsTelemetryHistory(limit: number = 20): Promise<any[]> {
    return request<any[]>(`/cloud/accounts/AWS/telemetry-history?limit=${limit}`)
  },

  async resetAwsTelemetryCheckpoint(): Promise<any> {
    return request<any>('/cloud/accounts/AWS/telemetry-checkpoints/reset', {
      method: 'POST',
    })
  },
}

