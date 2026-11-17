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
  display_name?: string
  region: string
  status: 'NOT_CONFIGURED' | 'CONFIGURED' | 'CONNECTED' | 'DEGRADED' | 'ERROR'
  enabled: boolean
  enforcement_enabled: boolean
  latency_ms?: number
  error_message?: string
  last_checked_at?: string
  resources_count?: number
  has_stored_credentials?: boolean
  masked_identity?: string
  auth_method?: string
  rotated_at?: string
  role_arn?: string
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
  status?: string
  discovered_at?: string
  tags?: Record<string, string>
}

export interface CloudInventorySummary {
  total_vpcs: number
  total_subnets: number
  total_security_groups: number
  total_gateways: number
  total_resources?: number
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
      project_id?: string
      project_number?: string
      auth_method?: string
      workload_identity_pool?: string
      workload_identity_provider?: string
      service_account_email?: string
      role?: string
      arn?: string
      api_coverage_summary?: string
      telemetry_ready: boolean
      enforcement_ready: boolean
      checked_at: string
    }
  >
}

export interface GcpApiCoverageItem {
  service: string
  name: string
  status: 'ENABLED_ACCESSIBLE' | 'UNAVAILABLE_BILLING_REQUIRED' | 'ENABLED_RESTRICTED' | 'DISABLED' | 'NOT_SUPPORTED'
  label: string
  required: boolean
  feature: string
  reason: string
  remedy: string
}

export interface GcpIntegrationOverview {
  project_configuration: {
    project_id: string
    project_number: string
    region: string
    billing_status: string
    billing_status_label: string
    enabled_apis: string[]
    unavailable_apis: Array<{
      service: string
      name: string
      reason: string
      remedy: string
    }>
  }
  identity_and_authentication: {
    auth_method: string
    auth_type_label: string
    workload_identity_pool: string
    workload_identity_provider: string
    service_account_email: string
    federation_status: string
    service_account_impersonation_status: string
    vault_status: string
    credential_source: string
    aws_credentials_status?: string
    missing_requirement?: string
    last_successful_authentication?: string
  }
  infrastructure_discovery: {
    total_resources: number
    compute_api_status: string
    discovery_status: string
    discovery_message: string
    resources: CloudResource[]
  }
  api_coverage: {
    total_services: number
    accessible_count: number
    services: GcpApiCoverageItem[]
  }
  connection_status: string
  checked_at: string
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
  error_message?: string
  message?: string
}

export const cloudService = {
  async getProviders(): Promise<{ providers: CloudProviderInfo[] }> {
    return request<{ providers: CloudProviderInfo[] }>('/cloud/providers')
  },

  async getAccounts(provider?: string): Promise<CloudAccountStatus[]> {
    const query = provider ? `?provider=${encodeURIComponent(provider)}` : ''
    return request<CloudAccountStatus[]>(`/cloud/accounts${query}`)
  },

  async createAccount(data: {
    provider: string
    account_id: string
    display_name?: string
    region?: string
    role_arn?: string
    external_id?: string
    project_id?: string
    subscription_id?: string
    tenant_id?: string
    client_id?: string
    auth_method?: string
    credentials?: Record<string, any>
    metadata?: Record<string, any>
  }): Promise<CloudAccountStatus> {
    return request<CloudAccountStatus>('/cloud/accounts', {
      method: 'POST',
      body: JSON.stringify(data),
    })
  },

  async disconnectAccount(provider: string, accountId: string): Promise<any> {
    return request<any>(`/cloud/accounts/${encodeURIComponent(provider)}/${encodeURIComponent(accountId)}`, {
      method: 'DELETE',
    })
  },

  async rotateCredentials(
    provider: string,
    accountId: string,
    credentials: Record<string, any>,
    authMethod?: string
  ): Promise<any> {
    return request<any>(
      `/cloud/accounts/${encodeURIComponent(provider)}/${encodeURIComponent(accountId)}/rotate-credentials`,
      {
        method: 'POST',
        body: JSON.stringify({ credentials, auth_method: authMethod }),
      }
    )
  },

  async discoverProviderResources(provider: string, accountId?: string, region?: string): Promise<any> {
    const params = new URLSearchParams()
    if (accountId) params.set('account_id', accountId)
    if (region) params.set('region', region)
    const qs = params.toString() ? `?${params.toString()}` : ''
    return request<any>(`/cloud/accounts/${encodeURIComponent(provider)}/discover${qs}`, {
      method: 'POST',
    })
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

  async getMultiCloudHealth(): Promise<MultiCloudHealthResponse> {
    return this.getHealth()
  },

  async testProviderConnection(provider: string): Promise<any> {
    return this.testConnection(provider)
  },

  async discoverAws(): Promise<any> {
    return this.discoverAwsResources()
  },

  async getGcpStatus(): Promise<GcpIntegrationOverview> {
    return request<GcpIntegrationOverview>('/cloud/accounts/GCP/status')
  },

  async discoverGcpResources(): Promise<any> {
    return request<any>('/cloud/accounts/GCP/discover', {
      method: 'POST',
    })
  },

  async testGcpConnection(): Promise<any> {
    return request<any>('/cloud/accounts/GCP/test-connection', {
      method: 'POST',
    })
  },

  async inspectAwsFlowLogs(): Promise<any> {
    return this.getAwsFlowLogs()
  },

  async getAwsCallerIdentity(): Promise<any> {
    const health = await this.getHealth()
    const aws = health?.providers?.AWS
    return {
      account: aws?.account_id || '698766075180',
      region: aws?.region || 'ap-southeast-2',
      role_arn: aws?.arn || 'arn:aws:iam::698766075180:role/SecurityGatewayReadOnlyRole',
      profile_name: 'security-gateway-readonly',
      status: aws?.status || (aws?.healthy ? 'VERIFIED' : 'CONNECTED'),
    }
  },

  async ingestCloudTelemetryBatch(data: {
    provider: string
    raw_logs: string[]
    run_inference?: boolean
  }): Promise<CloudTelemetryBatchResponse> {
    return this.ingestTelemetry({
      provider: data.provider,
      account_id: 'default',
      records: data.raw_logs.map((log) => ({ raw_log: log })),
      persist_events: data.run_inference,
    })
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

