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

export const DEFAULT_HYBRID_SCENARIOS: HybridScenarioInfo[] = [
  {
    id: 'benign',
    name: 'Normal On-Premises to Cloud HTTP Traffic',
    category: 'BENIGN',
    source_ip: '10.10.10.10',
    source_name: 'onprem-client',
    destination_ip: '10.20.10.20',
    destination_name: 'cloud-web',
    port: 8080,
    protocol: 'TCP',
    packets: 25,
    expected_action: 'Allow',
    description: 'Standard legitimate HTTP requests crossing the lab-router from an on-premise client to cloud web services.',
  },
  {
    id: 'port_scan',
    name: 'Multi-Port Reconnaissance Sweep',
    category: 'PORT_SCAN',
    source_ip: '10.10.10.50',
    source_name: 'traffic-generator',
    destination_ip: '10.20.10.40',
    destination_name: 'cloud-workload',
    port: 'Multiple (22, 80, 443, 8080, 9000)',
    protocol: 'TCP SYN',
    packets: 75,
    expected_action: 'Block',
    description: 'Systematic TCP port scanning attempting to enumerate accessible services on cloud-workload through the gateway.',
  },
  {
    id: 'traffic_spike',
    name: 'Volumetric HTTP Flood / Traffic Surge',
    category: 'TRAFFIC_SPIKE',
    source_ip: '10.10.10.50',
    source_name: 'traffic-generator',
    destination_ip: '10.20.10.20',
    destination_name: 'cloud-web',
    port: 8080,
    protocol: 'TCP',
    packets: 450,
    expected_action: 'Restrict',
    description: 'High-frequency burst of HTTP connections designed to test automated rate-limiting and burst anomaly detection.',
  },
  {
    id: 'suspicious_transfer',
    name: 'Large Data Exfiltration Transfer',
    category: 'SUSPICIOUS_TRANSFER',
    source_ip: '10.10.10.30',
    source_name: 'onprem-workload',
    destination_ip: '10.20.10.30',
    destination_name: 'cloud-db',
    port: 5432,
    protocol: 'TCP',
    packets: 320,
    expected_action: 'Block',
    description: 'Outbound transfer of oversized binary payloads simulating sensitive database exfiltration across cloud boundaries.',
  },
  {
    id: 'containment',
    name: 'Live Containment & Firewall Quarantine Verification',
    category: 'CONTAINMENT',
    source_ip: '10.10.10.50',
    source_name: 'traffic-generator',
    destination_ip: '10.20.10.20',
    destination_name: 'cloud-web',
    port: 8080,
    protocol: 'TCP / ICMP',
    packets: 50,
    expected_action: 'Verify Quarantine',
    description: 'Tests active firewall rule installation on lab-router, verifying that traffic from quarantined hosts is actively dropped.',
  },
  {
    id: 'brute_force',
    name: 'SSH Credential Brute-Force Authentication Surge',
    category: 'BRUTE_FORCE',
    source_ip: '10.10.10.50',
    source_name: 'traffic-generator',
    destination_ip: '10.20.10.40',
    destination_name: 'cloud-workload',
    port: 22,
    protocol: 'TCP / SSH',
    packets: 80,
    expected_action: 'Block',
    description: 'Repeated failed authentication attempts against SSH service attempting credential stuffing and unauthorized terminal access.',
  },
]

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
    model_name?: string
    version_id?: string
    feature_count?: number
    role?: string
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
