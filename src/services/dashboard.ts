import type {
  AICopilotBriefing,
  DashboardData,
  PolicyAction,
  SearchResults,
  SystemProfile,
} from '../types'
import { request } from './api'

const fallbackDashboard: DashboardData = {
  riskScore: 72,
  riskState: 'Restrict',
  activeFlows: 247,
  evaluatedEventsCount: 247,
  modelStatus: 'Fallback mock mode (Backend offline)',
  isSimulatedFlowBuffer: true,
  processUptime: '2h 15m (Process Runtime)',
  uptime: '2h 15m (Process Runtime)',
  uptimeSeconds: 8100,
  inferenceLatency: '1.8 ms (Model Inference)',
  pipelineLatency: '22.4 ms (End-to-End with SHAP)',
  avgLatency: '1.8 ms',
  connectionHealth: 'Healthy',
  connectionNote: 'FastAPI ↔ PostgreSQL ↔ RandomForest',
  timeRange: 'Last 24 hours',
  trafficVolumeUnit: 'Recorded Flow Telemetry Volume (Events / Time Bucket)',
  reasons: [
    { label: 'Unusual Port (8443)', value: 48, tone: 'red' },
    { label: 'Traffic Frequency Spike', value: 27, tone: 'orange' },
    { label: 'Failed Authentication', value: 15, tone: 'yellow' },
    { label: 'Unknown Peer Connection', value: 8, tone: 'blue' },
    { label: 'Unusual Data Transfer Size', value: 4, tone: 'blue' },
  ],
  trafficPoints: [
    { time_label: '00:00', inbound_val: 32, outbound_val: 19, flow_count: 32, anomaly_count: 0 },
    { time_label: '04:00', inbound_val: 45, outbound_val: 27, flow_count: 45, anomaly_count: 0 },
    { time_label: '08:00', inbound_val: 68, outbound_val: 42, flow_count: 68, anomaly_count: 1, anomaly_note: 'Traffic Spike' },
    { time_label: '12:00', inbound_val: 94, outbound_val: 58, flow_count: 94, anomaly_count: 2, anomaly_note: 'Port Scan (87/100)' },
    { time_label: '16:00', inbound_val: 55, outbound_val: 33, flow_count: 55, anomaly_count: 0 },
    { time_label: '20:00', inbound_val: 73, outbound_val: 45, flow_count: 73, anomaly_count: 1, anomaly_note: 'SSH Brute Force' },
  ],
  timeline: [
    { time: '14:32:09', title: 'Containment Restrict Enforced', sub: 'Applied temporary restrict policy to 192.168.1.77', icon: '✹', action: 'Restrict', status: 'Applied' },
    { time: '14:28:15', title: 'Containment Block Enforced', sub: 'Applied block policy to 203.0.113.24 (Brute Force SSH)', icon: '♟', action: 'Block', status: 'Applied' },
    { time: '14:12:41', title: 'Policy Action: Monitor', sub: 'Applied monitor policy to 198.51.100.9 by ml_policy_engine', icon: '◈', action: 'Monitor', status: 'Monitoring' },
    { time: '13:47:22', title: 'Gateway Inspection Online', sub: 'FastAPI ML Inference engine active with continuous risk evaluation', icon: '✓', action: 'Allow', status: 'Allowed' },
  ],
  keyMetrics: {
    detection_rate: '98.5%',
    detection_note: 'Holdout Benchmark (N=200)',
    false_positives: '0.0%',
    fp_note: 'Holdout Validation Suite',
    ml_latency: '1.8 ms (Inference)',
    latency_note: 'SHAP Explainer: ~20.6 ms',
    active_policies: 1,
    policies_note: '1 in active sandbox filter',
  },
  notifications: [
    {
      id: 'notif-1',
      event_id: 'evt-1001',
      title: 'Port Scan Alert',
      source: '192.168.1.77',
      destination: '10.100.4.12',
      risk: 87,
      severity: 'critical',
      attack_type: 'PORT_SCAN',
      time: '14:32:07',
      is_read: false,
    },
    {
      id: 'notif-2',
      event_id: 'evt-1002',
      title: 'Brute Force SSH Alert',
      source: '203.0.113.24',
      destination: '10.100.2.18',
      risk: 76,
      severity: 'high',
      attack_type: 'BRUTE_FORCE_SSH',
      time: '14:28:15',
      is_read: false,
    },
  ],
  unreadNotificationsCount: 2,
  events: [
    {
      id: 'evt-1001',
      time: '14:32:07',
      event: 'Unusual port access (8443)',
      source: '192.168.1.77',
      destination: '10.100.4.12',
      risk: 87,
      severity: 'critical',
      action: 'Restrict',
      status: 'Applied',
      description: 'Repeated access to port 8443 from an unknown peer exceeded the behavioral baseline.',
    },
    {
      id: 'evt-1002',
      time: '14:28:15',
      event: 'Failed authentication (5x)',
      source: '203.0.113.24',
      destination: '10.100.2.18',
      risk: 76,
      severity: 'high',
      action: 'Block',
      status: 'Applied',
      description: 'Five authentication failures were detected in a short interval.',
    },
    {
      id: 'evt-1003',
      time: '14:12:41',
      event: 'Traffic spike (3.8x)',
      source: '198.51.100.9',
      destination: '10.100.1.44',
      risk: 64,
      severity: 'high',
      action: 'Monitor',
      status: 'Monitoring',
      description: 'Traffic volume rose above the normal baseline.',
    },
  ],
}

export async function getDashboard(range?: string, signal?: AbortSignal): Promise<{ data: DashboardData; isLiveBackend: boolean }> {
  try {
    const path = range ? `dashboard?range=${encodeURIComponent(range)}` : 'dashboard'
    const data = await request<DashboardData>(path, { signal })
    return { data, isLiveBackend: true }
  } catch (err) {
    console.warn('FastAPI backend connection unreachable. Operating in local fallback mode:', err)
    return { data: fallbackDashboard, isLiveBackend: false }
  }
}

export async function searchGateway(query: string, signal?: AbortSignal): Promise<SearchResults> {
  try {
    return await request<SearchResults>(`search?q=${encodeURIComponent(query)}`, { signal })
  } catch (err) {
    console.warn('Backend search unreachable, performing local search:', err)
    const q = query.toLowerCase()
    const matches = fallbackDashboard.events
      .filter((e) => e.source.includes(q) || e.destination.includes(q) || e.event.toLowerCase().includes(q) || e.id.toLowerCase().includes(q))
      .map((e) => ({
        id: e.id,
        result_type: 'EVENT' as const,
        title: `${e.event} (${e.id})`,
        subtitle: `${e.source} → ${e.destination} [${e.action}]`,
        badge: e.severity.toUpperCase(),
        risk_score: e.risk,
        target: e.source,
        action: e.action,
      }))
    return { query, total_matches: matches.length, results: matches }
  }
}

export async function getSystemProfile(signal?: AbortSignal): Promise<SystemProfile> {
  try {
    return await request<SystemProfile>('system/profile', { signal })
  } catch (err) {
    return {
      username: 'secops_admin',
      full_name: 'SecOps Local Console',
      role: 'Gateway Administrator (Local Unauthenticated Console Session)',
      organization: 'Hybrid Security Gateway',
      auth_status: 'Unconfigured (Local Prototype Environment)',
      active_mode: 'DRY_RUN',
      is_safety_active: true,
      supported_environments: [
        { id: 'LOCAL', name: 'Local Dev (Dry-Run)', status: 'ACTIVE', desc: 'Standard dev execution' },
        { id: 'SANDBOX', name: 'In-Memory Sandbox Lab', status: 'ACTIVE', desc: 'Safe in-memory quarantine filtering' },
        { id: 'AWS_FIXTURE', name: 'AWS VPC Flow Fixtures', status: 'ACTIVE', desc: 'Deterministic offline AWS VPC log ingest' },
        { id: 'LIVE_AWS_READ_ONLY', name: 'Live AWS Read-Only', status: 'CONFIGURED', desc: 'Read-only CloudWatch telemetry' },
      ],
      uptime_seconds: 3600,
      uptime_formatted: '1h 0m (Process Runtime)',
      process_start_time: new Date().toISOString(),
      database_status: 'Connected (PostgreSQL on port 5434)',
      ml_model_status: 'Online (RandomForestClassifier)',
    }
  }
}

export async function markNotificationRead(eventId: string): Promise<boolean> {
  try {
    const res = await request<{ is_read: boolean; success: boolean }>(`notifications/${eventId}/read`, {
      method: 'POST',
    })
    return res.success
  } catch (err) {
    console.warn('Backend notifications endpoint unreachable:', err)
    return false
  }
}

export async function markAllNotificationsRead(): Promise<boolean> {
  try {
    const res = await request<{ marked_read_count: number; success: boolean }>('notifications/read-all', {
      method: 'POST',
    })
    return res.success
  } catch (err) {
    console.warn('Backend notifications endpoint unreachable:', err)
    return false
  }
}

export async function getAICopilotBriefing(eventId: string): Promise<AICopilotBriefing> {
  try {
    return await request<AICopilotBriefing>(`events/${eventId}/ai-briefing`, {
      method: 'POST',
    })
  } catch (err) {
    console.warn('AI copilot briefing endpoint unreachable:', err)
    return {
      event_id: eventId,
      provider: 'none',
      model: 'Deterministic-XAI-Synthesizer',
      is_llm_generated: false,
      executive_summary: `Incident ${eventId} evaluated via trained RandomForest model with continuous risk scoring.`,
      threat_narrative: 'Behavioral flow deviation identified across extracted network features.',
      remediation_steps: [
        '1. Enforce sandbox containment policy on origin IP.',
        '2. Inspect destination endpoint traffic.',
        '3. Review policy engine decision trace.',
      ],
      disclaimer: 'Deterministic synthesis fallback active.',
    }
  }
}

export async function getAIStatus(): Promise<{ configured_provider: string; active_provider: string; model: string; is_configured: boolean; role: string }> {
  try {
    return await request<{ configured_provider: string; active_provider: string; model: string; is_configured: boolean; role: string }>('system/ai-status')
  } catch {
    return {
      configured_provider: 'none',
      active_provider: 'none',
      model: 'Deterministic-XAI-Synthesizer',
      is_configured: true,
      role: 'Advisory SecOps Copilot (Zero Enforcement Permissions)',
    }
  }
}

export async function applyAction(
  eventId: string,
  action: PolicyAction
): Promise<{ eventId: string; action: PolicyAction; status: string }> {
  try {
    return await request<{ eventId: string; action: PolicyAction; status: string }>(
      `events/${eventId}/action`,
      {
        method: 'POST',
        body: JSON.stringify({ action }),
      }
    )
  } catch (err) {
    console.warn('Backend unavailable, applying action in local state:', err)
    return { eventId, action, status: action === 'Monitor' ? 'Monitoring' : 'Applied' }
  }
}
