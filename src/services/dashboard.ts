import type { DashboardData, PolicyAction } from '../types'
import { request } from './api'

const fallbackDashboard: DashboardData = {
  riskScore: 72,
  riskState: 'Restrict',
  activeFlows: 247,
  modelStatus: 'Fallback mock mode (Backend offline)',
  isSimulatedFlowBuffer: true,
  reasons: [
    { label: 'Unusual Port (8443)', value: 48, tone: 'red' },
    { label: 'Traffic Frequency Spike', value: 27, tone: 'orange' },
    { label: 'Failed Authentication', value: 15, tone: 'yellow' },
    { label: 'Unknown Peer Connection', value: 8, tone: 'blue' },
    { label: 'Unusual Data Transfer Size', value: 4, tone: 'blue' },
  ],
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
    {
      id: 'evt-1004',
      time: '13:47:22',
      event: 'New peer connection',
      source: '192.0.2.56',
      destination: '10.100.3.20',
      risk: 52,
      severity: 'medium',
      action: 'Allow',
      status: 'Allowed',
      description: 'A new peer was observed and allowed under the current policy.',
    },
    {
      id: 'evt-1005',
      time: '11:03:11',
      event: 'Large data transfer (2.1 GB)',
      source: '192.168.1.101',
      destination: '10.100.4.12',
      risk: 49,
      severity: 'medium',
      action: 'Monitor',
      status: 'Monitoring',
      description: 'Large data transfer flagged for continued observation.',
    },
  ],
}

export async function getDashboard(signal?: AbortSignal): Promise<{ data: DashboardData; isLiveBackend: boolean }> {
  try {
    const data = await request<DashboardData>('dashboard', { signal })
    return { data, isLiveBackend: true }
  } catch (err) {
    console.warn('FastAPI backend connection unreachable. Operating in local fallback mode:', err)
    return { data: fallbackDashboard, isLiveBackend: false }
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
