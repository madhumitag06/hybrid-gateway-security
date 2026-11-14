import React, { useState, useEffect } from 'react'
import type {
  CloudAccountStatus,
  CloudResource,
  CloudInventorySummary,
  MultiCloudHealthResponse,
  CloudTelemetryBatchResponse,
} from '../services/cloud'
import { cloudService } from '../services/cloud'

export const MultiCloudView: React.FC = () => {
  const [loading, setLoading] = useState<boolean>(true)
  const [error, setError] = useState<string | null>(null)
  const [accounts, setAccounts] = useState<CloudAccountStatus[]>([])
  const [resources, setResources] = useState<CloudResource[]>([])
  const [summary, setSummary] = useState<CloudInventorySummary | null>(null)
  const [health, setHealth] = useState<MultiCloudHealthResponse | null>(null)

  // Testing connection state
  const [testingProvider, setTestingProvider] = useState<string | null>(null)
  const [testResult, setTestResult] = useState<any | null>(null)

  // Telemetry Ingestion Console state
  const [selectedProvider, setSelectedProvider] = useState<'AWS' | 'GCP' | 'AZURE' | 'DOCKER_LAB'>('AWS')
  const [rawTelemetryInput, setRawTelemetryInput] = useState<string>(
    '2 aws-production-01 eni-0123456789abcdef0 10.20.10.15 10.20.10.2 44321 443 6 45 38500 1763160000 1763160030 ACCEPT OK'
  )
  const [ingestLoading, setIngestLoading] = useState<boolean>(false)
  const [ingestResponse, setIngestResponse] = useState<CloudTelemetryBatchResponse | null>(null)

  const loadData = async () => {
    setLoading(true)
    setError(null)
    try {
      const [accs, resList, summ, hlth] = await Promise.all([
        cloudService.getAccounts(),
        cloudService.getResources(),
        cloudService.getInventorySummary(),
        cloudService.getHealth(),
      ])
      setAccounts(accs)
      setResources(resList)
      setSummary(summ)
      setHealth(hlth)
    } catch (err: any) {
      console.error('Failed to load multi-cloud telemetry data:', err)
      setError(err?.message || 'Failed to communicate with multi-cloud registry API')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadData()
  }, [])

  const handleTestConnection = async (provider: string) => {
    setTestingProvider(provider)
    setTestResult(null)
    try {
      const res = await cloudService.testConnection(provider)
      setTestResult(res)
      // refresh health
      const hlth = await cloudService.getHealth()
      setHealth(hlth)
    } catch (err: any) {
      setTestResult({
        provider,
        status: 'ERROR',
        message: err?.message || 'Connection test failed',
      })
    } finally {
      setTestingProvider(null)
    }
  }

  const handleSampleSelect = (prov: 'AWS' | 'GCP' | 'AZURE' | 'DOCKER_LAB') => {
    setSelectedProvider(prov)
    setIngestResponse(null)
    if (prov === 'AWS') {
      setRawTelemetryInput(
        '2 aws-production-01 eni-0123456789abcdef0 10.20.10.15 10.20.10.2 44321 443 6 45 38500 1763160000 1763160030 ACCEPT OK'
      )
    } else if (prov === 'GCP') {
      setRawTelemetryInput(
        JSON.stringify(
          {
            insertId: 'gcp-sample-01',
            jsonPayload: {
              connection: {
                src_ip: '10.40.10.15',
                dest_ip: '10.40.10.2',
                src_port: 49152,
                dest_port: 443,
                protocol: 6,
              },
              bytes_sent: '28000',
              packets_sent: '35',
              start_time: '2026-11-15T00:00:00Z',
              end_time: '2026-11-15T00:00:10Z',
              rule_details: { action: 'ALLOW' },
            },
          },
          null,
          2
        )
      )
    } else if (prov === 'AZURE') {
      setRawTelemetryInput('1763160000,10.50.10.15,10.50.10.2,49200,443,T,I,A,B,30,22000,25,18000')
    } else {
      setRawTelemetryInput('10.10.10.15 10.20.10.2 50123 80 TCP')
    }
  }

  const handleIngestSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!rawTelemetryInput.trim()) return

    setIngestLoading(true)
    setIngestResponse(null)
    try {
      let recordPayload: any = rawTelemetryInput.trim()
      if (selectedProvider === 'GCP' && recordPayload.startsWith('{')) {
        try {
          recordPayload = JSON.parse(recordPayload)
        } catch {}
      }

      const res = await cloudService.ingestTelemetry({
        provider: selectedProvider,
        account_id: `${selectedProvider.toLowerCase()}-console-ingest`,
        records: [recordPayload],
        persist_events: true,
      })
      setIngestResponse(res)
    } catch (err: any) {
      alert(`Ingestion error: ${err?.message || 'Failed to ingest telemetry'}`)
    } finally {
      setIngestLoading(false)
    }
  }

  const getStatusBadge = (statusStr: string) => {
    const s = statusStr?.toUpperCase()
    if (s === 'CONNECTED' || s === 'HEALTHY' || s === 'ACTIVE' || s === 'READY') {
      return (
        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-emerald-100 text-emerald-800 dark:bg-emerald-950/60 dark:text-emerald-400 border border-emerald-300 dark:border-emerald-800">
          <span className="w-1.5 h-1.5 mr-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
          {s}
        </span>
      )
    }
    if (s === 'CONFIGURED') {
      return (
        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-sky-100 text-sky-800 dark:bg-sky-950/60 dark:text-sky-400 border border-sky-300 dark:border-sky-800">
          <span className="w-1.5 h-1.5 mr-1.5 rounded-full bg-sky-500"></span>
          {s}
        </span>
      )
    }
    if (s === 'DEGRADED') {
      return (
        <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-amber-100 text-amber-800 dark:bg-amber-950/60 dark:text-amber-400 border border-amber-300 dark:border-amber-800">
          {s}
        </span>
      )
    }
    return (
      <span className="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-semibold bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300 border border-slate-300 dark:border-slate-700">
        {s || 'UNKNOWN'}
      </span>
    )
  }

  return (
    <div className="space-y-6">
      {/* Executive Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 p-6 bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-bold tracking-tight text-slate-900 dark:text-white">
              Multi-Cloud Architecture & Telemetry
            </h1>
            {health && getStatusBadge(health.overall_status)}
            <span className="px-2.5 py-0.5 rounded-full text-xs font-medium bg-indigo-50 dark:bg-indigo-950/60 text-indigo-700 dark:text-indigo-400 border border-indigo-200 dark:border-indigo-800">
              XGBoost V2 Canonical (9 Features)
            </span>
            {accounts.length > 0 && (
              <span className="px-2 py-0.5 rounded-md text-xs bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-300 font-mono">
                {accounts.length} Accounts
              </span>
            )}
          </div>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            Unified multi-cloud abstraction layer integrating Amazon Web Services, Google Cloud Platform (Builders Hub),
            Microsoft Azure, and simulated Docker Hybrid Lab.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={loadData}
            disabled={loading}
            className="inline-flex items-center px-3.5 py-2 border border-slate-300 dark:border-slate-700 shadow-sm text-sm font-medium rounded-lg text-slate-700 dark:text-slate-200 bg-white dark:bg-slate-800 hover:bg-slate-50 dark:hover:bg-slate-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
          >
            {loading ? 'Refreshing...' : 'Refresh Health & Topology'}
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-lg bg-rose-50 dark:bg-rose-950/40 border border-rose-200 dark:border-rose-900 text-rose-700 dark:text-rose-300 text-sm">
          {error}
        </div>
      )}

      {/* Cloud Provider Adapters Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-5">
        {/* AWS Card */}
        <div className="bg-white dark:bg-slate-900 p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <div className="w-8 h-8 rounded-lg bg-amber-500/10 text-amber-600 dark:text-amber-400 flex items-center justify-center font-bold text-xs">
                  AWS
                </div>
                <div>
                  <h3 className="font-semibold text-slate-900 dark:text-white text-sm">Amazon Web Services</h3>
                  <p className="text-xs text-slate-500 dark:text-slate-400">VPC Flow Logs V2</p>
                </div>
              </div>
              {getStatusBadge(health?.providers?.AWS?.status || 'CONFIGURED')}
            </div>

            <div className="mt-3 space-y-1.5 text-xs text-slate-600 dark:text-slate-400 border-t border-slate-100 dark:border-slate-800/80 pt-3">
              <div className="flex justify-between">
                <span>Account ID:</span>
                <span className="font-mono text-slate-800 dark:text-slate-200 font-medium">aws-production-01</span>
              </div>
              <div className="flex justify-between">
                <span>Region:</span>
                <span className="font-mono text-slate-800 dark:text-slate-200">us-east-1</span>
              </div>
              <div className="flex justify-between">
                <span>Auth:</span>
                <span className="text-slate-800 dark:text-slate-200">STS AssumeRole / OIDC</span>
              </div>
              <div className="flex justify-between">
                <span>Containment:</span>
                <span className="text-slate-800 dark:text-slate-200">Security Groups / NACL</span>
              </div>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-100 dark:border-slate-800/80">
            <button
              onClick={() => handleTestConnection('AWS')}
              disabled={testingProvider === 'AWS'}
              className="w-full py-1.5 text-xs font-medium text-amber-700 dark:text-amber-400 bg-amber-50 dark:bg-amber-950/40 hover:bg-amber-100 rounded-lg border border-amber-200 dark:border-amber-900/60 transition"
            >
              {testingProvider === 'AWS' ? 'Testing...' : 'Test STS & Telemetry Probe'}
            </button>
          </div>
        </div>

        {/* GCP Card */}
        <div className="bg-white dark:bg-slate-900 p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <div className="w-8 h-8 rounded-lg bg-blue-500/10 text-blue-600 dark:text-blue-400 flex items-center justify-center font-bold text-xs">
                  GCP
                </div>
                <div>
                  <h3 className="font-semibold text-slate-900 dark:text-white text-sm">Google Cloud</h3>
                  <p className="text-xs text-slate-500 dark:text-slate-400">Google Builders Hub</p>
                </div>
              </div>
              {getStatusBadge(health?.providers?.GCP?.status || 'CONFIGURED')}
            </div>

            <div className="mt-3 space-y-1.5 text-xs text-slate-600 dark:text-slate-400 border-t border-slate-100 dark:border-slate-800/80 pt-3">
              <div className="flex justify-between">
                <span>Project ID:</span>
                <span className="font-mono text-slate-800 dark:text-slate-200 font-medium">gcp-builders-hub-prod</span>
              </div>
              <div className="flex justify-between">
                <span>Region:</span>
                <span className="font-mono text-slate-800 dark:text-slate-200">us-central1</span>
              </div>
              <div className="flex justify-between">
                <span>Identity:</span>
                <span className="text-slate-800 dark:text-slate-200">Workload Identity Fed.</span>
              </div>
              <div className="flex justify-between">
                <span>Containment:</span>
                <span className="text-slate-800 dark:text-slate-200">VPC Cloud Firewalls</span>
              </div>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-100 dark:border-slate-800/80">
            <button
              onClick={() => handleTestConnection('GCP')}
              disabled={testingProvider === 'GCP'}
              className="w-full py-1.5 text-xs font-medium text-blue-700 dark:text-blue-400 bg-blue-50 dark:bg-blue-950/40 hover:bg-blue-100 rounded-lg border border-blue-200 dark:border-blue-900/60 transition"
            >
              {testingProvider === 'GCP' ? 'Testing...' : 'Test WIF & Logging Probe'}
            </button>
          </div>
        </div>

        {/* Azure Card */}
        <div className="bg-white dark:bg-slate-900 p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <div className="w-8 h-8 rounded-lg bg-sky-500/10 text-sky-600 dark:text-sky-400 flex items-center justify-center font-bold text-xs">
                  AZ
                </div>
                <div>
                  <h3 className="font-semibold text-slate-900 dark:text-white text-sm">Microsoft Azure</h3>
                  <p className="text-xs text-slate-500 dark:text-slate-400">Network Watcher NSG</p>
                </div>
              </div>
              {getStatusBadge(health?.providers?.AZURE?.status || 'CONFIGURED')}
            </div>

            <div className="mt-3 space-y-1.5 text-xs text-slate-600 dark:text-slate-400 border-t border-slate-100 dark:border-slate-800/80 pt-3">
              <div className="flex justify-between">
                <span>Subscription:</span>
                <span className="font-mono text-slate-800 dark:text-slate-200 font-medium">sub-azure-enterprise</span>
              </div>
              <div className="flex justify-between">
                <span>Region:</span>
                <span className="font-mono text-slate-800 dark:text-slate-200">eastus</span>
              </div>
              <div className="flex justify-between">
                <span>Identity:</span>
                <span className="text-slate-800 dark:text-slate-200">Entra ID Federated OIDC</span>
              </div>
              <div className="flex justify-between">
                <span>Containment:</span>
                <span className="text-slate-800 dark:text-slate-200">NSG Security Rules</span>
              </div>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-100 dark:border-slate-800/80">
            <button
              onClick={() => handleTestConnection('AZURE')}
              disabled={testingProvider === 'AZURE'}
              className="w-full py-1.5 text-xs font-medium text-sky-700 dark:text-sky-400 bg-sky-50 dark:bg-sky-950/40 hover:bg-sky-100 rounded-lg border border-sky-200 dark:border-sky-900/60 transition"
            >
              {testingProvider === 'AZURE' ? 'Testing...' : 'Test Entra ID & NSG Probe'}
            </button>
          </div>
        </div>

        {/* Docker Lab Card */}
        <div className="bg-white dark:bg-slate-900 p-5 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm flex flex-col justify-between">
          <div>
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center gap-2">
                <div className="w-8 h-8 rounded-lg bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 flex items-center justify-center font-bold text-xs">
                  LAB
                </div>
                <div>
                  <h3 className="font-semibold text-slate-900 dark:text-white text-sm">Docker Hybrid Lab</h3>
                  <p className="text-xs text-slate-500 dark:text-slate-400">Local Simulated Cluster</p>
                </div>
              </div>
              {getStatusBadge('CONNECTED')}
            </div>

            <div className="mt-3 space-y-1.5 text-xs text-slate-600 dark:text-slate-400 border-t border-slate-100 dark:border-slate-800/80 pt-3">
              <div className="flex justify-between">
                <span>Router IP:</span>
                <span className="font-mono text-slate-800 dark:text-slate-200 font-medium">10.30.10.2:8099</span>
              </div>
              <div className="flex justify-between">
                <span>On-Prem Subnet:</span>
                <span className="font-mono text-slate-800 dark:text-slate-200">10.10.10.0/24</span>
              </div>
              <div className="flex justify-between">
                <span>Cloud Subnet:</span>
                <span className="font-mono text-slate-800 dark:text-slate-200">10.20.10.0/24</span>
              </div>
              <div className="flex justify-between">
                <span>Containment:</span>
                <span className="text-slate-800 dark:text-slate-200">iptables FORWARD / NullRoute</span>
              </div>
            </div>
          </div>

          <div className="mt-4 pt-3 border-t border-slate-100 dark:border-slate-800/80">
            <button
              onClick={() => handleTestConnection('DOCKER_LAB')}
              disabled={testingProvider === 'DOCKER_LAB'}
              className="w-full py-1.5 text-xs font-medium text-emerald-700 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-950/40 hover:bg-emerald-100 rounded-lg border border-emerald-200 dark:border-emerald-900/60 transition"
            >
              {testingProvider === 'DOCKER_LAB' ? 'Testing...' : 'Test Local Lab Bridge'}
            </button>
          </div>
        </div>
      </div>

      {/* Test Connection Output Modal / Box */}
      {testResult && (
        <div className="p-4 rounded-xl bg-slate-900 text-slate-100 border border-slate-700 font-mono text-xs">
          <div className="flex items-center justify-between pb-2 border-b border-slate-800 mb-2">
            <span className="font-semibold text-emerald-400">
              Provider Connection Diagnostic Result: {testResult.provider}
            </span>
            <button onClick={() => setTestResult(null)} className="text-slate-400 hover:text-white">
              ✕ Close
            </button>
          </div>
          <pre className="overflow-x-auto">{JSON.stringify(testResult, null, 2)}</pre>
        </div>
      )}

      {/* Network Resource Inventory Table */}
      <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm overflow-hidden">
        <div className="p-5 border-b border-slate-200 dark:border-slate-800 flex items-center justify-between">
          <div>
            <h2 className="text-base font-semibold text-slate-900 dark:text-white">
              Multi-Cloud Network Resource Inventory
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Discovered Virtual Private Clouds, Subnetworks, Gateways, and Firewall Security Policies.
            </p>
          </div>
          {summary && (
            <div className="flex items-center gap-2 text-xs font-medium text-slate-600 dark:text-slate-300">
              <span className="px-2.5 py-1 rounded-md bg-slate-100 dark:bg-slate-800">
                {summary.total_vpcs} VPCs / VNets
              </span>
              <span className="px-2.5 py-1 rounded-md bg-slate-100 dark:bg-slate-800">
                {summary.total_subnets} Subnets
              </span>
              <span className="px-2.5 py-1 rounded-md bg-slate-100 dark:bg-slate-800">
                {summary.total_security_groups} SGs / Firewalls
              </span>
            </div>
          )}
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs text-slate-600 dark:text-slate-300">
            <thead className="bg-slate-50 dark:bg-slate-800/60 text-slate-700 dark:text-slate-300 uppercase font-semibold">
              <tr>
                <th className="px-4 py-3">Provider</th>
                <th className="px-4 py-3">Resource Type</th>
                <th className="px-4 py-3">Name / Identifier</th>
                <th className="px-4 py-3">CIDR Block</th>
                <th className="px-4 py-3">Region / Zone</th>
                <th className="px-4 py-3">State</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
              {resources.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-4 py-6 text-center text-slate-400">
                    No resources currently discovered.
                  </td>
                </tr>
              ) : (
                resources.map((r, i) => (
                  <tr key={i} className="hover:bg-slate-50/50 dark:hover:bg-slate-800/40">
                    <td className="px-4 py-3 font-semibold">{r.provider}</td>
                    <td className="px-4 py-3">
                      <span className="px-2 py-0.5 rounded font-mono text-[11px] bg-slate-100 dark:bg-slate-800">
                        {r.resource_type}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-medium text-slate-900 dark:text-white">
                      {r.name}
                      <span className="block font-mono text-[10px] text-slate-400 truncate max-w-xs">
                        {r.resource_id}
                      </span>
                    </td>
                    <td className="px-4 py-3 font-mono">{r.cidr_block || '—'}</td>
                    <td className="px-4 py-3 font-mono">{r.region || 'global'}</td>
                    <td className="px-4 py-3">{getStatusBadge(r.state)}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Canonical Telemetry Ingestion Console */}
      <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm p-6">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 mb-4">
          <div>
            <h2 className="text-base font-semibold text-slate-900 dark:text-white">
              Live Multi-Cloud Telemetry Ingestion & XGBoost V2 Evaluation
            </h2>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Test canonical feature normalization and ML threat inference across AWS, GCP, Azure, and Docker Lab.
            </p>
          </div>

          <div className="flex items-center gap-1.5 bg-slate-100 dark:bg-slate-800 p-1 rounded-lg">
            {(['AWS', 'GCP', 'AZURE', 'DOCKER_LAB'] as const).map((prov) => (
              <button
                key={prov}
                onClick={() => handleSampleSelect(prov)}
                className={`px-3 py-1 rounded text-xs font-medium transition ${
                  selectedProvider === prov
                    ? 'bg-white dark:bg-slate-700 text-slate-900 dark:text-white shadow-sm'
                    : 'text-slate-600 dark:text-slate-400 hover:text-slate-900'
                }`}
              >
                {prov}
              </button>
            ))}
          </div>
        </div>

        <form onSubmit={handleIngestSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-semibold text-slate-700 dark:text-slate-300 mb-1">
              Raw {selectedProvider} Telemetry Log Record:
            </label>
            <textarea
              value={rawTelemetryInput}
              onChange={(e) => setRawTelemetryInput(e.target.value)}
              rows={4}
              className="w-full font-mono text-xs p-3 rounded-lg border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 focus:ring-2 focus:ring-indigo-500 focus:outline-none"
            />
          </div>

          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-500 dark:text-slate-400">
              Evaluated strictly via 9-feature schema without synthetic failed_auth_count.
            </span>
            <button
              type="submit"
              disabled={ingestLoading}
              className="px-4 py-2 bg-indigo-600 hover:bg-indigo-700 text-white rounded-lg text-xs font-medium shadow-sm transition disabled:opacity-50"
            >
              {ingestLoading ? 'Normalizing & Evaluating...' : 'Normalize & Evaluate Threat'}
            </button>
          </div>
        </form>

        {/* Telemetry Evaluation Result */}
        {ingestResponse && (
          <div className="mt-6 p-4 rounded-xl bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 space-y-4">
            <div className="flex items-center justify-between border-b border-slate-200 dark:border-slate-800 pb-3">
              <div className="flex items-center gap-3">
                <span className="font-semibold text-sm text-slate-900 dark:text-white">
                  Ingestion Evaluation Result ({ingestResponse.provider})
                </span>
                <span className="px-2 py-0.5 rounded text-xs bg-emerald-100 text-emerald-800 dark:bg-emerald-950 dark:text-emerald-300 font-medium">
                  {ingestResponse.status}
                </span>
              </div>
              <div className="text-xs text-slate-500 dark:text-slate-400">
                Parsing: {ingestResponse.parsing_duration_ms}ms | Inference: {ingestResponse.inference_duration_ms}ms
              </div>
            </div>

            {ingestResponse.flows.map((flow, idx) => (
              <div
                key={idx}
                className="grid grid-cols-2 md:grid-cols-4 gap-3 p-3 rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 text-xs"
              >
                <div>
                  <span className="text-slate-400 block">Traffic Session:</span>
                  <span className="font-mono font-medium text-slate-900 dark:text-white">
                    {flow.src_ip} → {flow.dst_ip}:{flow.dst_port}
                  </span>
                </div>
                <div>
                  <span className="text-slate-400 block">Attack Type / Threat:</span>
                  <span className="font-semibold text-slate-900 dark:text-white">
                    {flow.attack_type} ({flow.threat_level})
                  </span>
                </div>
                <div>
                  <span className="text-slate-400 block">Risk Score:</span>
                  <span className="font-mono font-semibold text-indigo-600 dark:text-indigo-400">
                    {flow.risk_score.toFixed(1)} / 100
                  </span>
                </div>
                <div>
                  <span className="text-slate-400 block">Policy Action:</span>
                  <span
                    className={`font-semibold ${
                      flow.policy_action === 'DROP' || flow.policy_action === 'BLOCK'
                        ? 'text-rose-600 dark:text-rose-400'
                        : 'text-emerald-600 dark:text-emerald-400'
                    }`}
                  >
                    {flow.policy_action}
                  </span>
                </div>
              </div>
            ))}

            <div className="text-[11px] font-mono text-slate-500 dark:text-slate-400 pt-2 flex flex-wrap gap-2">
              <span>Schema: {ingestResponse.normalization_report.schema_version}</span>
              <span>•</span>
              <span>Features: {ingestResponse.normalization_report.features_extracted.join(', ')}</span>
              <span>•</span>
              <span>
                Auth Synthesized:{' '}
                {ingestResponse.normalization_report.failed_auth_synthesized ? 'TRUE' : 'FALSE (Strictly Clean)'}
              </span>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
