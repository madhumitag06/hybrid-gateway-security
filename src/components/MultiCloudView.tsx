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

  // Dedicated AWS Phase 1 / Phase 2 state
  const [awsCallerIdentity, setAwsCallerIdentity] = useState<any | null>({
    account: '698766075180',
    region: 'ap-southeast-2',
    role_arn: 'arn:aws:iam::698766075180:role/SecurityGatewayReadOnlyRole',
    profile_name: 'security-gateway-readonly',
    status: 'CONNECTED',
  })
  const [awsDiscovery, setAwsDiscovery] = useState<any | null>(null)
  const [awsFlowLogs, setAwsFlowLogs] = useState<any | null>(null)
  const [isDiscoveringAws, setIsDiscoveringAws] = useState<boolean>(false)
  const [isInspectingFlowLogs, setIsInspectingFlowLogs] = useState<boolean>(false)
  const [isPollingAws, setIsPollingAws] = useState<boolean>(false)
  const [showIamGuide, setShowIamGuide] = useState<boolean>(false)
  const [lastSyncTime, setLastSyncTime] = useState<string | null>(null)
  const [resourceFilter, setResourceFilter] = useState<string>('ALL')
  const [typeFilter, setTypeFilter] = useState<string>('ALL')

  const [awsTelemetryStats, setAwsTelemetryStats] = useState<{
    total: number
    benign: number
    threats: number
    by_threat: Record<string, number>
    last_poll_time: string | null
  }>({
    total: 0,
    benign: 0,
    threats: 0,
    by_threat: {},
    last_poll_time: null,
  })

  // AWS Telemetry Ingestion Pipeline State
  const [awsTelemetryHistory, setAwsTelemetryHistory] = useState<any[]>([])
  const [showTelemetryHistory, setShowTelemetryHistory] = useState<boolean>(false)
  const [isResettingCheckpoint, setIsResettingCheckpoint] = useState<boolean>(false)
  const [telemetryMode, setTelemetryMode] = useState<'LIVE' | 'SANDBOX'>('LIVE')
  const [telemetryStatusInfo, setTelemetryStatusInfo] = useState<any | null>(null)

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

  const handleLoadTelemetryHistory = async () => {
    try {
      const history = await cloudService.getAwsTelemetryHistory(15)
      setAwsTelemetryHistory(history)
    } catch (e) {
      console.error('Failed to load telemetry history:', e)
    }
  }

  const handleLoadTelemetryStatus = async () => {
    try {
      const statusData = await cloudService.getAwsTelemetryStatus()
      setTelemetryStatusInfo(statusData)
      if (statusData?.sources) {
        setAwsFlowLogs({
          subscriptions_count: statusData.active_sources_count,
          subscriptions: statusData.sources,
        })
      }
    } catch (e) {
      console.error('Failed to load telemetry status:', e)
    }
  }

  const loadData = async (isManual = false) => {
    if (isManual) {
      setLoading(true)
      setError(null)
    }
    try {
      const [accsRes, resListRes, summRes, hlthRes] = await Promise.allSettled([
        cloudService.getAccounts(),
        cloudService.getResources(),
        cloudService.getInventorySummary(),
        cloudService.getHealth(),
      ])
      const accs = accsRes.status === 'fulfilled' ? accsRes.value : []
      const resList = resListRes.status === 'fulfilled' ? resListRes.value : []
      const summ = summRes.status === 'fulfilled' ? summRes.value : null
      const hlth = hlthRes.status === 'fulfilled' ? hlthRes.value : null

      setAccounts(accs)
      setResources(resList)
      setSummary(summ)
      setHealth(hlth)

      const awsHlth = hlth?.providers?.AWS
      if (awsHlth && awsHlth.account_id && awsHlth.account_id !== 'aws-production-01') {
        setAwsCallerIdentity((prev: any) => ({
          ...prev,
          account: awsHlth.account_id,
          region: awsHlth.region || 'ap-southeast-2',
          role: awsHlth.role || 'SecurityGatewayReadOnlyRole',
          status: awsHlth.status || 'CONNECTED',
        }))
        setLastSyncTime(new Date().toLocaleTimeString())
      }

      // Load initial telemetry pipeline health and history
      await Promise.allSettled([
        handleLoadTelemetryStatus(),
        handleLoadTelemetryHistory(),
      ])
    } catch (err: any) {
      console.error('Failed to load multi-cloud telemetry data:', err)
      setError(err?.message || 'Failed to communicate with multi-cloud registry API')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    let mounted = true
    Promise.allSettled([
      cloudService.getAccounts(),
      cloudService.getResources(),
      cloudService.getInventorySummary(),
      cloudService.getHealth(),
    ])
      .then(([accsRes, resListRes, summRes, hlthRes]) => {
        if (!mounted) return
        const accs = accsRes.status === 'fulfilled' ? accsRes.value : []
        const resList = resListRes.status === 'fulfilled' ? resListRes.value : []
        const summ = summRes.status === 'fulfilled' ? summRes.value : null
        const hlth = hlthRes.status === 'fulfilled' ? hlthRes.value : null

        setAccounts(accs)
        setResources(resList)
        setSummary(summ)
        setHealth(hlth)

        const awsHlth = hlth?.providers?.AWS
        if (awsHlth && awsHlth.account_id && awsHlth.account_id !== 'aws-production-01') {
          setAwsCallerIdentity((prev: any) => ({
            ...prev,
            account: awsHlth.account_id,
            region: awsHlth.region || 'ap-southeast-2',
            role: awsHlth.role || 'SecurityGatewayReadOnlyRole',
            status: awsHlth.status || 'CONNECTED',
          }))
          setLastSyncTime(new Date().toLocaleTimeString())
        }

        void Promise.allSettled([
          handleLoadTelemetryStatus(),
          handleLoadTelemetryHistory(),
        ]).finally(() => {
          if (mounted) setLoading(false)
        })
      })
      .catch((err: any) => {
        if (mounted) {
          setError(err?.message || 'Failed to communicate with multi-cloud registry API')
          setLoading(false)
        }
      })
    return () => {
      mounted = false
    }
  }, [])

  const handleTestConnection = async (provider: string) => {
    setTestingProvider(provider)
    setTestResult(null)
    try {
      const res = await cloudService.testConnection(provider)
      setTestResult(res)
      if (provider === 'AWS' && res.caller_identity) {
        setAwsCallerIdentity(res.caller_identity)
        setLastSyncTime(new Date().toLocaleTimeString())
      }
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

  const handleDiscoverAws = async () => {
    setIsDiscoveringAws(true)
    setError(null)
    try {
      const res = await cloudService.discoverAwsResources()
      setAwsDiscovery(res)
      if (res.caller_identity) {
        setAwsCallerIdentity(res.caller_identity)
      }
      setLastSyncTime(new Date().toLocaleTimeString())
      const [resList, summ] = await Promise.all([
        cloudService.getResources(),
        cloudService.getInventorySummary(),
      ])
      setResources(resList)
      setSummary(summ)
    } catch (err: any) {
      setError(`AWS Resource Discovery error: ${err?.message || String(err)}`)
    } finally {
      setIsDiscoveringAws(false)
    }
  }

  const handleResetCheckpoint = async () => {
    if (!window.confirm('Reset AWS VPC flow log ingestion checkpoints and clear deduplication cache?')) return
    setIsResettingCheckpoint(true)
    try {
      await cloudService.resetAwsTelemetryCheckpoint()
      await handleLoadTelemetryHistory()
      await handleLoadTelemetryStatus()
    } catch (err: any) {
      setError(`Reset error: ${err?.message || String(err)}`)
    } finally {
      setIsResettingCheckpoint(false)
    }
  }

  const handleInspectAwsFlowLogs = async () => {
    setIsInspectingFlowLogs(true)
    setError(null)
    try {
      const res = await cloudService.getAwsFlowLogs()
      setAwsFlowLogs(res)
    } catch (err: any) {
      setError(`AWS Flow Logs inspection error: ${err?.message || String(err)}`)
    } finally {
      setIsInspectingFlowLogs(false)
    }
  }

  const handlePollAwsTelemetry = async (mockFallback: boolean = false) => {
    setIsPollingAws(true)
    setError(null)
    setTelemetryMode(mockFallback ? 'SANDBOX' : 'LIVE')
    try {
      const res = await cloudService.pollAwsTelemetry({ limit: 50, mock_fallback: mockFallback })
      setIngestResponse(res)

      let benign = 0
      let threats = 0
      const threatMap: Record<string, number> = {}

      for (const f of res.flows) {
        if (f.threat_level === 'BENIGN' || f.threat_level === 'LOW') {
          benign += 1
        } else {
          threats += 1
          threatMap[f.attack_type] = (threatMap[f.attack_type] || 0) + 1
        }
      }

      setAwsTelemetryStats((prev) => ({
        total: prev.total + (res.records_parsed || 0),
        benign: prev.benign + benign,
        threats: prev.threats + threats,
        by_threat: { ...prev.by_threat, ...threatMap },
        last_poll_time: new Date().toLocaleTimeString(),
      }))

      await Promise.allSettled([
        handleLoadTelemetryHistory(),
        handleLoadTelemetryStatus(),
      ])
    } catch (err: any) {
      setError(`AWS Flow Log polling error: ${err?.message || String(err)}`)
    } finally {
      setIsPollingAws(false)
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

  const renderStatusBadge = (statusStr: string) => {
    const s = statusStr?.toUpperCase() || 'NOT_CONFIGURED'
    let bg = 'rgba(73, 72, 61, 0.4)'
    let color = 'var(--muted-cream)'
    let border = '1px solid var(--line)'
    let dotColor = 'var(--muted-cream)'

    if (s === 'CONNECTED' || s === 'VERIFIED' || s === 'HEALTHY' || s === 'ACTIVE' || s === 'READY') {
      bg = 'rgba(133, 139, 89, 0.16)'
      color = 'var(--olive-green)'
      border = '1px solid rgba(133, 139, 89, 0.35)'
      dotColor = 'var(--olive-green)'
    } else if (s === 'CONFIGURED' || s === 'STANDBY' || s === 'CONFIGURED_STANDBY') {
      bg = 'rgba(216, 201, 167, 0.15)'
      color = 'var(--pale-sand)'
      border = '1px solid rgba(216, 201, 167, 0.35)'
      dotColor = 'var(--pale-sand)'
    } else if (s === 'DEGRADED') {
      bg = 'rgba(200, 117, 85, 0.16)'
      color = 'var(--terracotta)'
      border = '1px solid rgba(200, 117, 85, 0.35)'
      dotColor = 'var(--terracotta)'
    } else if (s === 'AUTHENTICATION_FAILED' || s === 'ROLE_ASSUME_FAILED' || s === 'ERROR') {
      bg = 'rgba(184, 92, 84, 0.16)'
      color = 'var(--muted-red)'
      border = '1px solid rgba(184, 92, 84, 0.35)'
      dotColor = 'var(--muted-red)'
    }

    return (
      <span
        style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: '6px',
          padding: '2px 8px',
          borderRadius: '12px',
          fontSize: '11px',
          fontWeight: 600,
          background: bg,
          color: color,
          border: border,
          fontFamily: 'var(--font-mono)',
        }}
      >
        <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: dotColor }} />
        {s}
      </span>
    )
  }

  // Derive consolidated telemetry counts distinguishing latest run vs cumulative checkpoint vs active poll
  const latestRun = awsTelemetryHistory.length > 0 ? awsTelemetryHistory[0] : null
  const latestRunMetrics = telemetryStatusInfo?.latest_run_metrics
  const cumulativeCheckpointMetrics = telemetryStatusInfo?.cumulative_checkpoint_metrics

  // Latest Ingestion Run
  const latestDiscovered =
    latestRun?.records_discovered ??
    latestRunMetrics?.records_discovered ??
    0
  const latestEvaluated =
    latestRun?.records_ingested ??
    latestRunMetrics?.records_ingested ??
    0
  const latestDuplicates =
    latestRun?.records_duplicate_skipped ??
    latestRunMetrics?.records_duplicate_skipped ??
    0
  const latestThreats =
    latestRun?.high_risk_detected ??
    latestRunMetrics?.high_risk_detected ??
    0

  // Cumulative Checkpoint Records (total processed across all log streams)
  const cumulativeProcessed =
    cumulativeCheckpointMetrics?.total_records_processed ??
    telemetryStatusInfo?.checkpoints?.reduce((acc: number, c: any) => acc + (c.total_records_processed || 0), 0) ??
    0

  // Active Session Poll Totals (or fallback to latest run if session has not polled yet)
  const activeDiscovered = awsTelemetryStats.total > 0 ? awsTelemetryStats.total : latestDiscovered
  const activeEvaluated = awsTelemetryStats.total > 0 ? (awsTelemetryStats.benign + awsTelemetryStats.threats) : latestEvaluated
  const activeThreats = awsTelemetryStats.total > 0 ? awsTelemetryStats.threats : latestThreats
  const totalInvalid = telemetryStatusInfo?.metrics?.total_invalid_skipped ?? 0

  // Filtered resources
  const filteredResources = resources.filter((r) => {
    const matchProv = resourceFilter === 'ALL' || r.provider.toUpperCase() === resourceFilter.toUpperCase()
    const matchType = typeFilter === 'ALL' || r.resource_type.toUpperCase() === typeFilter.toUpperCase()
    return matchProv && matchType
  })

  const uniqueResourceTypes = Array.from(new Set(resources.map((r) => r.resource_type)))

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
      {/* Executive Header */}
      <div
        className="card"
        style={{
          padding: '20px 24px',
          background: 'var(--panel)',
          border: '1px solid var(--line)',
          borderRadius: 'var(--radius-sm)',
          display: 'flex',
          flexDirection: 'row',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '16px',
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
            <h1 style={{ margin: 0, fontSize: '22px', fontWeight: 700, color: 'var(--warm-cream)', fontFamily: 'var(--font-heading)' }}>
              Multi-Cloud Architecture & Telemetry
            </h1>
            {health && renderStatusBadge(health.overall_status)}
            <span
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                padding: '3px 10px',
                borderRadius: '12px',
                fontSize: '11px',
                fontWeight: 600,
                background: 'rgba(200, 117, 85, 0.16)',
                color: 'var(--terracotta)',
                border: '1px solid rgba(200, 117, 85, 0.35)',
              }}
            >
              XGBoost V2 Canonical (9 Features)
            </span>
            {accounts.length > 0 && (
              <span
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  padding: '3px 8px',
                  borderRadius: 'var(--radius-xs)',
                  fontSize: '11px',
                  fontFamily: 'var(--font-mono)',
                  background: 'var(--panel-inset)',
                  color: 'var(--muted-cream)',
                  border: '1px solid var(--line)',
                }}
              >
                {accounts.length} Accounts Configured
              </span>
            )}
          </div>
          <p style={{ margin: '6px 0 0', fontSize: '13px', color: 'var(--muted-cream)' }}>
            Unified multi-cloud security gateway connecting Amazon Web Services, Google Cloud Platform (Builders Hub),
            Microsoft Azure, and simulated Docker Hybrid Lab.
          </p>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <button
            onClick={() => loadData(true)}
            disabled={loading}
            className="primary"
            style={{
              padding: '8px 16px',
              fontSize: '12px',
              fontWeight: 600,
              cursor: loading ? 'not-allowed' : 'pointer',
              opacity: loading ? 0.6 : 1,
            }}
          >
            {loading ? 'Refreshing...' : '🔄 Refresh Health & Topology'}
          </button>
        </div>
      </div>

      {error && (
        <div
          className="auth-alert"
          style={{
            padding: '12px 16px',
            background: 'rgba(184, 92, 84, 0.16)',
            border: '1px solid var(--muted-red)',
            borderRadius: 'var(--radius-sm)',
            color: 'var(--warm-cream)',
            fontSize: '13px',
          }}
        >
          <b>Alert:</b> {error}
        </div>
      )}

      {/* Cloud Provider Adapters Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '16px' }}>
        {/* AWS Card */}
        <div
          className="card"
          style={{
            padding: '18px 20px',
            background: 'var(--panel)',
            border: '1px solid var(--line)',
            borderRadius: 'var(--radius-sm)',
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'space-between',
          }}
        >
          <div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <div
                  style={{
                    width: '32px',
                    height: '32px',
                    borderRadius: 'var(--radius-xs)',
                    background: 'rgba(200, 117, 85, 0.2)',
                    color: 'var(--terracotta)',
                    border: '1px solid rgba(200, 117, 85, 0.4)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontWeight: 700,
                    fontSize: '12px',
                  }}
                >
                  AWS
                </div>
                <div>
                  <h3 style={{ margin: 0, fontSize: '14px', fontWeight: 700, color: 'var(--warm-cream)' }}>
                    Amazon Web Services
                  </h3>
                  <small style={{ fontSize: '11px', color: 'var(--muted-cream)' }}>VPC Flow Logs V2</small>
                </div>
              </div>
              {renderStatusBadge(
                awsCallerIdentity?.status === 'VERIFIED'
                  ? 'CONNECTED'
                  : awsCallerIdentity?.status || health?.providers?.AWS?.status || 'CONNECTED'
              )}
            </div>

            <div
              style={{
                background: 'var(--panel-inset)',
                border: '1px solid var(--line-subtle)',
                borderRadius: 'var(--radius-xs)',
                padding: '10px 12px',
                display: 'flex',
                flexDirection: 'column',
                gap: '6px',
                fontSize: '12px',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--muted-cream)' }}>Account ID:</span>
                <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--warm-cream)', fontWeight: 600 }}>
                  {awsCallerIdentity?.account || '698766075180'}
                </span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--muted-cream)' }}>Region:</span>
                <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--warm-cream)' }}>
                  {awsCallerIdentity?.region || health?.providers?.AWS?.region || 'ap-southeast-2'}
                </span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--muted-cream)' }}>Assumed Role:</span>
                <span
                  style={{ fontFamily: 'var(--font-mono)', color: 'var(--warm-cream)', maxWidth: '160px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                  title={awsCallerIdentity?.role || 'SecurityGatewayReadOnlyRole'}
                >
                  {awsCallerIdentity?.role || 'SecurityGatewayReadOnlyRole'}
                </span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--muted-cream)' }}>Discovered Topology:</span>
                <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--olive-green)', fontWeight: 600 }}>
                  {loading
                    ? 'Discovering...'
                    : awsDiscovery
                    ? `${awsDiscovery.total_resources} AWS Resources`
                    : `${resources.filter((r) => r.provider === 'AWS').length} AWS Resources`}
                </span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--muted-cream)' }}>Flow Log Source:</span>
                <span style={{ color: 'var(--warm-cream)' }}>
                  {awsFlowLogs && awsFlowLogs.subscriptions_count > 0
                    ? `${awsFlowLogs.subscriptions_count} Active (${awsFlowLogs.subscriptions[0]?.destination_type || 'CloudWatch'})`
                    : '1 Active (CloudWatch)'}
                </span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--muted-cream)' }}>Last Checkpoint:</span>
                <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--muted-cream)', fontSize: '11px' }}>
                  {lastSyncTime || 'Active Ingestion'}
                </span>
              </div>
            </div>
          </div>

          <div style={{ marginTop: '14px', display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
              <button
                onClick={() => handleTestConnection('AWS')}
                disabled={testingProvider === 'AWS'}
                style={{
                  padding: '6px 10px',
                  fontSize: '11px',
                  fontWeight: 600,
                  background: 'var(--panel-inset)',
                  border: '1px solid var(--line)',
                  borderRadius: 'var(--radius-xs)',
                  color: 'var(--terracotta)',
                }}
              >
                {testingProvider === 'AWS' ? 'Testing...' : 'Test STS Identity'}
              </button>
              <button
                onClick={handleDiscoverAws}
                disabled={isDiscoveringAws}
                style={{
                  padding: '6px 10px',
                  fontSize: '11px',
                  fontWeight: 600,
                  background: 'var(--panel-inset)',
                  border: '1px solid var(--line)',
                  borderRadius: 'var(--radius-xs)',
                  color: 'var(--warm-cream)',
                }}
              >
                {isDiscoveringAws ? 'Discovering...' : 'Discover AWS VPCs'}
              </button>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
              <button
                onClick={handleInspectAwsFlowLogs}
                disabled={isInspectingFlowLogs}
                style={{
                  padding: '6px 10px',
                  fontSize: '11px',
                  fontWeight: 600,
                  background: 'var(--panel-inset)',
                  border: '1px solid var(--line)',
                  borderRadius: 'var(--radius-xs)',
                  color: 'var(--pale-sand)',
                }}
              >
                {isInspectingFlowLogs ? 'Inspecting...' : 'Inspect Flow Logs'}
              </button>
              <button
                onClick={() => handlePollAwsTelemetry(false)}
                disabled={isPollingAws}
                style={{
                  padding: '6px 10px',
                  fontSize: '11px',
                  fontWeight: 600,
                  background: 'rgba(133, 139, 89, 0.2)',
                  border: '1px solid rgba(133, 139, 89, 0.4)',
                  borderRadius: 'var(--radius-xs)',
                  color: 'var(--olive-green)',
                }}
              >
                {isPollingAws ? 'Polling...' : '⚡ Poll Live Logs'}
              </button>
            </div>
            <button
              onClick={() => setShowIamGuide(!showIamGuide)}
              style={{
                background: 'none',
                border: 'none',
                color: 'var(--muted-cream)',
                fontSize: '11px',
                textAlign: 'center',
                textDecoration: 'underline',
                cursor: 'pointer',
                marginTop: '4px',
              }}
            >
              {showIamGuide ? 'Hide AWS Setup Guide' : 'View AWS Read-Only Setup Guide'}
            </button>
          </div>
        </div>

        {/* GCP Card */}
        <div
          className="card"
          style={{
            padding: '18px 20px',
            background: 'var(--panel)',
            border: '1px solid var(--line)',
            borderRadius: 'var(--radius-sm)',
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'space-between',
          }}
        >
          <div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <div
                  style={{
                    width: '32px',
                    height: '32px',
                    borderRadius: 'var(--radius-xs)',
                    background: 'rgba(133, 139, 89, 0.2)',
                    color: 'var(--olive-green)',
                    border: '1px solid rgba(133, 139, 89, 0.4)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontWeight: 700,
                    fontSize: '12px',
                  }}
                >
                  GCP
                </div>
                <div>
                  <h3 style={{ margin: 0, fontSize: '14px', fontWeight: 700, color: 'var(--warm-cream)' }}>
                    Google Cloud Platform
                  </h3>
                  <small style={{ fontSize: '11px', color: 'var(--muted-cream)' }}>Google Builders Hub</small>
                </div>
              </div>
              {renderStatusBadge(health?.providers?.GCP?.status || 'CONFIGURED')}
            </div>

            <div
              style={{
                background: 'var(--panel-inset)',
                border: '1px solid var(--line-subtle)',
                borderRadius: 'var(--radius-xs)',
                padding: '10px 12px',
                display: 'flex',
                flexDirection: 'column',
                gap: '6px',
                fontSize: '12px',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--muted-cream)' }}>Project ID:</span>
                <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--warm-cream)', fontWeight: 600 }}>
                  gcp-builders-hub-prod
                </span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--muted-cream)' }}>Region:</span>
                <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--warm-cream)' }}>us-central1</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--muted-cream)' }}>Identity:</span>
                <span style={{ color: 'var(--warm-cream)' }}>Workload Identity Fed.</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--muted-cream)' }}>Discovered Topology:</span>
                <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--olive-green)', fontWeight: 600 }}>
                  {loading ? 'Discovering...' : `${resources.filter((r) => r.provider === 'GCP').length} GCP Resources`}
                </span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--muted-cream)' }}>Containment:</span>
                <span style={{ color: 'var(--warm-cream)' }}>VPC Cloud Firewalls</span>
              </div>
            </div>
          </div>

          <div style={{ marginTop: '14px' }}>
            <button
              onClick={() => handleTestConnection('GCP')}
              disabled={testingProvider === 'GCP'}
              style={{
                width: '100%',
                padding: '7px 12px',
                fontSize: '11px',
                fontWeight: 600,
                background: 'var(--panel-inset)',
                border: '1px solid var(--line)',
                borderRadius: 'var(--radius-xs)',
                color: 'var(--olive-green)',
              }}
            >
              {testingProvider === 'GCP' ? 'Testing...' : 'Test WIF & Logging Probe'}
            </button>
          </div>
        </div>

        {/* Azure Card */}
        <div
          className="card"
          style={{
            padding: '18px 20px',
            background: 'var(--panel)',
            border: '1px solid var(--line)',
            borderRadius: 'var(--radius-sm)',
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'space-between',
          }}
        >
          <div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <div
                  style={{
                    width: '32px',
                    height: '32px',
                    borderRadius: 'var(--radius-xs)',
                    background: 'rgba(92, 160, 211, 0.2)',
                    color: '#5CA0D3',
                    border: '1px solid rgba(92, 160, 211, 0.4)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontWeight: 700,
                    fontSize: '12px',
                  }}
                >
                  AZ
                </div>
                <div>
                  <h3 style={{ margin: 0, fontSize: '14px', fontWeight: 700, color: 'var(--warm-cream)' }}>
                    Microsoft Azure
                  </h3>
                  <small style={{ fontSize: '11px', color: 'var(--muted-cream)' }}>Network Watcher NSG</small>
                </div>
              </div>
              {renderStatusBadge(health?.providers?.AZURE?.status || 'CONFIGURED')}
            </div>

            <div
              style={{
                background: 'var(--panel-inset)',
                border: '1px solid var(--line-subtle)',
                borderRadius: 'var(--radius-xs)',
                padding: '10px 12px',
                display: 'flex',
                flexDirection: 'column',
                gap: '6px',
                fontSize: '12px',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--muted-cream)' }}>Subscription:</span>
                <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--warm-cream)', fontWeight: 600 }}>
                  sub-azure-enterprise
                </span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--muted-cream)' }}>Region:</span>
                <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--warm-cream)' }}>eastus</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--muted-cream)' }}>Identity:</span>
                <span style={{ color: 'var(--warm-cream)' }}>Entra ID Federated OIDC</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--muted-cream)' }}>Containment:</span>
                <span style={{ color: 'var(--warm-cream)' }}>NSG Security Rules</span>
              </div>
            </div>
          </div>

          <div style={{ marginTop: '14px' }}>
            <button
              onClick={() => handleTestConnection('AZURE')}
              disabled={testingProvider === 'AZURE'}
              style={{
                width: '100%',
                padding: '7px 12px',
                fontSize: '11px',
                fontWeight: 600,
                background: 'var(--panel-inset)',
                border: '1px solid var(--line)',
                borderRadius: 'var(--radius-xs)',
                color: '#5CA0D3',
              }}
            >
              {testingProvider === 'AZURE' ? 'Testing...' : 'Test Entra ID & NSG Probe'}
            </button>
          </div>
        </div>

        {/* Docker Lab Card */}
        <div
          className="card"
          style={{
            padding: '18px 20px',
            background: 'var(--panel)',
            border: '1px solid var(--line)',
            borderRadius: 'var(--radius-sm)',
            display: 'flex',
            flexDirection: 'column',
            justifyContent: 'space-between',
          }}
        >
          <div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '14px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <div
                  style={{
                    width: '32px',
                    height: '32px',
                    borderRadius: 'var(--radius-xs)',
                    background: 'rgba(216, 201, 167, 0.2)',
                    color: 'var(--pale-sand)',
                    border: '1px solid rgba(216, 201, 167, 0.4)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontWeight: 700,
                    fontSize: '12px',
                  }}
                >
                  LAB
                </div>
                <div>
                  <h3 style={{ margin: 0, fontSize: '14px', fontWeight: 700, color: 'var(--warm-cream)' }}>
                    Docker Hybrid Lab
                  </h3>
                  <small style={{ fontSize: '11px', color: 'var(--muted-cream)' }}>Local Gateway Cluster</small>
                </div>
              </div>
              {renderStatusBadge('CONNECTED')}
            </div>

            <div
              style={{
                background: 'var(--panel-inset)',
                border: '1px solid var(--line-subtle)',
                borderRadius: 'var(--radius-xs)',
                padding: '10px 12px',
                display: 'flex',
                flexDirection: 'column',
                gap: '6px',
                fontSize: '12px',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--muted-cream)' }}>Router API:</span>
                <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--warm-cream)', fontWeight: 600 }}>
                  10.30.10.2:8099
                </span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--muted-cream)' }}>On-Prem Subnet:</span>
                <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--warm-cream)' }}>10.10.10.0/24</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--muted-cream)' }}>Cloud Subnet:</span>
                <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--warm-cream)' }}>10.20.10.0/24</span>
              </div>
              <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                <span style={{ color: 'var(--muted-cream)' }}>Containment:</span>
                <span style={{ color: 'var(--warm-cream)' }}>iptables FORWARD / NullRoute</span>
              </div>
            </div>
          </div>

          <div style={{ marginTop: '14px' }}>
            <button
              onClick={() => handleTestConnection('DOCKER_LAB')}
              disabled={testingProvider === 'DOCKER_LAB'}
              style={{
                width: '100%',
                padding: '7px 12px',
                fontSize: '11px',
                fontWeight: 600,
                background: 'var(--panel-inset)',
                border: '1px solid var(--line)',
                borderRadius: 'var(--radius-xs)',
                color: 'var(--pale-sand)',
              }}
            >
              {testingProvider === 'DOCKER_LAB' ? 'Testing...' : 'Test Local Lab Bridge'}
            </button>
          </div>
        </div>
      </div>

      {/* AWS IAM Read-Only Setup Guide */}
      {showIamGuide && (
        <div
          className="card"
          style={{
            padding: '20px 24px',
            background: 'var(--panel-inset)',
            border: '1px solid var(--line)',
            borderRadius: 'var(--radius-sm)',
            display: 'flex',
            flexDirection: 'column',
            gap: '14px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid var(--line)', paddingBottom: '10px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <span style={{ fontSize: '15px', fontWeight: 700, color: 'var(--terracotta)' }}>
                🛡️ AWS IAM Read-Only Configuration & Telemetry Setup Guide
              </span>
              <span
                style={{
                  fontSize: '11px',
                  fontWeight: 600,
                  padding: '2px 8px',
                  borderRadius: '10px',
                  background: 'rgba(200, 117, 85, 0.2)',
                  color: 'var(--terracotta)',
                }}
              >
                Strictly Non-Mutating
              </span>
            </div>
            <button
              onClick={() => setShowIamGuide(false)}
              style={{ background: 'none', border: 'none', color: 'var(--muted-cream)', cursor: 'pointer', fontSize: '12px' }}
            >
              ✕ Close Guide
            </button>
          </div>

          <p style={{ margin: 0, fontSize: '12px', color: 'var(--muted-cream)' }}>
            The gateway connects to AWS via temporary STS credentials using an IAM Role with strictly read-only policies.
            Zero infrastructure mutations, write actions, or security group changes are permitted.
          </p>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '16px' }}>
            <div>
              <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--warm-cream)', display: 'block', marginBottom: '6px' }}>
                1. IAM Role Trust Policy (AssumeRole with ExternalId)
              </span>
              <pre
                style={{
                  margin: 0,
                  padding: '12px',
                  background: 'var(--bg)',
                  border: '1px solid var(--line)',
                  borderRadius: 'var(--radius-xs)',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '11px',
                  color: 'var(--pale-sand)',
                  overflowX: 'auto',
                }}
              >
{`{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::698766075180:root" },
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": { "sts:ExternalId": "AdaptiveGatewayAuth" }
      }
    }
  ]
}`}
              </pre>
            </div>

            <div>
              <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--warm-cream)', display: 'block', marginBottom: '6px' }}>
                2. Read-Only Policy Permissions
              </span>
              <pre
                style={{
                  margin: 0,
                  padding: '12px',
                  background: 'var(--bg)',
                  border: '1px solid var(--line)',
                  borderRadius: 'var(--radius-xs)',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '11px',
                  color: 'var(--olive-green)',
                  overflowX: 'auto',
                }}
              >
{`{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Ec2AndCloudWatchReadOnly",
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeVpcs",
        "ec2:DescribeSubnets",
        "ec2:DescribeRouteTables",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeNetworkAcls",
        "ec2:DescribeFlowLogs",
        "logs:DescribeLogGroups",
        "logs:FilterLogEvents"
      ],
      "Resource": "*"
    }
  ]
}`}
              </pre>
            </div>
          </div>
        </div>
      )}

      {/* Test Connection Output Diagnostic Box */}
      {testResult && (
        <div
          className="card"
          style={{
            padding: '16px 20px',
            background: 'var(--panel-inset)',
            border: '1px solid var(--line)',
            borderRadius: 'var(--radius-sm)',
            fontFamily: 'var(--font-mono)',
            fontSize: '12px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid var(--line)', paddingBottom: '8px', marginBottom: '10px' }}>
            <span style={{ fontWeight: 600, color: 'var(--olive-green)' }}>
              Provider Connection Diagnostic Result: {testResult.provider}
            </span>
            <button
              onClick={() => setTestResult(null)}
              style={{ background: 'none', border: 'none', color: 'var(--muted-cream)', cursor: 'pointer', fontSize: '12px' }}
            >
              ✕ Close
            </button>
          </div>
          <pre style={{ margin: 0, overflowX: 'auto', color: 'var(--warm-cream)', fontSize: '11px' }}>
            {JSON.stringify(testResult, null, 2)}
          </pre>
        </div>
      )}

      {/* Dedicated AWS VPC Flow Logs Telemetry Pipeline & Diagnostics Panel */}
      <div
        className="card"
        style={{
          padding: '22px 24px',
          background: 'var(--panel)',
          border: '1px solid var(--line)',
          borderRadius: 'var(--radius-sm)',
          display: 'flex',
          flexDirection: 'column',
          gap: '18px',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px', borderBottom: '1px solid var(--line)', paddingBottom: '14px' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
              <span
                style={{
                  padding: '2px 8px',
                  borderRadius: 'var(--radius-xs)',
                  background: 'rgba(200, 117, 85, 0.2)',
                  color: 'var(--terracotta)',
                  fontWeight: 700,
                  fontSize: '11px',
                }}
              >
                AWS TELEMETRY
              </span>
              <h2 style={{ margin: 0, fontSize: '16px', fontWeight: 700, color: 'var(--warm-cream)' }}>
                AWS VPC Flow Logs Telemetry Pipeline
              </h2>
              <span
                style={{
                  padding: '2px 8px',
                  borderRadius: '12px',
                  fontSize: '11px',
                  fontWeight: 600,
                  background: telemetryMode === 'LIVE' ? 'rgba(133, 139, 89, 0.16)' : 'rgba(216, 201, 167, 0.15)',
                  color: telemetryMode === 'LIVE' ? 'var(--olive-green)' : 'var(--pale-sand)',
                  border: telemetryMode === 'LIVE' ? '1px solid rgba(133, 139, 89, 0.35)' : '1px solid rgba(216, 201, 167, 0.35)',
                }}
              >
                {telemetryMode === 'LIVE' ? 'LIVE AWS TELEMETRY' : 'SANDBOX / FIXTURE MODE'}
              </span>
              <span
                style={{
                  padding: '2px 8px',
                  borderRadius: 'var(--radius-xs)',
                  fontSize: '11px',
                  fontFamily: 'var(--font-mono)',
                  background: 'var(--panel-inset)',
                  color: 'var(--muted-cream)',
                }}
              >
                XGBoost V2 (9 Features)
              </span>
            </div>
            <p style={{ margin: '4px 0 0', fontSize: '12px', color: 'var(--muted-cream)' }}>
              CloudWatch Logs & S3 VPC Flow Logs ingestion with incremental checkpoints, streaming decompression, and deduplication.
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
            <button
              onClick={() => handlePollAwsTelemetry(false)}
              disabled={isPollingAws}
              style={{
                padding: '6px 14px',
                background: 'rgba(133, 139, 89, 0.25)',
                color: 'var(--olive-green)',
                border: '1px solid rgba(133, 139, 89, 0.5)',
                borderRadius: 'var(--radius-xs)',
                fontWeight: 600,
                fontSize: '11px',
                cursor: isPollingAws ? 'not-allowed' : 'pointer',
              }}
            >
              {isPollingAws && telemetryMode === 'LIVE' ? 'Polling AWS Logs...' : '⚡ Poll Live AWS Logs'}
            </button>
            <button
              onClick={() => handlePollAwsTelemetry(true)}
              disabled={isPollingAws}
              style={{
                padding: '6px 14px',
                background: 'rgba(200, 117, 85, 0.2)',
                color: 'var(--terracotta)',
                border: '1px solid rgba(200, 117, 85, 0.4)',
                borderRadius: 'var(--radius-xs)',
                fontWeight: 600,
                fontSize: '11px',
                cursor: isPollingAws ? 'not-allowed' : 'pointer',
              }}
            >
              {isPollingAws && telemetryMode === 'SANDBOX' ? 'Running Sandbox...' : '🧪 Poll Sandbox Fixture'}
            </button>
            <button
              onClick={handleLoadTelemetryStatus}
              style={{
                padding: '6px 10px',
                background: 'var(--panel-inset)',
                color: 'var(--warm-cream)',
                border: '1px solid var(--line)',
                borderRadius: 'var(--radius-xs)',
                fontSize: '11px',
                cursor: 'pointer',
              }}
            >
              ↻ Refresh
            </button>
            <button
              onClick={() => setShowTelemetryHistory(!showTelemetryHistory)}
              style={{
                padding: '6px 10px',
                background: 'var(--panel-inset)',
                color: 'var(--warm-cream)',
                border: '1px solid var(--line)',
                borderRadius: 'var(--radius-xs)',
                fontSize: '11px',
                cursor: 'pointer',
              }}
            >
              {showTelemetryHistory ? 'Hide History' : `History (${awsTelemetryHistory.length})`}
            </button>
            <button
              onClick={handleResetCheckpoint}
              disabled={isResettingCheckpoint}
              style={{
                padding: '6px 10px',
                background: 'rgba(184, 92, 84, 0.16)',
                color: 'var(--muted-red)',
                border: '1px solid rgba(184, 92, 84, 0.4)',
                borderRadius: 'var(--radius-xs)',
                fontSize: '11px',
                cursor: isResettingCheckpoint ? 'not-allowed' : 'pointer',
              }}
              title="Reset CloudWatch / S3 checkpoints and deduplication cache"
            >
              {isResettingCheckpoint ? 'Resetting...' : 'Reset Checkpoints'}
            </button>
          </div>
        </div>

        {/* Operational Ingestion Metrics KPI Bar */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '12px' }}>
          <div
            className="card"
            style={{
              padding: '12px 14px',
              background: 'var(--panel-inset)',
              border: '1px solid var(--line)',
              borderRadius: 'var(--radius-xs)',
            }}
          >
            <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Discovered Records</span>
            <b style={{ fontSize: '18px', display: 'block', color: 'var(--warm-cream)', marginTop: '4px', fontFamily: 'var(--font-mono)' }}>
              {activeDiscovered}
            </b>
            <small style={{ fontSize: '10px', color: 'var(--muted-cream)' }}>
              {awsTelemetryStats.total > 0 ? 'Active Session Poll' : 'Latest Ingestion Run'}
            </small>
          </div>

          <div
            className="card"
            style={{
              padding: '12px 14px',
              background: 'var(--panel-inset)',
              border: '1px solid var(--line)',
              borderRadius: 'var(--radius-xs)',
            }}
          >
            <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Ingested & Evaluated</span>
            <b style={{ fontSize: '18px', display: 'block', color: 'var(--olive-green)', marginTop: '4px', fontFamily: 'var(--font-mono)' }}>
              {activeEvaluated}
            </b>
            <small style={{ fontSize: '10px', color: 'var(--muted-cream)' }}>
              {awsTelemetryStats.total > 0 ? 'Evaluated with XGBoost V2' : 'Latest Ingestion Run'}
            </small>
          </div>

          <div
            className="card"
            style={{
              padding: '12px 14px',
              background: 'var(--panel-inset)',
              border: '1px solid var(--line)',
              borderRadius: 'var(--radius-xs)',
            }}
          >
            <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Cumulative Checkpoint</span>
            <b style={{ fontSize: '18px', display: 'block', color: 'var(--sky-blue)', marginTop: '4px', fontFamily: 'var(--font-mono)' }}>
              {cumulativeProcessed}
            </b>
            <small style={{ fontSize: '10px', color: 'var(--muted-cream)' }}>Persistent Stream Total</small>
          </div>

          <div
            className="card"
            style={{
              padding: '12px 14px',
              background: 'var(--panel-inset)',
              border: '1px solid var(--line)',
              borderRadius: 'var(--radius-xs)',
            }}
          >
            <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Duplicates Skipped</span>
            <b style={{ fontSize: '18px', display: 'block', color: 'var(--pale-sand)', marginTop: '4px', fontFamily: 'var(--font-mono)' }}>
              {latestDuplicates}
            </b>
            <small style={{ fontSize: '10px', color: 'var(--muted-cream)' }}>DeduplicationCache (SHA-256)</small>
          </div>

          <div
            className="card"
            style={{
              padding: '12px 14px',
              background: 'var(--panel-inset)',
              border: '1px solid var(--line)',
              borderRadius: 'var(--radius-xs)',
            }}
          >
            <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Invalid / Truncated</span>
            <b style={{ fontSize: '18px', display: 'block', color: 'var(--muted-cream)', marginTop: '4px', fontFamily: 'var(--font-mono)' }}>
              {totalInvalid}
            </b>
            <small style={{ fontSize: '10px', color: 'var(--muted-cream)' }}>NODATA or malformed</small>
          </div>

          <div
            className="card"
            style={{
              padding: '12px 14px',
              background: 'var(--panel-inset)',
              border: '1px solid var(--line)',
              borderRadius: 'var(--radius-xs)',
            }}
          >
            <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>High-Risk Threats</span>
            <b
              style={{
                fontSize: '18px',
                display: 'block',
                color: activeThreats > 0 ? 'var(--terracotta)' : 'var(--olive-green)',
                marginTop: '4px',
                fontFamily: 'var(--font-mono)',
              }}
            >
              {activeThreats}
            </b>
            <small style={{ fontSize: '10px', color: 'var(--muted-cream)' }}>Risk Score ≥ 70 / 100</small>
          </div>

          <div
            className="card"
            style={{
              padding: '12px 14px',
              background: 'var(--panel-inset)',
              border: '1px solid var(--line)',
              borderRadius: 'var(--radius-xs)',
            }}
          >
            <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Ingestion Health</span>
            <b style={{ fontSize: '14px', display: 'block', color: 'var(--olive-green)', marginTop: '4px' }}>
              {telemetryStatusInfo?.metrics?.status || 'HEALTHY (Ready)'}
            </b>
            <small style={{ fontSize: '10px', color: 'var(--muted-cream)' }}>PostgreSQL Checkpoint</small>
          </div>
        </div>

        {/* Collapsible Telemetry History Table */}
        {showTelemetryHistory && (
          <div
            style={{
              border: '1px solid var(--line)',
              borderRadius: 'var(--radius-xs)',
              overflow: 'hidden',
              background: 'var(--panel-inset)',
            }}
          >
            <div style={{ padding: '10px 14px', background: 'var(--panel-secondary)', borderBottom: '1px solid var(--line)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--warm-cream)' }}>
                Persistent Ingestion Run Audit Logs (PostgreSQL)
              </span>
              <button
                onClick={handleLoadTelemetryHistory}
                style={{ background: 'none', border: 'none', color: 'var(--terracotta)', fontSize: '11px', cursor: 'pointer' }}
              >
                ↻ Refresh Audit History
              </button>
            </div>
            <div className="table-wrapper" style={{ maxHeight: '240px', overflowY: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '11px', textAlign: 'left' }}>
                <thead style={{ background: 'var(--panel-inset)', color: 'var(--muted-cream)', borderBottom: '1px solid var(--line)' }}>
                  <tr>
                    <th style={{ padding: '8px 12px' }}>Run ID</th>
                    <th style={{ padding: '8px 12px' }}>Source Type</th>
                    <th style={{ padding: '8px 12px' }}>Discovered</th>
                    <th style={{ padding: '8px 12px' }}>Ingested</th>
                    <th style={{ padding: '8px 12px' }}>Duplicates</th>
                    <th style={{ padding: '8px 12px' }}>Threats</th>
                    <th style={{ padding: '8px 12px' }}>Status</th>
                    <th style={{ padding: '8px 12px' }}>Ingested At</th>
                  </tr>
                </thead>
                <tbody style={{ fontFamily: 'var(--font-mono)' }}>
                  {awsTelemetryHistory.length === 0 ? (
                    <tr>
                      <td colSpan={8} style={{ padding: '16px', textAlign: 'center', color: 'var(--muted-cream)', fontFamily: 'var(--font-sans)' }}>
                        No previous ingestion runs recorded in PostgreSQL yet.
                      </td>
                    </tr>
                  ) : (
                    awsTelemetryHistory.map((item, idx) => (
                      <tr key={idx} style={{ borderBottom: '1px solid var(--line-subtle)' }}>
                        <td style={{ padding: '8px 12px', color: 'var(--warm-cream)' }}>{item.id}</td>
                        <td style={{ padding: '8px 12px' }}>{item.source_type}</td>
                        <td style={{ padding: '8px 12px' }}>{item.records_discovered}</td>
                        <td style={{ padding: '8px 12px' }}>{item.records_ingested}</td>
                        <td style={{ padding: '8px 12px' }}>{item.records_duplicate_skipped}</td>
                        <td style={{ padding: '8px 12px', color: item.high_risk_detected > 0 ? 'var(--terracotta)' : 'var(--olive-green)', fontWeight: 600 }}>
                          {item.high_risk_detected}
                        </td>
                        <td style={{ padding: '8px 12px' }}>
                          <span style={{ padding: '2px 6px', borderRadius: '4px', background: 'rgba(133, 139, 89, 0.2)', color: 'var(--olive-green)' }}>
                            {item.status}
                          </span>
                        </td>
                        <td style={{ padding: '8px 12px', fontFamily: 'var(--font-sans)', color: 'var(--muted-cream)' }}>
                          {item.ingested_at || '—'}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>

      {/* Network Resource Inventory Table */}
      <div
        className="card"
        style={{
          background: 'var(--panel)',
          border: '1px solid var(--line)',
          borderRadius: 'var(--radius-sm)',
          overflow: 'hidden',
        }}
      >
        <div style={{ padding: '16px 20px', borderBottom: '1px solid var(--line)', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px' }}>
          <div>
            <h2 style={{ margin: 0, fontSize: '16px', fontWeight: 700, color: 'var(--warm-cream)', fontFamily: 'var(--font-heading)' }}>
              Multi-Cloud Network Resource Inventory
            </h2>
            <p style={{ margin: '4px 0 0', fontSize: '12px', color: 'var(--muted-cream)' }}>
              Discovered Virtual Private Clouds, Subnetworks, Gateways, Route Tables, and Firewall Security Policies.
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexWrap: 'wrap' }}>
            {summary && (
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                <span style={{ padding: '3px 8px', borderRadius: 'var(--radius-xs)', background: 'var(--panel-inset)', color: 'var(--warm-cream)', fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
                  {summary.total_vpcs} VPCs
                </span>
                <span style={{ padding: '3px 8px', borderRadius: 'var(--radius-xs)', background: 'var(--panel-inset)', color: 'var(--warm-cream)', fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
                  {summary.total_subnets} Subnets
                </span>
                <span style={{ padding: '3px 8px', borderRadius: 'var(--radius-xs)', background: 'var(--panel-inset)', color: 'var(--warm-cream)', fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
                  {summary.total_security_groups} SGs
                </span>
                <span style={{ padding: '3px 8px', borderRadius: 'var(--radius-xs)', background: 'var(--panel-inset)', color: 'var(--warm-cream)', fontSize: '11px', fontFamily: 'var(--font-mono)' }}>
                  {summary.total_gateways} Gateways
                </span>
              </div>
            )}

            {/* Provider Filter */}
            <select
              value={resourceFilter}
              onChange={(e) => setResourceFilter(e.target.value)}
              style={{
                background: 'var(--panel-inset)',
                color: 'var(--warm-cream)',
                border: '1px solid var(--line)',
                padding: '4px 8px',
                borderRadius: 'var(--radius-xs)',
                fontSize: '11px',
              }}
            >
              <option value="ALL">All Providers ({resources.length})</option>
              <option value="AWS">AWS ({resources.filter((r) => r.provider === 'AWS').length})</option>
              <option value="GCP">GCP ({resources.filter((r) => r.provider === 'GCP').length})</option>
              <option value="AZURE">Azure ({resources.filter((r) => r.provider === 'AZURE').length})</option>
              <option value="DOCKER_LAB">Docker Lab ({resources.filter((r) => r.provider === 'DOCKER_LAB').length})</option>
            </select>

            {/* Type Filter */}
            <select
              value={typeFilter}
              onChange={(e) => setTypeFilter(e.target.value)}
              style={{
                background: 'var(--panel-inset)',
                color: 'var(--warm-cream)',
                border: '1px solid var(--line)',
                padding: '4px 8px',
                borderRadius: 'var(--radius-xs)',
                fontSize: '11px',
              }}
            >
              <option value="ALL">All Resource Types</option>
              {uniqueResourceTypes.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
          </div>
        </div>

        <div className="table-wrapper" style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '12px' }}>
            <thead style={{ background: 'var(--panel-inset)', color: 'var(--muted-cream)', borderBottom: '1px solid var(--line)' }}>
              <tr>
                <th style={{ padding: '10px 14px' }}>Provider</th>
                <th style={{ padding: '10px 14px' }}>Resource Type</th>
                <th style={{ padding: '10px 14px' }}>Name / Identifier</th>
                <th style={{ padding: '10px 14px' }}>Parent / VPC Reference</th>
                <th style={{ padding: '10px 14px' }}>CIDR Block</th>
                <th style={{ padding: '10px 14px' }}>Region / Zone</th>
                <th style={{ padding: '10px 14px' }}>Provenance</th>
                <th style={{ padding: '10px 14px' }}>Status</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={8} style={{ padding: '36px', textAlign: 'center', color: 'var(--muted-cream)' }}>
                    <div style={{ display: 'inline-flex', alignItems: 'center', gap: '10px' }}>
                      <span
                        style={{
                          display: 'inline-block',
                          width: '14px',
                          height: '14px',
                          border: '2px solid var(--olive-green)',
                          borderTopColor: 'transparent',
                          borderRadius: '50%',
                          animation: 'spin 1s linear infinite',
                        }}
                      />
                      <span>Loading Multi-Cloud Infrastructure Topology...</span>
                    </div>
                  </td>
                </tr>
              ) : filteredResources.length === 0 ? (
                <tr>
                  <td colSpan={8} style={{ padding: '24px', textAlign: 'center', color: 'var(--muted-cream)' }}>
                    No resources match the selected filter.
                  </td>
                </tr>
              ) : (
                filteredResources.map((r, i) => {
                  const isAws = r.provider === 'AWS'
                  const isGcp = r.provider === 'GCP'
                  const isLab = r.provider === 'DOCKER_LAB'
                  const provBg = isAws
                    ? 'rgba(200, 117, 85, 0.2)'
                    : isGcp
                    ? 'rgba(133, 139, 89, 0.2)'
                    : isLab
                    ? 'rgba(216, 201, 167, 0.2)'
                    : 'rgba(92, 160, 211, 0.2)'
                  const provColor = isAws
                    ? 'var(--terracotta)'
                    : isGcp
                    ? 'var(--olive-green)'
                    : isLab
                    ? 'var(--pale-sand)'
                    : '#5CA0D3'

                  return (
                    <tr
                      key={r.id || `${r.provider}-${r.resource_id}-${i}`}
                      style={{
                        borderBottom: '1px solid var(--line-subtle)',
                        background: i % 2 === 0 ? 'transparent' : 'rgba(255, 255, 255, 0.015)',
                      }}
                    >
                      <td style={{ padding: '10px 14px' }}>
                        <span
                          style={{
                            padding: '3px 8px',
                            borderRadius: '4px',
                            background: provBg,
                            color: provColor,
                            fontWeight: 700,
                            fontSize: '11px',
                            fontFamily: 'var(--font-mono)',
                          }}
                        >
                          {r.provider}
                        </span>
                      </td>
                      <td style={{ padding: '10px 14px' }}>
                        <span
                          style={{
                            padding: '2px 6px',
                            borderRadius: '3px',
                            fontFamily: 'var(--font-mono)',
                            fontSize: '11px',
                            background: 'var(--panel-inset)',
                            color: 'var(--warm-cream)',
                            border: '1px solid var(--line-subtle)',
                          }}
                        >
                          {r.resource_type}
                        </span>
                      </td>
                      <td style={{ padding: '10px 14px' }}>
                        <b style={{ color: 'var(--warm-cream)', display: 'block', fontSize: '12px' }}>
                          {r.name || r.resource_id}
                        </b>
                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: '10px', color: 'var(--muted-cream)' }}>
                          {r.resource_id}
                        </span>
                      </td>
                      <td style={{ padding: '10px 14px', fontFamily: 'var(--font-mono)', color: 'var(--muted-cream)' }}>
                        {r.vpc_id || r.parent_resource_id || '—'}
                      </td>
                      <td style={{ padding: '10px 14px', fontFamily: 'var(--font-mono)', color: 'var(--warm-cream)' }}>
                        {r.cidr_block || '—'}
                      </td>
                      <td style={{ padding: '10px 14px', fontFamily: 'var(--font-mono)', color: 'var(--muted-cream)' }}>
                        {r.zone || r.region || 'global'}
                      </td>
                      <td style={{ padding: '10px 14px' }}>
                        <span
                          style={{
                            padding: '2px 8px',
                            borderRadius: '10px',
                            fontSize: '10px',
                            fontWeight: 600,
                            fontFamily: 'var(--font-mono)',
                            background: isAws ? 'rgba(133, 139, 89, 0.16)' : 'rgba(216, 201, 167, 0.15)',
                            color: isAws ? 'var(--olive-green)' : 'var(--pale-sand)',
                            border: isAws ? '1px solid rgba(133, 139, 89, 0.3)' : '1px solid rgba(216, 201, 167, 0.3)',
                          }}
                        >
                          {isAws && awsCallerIdentity?.status === 'CONNECTED'
                            ? 'LIVE DISCOVERED'
                            : isLab
                            ? 'SIMULATED LAB'
                            : 'PERSISTED CACHE'}
                        </span>
                      </td>
                      <td style={{ padding: '10px 14px' }}>
                        {renderStatusBadge(r.state || 'AVAILABLE')}
                      </td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Canonical Telemetry Ingestion Console */}
      <div
        className="card"
        style={{
          padding: '22px 24px',
          background: 'var(--panel)',
          border: '1px solid var(--line)',
          borderRadius: 'var(--radius-sm)',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '12px', marginBottom: '16px' }}>
          <div>
            <h2 style={{ margin: 0, fontSize: '16px', fontWeight: 700, color: 'var(--warm-cream)', fontFamily: 'var(--font-heading)' }}>
              Live Multi-Cloud Telemetry Ingestion & XGBoost V2 Evaluation
            </h2>
            <p style={{ margin: '4px 0 0', fontSize: '12px', color: 'var(--muted-cream)' }}>
              Test canonical feature normalization and ML threat inference across AWS, GCP, Azure, and Docker Lab.
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', background: 'var(--panel-inset)', padding: '4px', borderRadius: 'var(--radius-xs)', border: '1px solid var(--line)' }}>
            {(['AWS', 'GCP', 'AZURE', 'DOCKER_LAB'] as const).map((prov) => (
              <button
                key={prov}
                onClick={() => handleSampleSelect(prov)}
                style={{
                  padding: '4px 10px',
                  borderRadius: 'var(--radius-xs)',
                  fontSize: '11px',
                  fontWeight: 600,
                  border: 'none',
                  background: selectedProvider === prov ? 'var(--terracotta)' : 'transparent',
                  color: selectedProvider === prov ? '#fff' : 'var(--muted-cream)',
                  cursor: 'pointer',
                }}
              >
                {prov}
              </button>
            ))}
          </div>
        </div>

        <form onSubmit={handleIngestSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
          <div>
            <label style={{ display: 'block', fontSize: '12px', fontWeight: 600, color: 'var(--warm-cream)', marginBottom: '6px' }}>
              Raw {selectedProvider} Telemetry Log Record:
            </label>
            <textarea
              value={rawTelemetryInput}
              onChange={(e) => setRawTelemetryInput(e.target.value)}
              rows={4}
              style={{
                width: '100%',
                boxSizing: 'border-box',
                fontFamily: 'var(--font-mono)',
                fontSize: '12px',
                padding: '12px',
                borderRadius: 'var(--radius-xs)',
                background: 'var(--panel-inset)',
                border: '1px solid var(--line)',
                color: 'var(--warm-cream)',
                outline: 'none',
              }}
            />
          </div>

          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '10px' }}>
            <span style={{ fontSize: '11px', color: 'var(--muted-cream)' }}>
              Evaluated strictly via canonical 9-feature schema without synthetic failed_auth_count.
            </span>
            <button
              type="submit"
              disabled={ingestLoading}
              className="primary"
              style={{
                padding: '8px 18px',
                fontSize: '12px',
                fontWeight: 600,
                cursor: ingestLoading ? 'not-allowed' : 'pointer',
                opacity: ingestLoading ? 0.6 : 1,
              }}
            >
              {ingestLoading ? 'Normalizing & Evaluating...' : 'Normalize & Evaluate Threat'}
            </button>
          </div>
        </form>

        {/* Telemetry Evaluation Result */}
        {ingestResponse && (
          <div
            style={{
              marginTop: '20px',
              padding: '16px 20px',
              borderRadius: 'var(--radius-xs)',
              background: 'var(--panel-inset)',
              border: '1px solid var(--line)',
              display: 'flex',
              flexDirection: 'column',
              gap: '12px',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid var(--line)', paddingBottom: '10px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <span style={{ fontSize: '13px', fontWeight: 700, color: 'var(--warm-cream)' }}>
                  Ingestion Evaluation Result ({ingestResponse.provider})
                </span>
                <span style={{ padding: '2px 8px', borderRadius: '10px', fontSize: '11px', background: 'rgba(133, 139, 89, 0.2)', color: 'var(--olive-green)', fontWeight: 600 }}>
                  {ingestResponse.status}
                </span>
              </div>
              <div style={{ fontSize: '11px', color: 'var(--muted-cream)', fontFamily: 'var(--font-mono)' }}>
                Parsing: {ingestResponse.parsing_duration_ms}ms | Inference: {ingestResponse.inference_duration_ms}ms
              </div>
            </div>

            {ingestResponse.flows.map((flow, idx) => (
              <div
                key={idx}
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
                  gap: '12px',
                  padding: '12px 14px',
                  background: 'var(--panel)',
                  border: '1px solid var(--line)',
                  borderRadius: 'var(--radius-xs)',
                  fontSize: '12px',
                }}
              >
                <div>
                  <span style={{ color: 'var(--muted-cream)', display: 'block', fontSize: '11px' }}>Traffic Session:</span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600, color: 'var(--warm-cream)' }}>
                    {flow.src_ip} → {flow.dst_ip}:{flow.dst_port}
                  </span>
                </div>
                <div>
                  <span style={{ color: 'var(--muted-cream)', display: 'block', fontSize: '11px' }}>Threat Classification:</span>
                  <span style={{ fontWeight: 600, color: flow.threat_level === 'BENIGN' ? 'var(--olive-green)' : 'var(--terracotta)' }}>
                    {flow.attack_type} ({flow.threat_level})
                  </span>
                </div>
                <div>
                  <span style={{ color: 'var(--muted-cream)', display: 'block', fontSize: '11px' }}>Risk Score:</span>
                  <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: flow.risk_score >= 70 ? 'var(--terracotta)' : 'var(--olive-green)' }}>
                    {flow.risk_score.toFixed(1)} / 100
                  </span>
                </div>
                <div>
                  <span style={{ color: 'var(--muted-cream)', display: 'block', fontSize: '11px' }}>Policy Action:</span>
                  <span
                    style={{
                      fontWeight: 600,
                      color: flow.policy_action === 'DROP' || flow.policy_action === 'BLOCK' ? 'var(--muted-red)' : 'var(--olive-green)',
                    }}
                  >
                    {flow.policy_action}
                  </span>
                </div>
              </div>
            ))}

            <div style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--muted-cream)', paddingTop: '6px', display: 'flex', flexWrap: 'wrap', gap: '8px' }}>
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
