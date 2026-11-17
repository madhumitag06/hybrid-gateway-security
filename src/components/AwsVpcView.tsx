/**
 * AWS VPC Flow Logs Console
 * ==========================
 * Dual-mode inspection and evaluation view for AWS VPC Flow Log records (Format v2):
 * 1. Live AWS Read-Only (Amazon CloudWatch Logs in ap-southeast-2, Account 698766075180)
 * 2. Pre-configured deterministic benchmark fixtures & raw log input
 *
 * Normalizes all flows to the canonical 9-feature schema and evaluates threats
 * using the authoritative Big Data XGBoost V2 model.
 */

import React, { useEffect, useState, useCallback } from 'react'
import {
  getAwsVpcSamples,
  ingestAwsVpcSample,
  ingestRawVpcLogs,
} from '../services/hybrid'
import { cloudService } from '../services/cloud'
import type { CloudTelemetryBatchResponse } from '../services/cloud'
import type { AwsVpcIngestionResponse, AwsVpcSampleFixtureInfo } from '../types'

export type AwsVpcViewMode = 'LIVE_AWS' | 'FIXTURES' | 'RAW'

interface AwsVpcViewProps {
  currentEnv?: string
  onSelectEnv?: (env: 'SANDBOX' | 'LOCAL' | 'AWS_FIXTURE' | 'LIVE_AWS') => void
  onTelemetryIngested?: (batch: CloudTelemetryBatchResponse) => void
}

export const AwsVpcView: React.FC<AwsVpcViewProps> = ({ currentEnv, onSelectEnv, onTelemetryIngested }) => {
  // Mode selection: derive based on currentEnv or explicit user selection
  const [userTabOverride, setUserTabOverride] = useState<AwsVpcViewMode | null>(null)
  const activeTab: AwsVpcViewMode = userTabOverride ?? (currentEnv === 'LIVE_AWS' ? 'LIVE_AWS' : 'FIXTURES')
  const setActiveTab = (tab: AwsVpcViewMode) => setUserTabOverride(tab)

  // Toast notifications
  const [toast, setToast] = useState<string | null>(null)

  // -------------------------------------------------------------
  // Offline Fixtures & Raw Log State
  // -------------------------------------------------------------
  const [samples, setSamples] = useState<AwsVpcSampleFixtureInfo[]>([])
  const [loadingSamples, setLoadingSamples] = useState(true)
  const [ingestingFixture, setIngestingFixture] = useState(false)
  const [activeSampleId, setActiveSampleId] = useState<string | null>(null)
  const [fixtureResponse, setFixtureResponse] = useState<AwsVpcIngestionResponse | null>(null)
  const [rawVpcText, setRawVpcText] = useState('')

  // -------------------------------------------------------------
  // Live AWS CloudWatch Telemetry State
  // -------------------------------------------------------------
  const [logGroup, setLogGroup] = useState('/aws/vpc/flowlogs/ap-southeast-2-default')
  const [polling, setPolling] = useState(false)
  const [telemetryStatus, setTelemetryStatus] = useState<
    | 'NOT_CONFIGURED'
    | 'CONNECTING'
    | 'CONNECTED'
    | 'POLLING'
    | 'EVENTS_RETRIEVED'
    | 'NO_NEW_EVENTS'
    | 'INGESTION_FAILED'
    | 'PARSE_FAILED'
    | 'DISCONNECTED'
  >('CONNECTING')
  const [telemetryBatch, setTelemetryBatch] = useState<CloudTelemetryBatchResponse | null>(null)
  const [telemetryStats, setTelemetryStats] = useState<any>(null)
  const [historyRuns, setHistoryRuns] = useState<any[]>([])
  const [pollLimit, setPollLimit] = useState(100)
  const [lastPollingError, setLastPollingError] = useState<string | null>(null)

  // Load sample fixtures
  useEffect(() => {
    let mounted = true
    getAwsVpcSamples()
      .then((data) => {
        if (mounted) {
          setSamples(data)
          setLoadingSamples(false)
        }
      })
      .catch((err) => {
        console.error('Failed to load AWS VPC samples:', err)
        if (mounted) setLoadingSamples(false)
      })
    return () => {
      mounted = false
    }
  }, [])

  // Load live telemetry status & history on mount or when switching to LIVE_AWS
  const refreshLiveTelemetryStatus = useCallback(async () => {
    try {
      const [statusRes, historyRes] = await Promise.all([
        cloudService.getAwsTelemetryStatus().catch((e: any) => ({ error: e?.message || String(e) })),
        cloudService.getAwsTelemetryHistory(10).catch(() => []),
      ])
      if (statusRes && !statusRes.error) {
        setTelemetryStats(statusRes)
        setTelemetryStatus((prev) => (prev === 'EVENTS_RETRIEVED' ? 'EVENTS_RETRIEVED' : 'CONNECTED'))
        setLastPollingError(null)
      } else if (statusRes && statusRes.error) {
        setTelemetryStats(null)
        setTelemetryStatus('INGESTION_FAILED')
        setLastPollingError(statusRes.error)
      }
      if (Array.isArray(historyRes)) {
        setHistoryRuns(historyRes)
      }
    } catch (err: any) {
      setTelemetryStats(null)
      setTelemetryStatus('INGESTION_FAILED')
      setLastPollingError(err.message || String(err))
    }
  }, [])

  useEffect(() => {
    if (activeTab === 'LIVE_AWS') {
      let mounted = true
      Promise.all([
        cloudService.getAwsTelemetryStatus().catch((e: any) => ({ error: e?.message || String(e) })),
        cloudService.getAwsTelemetryHistory(10).catch(() => []),
      ])
        .then(([statusRes, historyRes]) => {
          if (!mounted) return
          if (statusRes && !statusRes.error) {
            setTelemetryStats(statusRes)
            setTelemetryStatus((prev) => (prev === 'EVENTS_RETRIEVED' ? 'EVENTS_RETRIEVED' : 'CONNECTED'))
            setLastPollingError(null)
          } else if (statusRes && statusRes.error) {
            setTelemetryStats(null)
            setTelemetryStatus('INGESTION_FAILED')
            setLastPollingError(statusRes.error)
          }
          if (Array.isArray(historyRes)) {
            setHistoryRuns(historyRes)
          }
        })
        .catch((err: any) => {
          if (!mounted) return
          setTelemetryStats(null)
          setTelemetryStatus('INGESTION_FAILED')
          setLastPollingError(err.message || String(err))
        })
      return () => {
        mounted = false
      }
    }
  }, [activeTab])

  // Handle Poll CloudWatch Logs
  const handlePollCloudWatch = async () => {
    setPolling(true)
    setTelemetryStatus('POLLING')
    setToast(`Polling CloudWatch Logs group '${logGroup}' in ap-southeast-2...`)
    try {
      const res = await cloudService.pollAwsTelemetry({
        limit: pollLimit,
        log_group: logGroup.trim(),
        mock_fallback: false,
      })

      if (res.status === 'ERROR' || res.status === 'FAILED' || res.error_message) {
        setTelemetryStatus('INGESTION_FAILED')
        const msg = res.error_message || res.message || 'AWS CloudWatch polling failed.'
        setLastPollingError(msg)
        setToast(`CloudWatch poll notice: ${msg}`)
      } else if (res.records_received === 0 || res.status === 'NO_NEW_EVENTS') {
        setTelemetryStatus('NO_NEW_EVENTS')
        setLastPollingError(null)
        setToast(res.message || 'CloudWatch poll complete: No new flow events detected in selected log window.')
      } else if (res.status === 'PARSE_FAILED') {
        setTelemetryStatus('PARSE_FAILED')
        setToast('CloudWatch poll warning: Unable to parse incoming flow records.')
      } else {
        setTelemetryStatus('EVENTS_RETRIEVED')
        setTelemetryBatch(res)
        setLastPollingError(null)
        setToast(
          `Successfully ingested ${res.records_parsed} VPC flow records into ${res.records_aggregated} flows (${res.high_risk_flows_detected} high risk) with XGBoost V2.`
        )

        // Automatic dashboard synchronization notification on genuine newly ingested flows
        if (res.records_aggregated > 0 || res.records_parsed > 0) {
          onTelemetryIngested?.(res)
          window.dispatchEvent(
            new CustomEvent('hgs:telemetry-ingested', {
              detail: {
                provider: 'AWS',
                records_received: res.records_received,
                records_parsed: res.records_parsed,
                records_aggregated: res.records_aggregated,
                high_risk_detected: res.high_risk_flows_detected,
                status: res.status,
                timestamp: Date.now(),
              },
            })
          )
        }
      }
      await refreshLiveTelemetryStatus()
    } catch (err: any) {
      const errMsg = err.message || String(err)
      if (errMsg.toLowerCase().includes('parse') || errMsg.toLowerCase().includes('format') || errMsg.toLowerCase().includes('token')) {
        setTelemetryStatus('PARSE_FAILED')
      } else {
        setTelemetryStatus('INGESTION_FAILED')
      }
      setLastPollingError(errMsg)
      setToast(`CloudWatch poll error: ${errMsg}`)
    } finally {
      setPolling(false)
    }
  }

  // Handle Reset Checkpoint
  const handleResetCheckpoint = async () => {
    try {
      await cloudService.resetAwsTelemetryCheckpoint()
      setToast('CloudWatch telemetry checkpoints and deduplication cache reset.')
      await refreshLiveTelemetryStatus()
    } catch (err: any) {
      setToast(`Reset checkpoint error: ${err.message || String(err)}`)
    }
  }

  // Handle Ingest Sample Fixture
  const handleIngestSample = async (sampleId: string) => {
    setActiveSampleId(sampleId)
    setIngestingFixture(true)
    setToast(`Ingesting benchmark AWS VPC flow fixture '${sampleId}'...`)
    try {
      const res = await ingestAwsVpcSample(sampleId, true)
      setFixtureResponse(res)
      setToast(
        `Successfully evaluated ${res.total_flows_aggregated} flows (${res.high_risk_flows_count} high risk) from '${sampleId}'.`
      )
      if (res.total_flows_aggregated > 0) {
        window.dispatchEvent(
          new CustomEvent('hgs:telemetry-ingested', {
            detail: {
              provider: 'AWS_FIXTURE',
              records_received: res.total_records_parsed,
              records_parsed: res.total_records_parsed,
              records_aggregated: res.total_flows_aggregated,
              high_risk_detected: res.high_risk_flows_count,
              status: 'SUCCESS',
              timestamp: Date.now(),
            },
          })
        )
      }
    } catch (err: any) {
      setToast(`Ingestion error: ${err.message || String(err)}`)
    } finally {
      setIngestingFixture(false)
      setActiveSampleId(null)
    }
  }

  // Handle Ingest Raw Log Lines
  const handleIngestRaw = async () => {
    if (!rawVpcText.trim()) return
    setIngestingFixture(true)
    setToast('Parsing and evaluating raw AWS VPC flow log records...')
    try {
      const res = await ingestRawVpcLogs(rawVpcText, false, 'operator_custom_vpc_input')
      setFixtureResponse(res)
      setToast(
        `Ingested ${res.total_records_parsed} records into ${res.total_flows_aggregated} flow vectors.`
      )
    } catch (err: any) {
      setToast(`Error parsing raw VPC logs: ${err.message || String(err)}`)
    } finally {
      setIngestingFixture(false)
    }
  }

  // Mode tab change handler
  const switchTab = (tab: AwsVpcViewMode) => {
    setActiveTab(tab)
    if (tab === 'LIVE_AWS') {
      onSelectEnv?.('LIVE_AWS')
    } else if (tab === 'FIXTURES') {
      onSelectEnv?.('AWS_FIXTURE')
    }
  }

  return (
    <div className="aws-vpc-view-container" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      {/* Header & Mode Switcher */}
      <section className="intro" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '12px' }}>
        <div>
          <h1 style={{ display: 'flex', alignItems: 'center', gap: '8px', margin: '0 0 6px' }}>
            <span>☁️</span>
            <span>{activeTab === 'LIVE_AWS' ? 'Live AWS VPC Flow Logs' : 'AWS VPC Flow Logs Console'}</span>
          </h1>
          <p style={{ margin: 0 }}>
            {activeTab === 'LIVE_AWS'
              ? 'Real CloudWatch telemetry ingestion and authoritative Big Data XGBoost V2 threat inference.'
              : 'Inspect and evaluate standard AWS VPC Flow Log lines (v2 schema) crossing the hybrid cloud boundary.'}
          </p>
        </div>

        {/* View Mode Switcher Tabs */}
        <div style={{ display: 'flex', gap: '6px', background: 'var(--panel-inset)', padding: '4px', borderRadius: 'var(--radius-sm)' }}>
          <button
            type="button"
            className={`chip ${activeTab === 'LIVE_AWS' ? 'active' : ''}`}
            onClick={() => switchTab('LIVE_AWS')}
            style={{ fontWeight: activeTab === 'LIVE_AWS' ? 600 : 400 }}
          >
            ☁️ Live AWS Read-Only
          </button>
          <button
            type="button"
            className={`chip ${activeTab === 'FIXTURES' ? 'active' : ''}`}
            onClick={() => switchTab('FIXTURES')}
            style={{ fontWeight: activeTab === 'FIXTURES' ? 600 : 400 }}
          >
            📁 Benchmark Fixtures
          </button>
          <button
            type="button"
            className={`chip ${activeTab === 'RAW' ? 'active' : ''}`}
            onClick={() => switchTab('RAW')}
            style={{ fontWeight: activeTab === 'RAW' ? 600 : 400 }}
          >
            📝 Raw Log Input
          </button>
        </div>
      </section>

      {/* Toast Notification Alert */}
      {toast && (
        <div
          className="auth-alert"
          style={{
            background: 'var(--panel-elevated)',
            border: '1px solid var(--line-strong)',
            color: 'var(--warm-cream)',
            padding: '10px 14px',
            borderRadius: 'var(--radius-sm)',
            fontSize: '12px',
            display: 'flex',
            justifyContent: 'space-between',
            alignItems: 'center',
          }}
        >
          <span>ℹ️ {toast}</span>
          <button
            type="button"
            onClick={() => setToast(null)}
            style={{ background: 'none', border: 'none', color: 'var(--muted-cream)', cursor: 'pointer' }}
          >
            ✕
          </button>
        </div>
      )}

      {/* ============================================================= */}
      {/* TAB 1: LIVE AWS READ-ONLY TELEMETRY                           */}
      {/* ============================================================= */}
      {activeTab === 'LIVE_AWS' && (
        <>
          {/* Live AWS Read-Only Connection Banner */}
          <div
            className="card"
            style={{
              background: 'var(--panel)',
              border: '1px solid var(--line-strong)',
              borderRadius: 'var(--radius-sm)',
              padding: '16px',
              display: 'flex',
              flexDirection: 'column',
              gap: '12px',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '10px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                <span style={{ fontSize: '22px' }}>🛡️</span>
                <div>
                  <h3 style={{ margin: 0, fontSize: '15px', color: 'var(--warm-cream)' }}>
                    Amazon Web Services (AWS) Live CloudWatch Telemetry
                  </h3>
                  <span style={{ fontSize: '11.5px', color: 'var(--text-secondary)' }}>
                    Streaming read-only flow log ingestion via STS AssumeRole & named profile. Zero mutating permissions.
                  </span>
                </div>
              </div>

              <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                <span
                  className="pill"
                  style={{
                    background: 'var(--olive-green-muted)',
                    color: 'var(--olive-green)',
                    fontSize: '11px',
                    fontWeight: 600,
                  }}
                >
                  STRICTLY READ-ONLY
                </span>
                <span
                  className="pill"
                  style={{
                    background:
                      telemetryStatus === 'EVENTS_RETRIEVED'
                        ? 'rgba(16, 185, 129, 0.2)'
                        : telemetryStatus === 'CONNECTED'
                        ? 'var(--olive-green-muted)'
                        : telemetryStatus === 'POLLING'
                        ? 'var(--sky-blue-muted)'
                        : telemetryStatus === 'NO_NEW_EVENTS'
                        ? 'var(--panel-inset)'
                        : telemetryStatus === 'PARSE_FAILED'
                        ? 'rgba(245, 158, 11, 0.2)'
                        : 'var(--terracotta-muted)',
                    color:
                      telemetryStatus === 'EVENTS_RETRIEVED'
                        ? '#10b981'
                        : telemetryStatus === 'CONNECTED'
                        ? 'var(--olive-green)'
                        : telemetryStatus === 'POLLING'
                        ? 'var(--sky-blue)'
                        : telemetryStatus === 'NO_NEW_EVENTS'
                        ? 'var(--text-secondary)'
                        : telemetryStatus === 'PARSE_FAILED'
                        ? '#f59e0b'
                        : 'var(--terracotta)',
                    fontSize: '11px',
                    fontWeight: 600,
                  }}
                >
                  ● {telemetryStatus}
                </span>
              </div>
            </div>

            {/* AWS Configuration & Coordinates Grid */}
            <div
              style={{
                display: 'grid',
                gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
                gap: '10px',
                background: 'var(--panel-inset)',
                padding: '12px',
                borderRadius: 'var(--radius-xs)',
                fontSize: '11.5px',
              }}
            >
              <div>
                <span style={{ color: 'var(--text-secondary)', display: 'block' }}>AWS Account ID:</span>
                <code style={{ color: 'var(--warm-cream)' }}>698766075180</code>
              </div>
              <div>
                <span style={{ color: 'var(--text-secondary)', display: 'block' }}>Region:</span>
                <code style={{ color: 'var(--warm-cream)' }}>ap-southeast-2</code>
              </div>
              <div>
                <span style={{ color: 'var(--text-secondary)', display: 'block' }}>Target VPC:</span>
                <code style={{ color: 'var(--warm-cream)' }}>vpc-0fc9db63fecb34fad</code>
              </div>
              <div>
                <span style={{ color: 'var(--text-secondary)', display: 'block' }}>Flow Log ID:</span>
                <code style={{ color: 'var(--warm-cream)' }}>fl-0d236b31b1fd0d13e</code>
              </div>
              <div>
                <span style={{ color: 'var(--text-secondary)', display: 'block' }}>CloudWatch Log Group:</span>
                <code style={{ color: 'var(--terracotta)' }}>{logGroup}</code>
              </div>
              <div>
                <span style={{ color: 'var(--text-secondary)', display: 'block' }}>Assumed IAM Role:</span>
                <code style={{ color: 'var(--warm-cream)' }}>SecurityGatewayReadOnlyRole</code>
              </div>
              <div>
                <span style={{ color: 'var(--text-secondary)', display: 'block' }}>External ID:</span>
                <code style={{ color: 'var(--warm-cream)' }}>AdaptiveGatewayAuth</code>
              </div>
              <div>
                <span style={{ color: 'var(--text-secondary)', display: 'block' }}>AWS CLI Profile:</span>
                <code style={{ color: 'var(--warm-cream)' }}>security-gateway-readonly</code>
              </div>
            </div>

            {/* Live Polling Action Bar */}
            <div style={{ display: 'flex', gap: '10px', alignItems: 'center', flexWrap: 'wrap', marginTop: '4px' }}>
              <div style={{ flex: 1, minWidth: '280px', display: 'flex', gap: '8px', alignItems: 'center' }}>
                <label style={{ fontSize: '11.5px', color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}>
                  Log Group:
                </label>
                <input
                  type="text"
                  value={logGroup}
                  onChange={(e) => setLogGroup(e.target.value)}
                  style={{
                    flex: 1,
                    background: 'var(--panel-inset)',
                    border: '1px solid var(--line)',
                    borderRadius: 'var(--radius-xs)',
                    padding: '6px 10px',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '11px',
                    color: 'var(--warm-cream)',
                  }}
                />
              </div>

              <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                <select
                  value={pollLimit}
                  onChange={(e) => setPollLimit(Number(e.target.value))}
                  style={{
                    background: 'var(--panel-inset)',
                    border: '1px solid var(--line)',
                    borderRadius: 'var(--radius-xs)',
                    padding: '6px 8px',
                    fontSize: '11px',
                    color: 'var(--warm-cream)',
                  }}
                  aria-label="Polling batch limit"
                >
                  <option value={25}>Limit 25</option>
                  <option value={50}>Limit 50</option>
                  <option value={100}>Limit 100</option>
                  <option value={200}>Limit 200</option>
                </select>

                <button
                  type="button"
                  className="primary"
                  disabled={polling}
                  onClick={handlePollCloudWatch}
                  style={{ padding: '6px 16px', fontSize: '12px', fontWeight: 600 }}
                >
                  {polling ? '⚡ Polling CloudWatch...' : '⚡ Poll CloudWatch Logs'}
                </button>

                <button
                  type="button"
                  disabled={polling}
                  onClick={handleResetCheckpoint}
                  style={{
                    background: 'var(--panel-inset)',
                    border: '1px solid var(--line)',
                    borderRadius: 'var(--radius-xs)',
                    padding: '6px 10px',
                    fontSize: '11px',
                    color: 'var(--muted-cream)',
                    cursor: 'pointer',
                  }}
                >
                  ↺ Reset Checkpoint
                </button>

                <button
                  type="button"
                  disabled={polling}
                  onClick={refreshLiveTelemetryStatus}
                  style={{
                    background: 'var(--panel-inset)',
                    border: '1px solid var(--line)',
                    borderRadius: 'var(--radius-xs)',
                    padding: '6px 10px',
                    fontSize: '11px',
                    color: 'var(--muted-cream)',
                    cursor: 'pointer',
                  }}
                >
                  🔄 Refresh Status
                </button>
              </div>
            </div>
          </div>

          {/* Live Ingestion KPI Cards */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '12px' }}>
            <div className="card" style={{ padding: '12px 14px', background: 'var(--panel)', border: '1px solid var(--line)' }}>
              <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Discovered Records</span>
              <b style={{ fontSize: '18px', display: 'block', color: 'var(--warm-cream)', marginTop: '4px' }}>
                {telemetryBatch ? telemetryBatch.records_received : telemetryStats?.metrics?.total_records_ingested || 0}
              </b>
              <small style={{ fontSize: '10px', color: 'var(--muted-cream)' }}>CloudWatch filter_log_events</small>
            </div>

            <div className="card" style={{ padding: '12px 14px', background: 'var(--panel)', border: '1px solid var(--line)' }}>
              <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Ingested & Evaluated</span>
              <b style={{ fontSize: '18px', display: 'block', color: 'var(--olive-green)', marginTop: '4px' }}>
                {telemetryBatch ? telemetryBatch.records_aggregated : telemetryStats?.metrics?.total_records_parsed || 0}
              </b>
              <small style={{ fontSize: '10px', color: 'var(--muted-cream)' }}>Parsed canonical flow vectors</small>
            </div>

            <div className="card" style={{ padding: '12px 14px', background: 'var(--panel)', border: '1px solid var(--line)' }}>
              <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Duplicates Skipped</span>
              <b style={{ fontSize: '18px', display: 'block', color: 'var(--sky-blue)', marginTop: '4px' }}>
                {telemetryStats?.metrics?.total_duplicates_skipped || 0}
              </b>
              <small style={{ fontSize: '10px', color: 'var(--muted-cream)' }}>DeduplicationCache (SHA-256)</small>
            </div>

            <div className="card" style={{ padding: '12px 14px', background: 'var(--panel)', border: '1px solid var(--line)' }}>
              <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Invalid / Truncated</span>
              <b style={{ fontSize: '18px', display: 'block', color: 'var(--muted-cream)', marginTop: '4px' }}>
                {telemetryStats?.metrics?.total_invalid_skipped || 0}
              </b>
              <small style={{ fontSize: '10px', color: 'var(--muted-cream)' }}>Malformed or NODATA lines</small>
            </div>

            <div className="card" style={{ padding: '12px 14px', background: 'var(--panel)', border: '1px solid var(--line)' }}>
              <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>High-Risk Flows</span>
              <b
                style={{
                  fontSize: '18px',
                  display: 'block',
                  color: (telemetryBatch?.high_risk_flows_detected || 0) > 0 ? 'var(--terracotta)' : 'var(--olive-green)',
                  marginTop: '4px',
                }}
              >
                {telemetryBatch?.high_risk_flows_detected || 0}
              </b>
              <small style={{ fontSize: '10px', color: 'var(--muted-cream)' }}>Risk Score ≥ 70 / 100</small>
            </div>

            <div className="card" style={{ padding: '12px 14px', background: 'var(--panel)', border: '1px solid var(--line)' }}>
              <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>VPC Flow Actions</span>
              <div style={{ display: 'flex', gap: '12px', marginTop: '4px' }}>
                <div>
                  <small style={{ color: 'var(--olive-green)', display: 'block', fontSize: '10px' }}>ACCEPT</small>
                  <b style={{ fontSize: '15px', color: 'var(--olive-green)' }}>
                    {telemetryBatch ? telemetryBatch.flows_accepted : 0}
                  </b>
                </div>
                <div>
                  <small style={{ color: 'var(--terracotta)', display: 'block', fontSize: '10px' }}>REJECT</small>
                  <b style={{ fontSize: '15px', color: 'var(--terracotta)' }}>
                    {telemetryBatch ? telemetryBatch.flows_dropped : 0}
                  </b>
                </div>
              </div>
              <small style={{ fontSize: '10px', color: 'var(--muted-cream)' }}>AWS SG / NACL telemetry</small>
            </div>

            <div className="card" style={{ padding: '12px 14px', background: 'var(--panel)', border: '1px solid var(--line)' }}>
              <span style={{ fontSize: '11px', color: 'var(--text-secondary)' }}>Authoritative Model</span>
              <b style={{ fontSize: '13px', display: 'block', color: 'var(--terracotta)', marginTop: '4px' }}>
                XGBoost V2 (9 Feat)
              </b>
              <small style={{ fontSize: '9.5px', color: 'var(--muted-cream)' }}>
                pkt/byte/dur/rate/ports/thruput/size
              </small>
            </div>
          </div>

          {/* Last Polling Diagnostics / Error Alert */}
          {lastPollingError && (
            <div
              className="card"
              style={{
                padding: '12px 16px',
                background: 'var(--panel-elevated)',
                border: '1px solid var(--terracotta)',
                borderRadius: 'var(--radius-sm)',
              }}
            >
              <b style={{ color: 'var(--terracotta)', fontSize: '12px' }}>⚠️ Last CloudWatch Polling Diagnostics:</b>
              <p style={{ margin: '4px 0 0', fontSize: '11.5px', color: 'var(--warm-cream)', fontFamily: 'var(--font-mono)' }}>
                {lastPollingError}
              </p>
            </div>
          )}

          {/* Telemetry Evaluation Results Table */}
          {telemetryBatch && telemetryBatch.flows.length > 0 && (
            <section className="card" style={{ padding: '16px', background: 'var(--panel)', border: '1px solid var(--line)' }}>
              <div className="title-line" style={{ marginBottom: '12px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <h2 style={{ margin: 0, fontSize: '15px' }}>
                    Live CloudWatch Ingestion Telemetry: <code style={{ color: 'var(--terracotta)' }}>{telemetryBatch.account_id}</code>
                  </h2>
                  <span style={{ fontSize: '11px', color: 'var(--muted-cream)' }}>
                    {telemetryBatch.records_parsed} records parsed into {telemetryBatch.records_aggregated} flows in{' '}
                    {(telemetryBatch.parsing_duration_ms + telemetryBatch.inference_duration_ms).toFixed(1)} ms • Model: XGBoost V2 (Authoritative)
                  </span>
                </div>
                <span
                  className={`threat-tag ${telemetryBatch.high_risk_flows_detected > 0 ? 'HIGH' : 'LOW'}`}
                  style={{ fontSize: '11px' }}
                >
                  {telemetryBatch.high_risk_flows_detected} High Risk Flows
                </span>
              </div>

              <div className="table-wrapper" style={{ overflowX: 'auto' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px', textAlign: 'left' }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--line-strong)', color: 'var(--muted-cream)' }}>
                      <th style={{ padding: '8px 10px' }}>Flow Direction</th>
                      <th style={{ padding: '8px 10px' }}>Source IP</th>
                      <th style={{ padding: '8px 10px' }}>Dest IP:Port</th>
                      <th style={{ padding: '8px 10px' }}>Protocol</th>
                      <th style={{ padding: '8px 10px' }}>Packets</th>
                      <th style={{ padding: '8px 10px' }}>Bytes</th>
                      <th style={{ padding: '8px 10px' }}>XGBoost V2 Prediction</th>
                      <th style={{ padding: '8px 10px' }}>Risk Score</th>
                      <th style={{ padding: '8px 10px' }}>Policy Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {telemetryBatch.flows.map((flow, i) => (
                      <tr key={flow.flow_id || i} style={{ borderBottom: '1px solid var(--line-subtle)', color: 'var(--warm-cream)' }}>
                        <td style={{ padding: '8px 10px', fontSize: '11px' }}>
                          <span className="prov-badge" style={{ fontSize: '9.5px' }}>
                            {flow.flow_direction || 'CROSS_ZONE'}
                          </span>
                        </td>
                        <td style={{ padding: '8px 10px', fontFamily: 'var(--font-mono)' }}>{flow.src_ip}</td>
                        <td style={{ padding: '8px 10px', fontFamily: 'var(--font-mono)', color: 'var(--terracotta)' }}>
                          {flow.dst_ip}:{flow.dst_port}
                        </td>
                        <td style={{ padding: '8px 10px' }}>{flow.protocol}</td>
                        <td style={{ padding: '8px 10px' }}>{flow.packet_count}</td>
                        <td style={{ padding: '8px 10px' }}>{flow.byte_count.toLocaleString()}</td>
                        <td style={{ padding: '8px 10px', fontWeight: 600 }}>
                          <span style={{ color: flow.attack_type === 'BENIGN' ? 'var(--olive-green)' : 'var(--terracotta)' }}>
                            {flow.attack_type}
                          </span>
                        </td>
                        <td style={{ padding: '8px 10px' }}>
                          <span
                            className="pill"
                            style={{
                              fontSize: '10.5px',
                              background: flow.risk_score >= 70 ? 'var(--terracotta-muted)' : 'var(--olive-green-muted)',
                              color: flow.risk_score >= 70 ? 'var(--terracotta)' : 'var(--olive-green)',
                            }}
                          >
                            {Math.round(flow.risk_score)}/100
                          </span>
                        </td>
                        <td style={{ padding: '8px 10px', fontWeight: 600 }}>
                          <span
                            style={{
                              color:
                                flow.policy_action.toUpperCase() === 'ALLOW'
                                  ? 'var(--olive-green)'
                                  : flow.policy_action.toUpperCase() === 'MONITOR'
                                  ? 'var(--sky-blue)'
                                  : 'var(--terracotta)',
                            }}
                          >
                            {flow.policy_action}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}

          {/* Empty Polling State */}
          {(!telemetryBatch || telemetryBatch.flows.length === 0) && (
            <div
              className="card"
              style={{
                padding: '24px',
                textAlign: 'center',
                background: 'var(--panel)',
                border: '1px dashed var(--line)',
                borderRadius: 'var(--radius-sm)',
              }}
            >
              <span style={{ fontSize: '28px', display: 'block', marginBottom: '8px' }}>☁️</span>
              <b style={{ color: 'var(--warm-cream)', fontSize: '14px', display: 'block' }}>
                {telemetryStatus === 'NO_NEW_EVENTS'
                  ? 'No New VPC Flow Log Events Detected'
                  : 'Ready to Poll Live AWS CloudWatch Telemetry'}
              </b>
              <p style={{ color: 'var(--text-secondary)', fontSize: '12px', maxWidth: '480px', margin: '6px auto 14px' }}>
                {telemetryStatus === 'NO_NEW_EVENTS'
                  ? 'All flow log records up to the current incremental checkpoint have been ingested. Click below to poll for newly recorded events.'
                  : 'Click the button below to retrieve real VPC flow log events from Amazon CloudWatch Logs and evaluate them through XGBoost V2.'}
              </p>
              <button
                type="button"
                className="primary"
                disabled={polling}
                onClick={handlePollCloudWatch}
                style={{ padding: '8px 20px', fontSize: '12.5px' }}
              >
                {polling ? '⚡ Polling CloudWatch...' : '⚡ Poll CloudWatch Logs Now'}
              </button>
            </div>
          )}

          {/* Ingestion Audit & Checkpoint History */}
          {historyRuns.length > 0 && (
            <section className="card" style={{ padding: '16px', background: 'var(--panel)', border: '1px solid var(--line)' }}>
              <h3 style={{ margin: '0 0 10px', fontSize: '13.5px', color: 'var(--warm-cream)' }}>
                Recent CloudWatch Ingestion Audit Log
              </h3>
              <div className="table-wrapper" style={{ overflowX: 'auto' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '11.5px', textAlign: 'left' }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--line-strong)', color: 'var(--muted-cream)' }}>
                      <th style={{ padding: '6px 8px' }}>Timestamp</th>
                      <th style={{ padding: '6px 8px' }}>Source Identifier</th>
                      <th style={{ padding: '6px 8px' }}>Ingested</th>
                      <th style={{ padding: '6px 8px' }}>Duplicates</th>
                      <th style={{ padding: '6px 8px' }}>High-Risk</th>
                      <th style={{ padding: '6px 8px' }}>Duration</th>
                      <th style={{ padding: '6px 8px' }}>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {historyRuns.map((run, idx) => (
                      <tr key={run.id || idx} style={{ borderBottom: '1px solid var(--line-subtle)', color: 'var(--warm-cream)' }}>
                        <td style={{ padding: '6px 8px', fontFamily: 'var(--font-mono)' }}>
                          {run.created_at ? new Date(run.created_at).toLocaleTimeString() : 'N/A'}
                        </td>
                        <td style={{ padding: '6px 8px', fontFamily: 'var(--font-mono)' }}>{run.source_identifier}</td>
                        <td style={{ padding: '6px 8px' }}>{run.records_ingested}</td>
                        <td style={{ padding: '6px 8px' }}>{run.records_duplicate_skipped}</td>
                        <td style={{ padding: '6px 8px', color: run.high_risk_detected > 0 ? 'var(--terracotta)' : 'inherit' }}>
                          {run.high_risk_detected}
                        </td>
                        <td style={{ padding: '6px 8px' }}>{(run.duration_ms || 0).toFixed(0)} ms</td>
                        <td style={{ padding: '6px 8px' }}>
                          <span className="pill" style={{ fontSize: '10px', background: 'var(--panel-inset)' }}>
                            {run.status}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}
        </>
      )}

      {/* ============================================================= */}
      {/* TAB 2 & 3: OFFLINE FIXTURES & RAW INPUT                       */}
      {/* ============================================================= */}
      {(activeTab === 'FIXTURES' || activeTab === 'RAW') && (
        <>
          {/* Transparency Banner for Simulated/Offline Telemetry */}
          <div
            className="card"
            style={{
              background: 'var(--panel-muted)',
              border: '1px solid var(--line)',
              borderRadius: 'var(--radius-sm)',
              padding: '12px 16px',
              display: 'flex',
              alignItems: 'center',
              gap: '12px',
            }}
          >
            <span style={{ fontSize: '20px' }}>⚠️</span>
            <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
              <b style={{ color: 'var(--warm-cream)' }}>Simulated Cloud Telemetry Notice:</b> VPC flow logs shown here represent synthetic telemetry generated in the virtual hybrid lab (10.20.10.0/24, region us-east-1). To inspect live AWS CloudWatch logs from account 698766075180, switch to <b>Live AWS Read-Only</b> mode above.
            </div>
          </div>

          {activeTab === 'FIXTURES' && (
            <div className="card" style={{ padding: '16px', background: 'var(--panel)', border: '1px solid var(--line)' }}>
              <h2 style={{ fontSize: '14px', margin: '0 0 10px', color: 'var(--warm-cream)' }}>
                Pre-Configured Offline Benchmark Fixtures
              </h2>
              <p style={{ fontSize: '11.5px', color: 'var(--text-secondary)', margin: '0 0 14px' }}>
                Click any fixture to trigger deterministic flow log parsing and AI threat evaluation:
              </p>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                {loadingSamples ? (
                  <small style={{ color: 'var(--muted-cream)' }}>Loading benchmark fixtures...</small>
                ) : (
                  samples.map((s) => {
                    const isSelected = activeSampleId === s.sample_id
                    return (
                      <div
                        key={s.sample_id}
                        style={{
                          background: 'var(--panel-inset)',
                          border: '1px solid var(--line-subtle)',
                          borderRadius: 'var(--radius-sm)',
                          padding: '10px 12px',
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center',
                        }}
                      >
                        <div>
                          <b style={{ color: 'var(--warm-cream)', fontSize: '12.5px' }}>{s.name}</b>
                          <small style={{ color: 'var(--muted-cream)', display: 'block', fontSize: '11px', marginTop: '2px' }}>
                            {s.record_count} records • {s.description}
                          </small>
                        </div>
                        <button
                          type="button"
                          className="primary"
                          disabled={ingestingFixture}
                          onClick={() => handleIngestSample(s.sample_id)}
                          style={{ fontSize: '11px', padding: '5px 10px', whiteSpace: 'nowrap' }}
                        >
                          {isSelected ? 'Evaluating...' : 'Ingest Fixture'}
                        </button>
                      </div>
                    )
                  })
                )}
              </div>
            </div>
          )}

          {activeTab === 'RAW' && (
            <div className="card" style={{ padding: '16px', background: 'var(--panel)', border: '1px solid var(--line)' }}>
              <h2 style={{ fontSize: '14px', margin: '0 0 10px', color: 'var(--warm-cream)' }}>
                Raw AWS VPC Flow Log Input (Version 2 Format)
              </h2>
              <p style={{ fontSize: '11.5px', color: 'var(--text-secondary)', margin: '0 0 10px' }}>
                Paste space-separated VPC flow log records (e.g. <code>2 123456789012 eni-sim01 10.10.10.10 10.20.10.20 443 8080 6 25 15000 ...</code>):
              </p>

              <textarea
                value={rawVpcText}
                onChange={(e) => setRawVpcText(e.target.value)}
                placeholder="2 123456789012 eni-0123456789abcdef0 10.10.10.50 10.20.10.40 49152 80 6 75 4500 1620000000 1620000060 ACCEPT OK"
                rows={7}
                style={{
                  width: '100%',
                  background: 'var(--panel-inset)',
                  border: '1px solid var(--line)',
                  borderRadius: 'var(--radius-xs)',
                  padding: '8px 10px',
                  fontFamily: 'var(--font-mono)',
                  fontSize: '11px',
                  color: 'var(--warm-cream)',
                  boxSizing: 'border-box',
                  resize: 'vertical',
                  marginBottom: '10px',
                }}
              />

              <button
                type="button"
                className="primary"
                disabled={ingestingFixture || !rawVpcText.trim()}
                onClick={handleIngestRaw}
                style={{ width: '100%', padding: '8px 12px', fontSize: '12px' }}
              >
                {ingestingFixture ? 'Evaluating...' : 'Ingest & Evaluate Raw Lines'}
              </button>
            </div>
          )}

          {/* Fixture / Raw Ingestion Results Display */}
          {fixtureResponse && (
            <section className="card" style={{ padding: '16px', background: 'var(--panel)', border: '1px solid var(--line)' }}>
              <div className="title-line" style={{ marginBottom: '12px', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div>
                  <h2 style={{ margin: 0, fontSize: '15px' }}>
                    VPC Ingestion Telemetry: <code style={{ color: 'var(--terracotta)' }}>{fixtureResponse.source_label}</code>
                  </h2>
                  <span style={{ fontSize: '11px', color: 'var(--muted-cream)' }}>
                    {fixtureResponse.total_records_parsed} records parsed into {fixtureResponse.total_flows_aggregated} flows in{' '}
                    {fixtureResponse.total_duration_ms} ms
                  </span>
                </div>
                <span
                  className={`threat-tag ${fixtureResponse.high_risk_flows_count > 0 ? 'HIGH' : 'LOW'}`}
                  style={{ fontSize: '11px' }}
                >
                  {fixtureResponse.high_risk_flows_count} High Risk Flows
                </span>
              </div>

              <div className="table-wrapper" style={{ overflowX: 'auto' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px', textAlign: 'left' }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--line-strong)', color: 'var(--muted-cream)' }}>
                      <th style={{ padding: '8px 10px' }}>Flow Direction</th>
                      <th style={{ padding: '8px 10px' }}>Source IP</th>
                      <th style={{ padding: '8px 10px' }}>Dest IP:Port</th>
                      <th style={{ padding: '8px 10px' }}>Packets</th>
                      <th style={{ padding: '8px 10px' }}>Bytes</th>
                      <th style={{ padding: '8px 10px' }}>ML Prediction</th>
                      <th style={{ padding: '8px 10px' }}>Risk Score</th>
                      <th style={{ padding: '8px 10px' }}>Policy Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {fixtureResponse.results.slice(0, 15).map((r: any, i: number) => {
                      const attackType = r.prediction?.attack_type ?? r.attack_type ?? r.predicted_class ?? 'BENIGN'
                      const riskScore = Math.round(r.prediction?.risk_score ?? r.risk_score ?? 0)
                      const policyAction = r.policy_decision?.policy_action ?? r.policy_action ?? 'Allow'
                      const dstPort = r.dst_port ?? r.destination_port ?? 80
                      const direction = r.traffic_direction ?? r.flow_direction ?? r.transit_zone ?? 'CROSS_ZONE'

                      return (
                        <tr key={i} style={{ borderBottom: '1px solid var(--line-subtle)', color: 'var(--warm-cream)' }}>
                          <td style={{ padding: '8px 10px', fontSize: '11px' }}>
                            <span className="prov-badge" style={{ fontSize: '9.5px' }}>
                              {direction}
                            </span>
                          </td>
                          <td style={{ padding: '8px 10px', fontFamily: 'var(--font-mono)' }}>{r.source_ip}</td>
                          <td style={{ padding: '8px 10px', fontFamily: 'var(--font-mono)', color: 'var(--terracotta)' }}>
                            {r.destination_ip}:{dstPort}
                          </td>
                          <td style={{ padding: '8px 10px' }}>{r.packet_count}</td>
                          <td style={{ padding: '8px 10px' }}>{r.byte_count.toLocaleString()}</td>
                          <td style={{ padding: '8px 10px', fontWeight: 600 }}>
                            <span style={{ color: attackType === 'BENIGN' ? 'var(--olive-green)' : 'var(--terracotta)' }}>
                              {attackType}
                            </span>
                          </td>
                          <td style={{ padding: '8px 10px' }}>
                            <span
                              className="pill"
                              style={{
                                fontSize: '10.5px',
                                background: riskScore >= 70 ? 'var(--terracotta-muted)' : 'var(--olive-green-muted)',
                                color: riskScore >= 70 ? 'var(--terracotta)' : 'var(--olive-green)',
                              }}
                            >
                              {riskScore}/100
                            </span>
                          </td>
                          <td style={{ padding: '8px 10px', fontWeight: 600 }}>
                            <span
                              style={{
                                color:
                                  policyAction.toUpperCase() === 'ALLOW'
                                    ? 'var(--olive-green)'
                                    : policyAction.toUpperCase() === 'MONITOR'
                                    ? 'var(--sky-blue)'
                                    : 'var(--terracotta)',
                              }}
                            >
                              {policyAction}
                            </span>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            </section>
          )}
        </>
      )}
    </div>
  )
}
