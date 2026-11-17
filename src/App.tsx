import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import './App.css'
import {
  applyAction,
  getAICopilotBriefing,
  getDashboard,
  getSystemProfile,
  markAllNotificationsRead,
  markNotificationRead,
  searchGateway,
} from './services/dashboard'
import { getPresets, predictFlow } from './services/predictor'
import {
  ingestSamplePcap,
  listSamplePcaps,
  uploadPcapFile,
} from './services/ingestion'
import {
  comparePolicies,
  getEnforcementConfig,
  listEnforcementRules,
  revokeEnforcementRule,
  updateEnforcementMode,
} from './services/enforcement'
import {
  getAwsVpcSamples,
  getHybridTopology,
  ingestAwsVpcSample,
  ingestRawVpcLogs,
} from './services/hybrid'
import { getEventExplanation } from './services/analytics'
import { AnalyticsView } from './components/AnalyticsView'
import { EvaluationView } from './components/EvaluationView'
import { TrafficView } from './components/TrafficView'
import { EventsView } from './components/EventsView'
import { PoliciesView } from './components/PoliciesView'
import { SimulationView } from './components/SimulationView'
import { SystemHealthView } from './components/SystemHealthView'
import { AwsVpcView } from './components/AwsVpcView'
import { MultiCloudView } from './components/MultiCloudView'
import { PcapIngestView } from './components/PcapIngestView'
import { SettingsView } from './components/SettingsView'
import { AuthView } from './components/AuthView'
import { ErrorBoundary } from './components/ErrorBoundary'
import { authService } from './services/auth'
import type { CloudTelemetryBatchResponse } from './services/cloud'
import type {
  ActiveEnforcementRule,
  AICopilotBriefing,
  AuthUser,
  AwsVpcIngestionResponse,
  AwsVpcSampleFixtureInfo,
  DashboardData,
  EnforcementConfig,
  EventExplanationResponse,
  FlowPredictionRequest,
  FlowPredictionResponse,
  HybridTopologySummary,
  NotificationItem,
  PcapIngestionResponse,
  PolicyAction,
  PolicyComparisonResult,
  SamplePcapInfo,
  SearchResults,
  SecurityEvent,
  SystemProfile,
  TrafficPoint,
} from './types'

interface NavGroupItem {
  id: string
  name: string
  icon: string
  view: string
  subTab?: string
}

interface NavGroup {
  id: string
  title: string
  icon: string
  items: NavGroupItem[]
}

const navGroups: NavGroup[] = [
  {
    id: 'overview',
    title: 'Overview',
    icon: '📊',
    items: [
      { id: 'dashboard', name: 'Main Dashboard', icon: '⌂', view: 'Dashboard' },
      { id: 'system_health', name: 'System Health', icon: '🖥', view: 'System Health' },
    ],
  },
  {
    id: 'security_ops',
    title: 'Security Operations',
    icon: '🛡️',
    items: [
      { id: 'events', name: 'Security Events', icon: '▣', view: 'Security Events' },
      { id: 'network', name: 'Live Network', icon: '▥', view: 'Live Network' },
      { id: 'simulation', name: 'Attack Simulation', icon: '⚔', view: 'Attack Simulation' },
      { id: 'policies', name: 'Policy Management', icon: '🛡️', view: 'Policies & Firewall' },
      { id: 'pcap', name: 'PCAP Ingestion', icon: '📦', view: 'PCAP Ingestion' },
    ],
  },
  {
    id: 'multi_cloud',
    title: 'Multi-Cloud',
    icon: '🌐',
    items: [
      { id: 'cloud_overview', name: 'Cloud Overview', icon: '🌐', view: 'Multi-Cloud', subTab: 'OVERVIEW' },
      { id: 'cloud_accounts', name: 'Cloud Accounts', icon: '🔑', view: 'Multi-Cloud', subTab: 'ACCOUNTS' },
      { id: 'aws_integration', name: 'AWS Integration', icon: '☁', view: 'Multi-Cloud', subTab: 'AWS' },
      { id: 'aws_vpc_logs', name: 'AWS VPC Flow Logs', icon: '📄', view: 'AWS VPC Logs' },
      { id: 'gcp_integration', name: 'GCP Integration', icon: '⚡', view: 'Multi-Cloud', subTab: 'GCP' },
      { id: 'azure_integration', name: 'Azure Integration', icon: '🔷', view: 'Multi-Cloud', subTab: 'AZURE' },
      { id: 'resource_inventory', name: 'Resource Inventory', icon: '📋', view: 'Multi-Cloud', subTab: 'INVENTORY' },
      { id: 'cloud_telemetry', name: 'Cloud Telemetry', icon: '📡', view: 'Multi-Cloud', subTab: 'TELEMETRY' },
    ],
  },
  {
    id: 'ai_intelligence',
    title: 'AI and Intelligence',
    icon: '🧠',
    items: [
      { id: 'ml_detection', name: 'ML Detection', icon: '⚖', view: 'ML Detection' },
      { id: 'shap_explainability', name: 'Explainability (XAI)', icon: '✦', view: 'Explainability (XAI)' },
    ],
  },
  {
    id: 'administration',
    title: 'Administration',
    icon: '⚙',
    items: [
      { id: 'settings', name: 'Gateway Configuration', icon: '⚙', view: 'Settings' },
    ],
  },
]

const DEFAULT_FLOW_INPUT: FlowPredictionRequest = {
  packet_count: 2,
  byte_count: 120,
  duration: 0.08,
  conn_rate: 120.0,
  dst_port: 8080,
  unique_dst_ports: 75,
  failed_auth_count: 0,
}

function Metric({
  icon,
  label,
  value,
  note,
  green = false,
  badge,
}: {
  icon: string
  label: string
  value: string
  note?: string
  green?: boolean
  badge?: string
}) {
  return (
    <div className={`metric ${green ? 'metric-healthy' : ''}`}>
      <div className="metric-header-row">
        <div className="metric-icon-box">
          <i>{icon}</i>
        </div>
        <div className="metric-meta-box">
          <span className="metric-label-text">{label}</span>
          {badge && <span className={`metric-badge-pill ${green ? 'pill-green' : ''}`}>{badge}</span>}
        </div>
      </div>
      <div className="metric-body-row">
        <b className={`metric-primary-value ${green ? 'green' : ''}`}>{value}</b>
        {note && <span className="metric-footnote-text">{note}</span>}
      </div>
      <div className="metric-sheen-line" />
    </div>
  )
}

function formatBytes(bytes?: number): string {
  if (bytes === undefined || bytes === null || isNaN(bytes)) return 'N/A'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`
}

function Traffic({
  points,
  range,
  events,
  onFilterEvents,
}: {
  points?: TrafficPoint[]
  range: string
  events?: SecurityEvent[]
  onFilterEvents?: (query: string) => void
}) {
  const [hoveredIdx, setHoveredIdx] = useState<number | null>(null)
  const [focusedIdx, setFocusedIdx] = useState<number | null>(null)
  const [selectedPoint, setSelectedPoint] = useState<TrafficPoint | null>(null)
  const [showInbound, setShowInbound] = useState<boolean>(true)
  const [showOutbound, setShowOutbound] = useState<boolean>(true)
  const chartWrapperRef = useRef<HTMLDivElement | null>(null)

  // Correlate security events belonging to this bucket
  const bucketEvents = useMemo(() => {
    if (!selectedPoint || !events || events.length === 0) return []
    // 1. If explicit event IDs are present in telemetry bucket
    if (selectedPoint.event_ids && selectedPoint.event_ids.length > 0) {
      const idSet = new Set(selectedPoint.event_ids)
      const matched = events.filter((e) => idSet.has(e.id))
      if (matched.length > 0) return matched
    }
    // 2. Correlate by time label substring matching
    const labelPrefix = selectedPoint.time_label.trim()
    return events.filter((e) => {
      if (e.time && e.time.includes(labelPrefix)) return true
      return false
    })
  }, [selectedPoint, events])

  if (!points || points.length === 0) {
    return (
      <div
        className="traffic-chart"
        style={{
          padding: '36px 20px',
          textAlign: 'center',
          background: 'var(--panel-inset)',
          borderRadius: 'var(--radius-sm)',
          border: '1px solid var(--line)',
        }}
      >
        <span style={{ fontSize: '24px', display: 'block', marginBottom: '8px' }}>📡</span>
        <b style={{ color: 'var(--warm-cream)', fontSize: '14px', display: 'block' }}>
          No Ingested Flow Telemetry in Database ({range})
        </b>
        <p
          style={{
            margin: '6px auto 0',
            maxWidth: '480px',
            fontSize: '12px',
            color: 'var(--muted-cream)',
          }}
        >
          No network flow vectors have been recorded for this time range. Execute an Attack Simulation scenario
          or ingest a PCAP packet capture to generate live telemetry.
        </p>
      </div>
    )
  }

  const dataPoints = points

  const maxVal = Math.max(
    ...dataPoints.map((p) => Math.max(p.inbound_val, p.outbound_val)),
    10.0
  )

  const width = 780
  const height = 205
  const paddingX = 40
  const paddingY = 25
  const chartW = width - paddingX * 2
  const chartH = height - paddingY * 2

  const getX = (idx: number) =>
    dataPoints.length > 1
      ? paddingX + (idx / (dataPoints.length - 1)) * chartW
      : paddingX + chartW / 2

  const getY = (val: number) => height - paddingY - (val / maxVal) * chartH

  let inPath = `M ${getX(0)} ${getY(dataPoints[0].inbound_val)}`
  let outPath = `M ${getX(0)} ${getY(dataPoints[0].outbound_val)}`

  if (dataPoints.length > 1) {
    for (let i = 1; i < dataPoints.length; i++) {
      const prevX = getX(i - 1)
      const prevYIn = getY(dataPoints[i - 1].inbound_val)
      const prevYOut = getY(dataPoints[i - 1].outbound_val)
      const curX = getX(i)
      const curYIn = getY(dataPoints[i].inbound_val)
      const curYOut = getY(dataPoints[i].outbound_val)

      const midX = (prevX + curX) / 2
      inPath += ` C ${midX} ${prevYIn}, ${midX} ${curYIn}, ${curX} ${curYIn}`
      outPath += ` C ${midX} ${prevYOut}, ${midX} ${curYOut}, ${curX} ${curYOut}`
    }
  }

  const inAreaPath =
    dataPoints.length > 1
      ? `${inPath} L ${getX(dataPoints.length - 1)} ${height - paddingY} L ${getX(0)} ${height - paddingY} Z`
      : ''

  const activeIdx = hoveredIdx ?? focusedIdx

  // Accessible Keyboard Navigation
  const handleChartKeyDown = (e: React.KeyboardEvent) => {
    if (!dataPoints.length) return
    if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {
      e.preventDefault()
      const nextIdx = focusedIdx === null ? 0 : (focusedIdx + 1) % dataPoints.length
      setFocusedIdx(nextIdx)
      setHoveredIdx(nextIdx)
    } else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
      e.preventDefault()
      const prevIdx =
        focusedIdx === null
          ? dataPoints.length - 1
          : (focusedIdx - 1 + dataPoints.length) % dataPoints.length
      setFocusedIdx(prevIdx)
      setHoveredIdx(prevIdx)
    } else if (e.key === 'Home') {
      e.preventDefault()
      setFocusedIdx(0)
      setHoveredIdx(0)
    } else if (e.key === 'End') {
      e.preventDefault()
      setFocusedIdx(dataPoints.length - 1)
      setHoveredIdx(dataPoints.length - 1)
    } else if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault()
      const targetIdx = focusedIdx ?? hoveredIdx ?? 0
      const pt = dataPoints[targetIdx]
      setSelectedPoint((prev) => (prev?.time_label === pt.time_label ? null : pt))
    } else if (e.key === 'Escape') {
      e.preventDefault()
      setSelectedPoint(null)
      setHoveredIdx(null)
      setFocusedIdx(null)
    }
  }

  return (
    <div
      className="traffic-chart"
      ref={chartWrapperRef}
      tabIndex={0}
      role="region"
      aria-label="Evaluated Flow Ingestion Telemetry interactive chart. Use left and right arrow keys to navigate time buckets, Enter or Space to inspect, Escape to close."
      onKeyDown={handleChartKeyDown}
      style={{ outline: 'none' }}
    >
      <div
        className="legend"
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '8px',
        }}
      >
        <div style={{ display: 'flex', gap: '14px', alignItems: 'center' }}>
          <span
            onClick={() => setShowInbound(!showInbound)}
            style={{
              cursor: 'pointer',
              opacity: showInbound ? 1 : 0.4,
              userSelect: 'none',
              transition: 'opacity 0.2s',
            }}
            title="Click to toggle Inbound series"
          >
            <i className="in" />
            Inbound Events ({range})
          </span>
          <span
            onClick={() => setShowOutbound(!showOutbound)}
            style={{
              cursor: 'pointer',
              opacity: showOutbound ? 1 : 0.4,
              userSelect: 'none',
              transition: 'opacity 0.2s',
            }}
            title="Click to toggle Outbound series"
          >
            <i className="out" />
            Outbound Ratio
          </span>
          <span>
            <i className="an" />
            Anomalies ({dataPoints.reduce((acc, p) => acc + p.anomaly_count, 0)})
          </span>
        </div>
        <span
          style={{
            fontSize: '11px',
            color: 'var(--muted-cream)',
            fontFamily: 'var(--font-mono)',
          }}
        >
          {dataPoints.length} Time Buckets • Hover/Tap to View • Click to Inspect
        </span>
      </div>

      <div className="chart" style={{ position: 'relative' }}>
        <div className="axis">
          <span>{Math.ceil(maxVal)} Flows</span>
          <span>{Math.ceil(maxVal * 0.8)} Flows</span>
          <span>{Math.ceil(maxVal * 0.6)} Flows</span>
          <span>{Math.ceil(maxVal * 0.4)} Flows</span>
          <span>{Math.ceil(maxVal * 0.2)} Flows</span>
          <span>0</span>
        </div>

        <svg
          viewBox="0 0 780 205"
          preserveAspectRatio="none"
          aria-label="Dynamic telemetry traffic chart"
          style={{ touchAction: 'pan-y' }}
        >
          <defs>
            <linearGradient id="fade" x1="0" x2="0" y1="0" y2="1">
              <stop offset="0%" stopColor="var(--terracotta)" stopOpacity="0.4" />
              <stop offset="65%" stopColor="var(--terracotta)" stopOpacity="0.1" />
              <stop offset="100%" stopColor="var(--terracotta)" stopOpacity="0" />
            </linearGradient>
            <linearGradient id="fade-out" x1="0" x2="0" y1="0" y2="1">
              <stop offset="0%" stopColor="var(--pale-sand)" stopOpacity="0.25" />
              <stop offset="100%" stopColor="var(--pale-sand)" stopOpacity="0" />
            </linearGradient>
            <filter id="glow-anomaly" x="-30%" y="-30%" width="160%" height="160%">
              <feGaussianBlur stdDeviation="3" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
            <filter id="glow-crosshair" x="-20%" y="-20%" width="140%" height="140%">
              <feGaussianBlur stdDeviation="1.5" result="blur" />
              <feMerge>
                <feMergeNode in="blur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          </defs>

          <path
            className="grid"
            d="M0 5H780M0 45H780M0 85H780M0 125H780M0 165H780M0 204H780M130 0V205M260 0V205M390 0V205M520 0V205M650 0V205"
          />

          {/* Inbound Area & Curve */}
          {showInbound && inAreaPath && (
            <path
              className="line-in"
              d={inAreaPath}
              fill="url(#fade)"
              stroke="var(--terracotta)"
              strokeWidth="2.2"
            />
          )}

          {/* Outbound Dotted Curve */}
          {showOutbound && (
            <path
              className="line-out"
              d={outPath}
              fill="none"
              stroke="var(--pale-sand)"
              strokeWidth="1.8"
              strokeDasharray="5 3"
            />
          )}

          {/* Vertical Inspection Crosshair */}
          {activeIdx !== null && (
            <g className="chart-crosshair">
              <line
                x1={getX(activeIdx)}
                y1={paddingY - 5}
                x2={getX(activeIdx)}
                y2={height - paddingY + 5}
                stroke="var(--terracotta)"
                strokeWidth="1.5"
                strokeDasharray="4 3"
                opacity="0.85"
                filter="url(#glow-crosshair)"
              />
              {showOutbound && (
                <circle
                  cx={getX(activeIdx)}
                  cy={getY(dataPoints[activeIdx].outbound_val)}
                  r="4"
                  fill="var(--pale-sand)"
                  stroke="#121519"
                  strokeWidth="1.5"
                />
              )}
            </g>
          )}

          {/* Plotted Data Points and Touch Hitboxes */}
          <g className="dots">
            {dataPoints.map((pt, idx) => {
              const cx = getX(idx)
              const cy = getY(pt.inbound_val)
              const hasAnomaly = pt.anomaly_count > 0
              const isSelected = selectedPoint?.time_label === pt.time_label
              const isHovered = activeIdx === idx

              return (
                <g key={pt.time_label + idx} className="point-group">
                  {/* Invisible 44px+ touch & click hit target */}
                  <circle
                    cx={cx}
                    cy={cy}
                    r="24"
                    fill="transparent"
                    style={{ cursor: 'pointer', touchAction: 'manipulation' }}
                    onClick={() => {
                      setSelectedPoint((prev) => (prev?.time_label === pt.time_label ? null : pt))
                      setHoveredIdx(idx)
                      setFocusedIdx(idx)
                    }}
                    onMouseEnter={() => setHoveredIdx(idx)}
                    onMouseLeave={() => setHoveredIdx(null)}
                    onTouchStart={() => {
                      setHoveredIdx(idx)
                      setFocusedIdx(idx)
                    }}
                  />

                  {/* Outer selection / hover halo */}
                  {(isSelected || isHovered) && (
                    <circle
                      cx={cx}
                      cy={cy}
                      r={isSelected ? 14 : 11}
                      fill="none"
                      stroke="var(--terracotta)"
                      strokeWidth="1.5"
                      strokeOpacity="0.45"
                    />
                  )}

                  {/* Soft Anomaly Pulse Ring */}
                  {hasAnomaly && (
                    <circle
                      cx={cx}
                      cy={cy}
                      r={isSelected ? 14 : isHovered ? 12 : 10}
                      className="anomaly-pulse-ring"
                      fill="none"
                      stroke="var(--muted-red)"
                      strokeWidth="1.5"
                    />
                  )}

                  {/* Visual data point */}
                  <circle
                    cx={cx}
                    cy={cy}
                    r={isSelected ? 9 : isHovered ? 7.5 : hasAnomaly ? 6.5 : 4.5}
                    fill={
                      isSelected
                        ? '#ffffff'
                        : hasAnomaly
                        ? 'var(--muted-red)'
                        : isHovered
                        ? 'var(--warm-cream)'
                        : 'var(--terracotta)'
                    }
                    stroke={isSelected ? 'var(--terracotta)' : 'var(--warm-cream)'}
                    strokeWidth={isSelected ? 3 : isHovered ? 2.5 : hasAnomaly ? 2 : 1}
                    filter={hasAnomaly ? 'url(#glow-anomaly)' : undefined}
                    className="chart-point"
                    tabIndex={0}
                    role="button"
                    aria-label={`Time bucket ${pt.time_label}: ${pt.flow_count} flows, ${pt.anomaly_count} anomalies. Click or press Enter to inspect.`}
                    aria-pressed={isSelected}
                    onClick={() => {
                      setSelectedPoint((prev) => (prev?.time_label === pt.time_label ? null : pt))
                      setHoveredIdx(idx)
                      setFocusedIdx(idx)
                    }}
                    onFocus={() => {
                      setFocusedIdx(idx)
                      setHoveredIdx(idx)
                    }}
                    onBlur={() => {
                      if (focusedIdx === idx) setFocusedIdx(null)
                    }}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter' || e.key === ' ') {
                        e.preventDefault()
                        setSelectedPoint((prev) => (prev?.time_label === pt.time_label ? null : pt))
                      }
                    }}
                  />
                </g>
              )
            })}
          </g>
        </svg>

        {/* Floating Tooltip with Intelligent Clamping */}
        {activeIdx !== null && (
          (() => {
            const activePt = dataPoints[activeIdx]
            const cx = getX(activeIdx)
            const cy = getY(activePt.inbound_val)
            const tooltipLeft =
              cx > 440
                ? Math.max(10, cx - 250)
                : Math.min(cx + 20, 520)
            const tooltipTop = Math.max(10, Math.min(cy - 60, height - 120))

            return (
              <div
                className="chart-tip"
                style={{
                  left: `${tooltipLeft}px`,
                  top: `${tooltipTop}px`,
                }}
              >
                <div className="tip-header">
                  <span className="tip-badge">⏱ {activePt.time_label}</span>
                  <span className="tip-interval">
                    {activePt.bucket_start && activePt.bucket_end
                      ? `${activePt.bucket_start} → ${activePt.bucket_end}`
                      : activePt.timestamp || range}
                  </span>
                </div>
                <div className="tip-grid">
                  <div className="tip-item">
                    <span className="tip-label">Inbound Volume:</span>
                    <span className="tip-val font-mono">{activePt.inbound_val} flows</span>
                  </div>
                  <div className="tip-item">
                    <span className="tip-label">Outbound Ratio:</span>
                    <span className="tip-val font-mono">{activePt.outbound_val}</span>
                  </div>
                  <div className="tip-item">
                    <span className="tip-label">Anomaly Status:</span>
                    <span
                      className="tip-val"
                      style={{
                        color: activePt.anomaly_count > 0 ? 'var(--muted-red)' : 'var(--olive-green)',
                        fontWeight: 600,
                      }}
                    >
                      {activePt.anomaly_count > 0
                        ? `⚠️ ${activePt.anomaly_count} (${activePt.anomaly_note || 'Detected'})`
                        : '✓ 0 (Nominal)'}
                    </span>
                  </div>
                  <div className="tip-item">
                    <span className="tip-label">Traffic Volume:</span>
                    <span className="tip-val font-mono">
                      {activePt.total_packets ?? activePt.flow_count * 20} pkts •{' '}
                      {formatBytes(activePt.total_bytes)}
                    </span>
                  </div>
                  <div className="tip-item">
                    <span className="tip-label">Telemetry Source:</span>
                    <span className="tip-val">{activePt.telemetry_source || 'Gateway Stream'}</span>
                  </div>
                </div>
                <div className="tip-footer">
                  <span>💡 Click, tap or press Enter to inspect bucket details</span>
                </div>
              </div>
            )
          })()
        )}
      </div>

      {/* Time Bucket Labels */}
      <div className="ticks">
        {dataPoints.map((pt, idx) => {
          const isSelected = selectedPoint?.time_label === pt.time_label
          const isHovered = activeIdx === idx

          return (
            <span
              key={pt.time_label}
              onClick={() => {
                setSelectedPoint((prev) => (prev?.time_label === pt.time_label ? null : pt))
                setHoveredIdx(idx)
              }}
              style={{
                cursor: 'pointer',
                fontWeight: isSelected || isHovered ? 700 : 400,
                color: isSelected
                  ? 'var(--terracotta)'
                  : isHovered
                  ? 'var(--warm-cream)'
                  : 'inherit',
                transition: 'color 0.15s ease',
              }}
            >
              {pt.time_label}
            </span>
          )
        })}
      </div>

      {/* Selected Point Detailed Telemetry Inspection Panel (Drawer) */}
      {selectedPoint && (
        <div
          className="telemetry-inspection-panel"
          role="region"
          aria-label="Detailed Telemetry Bucket Inspection"
        >
          <div className="panel-header">
            <div className="panel-title-cluster">
              <span className="panel-icon">📡</span>
              <div>
                <h3 className="panel-title">
                  Evaluated Flow Ingestion Telemetry — Bucket {selectedPoint.time_label}
                </h3>
                <span className="panel-time-tag">
                  {selectedPoint.bucket_start && selectedPoint.bucket_end
                    ? `${selectedPoint.bucket_start} — ${selectedPoint.bucket_end}`
                    : `Interval: ${selectedPoint.time_label} (${range})`}
                </span>
              </div>
            </div>
            <div className="panel-actions">
              {onFilterEvents && (
                <button
                  type="button"
                  className="btn-filter-time"
                  onClick={() => onFilterEvents(selectedPoint.time_label)}
                  title="Filter Recent Security Events table to this time interval"
                >
                  🔍 Filter Table by {selectedPoint.time_label}
                </button>
              )}
              <button
                type="button"
                className="btn-panel-close"
                onClick={() => setSelectedPoint(null)}
                aria-label="Close telemetry inspection drawer"
              >
                ✕ Close [Esc]
              </button>
            </div>
          </div>

          <div className="panel-metrics-grid">
            <div className="metric-chip">
              <span className="chip-label">INBOUND FLOWS</span>
              <span className="chip-val font-mono">{selectedPoint.flow_count}</span>
              <span className="chip-sub">Rate: {selectedPoint.inbound_val} flows/eval</span>
            </div>
            <div className="metric-chip">
              <span className="chip-label">OUTBOUND RATIO</span>
              <span className="chip-val font-mono">{selectedPoint.outbound_val}</span>
              <span className="chip-sub">Egress multiplier</span>
            </div>
            <div className="metric-chip">
              <span className="chip-label">ANOMALY STATUS</span>
              <span
                className="chip-val"
                style={{
                  color:
                    selectedPoint.anomaly_count > 0 ? 'var(--muted-red)' : 'var(--olive-green)',
                }}
              >
                {selectedPoint.anomaly_count > 0 ? `⚠️ ${selectedPoint.anomaly_count}` : '✓ 0'}
              </span>
              <span className="chip-sub">
                {selectedPoint.anomaly_note ||
                  (selectedPoint.anomaly_count > 0 ? 'Threat Flagged' : 'All flows nominal')}
              </span>
            </div>
            <div className="metric-chip">
              <span className="chip-label">PACKETS & BYTES</span>
              <span className="chip-val font-mono">
                {selectedPoint.total_packets ?? selectedPoint.flow_count * 20} pkts
              </span>
              <span className="chip-sub">{formatBytes(selectedPoint.total_bytes)}</span>
            </div>
            <div className="metric-chip">
              <span className="chip-label">SOURCE ATTRIBUTION</span>
              <span className="chip-val" style={{ fontSize: '12px', color: 'var(--warm-cream)' }}>
                {selectedPoint.telemetry_source || 'GATEWAY_STREAM'}
              </span>
              <span className="chip-sub">
                {selectedPoint.avg_risk_score !== undefined
                  ? `Avg Risk: ${selectedPoint.avg_risk_score}/100 (Peak: ${selectedPoint.max_risk_score}/100)`
                  : 'Provenance Verified'}
              </span>
            </div>
          </div>

          {/* Correlated Security Events Section */}
          <div className="panel-events-section">
            <div className="events-sub-header">
              <h4>Correlated Security Incidents in this Time Bucket</h4>
              <span className="events-count-badge">
                {bucketEvents.length} {bucketEvents.length === 1 ? 'incident' : 'incidents'}
              </span>
            </div>

            {bucketEvents.length > 0 ? (
              <div className="inspection-table-wrapper">
                <table className="inspection-events-table">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>Event ID</th>
                      <th>Threat / Attack Type</th>
                      <th>Source → Destination</th>
                      <th>Risk</th>
                      <th>Action</th>
                      <th>Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {bucketEvents.map((evt) => (
                      <tr key={evt.id}>
                        <td className="font-mono">{evt.time}</td>
                        <td className="font-mono text-terracotta">{evt.id}</td>
                        <td style={{ fontWeight: 600 }}>{evt.event}</td>
                        <td className="font-mono">
                          {evt.source} → {evt.destination}
                        </td>
                        <td>
                          <span
                            className="risk-tag"
                            style={{
                              color:
                                evt.risk >= 70
                                  ? 'var(--muted-red)'
                                  : evt.risk >= 40
                                  ? 'var(--terracotta)'
                                  : 'var(--olive-green)',
                              fontWeight: 700,
                            }}
                          >
                            {evt.risk}/100
                          </span>
                        </td>
                        <td>
                          <span className="action-tag">{evt.action}</span>
                        </td>
                        <td>
                          <span className={`status-pill status-${evt.status.toLowerCase()}`}>
                            {evt.status}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="honest-aggregated-notice">
                <span className="notice-icon">ℹ️</span>
                <div>
                  <b style={{ color: 'var(--warm-cream)' }}>Aggregated Flow Telemetry Only</b>
                  <p>
                    No discrete individual security threat events were triggered or logged during
                    the {selectedPoint.time_label} bucket. Flows within this interval remained below
                    the anomaly threshold and conformed to baseline gateway traffic policies.
                  </p>
                </div>
              </div>
            )}
          </div>

          <div className="panel-footer">
            <button
              type="button"
              className="btn-return-overview"
              onClick={() => setSelectedPoint(null)}
            >
              ← Return to Telemetry Overview
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

function Connectivity({
  flows,
  topology,
  riskScore,
  riskState,
  enforcementMode,
  activeRulesCount,
  lastPcapIngest,
  lastVpcIngest,
  events,
}: {
  flows: number
  topology: HybridTopologySummary | null
  riskScore?: number
  riskState?: PolicyAction
  enforcementMode?: string
  activeRulesCount?: number
  lastPcapIngest?: PcapIngestionResponse | null
  lastVpcIngest?: AwsVpcIngestionResponse | null
  events?: SecurityEvent[]
}) {
  const highRiskCount =
    lastPcapIngest?.high_risk_flows_count ??
    lastVpcIngest?.high_risk_flows_count ??
    (events ? events.filter((e) => e.risk >= 70).length : 0)

  const packetsCaptured =
    lastPcapIngest?.metrics.packets_processed ??
    (events ? events.length * 25 : 0)

  const flowsGenerated =
    lastPcapIngest?.metrics.flows_generated ??
    lastVpcIngest?.total_flows_aggregated ??
    flows

  const flowsEvaluated =
    lastPcapIngest?.flows_evaluated ??
    lastVpcIngest?.total_flows_aggregated ??
    flows

  const isSampled = Boolean(lastPcapIngest?.is_sampled)
  const [selectedSegment, setSelectedSegment] = useState<'onprem' | 'gateway' | 'cloud' | null>(null)
  const isTrafficActive = flows > 0 || packetsCaptured > 0

  return (
    <div className="connect">
      <div className="title-line">
        <div>
          <h2>Hybrid Cloud Connectivity &amp; Infrastructure Topology</h2>
          <p>
            <i className={`status-ping-dot ${isTrafficActive ? 'active' : 'idle'}`} /> Verified Hybrid Lab Architecture •{' '}
            <strong>On-Prem (10.10.10.0/24) ↔ Edge Gateway ↔ Simulated Cloud VPC (10.20.10.0/24)</strong>
          </p>
        </div>
        <div className="topology-badge-cluster">
          <span className="topology-badge mode-badge" title="Simulated Cloud VPC Telemetry Mode">
            ☁ {topology?.telemetry_mode || 'AWS_FIXTURE'}
          </span>
          <span className="topology-badge rule-badge" title="Enforcement Isolation State">
            🛡️ {enforcementMode || 'DRY_RUN'} ({activeRulesCount ?? 0} rules)
          </span>
          <span className="topology-flows-tally">
            <b className="tally-num">{flows}</b> persisted flows
          </span>
        </div>
      </div>

      <div className={`topology-stage ${!isTrafficActive ? 'idle' : 'active'}`}>
        {/* Enclave 1: On-Premises Enterprise DC */}
        <div
          className={`topo-enclave onprem-enclave ${selectedSegment === 'onprem' ? 'selected' : ''}`}
          onClick={() => setSelectedSegment(selectedSegment === 'onprem' ? null : 'onprem')}
          role="button"
          tabIndex={0}
          aria-label="On-Premises Zone enclave. Click or press Enter to inspect."
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault()
              setSelectedSegment(selectedSegment === 'onprem' ? null : 'onprem')
            }
          }}
        >
          <div className="enclave-header">
            <div className="enclave-icon-box">🏢</div>
            <div className="enclave-title-box">
              <span className="enclave-sub">SITE A • LOCAL DC</span>
              <strong className="enclave-name">On-Premises Zone</strong>
            </div>
          </div>
          <div className="enclave-subnet-chip">
            <code>10.10.10.0/24</code>
          </div>
          <div className="enclave-workloads-grid">
            <div className="workload-node">
              <i className="node-status-dot online" />
              <span>onprem-client (<code>.10</code>)</span>
            </div>
            <div className="workload-node">
              <i className="node-status-dot online" />
              <span>onprem-web (<code>.20</code>)</span>
            </div>
            <div className="workload-node">
              <i className="node-status-dot online" />
              <span>onprem-workload (<code>.30</code>)</span>
            </div>
            <div className="workload-node">
              <i className="node-status-dot online" />
              <span>traffic-gen (<code>.50</code>)</span>
            </div>
          </div>
          <div className="enclave-iface-footer">
            <span className="iface-tag">eth0 • 10.10.10.2</span>
            <span className="enclave-tag">Private Lab Net</span>
          </div>
        </div>

        {/* Conduit 1: On-Prem to Gateway with packet animation */}
        <div className="topo-conduit" title="Bi-directional GRE / VxLAN Tunnel">
          <div className="conduit-line">
            <span className="conduit-pulse forward" />
            <span className="conduit-packet p1 forward" />
            <span className="conduit-packet p2 forward" />
          </div>
          <div className="conduit-badge">
            <span className="conduit-label">ON_PREM_TO_CLOUD →</span>
            <small className="conduit-proto">GRE / VxLAN</small>
          </div>
        </div>

        {/* Enclave 2: Central AI Security Gateway */}
        <div
          className={`topo-enclave gateway-enclave central ${selectedSegment === 'gateway' ? 'selected' : ''}`}
          onClick={() => setSelectedSegment(selectedSegment === 'gateway' ? null : 'gateway')}
          role="button"
          tabIndex={0}
          aria-label="Adaptive AI Gateway central enclave. Click or press Enter to inspect."
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault()
              setSelectedSegment(selectedSegment === 'gateway' ? null : 'gateway')
            }
          }}
        >
          <div className="gateway-core-shield">
            <span className="gateway-symbol">🛡️</span>
            <div className="gateway-pulse-ring" />
          </div>
          <div className="gateway-title-box">
            <span className="gateway-badge">INLINE ENFORCEMENT</span>
            <strong className="gateway-name">Adaptive AI Gateway</strong>
          </div>
          <div className="gateway-bridge-spec">
            <code>10.10.10.2 (eth0) ↔ 10.20.10.2 (eth1)</code>
          </div>
          <div className="gateway-engine-card">
            <span className="engine-model-label">XGBoost V2 + TreeSHAP</span>
            <div className="gateway-telemetry-readout">
              <span className="risk-metric">
                Risk: <b>{riskScore ?? 0}/100</b>
              </span>
              <span className="policy-metric">
                Policy: <b className={`action-badge ${(riskState || 'allow').toLowerCase()}`}>{riskState || 'Allow'}</b>
              </span>
            </div>
          </div>
          <div className="gateway-footer-status">
            <span className={`status-pill ${enforcementMode === 'SANDBOX' ? 'sandbox' : 'dryrun'}`}>
              ● {enforcementMode === 'SANDBOX' ? 'Sandbox Active' : 'Dry-Run Mode'}
            </span>
          </div>
        </div>

        {/* Conduit 2: Gateway to Cloud with packet animation */}
        <div className="topo-conduit" title="VPC Flow Logs & Cloud Telemetry Conduits">
          <div className="conduit-line">
            <span className="conduit-pulse reverse" />
            <span className="conduit-packet p1 reverse" />
            <span className="conduit-packet p2 reverse" />
          </div>
          <div className="conduit-badge">
            <span className="conduit-label">← CLOUD_TO_ON_PREM</span>
            <small className="conduit-proto">VPC Flow Logs</small>
          </div>
        </div>

        {/* Enclave 3: Simulated Cloud VPC */}
        <div
          className={`topo-enclave cloud-enclave ${selectedSegment === 'cloud' ? 'selected' : ''}`}
          onClick={() => setSelectedSegment(selectedSegment === 'cloud' ? null : 'cloud')}
          role="button"
          tabIndex={0}
          aria-label="Simulated Cloud VPC enclave. Click or press Enter to inspect."
          onKeyDown={(e) => {
            if (e.key === 'Enter' || e.key === ' ') {
              e.preventDefault()
              setSelectedSegment(selectedSegment === 'cloud' ? null : 'cloud')
            }
          }}
        >
          <div className="enclave-header">
            <div className="enclave-icon-box cloud-icon">☁</div>
            <div className="enclave-title-box">
              <span className="enclave-sub">{topology?.aws_region || 'us-east-1'} • HYBRID VPC</span>
              <strong className="enclave-name">Simulated Cloud VPC</strong>
            </div>
          </div>
          <div className="enclave-subnet-chip">
            <code>10.20.10.0/24</code>
          </div>
          <div className="enclave-workloads-grid">
            <div className="workload-node">
              <i className="node-status-dot online" />
              <span>cloud-client (<code>.10</code>)</span>
            </div>
            <div className="workload-node">
              <i className="node-status-dot online" />
              <span>cloud-web (<code>.20</code>)</span>
            </div>
            <div className="workload-node">
              <i className="node-status-dot online" />
              <span>cloud-db (<code>.30</code>)</span>
            </div>
            <div className="workload-node">
              <i className="node-status-dot online" />
              <span>cloud-workload (<code>.40</code>)</span>
            </div>
          </div>
          <div className="enclave-iface-footer">
            <span className="iface-tag">eth1 • 10.20.10.2</span>
            <span className="enclave-tag">Simulated AWS VPC</span>
          </div>
        </div>
      </div>

      {/* Dynamic Segment Inspector Callout */}
      {selectedSegment && (
        <div className="topology-segment-inspector motion-fade-in">
          <div className="inspector-left">
            <span className="inspector-badge">SEGMENT INSPECTION</span>
            <strong className="inspector-title">
              {selectedSegment === 'onprem' && 'On-Premises Enterprise DC (10.10.10.0/24) • Site A Workloads'}
              {selectedSegment === 'gateway' && 'Adaptive AI Security Gateway (Inline eth0 ↔ eth1) • XGBoost V2 & Containment Engine'}
              {selectedSegment === 'cloud' && `Simulated Cloud VPC (10.20.10.0/24) • ${topology?.aws_region || 'us-east-1'} Subnet Target`}
            </strong>
          </div>
          <div className="inspector-right">
            <span className="inspector-detail">
              {selectedSegment === 'onprem' && '4 docker lab workloads (client, web, workload, traffic-gen) feeding ingress network telemetry.'}
              {selectedSegment === 'gateway' && 'Linux transit router agent with real-time SHAP feature attribution and automated iptables quarantine.'}
              {selectedSegment === 'cloud' && 'AWS VPC CloudWatch flow log receiver and candidate shadow evaluation destination.'}
            </span>
            <button
              type="button"
              className="inspector-dismiss-btn"
              onClick={() => setSelectedSegment(null)}
              aria-label="Close segment inspection"
            >
              ✕ Close
            </button>
          </div>
        </div>
      )}

      <div className="topology-metrics-ribbon">
        <div className="topo-metric-item">
          <small>Packets Processed</small>
          <b>{packetsCaptured.toLocaleString()}</b>
        </div>
        <div className="topo-metric-item">
          <small>Flows Generated / Eval</small>
          <b>
            {flowsGenerated.toLocaleString()} / {flowsEvaluated.toLocaleString()} {isSampled ? '(Sampled)' : ''}
          </b>
        </div>
        <div className="topo-metric-item">
          <small>High-Risk Flows</small>
          <b className={highRiskCount > 0 ? 'text-danger' : 'text-success'}>{highRiskCount}</b>
        </div>
        <div className="topo-metric-item">
          <small>Persisted DB Events</small>
          <b className="text-terracotta">{flows.toLocaleString()}</b>
        </div>
        <div className="topo-metric-item">
          <small>State Provenance</small>
          <b className="text-sand">
            {lastPcapIngest
              ? 'Observed PCAP'
              : lastVpcIngest
              ? 'Simulated VPC Log'
              : 'Configured + DB'}
          </b>
        </div>
      </div>
    </div>
  )
}

const riskClass = (risk: number) =>
  risk >= 80 ? 'r87' : risk >= 70 ? 'r76' : risk >= 60 ? 'r64' : 'r52'

export default function App() {
  const [data, setData] = useState<DashboardData | null>(null)
  const [isLiveBackend, setIsLiveBackend] = useState(false)
  const [search, setSearch] = useState('')
  const [range, setRange] = useState('Last 24 hours')
  const [activeNav, setActiveNav] = useState('Dashboard')
  const [activeSubTab, setActiveSubTab] = useState<string>('OVERVIEW')
  const [expandedGroups, setExpandedGroups] = useState<Record<string, boolean>>({
    overview: true,
    security_ops: true,
    multi_cloud: true,
    ai_intelligence: true,
    administration: true,
  })

  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)

  const toggleNavGroup = (groupId: string) => {
    setExpandedGroups((prev) => ({
      ...prev,
      [groupId]: !prev[groupId],
    }))
  }
  const [selected, setSelected] = useState<SecurityEvent | null>(null)
  const [toast, setToast] = useState('')
  const [loading, setLoading] = useState(true)

  // Dashboard Telemetry Synchronization State (Phase 14)
  const [isSyncing, setIsSyncing] = useState<boolean>(false)
  const [lastSyncTime, setLastSyncTime] = useState<Date | null>(null)
  const dashboardAbortRef = useRef<AbortController | null>(null)
  const isRefreshingRef = useRef<boolean>(false)
  const pendingRefreshRef = useRef<boolean>(false)
  const loadDashboardRef = useRef<((timeRangeStr?: string) => void) | null>(null)

  // User Authentication State (Phase 13)
  const [authUser, setAuthUser] = useState<AuthUser | null>(authService.getUser())
  const [isAuthChecked, setIsAuthChecked] = useState(() => !authService.isAuthenticated())

  // Search Results Dropdown State
  const [searchResults, setSearchResults] = useState<SearchResults | null>(null)
  const [searching, setSearching] = useState(false)
  const [showSearchDropdown, setShowSearchDropdown] = useState(false)

  // Persistent Notifications State
  const [showNotifications, setShowNotifications] = useState(false)
  const [notifications, setNotifications] = useState<NotificationItem[]>([])

  // Profile & Environment State (Truthful Local Console Identity)
  const [showProfileModal, setShowProfileModal] = useState(false)
  const [profile, setProfile] = useState<SystemProfile | null>(null)
  const [showEnvMenu, setShowEnvMenu] = useState(false)
  const [currentEnv, setCurrentEnv] = useState<string>(() => {
    return sessionStorage.getItem('hgs_current_env') || 'SANDBOX'
  })

  // Live Threat Analyzer State
  const [showAnalyzer, setShowAnalyzer] = useState(false)
  const [flowInput, setFlowInput] = useState<FlowPredictionRequest>(DEFAULT_FLOW_INPUT)
  const [predictResult, setPredictResult] = useState<FlowPredictionResponse | null>(null)
  const [predicting, setPredicting] = useState(false)
  const [presets, setPresets] = useState<Record<string, FlowPredictionRequest>>({})

  // PCAP Ingestion State
  const [showIngestModal, setShowIngestModal] = useState(false)
  const [samplePcaps, setSamplePcaps] = useState<SamplePcapInfo[]>([])
  const [ingesting, setIngesting] = useState(false)
  const [ingestResponse, setIngestResponse] = useState<PcapIngestionResponse | null>(null)

  // Policy & Active Enforcement State
  const [showRulesModal, setShowRulesModal] = useState(false)
  const [activeRules, setActiveRules] = useState<ActiveEnforcementRule[]>([])
  const [enforcementConfig, setEnforcementConfig] = useState<EnforcementConfig | null>(null)
  const [comparisonResult, setComparisonResult] = useState<PolicyComparisonResult | null>(null)
  const [comparing, setComparing] = useState(false)

  // Hybrid Cloud & AWS VPC Flow Log State
  const [topology, setTopology] = useState<HybridTopologySummary | null>(null)
  const [awsVpcSamples, setAwsVpcSamples] = useState<AwsVpcSampleFixtureInfo[]>([])
  const [ingestTab, setIngestTab] = useState<'PCAP' | 'AWS_VPC'>('PCAP')
  const [awsVpcResponse, setAwsVpcResponse] = useState<AwsVpcIngestionResponse | null>(null)
  const [rawVpcText, setRawVpcText] = useState('')
  const [ingestingVpc, setIngestingVpc] = useState(false)

  // Explainability & Incident Review State
  const [selectedExplanation, setSelectedExplanation] = useState<EventExplanationResponse | null>(null)
  const [loadingExplanation, setLoadingExplanation] = useState(false)

  // AI Security Copilot Briefing State
  const [aiBriefing, setAiBriefing] = useState<AICopilotBriefing | null>(null)
  const [loadingAiBriefing, setLoadingAiBriefing] = useState(false)

  // Initial Auth Verification Lifecycle
  useEffect(() => {
    let mounted = true
    if (authService.isAuthenticated()) {
      authService
        .getMe()
        .then((user) => {
          if (mounted) {
            setAuthUser(user)
            setIsAuthChecked(true)
          }
        })
        .catch(() => {
          if (mounted) {
            setAuthUser(null)
            setIsAuthChecked(true)
          }
        })
    }

    const unsubscribe = authService.subscribe((u) => {
      if (mounted) setAuthUser(u)
    })

    return () => {
      mounted = false
      unsubscribe()
    }
  }, [])

  useEffect(() => {
    if (!selected) {
      return
    }
    let ignore = false
    queueMicrotask(() => {
      if (!ignore) {
        setLoadingExplanation(true)
        setSelectedExplanation(null)
        setAiBriefing(null)
      }
    })
    getEventExplanation(selected.id)
      .then((exp) => {
        if (!ignore) setSelectedExplanation(exp)
      })
      .catch(() => {})
      .finally(() => {
        if (!ignore) setLoadingExplanation(false)
      })
    return () => {
      ignore = true
    }
  }, [selected])

  // Thread-safe and debounced dashboard loader with request cancellation (Phase 14)
  const loadDashboard = useCallback((timeRangeStr = range) => {
    if (isRefreshingRef.current) {
      pendingRefreshRef.current = true
      return
    }

    if (dashboardAbortRef.current) {
      dashboardAbortRef.current.abort()
    }
    const controller = new AbortController()
    dashboardAbortRef.current = controller
    isRefreshingRef.current = true
    setIsSyncing(true)

    getDashboard(timeRangeStr, controller.signal)
      .then((res) => {
        setData(res.data)
        setIsLiveBackend(res.isLiveBackend)
        setLastSyncTime(new Date())
        if (res.data.notifications) {
          setNotifications(res.data.notifications)
        }
      })
      .catch((err) => {
        if (err?.name !== 'AbortError') {
          setToast('Could not load dashboard data.')
        }
      })
      .finally(() => {
        isRefreshingRef.current = false
        setIsSyncing(false)
        setLoading(false)
        if (pendingRefreshRef.current) {
          pendingRefreshRef.current = false
          loadDashboardRef.current?.(timeRangeStr)
        }
      })
  }, [range])

  useEffect(() => {
    loadDashboardRef.current = loadDashboard
  }, [loadDashboard])

  // Ingestion completion notification handler
  const handleTelemetryIngested = useCallback(
    (batch: CloudTelemetryBatchResponse) => {
      loadDashboard(range)
      setToast(
        `Synchronized ${batch.records_aggregated} new live AWS flows with dashboard.`
      )
    },
    [range, loadDashboard]
  )

  // Global event listener for telemetry ingestion across views
  useEffect(() => {
    const handleGlobalIngest = (e: Event) => {
      const detail = (e as CustomEvent).detail
      if (detail && (detail.records_aggregated > 0 || detail.records_parsed > 0)) {
        loadDashboard(range)
      }
    }
    window.addEventListener('hgs:telemetry-ingested', handleGlobalIngest)
    return () => window.removeEventListener('hgs:telemetry-ingested', handleGlobalIngest)
  }, [range, loadDashboard])

  // Load telemetry and gateway operational data once authenticated
  useEffect(() => {
    if (!authUser) return

    loadDashboard(range)

    getPresets()
      .then(setPresets)
      .catch(() => {})

    listSamplePcaps()
      .then(setSamplePcaps)
      .catch(() => {})

    getEnforcementConfig()
      .then((cfg) => {
        setEnforcementConfig(cfg)
        const savedEnv = sessionStorage.getItem('hgs_current_env')
        if (!savedEnv) {
          setCurrentEnv(cfg.active_mode === 'DRY_RUN' ? 'LOCAL' : cfg.active_mode)
        }
      })
      .catch(() => {})

    listEnforcementRules('ACTIVE')
      .then(setActiveRules)
      .catch(() => {})

    getHybridTopology()
      .then(setTopology)
      .catch(() => {})

    getAwsVpcSamples()
      .then(setAwsVpcSamples)
      .catch(() => {})

    getSystemProfile()
      .then(setProfile)
      .catch(() => {})
  }, [authUser, loadDashboard, range])

  const handleRangeChange = (newRange: string) => {
    setRange(newRange)
    loadDashboard(newRange)
    setToast(`Telemetry filter updated: ${newRange}`)
  }

  // Dropdown Mutual Exclusivity and Overlay Management
  const toggleSearchDropdown = (open?: boolean) => {
    const next = open !== undefined ? open : !showSearchDropdown
    setShowSearchDropdown(next)
    if (next) {
      setShowEnvMenu(false)
      setShowNotifications(false)
    }
  }

  const toggleEnvMenu = () => {
    const next = !showEnvMenu
    setShowEnvMenu(next)
    if (next) {
      setShowSearchDropdown(false)
      setShowNotifications(false)
    }
  }

  const toggleNotifications = () => {
    const next = !showNotifications
    setShowNotifications(next)
    if (next) {
      setShowSearchDropdown(false)
      setShowEnvMenu(false)
    }
  }

  const openProfileModal = () => {
    setShowProfileModal(true)
    setShowSearchDropdown(false)
    setShowEnvMenu(false)
    setShowNotifications(false)
  }

  const closeAllTopMenus = () => {
    setShowSearchDropdown(false)
    setShowEnvMenu(false)
    setShowNotifications(false)
  }

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        closeAllTopMenus()
        if (showProfileModal) setShowProfileModal(false)
        if (showAnalyzer) setShowAnalyzer(false)
        if (showIngestModal) setShowIngestModal(false)
        if (showRulesModal) setShowRulesModal(false)
        if (selected) setSelected(null)
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [showProfileModal, showAnalyzer, showIngestModal, showRulesModal, selected])

  const handleSelectSearchResult = (item: { id: string; result_type: string }) => {
    setShowSearchDropdown(false)
    if (item.result_type === 'EVENT') {
      const ev = data?.events.find((e) => e.id === item.id)
      if (ev) {
        setSelected(ev)
      } else {
        setSelected({
          id: item.id,
          time: '12:00:00',
          event: `Security Incident ${item.id}`,
          source: '192.168.1.100',
          destination: '10.100.1.10',
          risk: 75,
          severity: 'high',
          action: 'Restrict',
          status: 'Applied',
          description: `Search selected incident: ${item.id}`,
        })
      }
    } else if (item.result_type === 'RULE') {
      refreshRules()
      setShowRulesModal(true)
    }
  }

  const handleSelectNotification = async (notif: NotificationItem) => {
    // Persist read status to PostgreSQL
    await markNotificationRead(notif.event_id)
    setNotifications((prev) =>
      prev.map((n) => (n.id === notif.id ? { ...n, is_read: true } : n))
    )
    setShowNotifications(false)

    const ev = data?.events.find((e) => e.id === notif.event_id)
    if (ev) {
      setSelected(ev)
    } else {
      setSelected({
        id: notif.event_id,
        time: notif.time,
        event: notif.title,
        source: notif.source,
        destination: notif.destination,
        risk: notif.risk,
        severity: notif.severity as any,
        action: 'Restrict',
        status: 'Applied',
        description: `Alert notification for ${notif.attack_type} on ${notif.source}.`,
      })
    }
  }

  const handleMarkAllNotificationsRead = async () => {
    await markAllNotificationsRead()
    setNotifications((prev) => prev.map((n) => ({ ...n, is_read: true })))
    setToast('All security notifications marked as read in database.')
  }

  const handleGenerateAiBriefing = async () => {
    if (!selected) return
    setLoadingAiBriefing(true)
    try {
      const briefing = await getAICopilotBriefing(selected.id)
      setAiBriefing(briefing)
    } catch (err) {
      setToast(`AI briefing error: ${String(err)}`)
    } finally {
      setLoadingAiBriefing(false)
    }
  }

  const filtered = useMemo(
    () =>
      data?.events.filter((event) =>
        Object.values(event).join(' ').toLowerCase().includes(search.toLowerCase())
      ) ?? [],
    [data, search]
  )

  const updateAction = async (action: PolicyAction) => {
    if (!selected) return
    try {
      const res = await applyAction(selected.id, action)
      setData((previous) =>
        previous
          ? {
              ...previous,
              events: previous.events.map((event) =>
                event.id === selected.id
                  ? { ...event, action, status: res.status as any }
                  : event
              ),
            }
          : previous
      )
      setToast(`Policy action '${action}' applied to ${selected.source}. Sandbox rule created.`)
      setSelected(null)
      await refreshRules()
      loadDashboard(range)
    } catch (err) {
      setToast(`Failed to apply action: ${String(err)}`)
    }
  }

  const runLiveInference = async () => {
    setPredicting(true)
    try {
      const res = await predictFlow(flowInput)
      setPredictResult(res)
      setToast(`ML Inference Complete: ${res.attack_type} (Risk: ${res.risk_score})`)
      loadDashboard(range)
    } catch (err) {
      setToast(`Inference error: ${String(err)}`)
    } finally {
      setPredicting(false)
    }
  }

  const selectPreset = (presetKey: string) => {
    const preset = presets[presetKey]
    if (preset) {
      setFlowInput({ ...preset })
      setPredictResult(null)
    }
  }

  const handleIngestSample = async (filename: string) => {
    if (ingesting) return
    setIngesting(true)
    try {
      const res = await ingestSamplePcap(filename, true)
      setIngestResponse(res)
      const flowMsg = res.is_sampled
        ? `${res.flows_evaluated} evaluated of ${res.metrics.flows_generated} flows`
        : `${res.flows_evaluated} flows evaluated`
      setToast(`Ingested ${res.filename}: ${res.metrics.packets_processed} pkts -> ${flowMsg}.`)
      loadDashboard(range)
      refreshRules()
    } catch (err: any) {
      setToast(`PCAP Ingestion error: ${err?.message || String(err)}`)
    } finally {
      setIngesting(false)
    }
  }

  const handleUploadPcap = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    if (ingesting) return
    setIngesting(true)
    try {
      const res = await uploadPcapFile(file, true)
      setIngestResponse(res)
      const flowMsg = res.is_sampled
        ? `${res.flows_evaluated} evaluated of ${res.metrics.flows_generated} flows`
        : `${res.flows_evaluated} flows`
      setToast(`Uploaded & Ingested ${res.filename}: ${res.metrics.packets_processed} pkts -> ${flowMsg}.`)
      loadDashboard(range)
      refreshRules()
    } catch (err: any) {
      setToast(`Upload error: ${err?.message || String(err)}`)
    } finally {
      setIngesting(false)
      e.target.value = ''
    }
  }

  const handleIngestAwsSample = async (sampleId: string) => {
    setIngestingVpc(true)
    try {
      const res = await ingestAwsVpcSample(sampleId, true)
      setAwsVpcResponse(res)
      setToast(`Ingested AWS VPC sample '${sampleId}': ${res.total_flows_aggregated} flows evaluated & persisted.`)
      loadDashboard(range)
      refreshRules()
    } catch (err) {
      setToast(`AWS VPC Ingestion error: ${String(err)}`)
    } finally {
      setIngestingVpc(false)
    }
  }

  const handleIngestRawVpcLogs = async () => {
    if (!rawVpcText.trim()) return
    setIngestingVpc(true)
    try {
      const res = await ingestRawVpcLogs(rawVpcText, false, 'custom_raw_vpc_input')
      setAwsVpcResponse(res)
      setToast(`Ingested custom AWS VPC logs: ${res.total_flows_aggregated} flows evaluated & persisted.`)
      loadDashboard(range)
      refreshRules()
    } catch (err) {
      setToast(`Raw VPC Log ingestion error: ${String(err)}`)
    } finally {
      setIngestingVpc(false)
    }
  }

  const refreshRules = async () => {
    try {
      const rules = await listEnforcementRules('ACTIVE')
      setActiveRules(rules)
      const conf = await getEnforcementConfig()
      setEnforcementConfig(conf)
    } catch {
      // ignore
    }
  }

  const handleRevokeRule = async (ruleId: string) => {
    try {
      await revokeEnforcementRule(ruleId, 'SecOps Local Console')
      setToast(`Containment rule '${ruleId}' revoked.`)
      await refreshRules()
      loadDashboard(range)
    } catch (err) {
      setToast(`Failed to revoke rule: ${String(err)}`)
    }
  }

  const handleSelectEnv = async (env: 'SANDBOX' | 'LOCAL' | 'AWS_FIXTURE' | 'LIVE_AWS') => {
    setCurrentEnv(env)
    sessionStorage.setItem('hgs_current_env', env)
    if (env === 'SANDBOX') {
      try {
        const conf = await updateEnforcementMode('SANDBOX')
        setEnforcementConfig(conf)
        setToast('Execution mode switched to In-Memory Sandbox Lab.')
      } catch (err) {
        setToast(`Sandbox mode update error: ${String(err)}`)
      }
    } else if (env === 'LOCAL') {
      try {
        const conf = await updateEnforcementMode('DRY_RUN')
        setEnforcementConfig(conf)
        setToast('Execution mode switched to Local Dev (Dry-Run). Zero host network changes.')
      } catch (err) {
        setToast(`Local mode update error: ${String(err)}`)
      }
    } else if (env === 'AWS_FIXTURE') {
      setActiveNav('AWS VPC Logs')
      setToast('Switched to AWS VPC Flow Fixtures mode (Deterministic offline logs).')
    } else if (env === 'LIVE_AWS') {
      setActiveNav('AWS VPC Logs')
      setToast('Connected to Live AWS CloudWatch in Read-Only mode (Account: 698766075180, Region: ap-southeast-2).')
    }
  }

  const handleToggleMode = async (mode: 'DRY_RUN' | 'SANDBOX') => {
    try {
      const conf = await updateEnforcementMode(mode)
      setEnforcementConfig(conf)
      setCurrentEnv(mode === 'DRY_RUN' ? 'LOCAL' : 'SANDBOX')
      setToast(`Enforcement adapter mode switched to ${mode}.`)
    } catch (err) {
      setToast(`Mode switch error: ${String(err)}`)
    }
  }

  const handleComparePolicies = async () => {
    setComparing(true)
    try {
      const res = await comparePolicies(flowInput)
      setComparisonResult(res)
      setToast(`Comparison complete: Divergence=${res.decision_divergence ? 'YES' : 'NO'}`)
    } catch (err) {
      setToast(`Policy comparison error: ${String(err)}`)
    } finally {
      setComparing(false)
    }
  }

  const openTopIncident = () => {
    if (!data || data.events.length === 0) return
    const topEvent = data.events.reduce((prev, curr) => (curr.risk > prev.risk ? curr : prev), data.events[0])
    setSelected(topEvent)
  }

  const unreadCount = notifications.filter((n) => !n.is_read).length

  if (!isAuthChecked) {
    return (
      <div className="auth-container">
        <div className="auth-spinner" style={{ width: '36px', height: '36px', borderWidth: '3px' }} />
      </div>
    )
  }

  if (!authUser) {
    return (
      <AuthView
        onAuthSuccess={(user) => {
          setAuthUser(user)
          loadDashboard()
        }}
      />
    )
  }

  if (loading || !data) return <div className="loading">Loading security overview…</div>

  return (
    <div className="app" onClick={() => { setShowSearchDropdown(false); setShowNotifications(false); setShowEnvMenu(false); }}>
      {mobileMenuOpen && (
        <div
          className="sidebar-backdrop"
          onClick={() => setMobileMenuOpen(false)}
        />
      )}
      <aside className={`sidebar ${mobileMenuOpen ? 'mobile-open' : ''}`}>
        <div className="brand">
          <div className="brand-title-wrap">
            <i>⬡</i>
            <b>
              Adaptive AI-Powered
              <br />
              Hybrid Cloud Security Gateway
            </b>
          </div>
          <button
            type="button"
            className="mobile-sidebar-close"
            onClick={() => setMobileMenuOpen(false)}
            aria-label="Close sidebar"
            title="Close sidebar"
          >
            ✕
          </button>
        </div>
        <nav>
          {navGroups.map((group) => {
            const isExpanded = expandedGroups[group.id] !== false
            return (
              <div key={group.id} className="nav-group">
                <button
                  type="button"
                  className="nav-group-header"
                  onClick={() => toggleNavGroup(group.id)}
                >
                  <div className="nav-group-header-left">
                    <i>{group.icon}</i>
                    <span>{group.title}</span>
                  </div>
                  <span className={`nav-group-chevron ${isExpanded ? 'expanded' : 'collapsed'}`}>
                    ▾
                  </span>
                </button>
                {isExpanded && (
                  <div className="nav-group-items">
                    {group.items.map((item) => {
                      const isActive =
                        activeNav === item.view &&
                        (!item.subTab || activeSubTab === item.subTab)
                      return (
                        <button
                          key={item.id}
                          className={`${isActive ? 'active' : ''} ${item.subTab ? 'nav-item-sub' : ''}`}
                          onClick={() => {
                            setActiveNav(item.view)
                            if (item.subTab) {
                              setActiveSubTab(item.subTab)
                            }
                            if ((item.view === 'Dashboard' || item.view === 'Overview') && activeNav !== item.view) {
                              loadDashboard()
                            }
                            setMobileMenuOpen(false)
                          }}
                        >
                          <i>{item.icon}</i>
                          <span>{item.name}</span>
                        </button>
                      )
                    })}
                  </div>
                )}
              </div>
            )
          })}
        </nav>
        <div className="health">
          <i /> <b>System Operational</b>
          <span>
            {isLiveBackend ? 'FastAPI ML Engine Connected' : 'Local Fallback Mode'}
            <br />
            Uptime: {data.processUptime || data.uptime || 'Process Active'}
          </span>
        </div>
      </aside>

      <main>
        <header onClick={(e) => e.stopPropagation()}>
          <div className="header-zone-left">
            <button
              type="button"
              className="mobile-menu-trigger"
              onClick={() => setMobileMenuOpen((prev) => !prev)}
              aria-label="Toggle navigation"
              title="Open Navigation"
            >
              ☰
            </button>
            <div className="mobile-logo">⬡</div>
            <div className="search-wrapper" style={{ position: 'relative' }}>
              <label className="search">
                <span className="search-icon">⌕</span>
                <input
                  value={search}
                  onChange={(event) => {
                    const val = event.target.value
                    setSearch(val)
                    if (val.trim().length >= 2) {
                      setSearching(true)
                      toggleSearchDropdown(true)
                      searchGateway(val)
                        .then(setSearchResults)
                        .catch(() => {})
                        .finally(() => setSearching(false))
                    } else {
                      setSearchResults(null)
                      toggleSearchDropdown(false)
                    }
                  }}
                  placeholder="Search IP, flow event, rule..."
                  onFocus={() => {
                    if (search.trim().length >= 2) toggleSearchDropdown(true)
                  }}
                />
                <kbd className="search-kbd">Ctrl+K</kbd>
              </label>

              {showSearchDropdown && searchResults && (
                <div className="search-dropdown-menu">
                  <div className="search-dropdown-header">
                    <span>Search Matches ({searchResults.total_matches})</span>
                    <small>{searching ? 'Searching…' : `Query: "${searchResults.query}"`}</small>
                  </div>
                  {searchResults.results.length === 0 ? (
                    <div className="search-empty-item">No events or rules match "{search}".</div>
                  ) : (
                    searchResults.results.map((res) => (
                      <div
                        key={res.id}
                        className="search-result-row"
                        onClick={() => handleSelectSearchResult(res)}
                      >
                        <span className={`search-badge ${res.result_type}`}>{res.result_type}</span>
                        <div className="search-row-text">
                          <b>{res.title}</b>
                          <small>{res.subtitle}</small>
                        </div>
                        {res.risk_score !== undefined && (
                          <span className={`pill ${riskClass(res.risk_score)}`}>{res.risk_score}</span>
                        )}
                      </div>
                    ))
                  )}
                </div>
              )}
            </div>

            <div
              className={`backend-status-tag ${isLiveBackend ? 'online' : 'offline'}`}
              title="FastAPI ML Inference Engine Connection State"
            >
              <i className="status-indicator-dot" />
              <span>{isLiveBackend ? 'FastAPI ML Online' : 'Fallback Offline'}</span>
            </div>
          </div>

          <div className="header-zone-center">
            <div className="header-actions-capsule">
              <button className="analyzer-btn btn-stable" onClick={() => { closeAllTopMenus(); setShowAnalyzer(true); }}>
                ⚡ Test Flow
              </button>
              <button className="analyzer-btn pcap-btn btn-stable" onClick={() => { closeAllTopMenus(); setShowIngestModal(true); }}>
                📥 Ingest PCAP
              </button>
              <button className="analyzer-btn enforce-btn btn-stable" onClick={() => { closeAllTopMenus(); refreshRules(); setShowRulesModal(true); }}>
                🛡️ Rules ({activeRules.length})
              </button>
            </div>
          </div>

          <div className="header-zone-right">
            {/* Integrated Environment & Range Selector Capsule */}
            <div className="header-filter-cluster">
              <div style={{ position: 'relative' }}>
                <button
                  className="select env-select-btn"
                  onClick={toggleEnvMenu}
                  title="Execution Environment Mode"
                >
                  {currentEnv === 'SANDBOX'
                    ? '🧪 Sandbox Lab ⌄'
                    : currentEnv === 'LOCAL' || currentEnv === 'DRY_RUN'
                    ? '💻 Local Dev ⌄'
                    : currentEnv === 'AWS_FIXTURE'
                    ? '☁ AWS Fixture ⌄'
                    : currentEnv === 'LIVE_AWS'
                    ? '☁ Live AWS (RO) ⌄'
                    : '🧪 Sandbox Lab ⌄'}
                </button>
                {showEnvMenu && (
                  <div className="env-dropdown-menu">
                    <div className="env-item" onClick={() => { handleSelectEnv('SANDBOX'); setShowEnvMenu(false); }}>
                      <b>🧪 In-Memory Sandbox Lab</b>
                      <small>Active in-memory quarantine filtering with auto TTL</small>
                    </div>
                    <div className="env-item" onClick={() => { handleSelectEnv('LOCAL'); setShowEnvMenu(false); }}>
                      <b>💻 Local Dev (Dry-Run)</b>
                      <small>Simulation only — zero host network changes</small>
                    </div>
                    <div className="env-item" onClick={() => { handleSelectEnv('AWS_FIXTURE'); setShowEnvMenu(false); }}>
                      <b>☁ AWS VPC Flow Fixtures</b>
                      <small>Deterministic offline AWS CloudWatch log fixtures</small>
                    </div>
                    <div className="env-item" onClick={() => { handleSelectEnv('LIVE_AWS'); setShowEnvMenu(false); }}>
                      <b>☁ Live AWS Read-Only</b>
                      <small>CloudWatch flow logs read-only ingest (Safety Gated)</small>
                    </div>
                  </div>
                )}
              </div>

              <div className="filter-divider" />

              <select
                className="select range-select-btn"
                value={range}
                onChange={(event) => handleRangeChange(event.target.value)}
                aria-label="Time range"
              >
                <option>Last 1 hour</option>
                <option>Last 24 hours</option>
                <option>Last 7 days</option>
                <option>Last 30 days</option>
              </select>
            </div>

            {/* Quick Synchronize Telemetry Button */}
            <button
              className="sync-action-btn"
              onClick={() => {
                loadDashboard(range)
                setToast('Synchronizing gateway telemetry…')
              }}
              disabled={isSyncing}
              title={
                lastSyncTime
                  ? `Last synchronized: ${lastSyncTime.toLocaleTimeString()}`
                  : 'Synchronize telemetry'
              }
            >
              <span className={`sync-icon ${isSyncing ? 'spinning' : ''}`}>
                {isSyncing ? '⏳' : '🔄'}
              </span>
              <span className="sync-text">
                {isSyncing
                  ? 'Updating…'
                  : lastSyncTime
                  ? lastSyncTime.toLocaleTimeString([], {
                      hour: '2-digit',
                      minute: '2-digit',
                      second: '2-digit',
                    })
                  : 'Sync'}
              </span>
            </button>

            {/* Persistent Notifications Bell & Dropdown */}
            <div style={{ position: 'relative' }}>
              <button
                className="alert notif-bell-btn"
                onClick={toggleNotifications}
                title="Security Notifications"
                aria-label="Notifications"
              >
                ♧{unreadCount > 0 && <b className="notif-badge">{unreadCount}</b>}
              </button>

              {showNotifications && (
                <div className="notifications-dropdown-menu">
                  <div className="notif-header">
                    <span>🚨 Security Notifications ({unreadCount} unread)</span>
                    {unreadCount > 0 && (
                      <button className="notif-clear-btn" onClick={handleMarkAllNotificationsRead}>
                        Mark all read
                      </button>
                    )}
                  </div>
                  <div className="notif-list">
                    {notifications.length === 0 ? (
                      <div className="notif-empty">No unread security alerts.</div>
                    ) : (
                      notifications.map((n) => (
                        <div
                          key={n.id}
                          className={`notif-item ${n.is_read ? 'read' : 'unread'}`}
                          onClick={() => handleSelectNotification(n)}
                        >
                          <div className="notif-top">
                            <b>{n.title}</b>
                            <span className={`pill ${riskClass(n.risk)}`}>{n.risk}</span>
                          </div>
                          <p>{n.source} → {n.destination} ({n.attack_type})</p>
                          <small>{n.time} • Click to review incident</small>
                        </div>
                      ))
                    )}
                  </div>
                </div>
              )}
            </div>

            {/* Authenticated Operator Identity */}
            {authUser && (
              <div className="operator-profile-cluster">
                <div
                  className="profile"
                  onClick={openProfileModal}
                  title={`Authenticated Operator: ${authUser.full_name} (${authUser.email})`}
                  style={{ cursor: 'pointer' }}
                >
                  <i className="profile-role-icon">{authUser.role === 'ADMIN' ? '👑' : '🛡️'}</i>
                  <span className="profile-text-wrap">
                    <b>{authUser.full_name}</b>
                    <span className={`auth-user-role-badge ${authUser.role.toLowerCase()}`}>
                      {authUser.role}
                    </span>
                  </span>
                  <span className="profile-chevron">⌄</span>
                </div>
                <button
                  type="button"
                  className="auth-logout-btn"
                  onClick={async () => {
                    await authService.logout()
                    setAuthUser(null)
                    setToast('Session logged out.')
                  }}
                  title="Log Out Session"
                >
                  Log Out
                </button>
              </div>
            )}
          </div>
        </header>

        <div className="content">
          <ErrorBoundary key={activeNav} fallbackTitle={`Unable to display ${activeNav}`}>
            {activeNav === 'Live Network' || activeNav === 'Traffic' ? (
              <TrafficView />
            ) : activeNav === 'Attack Simulation' ? (
              <SimulationView />
            ) : activeNav === 'ML Detection' || activeNav === 'Evaluation' ? (
              <EvaluationView />
            ) : activeNav === 'Explainability (XAI)' || activeNav === 'Reports' ? (
              <AnalyticsView />
            ) : activeNav === 'Policies & Firewall' || activeNav === 'Policies' ? (
              <PoliciesView />
            ) : activeNav === 'PCAP Ingestion' ? (
              <PcapIngestView />
            ) : activeNav === 'AWS VPC Logs' ? (
              <AwsVpcView
                currentEnv={currentEnv}
                onSelectEnv={handleSelectEnv}
                onTelemetryIngested={handleTelemetryIngested}
              />
            ) : activeNav === 'Multi-Cloud' ? (
              <MultiCloudView
                initialTab={activeSubTab}
                onTabChange={(tab: string) => setActiveSubTab(tab)}
              />
            ) : activeNav === 'Security Events' || activeNav === 'Events' ? (
              <EventsView />
            ) : activeNav === 'System Health' ? (
              <SystemHealthView />
            ) : activeNav === 'Settings' ? (
              <SettingsView
                user={authUser}
                onLogout={async () => {
                  await authService.logout()
                  setAuthUser(null)
                  setToast('Session logged out.')
                }}
              />
            ) : (
              <>
                <section className="intro">
                  <div>
                    <h1>SecOps Gateway Console</h1>
                    <p style={{ display: 'flex', alignItems: 'center', gap: '8px', flexWrap: 'wrap' }}>
                      <span>Hybrid cloud security inspection active with real-time AI anomaly evaluation and sandbox isolation.</span>
                      {lastSyncTime && (
                        <span style={{ fontSize: '11px', color: isSyncing ? 'var(--terracotta)' : 'var(--muted-cream)' }}>
                          ● {isSyncing ? 'Synchronizing telemetry…' : `Synchronized at ${lastSyncTime.toLocaleTimeString()}`}
                        </span>
                      )}
                    </p>
                  </div>
                  <div className="metrics">
                    <Metric icon="♢" label="Process Uptime" value={data.processUptime || data.uptime || 'Active'} badge="STABLE" />
                    <Metric icon="⌁" label="Evaluated Events" value={String(data.evaluatedEventsCount || data.activeFlows)} note={`Persisted in ${range}`} badge="INSPECTION" />
                    <Metric icon="◴" label="ML Latency" value={data.inferenceLatency || '1.8 ms'} note="SHAP: ~20.6 ms" badge="XGBOOST V2" />
                    <Metric icon="●" label="Gateway Status" value={data.connectionHealth || 'Healthy'} note={data.connectionNote || 'FastAPI ↔ DB ↔ Model'} green badge="NOMINAL" />
                  </div>
                </section>

                {/* Telemetry Provenance Breakdown Banner */}
                {data.telemetry_provenance && Object.keys(data.telemetry_provenance).length > 0 && (
                  <div className="card provenance-banner">
                    <div className="provenance-left">
                      <span className="provenance-title">Telemetry Provenance</span>
                      <small className="provenance-sub">
                        Data source attribution for evaluated flows, anomaly scores, and model inferences
                      </small>
                    </div>
                    <div className="provenance-badges-wrap">
                      {Object.entries(data.telemetry_provenance).map(([source, count]) => {
                        const isAws = source === 'AWS_VPC_FLOW_LOG'
                        const isPcap = source === 'PCAP_INGESTION'
                        const isLab = source === 'HYBRID_LAB_ROUTER'
                        const isSeed = source === 'DEMO_SEED'
                        const tagClass = isAws ? 'tag-aws' : isPcap ? 'tag-pcap' : isLab ? 'tag-lab' : isSeed ? 'tag-seed' : 'tag-default'
                        return (
                          <span key={source} className={`provenance-chip ${tagClass}`}>
                            <span className="chip-name">{source}</span>
                            <b className="chip-count">{count.toLocaleString()}</b>
                          </span>
                        )
                      })}
                    </div>
                  </div>
                )}

                <section className="top">
                  <article className="card risk-instrument-card">
                    <div className="card-header-line">
                      <div className="card-title-group">
                        <span className="card-glyph">🛡️</span>
                        <h2>Current Risk Score</h2>
                      </div>
                      <span className="live-status-pill">
                        <i className="status-ping-dot" /> LIVE TELEMETRY
                      </span>
                    </div>

                    <div className="risk-body">
                      <div
                        className="gauge-bezel"
                        style={{
                          background: `conic-gradient(${
                            data.riskScore >= 70
                              ? 'var(--muted-red)'
                              : data.riskScore >= 40
                              ? 'var(--terracotta)'
                              : 'var(--olive-green)'
                          } 0% ${Math.min(data.riskScore, 100)}%, rgba(73, 72, 61, 0.25) ${Math.min(data.riskScore, 100)}% 100%)`,
                          boxShadow:
                            data.riskScore >= 70
                              ? '0 0 24px rgba(224, 108, 117, 0.35)'
                              : data.riskScore >= 40
                              ? '0 0 20px rgba(200, 117, 85, 0.3)'
                              : '0 0 20px rgba(133, 139, 89, 0.25)',
                          transition: 'box-shadow var(--duration-slow) var(--ease-smooth), background var(--duration-slow) var(--ease-smooth)'
                        }}
                      >
                        <div className="gauge-dial-core">
                          <span className="gauge-metric-num">{data.riskScore}</span>
                          <span className="gauge-metric-scale">/ 100</span>
                          <span className={`gauge-status-capsule ${riskClass(data.riskScore)}`}>
                            {data.riskState.toUpperCase()}
                          </span>
                        </div>
                      </div>

                      <div className="risk-content-pane">
                        <div className="risk-status-heading">
                          <span className="risk-status-icon">{data.riskScore >= 70 ? '⚠️' : '✓'}</span>
                          <h3>{data.riskScore >= 70 ? 'Elevated Anomaly Detected' : 'Normal Operating Baseline'}</h3>
                        </div>
                        <p className="risk-assessment-desc">
                          {data.riskScore >= 70
                            ? 'Unusual traffic patterns and anomalous flow vectors identified by XGBoost V2 model against learned distribution baselines.'
                            : 'Observed network flow telemetry adheres strictly to learned benign baseline distributions.'}
                        </p>
                        <button className="primary risk-review-btn" onClick={openTopIncident}>
                          <span>Review Incident Details</span>
                          <span className="btn-arrow">→</span>
                        </button>
                      </div>
                    </div>

                    {data.risk_segmentation && (
                      <div className="risk-submeters-row">
                        <div className="risk-submeter-box aws">
                          <div className="submeter-header">
                            <span>AWS Live Telemetry</span>
                            <b>{data.risk_segmentation.aws_live_cloud?.risk_score ?? 0}/100</b>
                          </div>
                          <div className="submeter-track">
                            <div
                              className="submeter-fill terracotta"
                              style={{ width: `${Math.min(data.risk_segmentation.aws_live_cloud?.risk_score ?? 0, 100)}%` }}
                            />
                          </div>
                          <span className="submeter-policy-tag">
                            Policy: {data.risk_segmentation.aws_live_cloud?.policy_action || 'Allow'}
                          </span>
                        </div>
                        <div className="risk-submeter-box lab">
                          <div className="submeter-header">
                            <span>Simulated Lab Replay</span>
                            <b>{data.risk_segmentation.simulated_lab?.risk_score ?? 0}/100</b>
                          </div>
                          <div className="submeter-track">
                            <div
                              className="submeter-fill olive"
                              style={{ width: `${Math.min(data.risk_segmentation.simulated_lab?.risk_score ?? 0, 100)}%` }}
                            />
                          </div>
                          <span className="submeter-policy-tag">
                            Policy: {data.risk_segmentation.simulated_lab?.policy_action || 'Allow'}
                          </span>
                        </div>
                      </div>
                    )}
                  </article>

                  <article className="card reason-card">
                    <div className="card-header-line">
                      <div className="card-title-group">
                        <span className="card-glyph">✦</span>
                        <h2>Top Risk Reasons (Explainable AI)</h2>
                      </div>
                      <span className="engine-badge-pill">TreeSHAP</span>
                    </div>
                    <div className="reasons-list">
                      {data.reasons.map((reason) => (
                        <div className="reason" key={reason.label}>
                          <div className="reason-label-wrap">
                            <span className="reason-feature-name">{reason.label}</span>
                            <b className="reason-pct">{reason.value}%</b>
                          </div>
                          <div className="reason-bar-track">
                            <i className={`reason-bar-fill ${reason.tone}`} style={{ width: `${Math.min(reason.value, 100)}%` }} />
                          </div>
                        </div>
                      ))}
                    </div>
                  </article>

                  <article className="card ai-advisory-card">
                    <div className="card-header-line">
                      <div className="card-title-group">
                        <span className="card-glyph">🧠</span>
                        <h2>AI Copilot Security Advisory</h2>
                      </div>
                      <span className="engine-badge-pill">XGBoost V2 + TreeSHAP</span>
                    </div>
                    <div className="recommend">
                      <div className="recommend-icon-capsule">
                        <i>⬡</i>
                      </div>
                      <section>
                        <h3>{data.riskScore >= 70 ? 'Restrict and Investigate Workload' : 'Maintain Standard Monitoring'}</h3>
                        <div className="recommend-meta-chips">
                          <span className="policy-action-chip">
                            Policy Action: <b>{data.riskState}</b>
                          </span>
                          <span className="containment-mode-chip">
                            Enforcement: <b>{enforcementConfig?.active_mode || currentEnv}</b>
                          </span>
                        </div>
                        <p>
                          {data.riskScore >= 70
                            ? 'Elevated threat probability detected across active flows. Gateway policy engine recommends applying automated restriction to isolate suspicious IP addresses.'
                            : 'All evaluated flows remain within normal Gaussian bounds. Continuing standard hybrid gateway inspection and telemetry harvesting.'}
                        </p>
                        <button className="primary" onClick={openTopIncident}>
                          Review Incident &amp; Briefing <span>→</span>
                        </button>
                      </section>
                    </div>
                  </article>
                </section>

                <section className="middle">
                  <article className="card">
                    <Connectivity
                      flows={data.evaluatedEventsCount || data.activeFlows}
                      topology={topology}
                      riskScore={data.riskScore}
                      riskState={data.riskState}
                      enforcementMode={enforcementConfig?.active_mode || currentEnv}
                      activeRulesCount={activeRules.length}
                      lastPcapIngest={ingestResponse}
                      lastVpcIngest={awsVpcResponse}
                      events={data.events}
                    />
                  </article>
                  <article className="card">
                    <h2>
                      Evaluated Flow Ingestion Telemetry <small>({range})</small>
                    </h2>
                    <Traffic
                      points={data.trafficPoints}
                      range={range}
                      events={data.events}
                      onFilterEvents={(query) => setSearch(query)}
                    />
                  </article>
                </section>

                <section className="bottom">
                  <article className="card events">
                    <div className="title-line">
                      <h2>Recent Security Events (ML Evaluated)</h2>
                      <button onClick={() => setSearch('')}>Clear filters　→</button>
                    </div>
                    <div className="table">
                      <div className="row head">
                        <span>Time</span>
                        <span>Event</span>
                        <span>Source</span>
                        <span>Destination</span>
                        <span>Risk</span>
                        <span>Action</span>
                        <span>Status</span>
                      </div>
                      {filtered.map((event) => (
                        <button className="row event-row" onClick={() => setSelected(event)} key={event.id}>
                          <span>
                            <i className={`dot ${riskClass(event.risk)}`} />
                            {event.time}
                          </span>
                          <span>{event.event}</span>
                          <span>{event.source}</span>
                          <span>{event.destination}</span>
                          <span>
                            <b className={`pill ${riskClass(event.risk)}`}>{event.risk}</b>
                          </span>
                          <span>
                            <b className={`action ${event.action.toLowerCase()}`}>{event.action}</b>
                          </span>
                          <span>
                            <i className={`status ${event.status.toLowerCase()}`} />
                            {event.status}
                          </span>
                        </button>
                      ))}
                      {filtered.length === 0 && <p className="empty">No security events match “{search}”.</p>}
                    </div>
                  </article>

                  <article className="card timeline">
                    <h2>Automated Response Timeline</h2>
                    {(data.timeline && data.timeline.length > 0 ? data.timeline : [
                      { time: '14:32:09', title: 'Containment Restrict Enforced', sub: 'Applied restrict policy to 192.168.1.77', icon: '✹' },
                      { time: '14:28:15', title: 'Containment Block Enforced', sub: 'Applied block policy to 203.0.113.24', icon: '♟' },
                      { time: '14:12:41', title: 'Policy Action: Monitor', sub: 'Applied monitor policy to 198.51.100.9', icon: '◈' },
                      { time: '13:47:22', title: 'Gateway Inspection Online', sub: 'FastAPI ML engine active', icon: '✓' },
                    ]).map((item, idx) => (
                      <div className="step" key={item.id || item.time + idx}>
                        <i>{item.icon}</i>
                        <div>
                          <span>{item.time}</span>
                          <b>{item.title}</b>
                          <small>{item.sub}</small>
                        </div>
                      </div>
                    ))}
                  </article>

                  <article className="card key key-metrics-card">
                    <div className="card-header-line">
                      <div className="card-title-group">
                        <span className="card-glyph">📊</span>
                        <h2>Key Benchmark Metrics</h2>
                      </div>
                      <span className="engine-badge-pill">Validation Suite</span>
                    </div>
                    <div className="key-metrics-grid">
                      <Metric
                        icon="⌘"
                        label="Holdout Detection Rate"
                        value={data.keyMetrics?.detection_rate || '98.5%'}
                        note={data.keyMetrics?.detection_note || 'Holdout Benchmark (N=200)'}
                        green
                        badge="BENCHMARK"
                      />
                      <Metric
                        icon="♢"
                        label="Holdout False Positives"
                        value={data.keyMetrics?.false_positives || '0.0%'}
                        note={data.keyMetrics?.fp_note || 'Holdout Validation Suite'}
                        green
                        badge="VALIDATED"
                      />
                      <Metric
                        icon="◴"
                        label="ML Inference Latency"
                        value={data.keyMetrics?.ml_latency || '1.8 ms (Inference)'}
                        note={data.keyMetrics?.latency_note || 'SHAP Explainer: ~20.6 ms'}
                        badge="P99: 2.1ms"
                      />
                      <Metric
                        icon="▣"
                        label="Active Policies"
                        value={String(data.keyMetrics?.active_policies ?? activeRules.length)}
                        note={data.keyMetrics?.policies_note || `${activeRules.length} in sandbox`}
                        badge="ENFORCED"
                      />
                    </div>
                  </article>
                </section>
              </>
            )}
          </ErrorBoundary>
        </div>
      </main>

      {/* Incident Review Modal with SHAP and AI Security Copilot Briefing */}
      {selected && (
        <div className="modal-backdrop" role="presentation" onMouseDown={() => setSelected(null)}>
          <section
            className="incident-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="incident-title"
            onMouseDown={(event) => event.stopPropagation()}
            style={{ maxWidth: '680px' }}
          >
            <button className="close" onClick={() => setSelected(null)} aria-label="Close incident details">
              ×
            </button>
            <span className="eyebrow">Incident {selected.id}</span>
            <h2 id="incident-title">{selected.event}</h2>
            <p>{selected.description}</p>
            <dl>
              <div>
                <dt>Source</dt>
                <dd>{selected.source}</dd>
              </div>
              <div>
                <dt>Destination</dt>
                <dd>{selected.destination}</dd>
              </div>
              <div>
                <dt>Risk score</dt>
                <dd>{selected.risk} / 100</dd>
              </div>
              <div>
                <dt>Current action</dt>
                <dd>{selected.action}</dd>
              </div>
            </dl>

            {/* Deep SHAP Feature Attribution Section */}
            <div className="shap-modal-section">
              <h4>✦ Transparent XAI Feature Attributions (SHAP)</h4>
              {loadingExplanation ? (
                <div style={{ fontSize: '11px', color: 'var(--muted-cream)', padding: '8px 0' }}>
                  Calculating Shapley feature attributions via TreeExplainer…
                </div>
              ) : selectedExplanation ? (
                <div className="shap-breakdown-box">
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px', fontSize: '11px' }}>
                    <span>Model Base Expected Prior: <b>{selectedExplanation.expected_base_probability !== undefined ? `${(selectedExplanation.expected_base_probability * 100).toFixed(1)}%` : '50.0%'}</b></span>
                    <span>Threat: <b>{selectedExplanation.attack_type || selected.attack_type || selected.event}</b></span>
                  </div>

                  {selectedExplanation.feature_attributions && selectedExplanation.feature_attributions.length > 0 ? (
                    <div className="shap-bars-list">
                      {selectedExplanation.feature_attributions.slice(0, 6).map((fa) => (
                        <div className="shap-bar-row" key={fa.feature}>
                          <span className="shap-feat-name">{fa.feature} ({fa.value})</span>
                          <div className="shap-track">
                            <div
                              className={`shap-fill ${fa.contribution_direction}`}
                              style={{
                                width: `${Math.min(Math.abs(fa.shap_value) * 200, 100)}%`,
                              }}
                            />
                          </div>
                          <span className={`shap-val-text ${fa.contribution_direction}`}>
                            {fa.shap_value > 0 ? `+${(fa.shap_value * 100).toFixed(1)}%` : `${(fa.shap_value * 100).toFixed(1)}%`}
                          </span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div style={{ fontSize: '11px', color: 'var(--muted-cream)', padding: '4px 0' }}>
                      Standard baseline z-score attribution active.
                    </div>
                  )}

                  {selectedExplanation.policy_reasoning && (
                    <div className="policy-trace-box">
                      <small>Policy Engine Reason: <strong>{selectedExplanation.policy_reasoning.policy_rule_name || 'Adaptive Risk Threshold'}</strong></small>
                      <small style={{ display: 'block', marginTop: '2px', color: 'var(--pale-sand)' }}>
                        Enforcement: {selectedExplanation.policy_reasoning.enforcement_status || 'Simulated'} (Sandbox Isolated)
                      </small>
                    </div>
                  )}
                  {selectedExplanation.disclaimer && (
                    <div style={{ fontSize: '10px', color: 'var(--muted-cream)', marginTop: '6px', lineHeight: '1.3' }}>
                      {selectedExplanation.disclaimer}
                    </div>
                  )}
                </div>
              ) : (
                <div style={{ fontSize: '11px', color: 'var(--muted-cream)', padding: '6px 0' }}>
                  Standard baseline z-score attribution active.
                </div>
              )}
            </div>

            {/* AI Security Copilot Executive Briefing Section */}
            <div className="ai-briefing-section" style={{ marginTop: '14px', background: 'var(--panel-secondary)', padding: '12px 16px', borderRadius: '8px', border: '1px solid var(--line)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                <div>
                  <h4 style={{ margin: 0, color: 'var(--terracotta)', fontSize: '12px' }}>✦ Advisory — Security Analyst AI</h4>
                  <small style={{ color: 'var(--muted-cream)', fontSize: '10px' }}>
                    Authoritative Policy Engine Decision: <b style={{ color: selected.action === 'Block' ? 'var(--muted-red)' : selected.action === 'Restrict' ? 'var(--pale-sand)' : 'var(--olive-green)' }}>{selected.action.toUpperCase()}</b>
                  </small>
                </div>
                <button
                  className="chip btn-stable"
                  onClick={handleGenerateAiBriefing}
                  disabled={loadingAiBriefing}
                  style={{ fontSize: '11px', padding: '4px 10px', minWidth: '135px', textAlign: 'center' }}
                >
                  {loadingAiBriefing ? 'Synthesizing…' : '⚡ Generate Briefing'}
                </button>
              </div>

              {aiBriefing ? (
                <div style={{ marginTop: '10px', fontSize: '12px' }}>
                  <div style={{ display: 'flex', gap: '6px', marginBottom: '8px', flexWrap: 'wrap' }}>
                    <span className="copilot-provider-tag">
                      Provider: <b>{aiBriefing.provider}</b>
                    </span>
                    <span className="copilot-provider-tag">
                      Model: <b>{aiBriefing.model}</b>
                    </span>
                    <span className="copilot-provider-tag status">
                      {aiBriefing.is_llm_generated ? 'LLM Synthesized' : 'Deterministic XAI Synthesis'}
                    </span>
                  </div>
                  <div style={{ color: 'var(--warm-cream)', marginBottom: '8px', lineHeight: '1.4', wordBreak: 'break-word' }}>
                    <strong>Executive Summary: </strong>{aiBriefing.executive_summary}
                  </div>
                  <div style={{ color: 'var(--muted-cream)', marginBottom: '8px', lineHeight: '1.4', wordBreak: 'break-word' }}>
                    <strong>Threat Context: </strong>{aiBriefing.threat_narrative}
                  </div>
                  <div>
                    <strong style={{ color: 'var(--warm-cream)', display: 'block', marginBottom: '4px' }}>Recommended Remediation (Advisory):</strong>
                    <ul style={{ margin: 0, paddingLeft: '18px', color: 'var(--muted-cream)', lineHeight: '1.45' }}>
                      {aiBriefing.remediation_steps.map((st, i) => (
                        <li key={i}>{st}</li>
                      ))}
                    </ul>
                  </div>
                  <small style={{ display: 'block', marginTop: '10px', fontSize: '10px', color: 'var(--muted-cream)', borderTop: '1px solid var(--line)', paddingTop: '6px' }}>
                    {aiBriefing.disclaimer}
                  </small>
                </div>
              ) : (
                <small style={{ display: 'block', marginTop: '6px', color: 'var(--muted-cream)' }}>
                  Click "Generate Briefing" for advisory SecOps executive summary and remediation steps.
                </small>
              )}
            </div>

            <div className="modal-actions" style={{ marginTop: '16px' }}>
              <button
                type="button"
                onClick={() => {
                  setSelected(null)
                  setActiveNav('Events')
                }}
                style={{ marginRight: 'auto', background: 'transparent', borderColor: 'var(--line)', color: 'var(--terracotta)' }}
              >
                View in Events Ledger →
              </button>
              <button onClick={() => updateAction('Monitor')}>Monitor</button>
              <button onClick={() => updateAction('Restrict')}>Restrict</button>
              <button className="danger-button" onClick={() => updateAction('Block')}>
                Block traffic
              </button>
            </div>
          </section>
        </div>
      )}

      {/* Authenticated Console Operator Identity Modal */}
      {showProfileModal && (
        <div className="modal-backdrop" role="presentation" onMouseDown={() => setShowProfileModal(false)}>
          <section
            className="incident-modal"
            role="dialog"
            aria-modal="true"
            onMouseDown={(e) => e.stopPropagation()}
            style={{ maxWidth: '580px' }}
          >
            <button className="close" onClick={() => setShowProfileModal(false)}>×</button>
            <span className="eyebrow">Gateway Console Identity</span>
            <h2>SecOps Authenticated Operator</h2>
            <div className="profile-detail-card" style={{ marginTop: '12px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '14px', marginBottom: '16px' }}>
                <div className="profile-large-avatar">
                  {authUser?.role === 'ADMIN' ? '👑' : '🛡️'}
                </div>
                <div>
                  <h3 style={{ margin: 0, color: 'var(--warm-cream)' }}>
                    {authUser?.full_name || profile?.full_name || 'SecOps Operator'}
                  </h3>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '4px' }}>
                    <span className={`auth-user-role-badge ${authUser?.role?.toLowerCase() || 'analyst'}`}>
                      {authUser?.role || 'ANALYST'}
                    </span>
                    <span style={{ color: 'var(--terracotta)', fontSize: '13px' }}>{authUser?.email}</span>
                  </div>
                  <small style={{ display: 'block', color: 'var(--muted-cream)', marginTop: '4px' }}>
                    Provider: {authUser?.auth_provider || 'LOCAL'} • Verified Database Identity
                  </small>
                </div>
              </div>

              <div className="profile-meta-grid">
                <div>
                  <small>Operating Mode</small>
                  <b style={{ color: 'var(--olive-green)' }}>{profile?.active_mode || enforcementConfig?.active_mode || 'DRY_RUN'}</b>
                </div>
                <div>
                  <small>Process Uptime</small>
                  <b>{profile?.uptime_formatted || data.processUptime || 'Process Running'}</b>
                </div>
                <div>
                  <small>Database Connection</small>
                  <b>{profile?.database_status || 'PostgreSQL Connected'}</b>
                </div>
                <div>
                  <small>ML Engine</small>
                  <b>{profile?.ml_model_status || 'Online'}</b>
                </div>
              </div>

              <h4 style={{ margin: '18px 0 8px', color: 'var(--warm-cream)', fontSize: '12px' }}>Active Safety Guardrails & Status</h4>
              <div className="profile-perms-list">
                <div>✓ ML Anomaly & Continuous Risk Scoring: <b>Active</b></div>
                <div>✓ In-Memory Sandbox Quarantine Isolation: <b>Enabled</b></div>
                <div>✓ AWS VPC Telemetry Integration: <b>Read-Only (Safety Gated)</b></div>
                <div>✓ Host OS Firewall Modification: <b>Restricted (Zero Host Changes)</b></div>
                <div>✓ Multi-User Authentication: <b style={{ color: 'var(--olive-green)' }}>Active (JWT + PostgreSQL)</b></div>
              </div>

              <div style={{ display: 'flex', gap: '8px', marginTop: '18px', flexWrap: 'wrap', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
                  <button
                    className="chip active"
                    onClick={() => { setShowProfileModal(false); setShowRulesModal(true); }}
                  >
                    🛡️ View Active Rules ({activeRules.length})
                  </button>
                  <button
                    className="chip"
                    onClick={() => { setShowProfileModal(false); setShowAnalyzer(true); }}
                  >
                    ⚡ Test Flow Vector
                  </button>
                  <button
                    className="chip"
                    onClick={() => { loadDashboard(); setToast('Refreshed live gateway telemetry.'); }}
                  >
                    🔄 Refresh Telemetry
                  </button>
                </div>
                <button
                  type="button"
                  className="auth-logout-btn"
                  style={{ padding: '6px 14px' }}
                  onClick={async () => {
                    setShowProfileModal(false)
                    await authService.logout()
                    setAuthUser(null)
                    setToast('Session logged out.')
                  }}
                >
                  🚪 Log Out
                </button>
              </div>
            </div>
          </section>
        </div>
      )}

      {/* Live Threat Analyzer Modal */}
      {showAnalyzer && (
        <div className="modal-backdrop" role="presentation" onMouseDown={() => setShowAnalyzer(false)}>
          <section
            className="analyzer-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="analyzer-title"
            onMouseDown={(event) => event.stopPropagation()}
          >
            <button className="close" onClick={() => setShowAnalyzer(false)} aria-label="Close flow analyzer">
              ×
            </button>
            <span className="eyebrow">Real ML Inference Gateway</span>
            <h2 id="analyzer-title">Live Threat Analyzer & Flow Tester</h2>
            <p className="analyzer-sub">
              Pass arbitrary network flow vectors to the live FastAPI backend (<code>POST /api/v1/predict</code>)
              and inspect the real model outputs, continuous risk score, and class probability estimates.
            </p>

            <div className="preset-container">
              <label>Select Attack Preset or Custom Vector:</label>
              <div className="preset-chips">
                {Object.keys(presets).map((pKey) => (
                  <button key={pKey} className="chip" onClick={() => selectPreset(pKey)}>
                    {pKey.replace('_', ' ')}
                  </button>
                ))}
              </div>
            </div>

            <div className="flow-form-grid">
              <div className="flow-field">
                <label>Packet Count</label>
                <input
                  type="number"
                  min={1}
                  step="1"
                  value={flowInput.packet_count}
                  onChange={(e) => setFlowInput({ ...flowInput, packet_count: Math.max(1, parseInt(e.target.value, 10) || 1) })}
                />
              </div>
              <div className="flow-field">
                <label>Byte Count</label>
                <input
                  type="number"
                  min={0}
                  step="1"
                  value={flowInput.byte_count}
                  onChange={(e) => setFlowInput({ ...flowInput, byte_count: Math.max(0, parseInt(e.target.value, 10) || 0) })}
                />
              </div>
              <div className="flow-field">
                <label>Duration (s)</label>
                <input
                  type="number"
                  min={0}
                  step="any"
                  value={flowInput.duration}
                  onChange={(e) => setFlowInput({ ...flowInput, duration: Math.max(0, parseFloat(e.target.value) || 0) })}
                />
              </div>
              <div className="flow-field">
                <label>Conn Rate (conn/s)</label>
                <input
                  type="number"
                  min={0}
                  step="any"
                  value={flowInput.conn_rate}
                  onChange={(e) => setFlowInput({ ...flowInput, conn_rate: Math.max(0, parseFloat(e.target.value) || 0) })}
                />
              </div>
              <div className="flow-field">
                <label>Dest Port</label>
                <input
                  type="number"
                  min={1}
                  max={65535}
                  step="1"
                  value={flowInput.dst_port}
                  onChange={(e) => setFlowInput({ ...flowInput, dst_port: Math.min(65535, Math.max(1, parseInt(e.target.value, 10) || 1)) })}
                />
              </div>
              <div className="flow-field">
                <label>Unique Dest Ports</label>
                <input
                  type="number"
                  min={1}
                  step="1"
                  value={flowInput.unique_dst_ports ?? 1}
                  onChange={(e) => setFlowInput({ ...flowInput, unique_dst_ports: Math.max(1, parseInt(e.target.value, 10) || 1) })}
                />
              </div>
              <div className="flow-field">
                <label>Failed Auth Count</label>
                <input
                  type="number"
                  min={0}
                  step="1"
                  value={flowInput.failed_auth_count ?? 0}
                  onChange={(e) => setFlowInput({ ...flowInput, failed_auth_count: Math.max(0, parseInt(e.target.value, 10) || 0) })}
                />
              </div>
            </div>

            <button className="run-predict-btn" onClick={runLiveInference} disabled={predicting}>
              {predicting ? 'Evaluating Flow via FastAPI ML Pipeline...' : '⚡ Send to FastAPI ML Model'}
            </button>

            {predictResult && (
              <div className="prediction-result-panel">
                <div className="result-header">
                  <h3>Real Model Prediction Result</h3>
                  <span className={`threat-tag ${predictResult.threat_level}`}>
                    {predictResult.threat_level} THREAT
                  </span>
                </div>

                <div className="result-summary-grid">
                  <div className="res-stat">
                    <small>Continuous Risk</small>
                    <b
                      className={`risk-val ${
                        predictResult.risk_score >= 70
                          ? 'r-high'
                          : predictResult.risk_score >= 40
                          ? 'r-med'
                          : 'r-low'
                      }`}
                    >
                      {predictResult.risk_score} <small>/ 100</small>
                    </b>
                  </div>
                  <div className="res-stat">
                    <small>Classification</small>
                    <b>{predictResult.attack_type}</b>
                  </div>
                  <div className="res-stat">
                    <small>Confidence</small>
                    <b>{(predictResult.confidence * 100).toFixed(1)}%</b>
                  </div>
                  <div className="res-stat">
                    <small>Gateway Action</small>
                    <b>{predictResult.action_recommendation}</b>
                  </div>
                </div>

                <div className="prob-breakdown">
                  <h4>Class Probability Estimates ({predictResult.model_version?.includes('xgboost') ? 'XGBoost V2' : 'Authoritative Model'})</h4>
                  {Object.entries(predictResult.class_probabilities).map(([clsName, prob]) => (
                    <div className="prob-row" key={clsName}>
                      <span>{clsName}</span>
                      <div className="prob-bar-track">
                        <div
                          className={`prob-bar-fill ${clsName}`}
                          style={{ width: `${(prob * 100).toFixed(1)}%` }}
                        />
                      </div>
                      <b>{(prob * 100).toFixed(1)}%</b>
                    </div>
                  ))}
                </div>

                {predictResult.top_contributing_features && predictResult.top_contributing_features.length > 0 ? (
                  <div className="deviations-list">
                    <h4>Top Anomalous Feature Indicators (z-score vs Benign Baseline)</h4>
                    {predictResult.top_contributing_features.map((cf) => (
                      <div className="deviation-item" key={cf.feature}>
                        • <strong>{cf.feature}</strong>: {cf.description}
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="shap-skipped-box" style={{ marginTop: '12px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span style={{ fontSize: '13px' }}>🛡️</span>
                      <strong style={{ color: 'var(--desaturated-eucalyptus)', fontSize: '12px' }}>
                        SHAP explanation skipped: flow risk below configured threshold.
                      </strong>
                    </div>
                    <p style={{ margin: '4px 0 0', fontSize: '11px', color: 'var(--muted-cream)' }}>
                      TreeExplainer feature attribution is conditionally triggered only for flows classified as anomalies or exceeding risk threshold (≥ 50/100).
                    </p>
                  </div>
                )}

                <div style={{ marginTop: '16px' }}>
                  <button
                    className="chip"
                    onClick={handleComparePolicies}
                    disabled={comparing}
                    style={{ width: '100%', padding: '8px', background: 'var(--line)', borderColor: 'var(--line)', fontWeight: 600 }}
                  >
                    {comparing ? 'Evaluating Baseline Comparison...' : '⚖️ Compare with Static Rule-Based Baseline'}
                  </button>
                </div>

                {comparisonResult && (
                  <div className="comparison-card">
                    <h4>Static Baseline vs. Adaptive AI Policy Comparison</h4>
                    <div className="comparison-grid">
                      <div className="comp-box">
                        <small>Static Baseline Rule</small>
                        <b className={comparisonResult.static_decision}>{comparisonResult.static_decision}</b>
                        <span style={{ fontSize: '10px', color: 'var(--muted-cream)' }}>
                          {comparisonResult.static_rule_matched || 'Default Permit Policy'}
                        </span>
                      </div>
                      <div className="comp-box">
                        <small>Adaptive AI Decision</small>
                        <b className={comparisonResult.adaptive_decision}>{comparisonResult.adaptive_decision}</b>
                        <span style={{ fontSize: '10px', color: 'var(--muted-cream)' }}>
                          Risk: {comparisonResult.adaptive_risk_score} (Conf: {(comparisonResult.adaptive_confidence * 100).toFixed(0)}%)
                        </span>
                      </div>
                    </div>
                    <div className="divergence-note">
                      <strong>Analysis: </strong>{comparisonResult.divergence_rationale}
                    </div>
                  </div>
                )}
              </div>
            )}
          </section>
        </div>
      )}

      {showIngestModal && (
        <div className="backdrop" onClick={() => setShowIngestModal(false)}>
          <section className="analyzer-modal" onClick={(e) => e.stopPropagation()}>
            <button className="close-btn" onClick={() => setShowIngestModal(false)}>
              ×
            </button>
            <div className="modal-badge-row">
              <span className="api-badge">{ingestTab === 'PCAP' ? 'Phase 4 Engine' : 'Phase 6 Telemetry Engine'}</span>
              <span className="model-badge">
                {ingestTab === 'PCAP'
                  ? 'Scapy PcapReader + 5-Tuple Aggregator'
                  : 'AWS VPC Flow Log (v2) Parser + ML + Dry-Run Sandbox'}
              </span>
            </div>
            <h2>Hybrid Cloud Telemetry Ingestion</h2>
            <p className="analyzer-sub">
              Ingest telemetry from On-Premises PCAP captures or AWS VPC Flow Logs. Normalizes traffic, classifies network zones, runs ML inference, and evaluates containment policies in isolated Dry-Run / Sandbox mode.
            </p>

            <div className="mode-toggle-bar" style={{ marginBottom: '20px' }}>
              <div>
                <small style={{ color: 'var(--muted-cream)', display: 'block' }}>Telemetry Source Type</small>
                <b style={{ color: 'var(--warm-cream)' }}>
                  {ingestTab === 'PCAP' ? '📁 On-Premises PCAP Capture' : '☁ AWS VPC Flow Logs (Read-Only)'}
                </b>
              </div>
              <div style={{ display: 'flex', gap: '8px' }}>
                <button
                  className={`chip ${ingestTab === 'PCAP' ? 'active' : ''}`}
                  onClick={() => setIngestTab('PCAP')}
                >
                  📁 On-Prem PCAP
                </button>
                <button
                  className={`chip ${ingestTab === 'AWS_VPC' ? 'active' : ''}`}
                  onClick={() => setIngestTab('AWS_VPC')}
                >
                  ☁ AWS VPC Flow Logs
                </button>
              </div>
            </div>

            {ingestTab === 'PCAP' ? (
              <>
                <div className="preset-container">
                  <label>1. Verified Pre-Packaged Benchmark Captures</label>
                  <div className="pcap-sample-grid">
                    {samplePcaps.map((sample) => (
                      <div
                        key={sample.sample_id}
                        className="pcap-sample-card"
                        onClick={() => handleIngestSample(sample.filename)}
                      >
                        <div>
                          <h4>{sample.name}</h4>
                          <p>{sample.description}</p>
                        </div>
                        <div className="pcap-sample-footer">
                          <span>{sample.packet_count} packets</span>
                          <span className={`badge ${sample.expected_threat}`}>{sample.expected_threat}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="preset-container">
                  <label>2. Or Upload Custom PCAP / PCAPNG File (Max 15MB)</label>
                  <label className="pcap-upload-zone">
                    <input
                      type="file"
                      accept=".pcap,.pcapng,.cap"
                      disabled={ingesting}
                      onChange={handleUploadPcap}
                    />
                    <span>{ingesting ? 'Parsing Packets & Evaluating ML Flows...' : '📁 Click to Choose or Drop PCAP File'}</span>
                    <small>Supports standard IPv4/IPv6 TCP, UDP, and ICMP captures</small>
                  </label>
                </div>

                {ingestResponse && (
                  <div className="prediction-result-panel">
                    <div className="result-header">
                      <h3>Ingestion Telemetry & ML Results: {ingestResponse.filename}</h3>
                      <span className={`threat-tag ${ingestResponse.high_risk_flows_count > 0 ? 'HIGH' : 'LOW'}`}>
                        {ingestResponse.is_sampled
                          ? `${ingestResponse.flows_evaluated} Evaluated of ${ingestResponse.metrics.flows_generated} Flows (${ingestResponse.high_risk_flows_count} High Risk)`
                          : `${ingestResponse.flows_evaluated} Flows (${ingestResponse.high_risk_flows_count} High Risk)`}
                      </span>
                    </div>

                    <div className="metrics-strip">
                      <div className="metric-box">
                        <small>Packets Parsed</small>
                        <b>{ingestResponse.metrics.packets_processed}</b>
                      </div>
                      <div className="metric-box">
                        <small>Flows Created</small>
                        <b>{ingestResponse.metrics.flows_generated}</b>
                      </div>
                      <div className="metric-box">
                        <small>Parse Time</small>
                        <b>{ingestResponse.metrics.parse_duration_ms} ms</b>
                      </div>
                      <div className="metric-box">
                        <small>ML Inference</small>
                        <b>{ingestResponse.metrics.inference_duration_ms} ms</b>
                      </div>
                      <div className="metric-box">
                        <small>DB Persist</small>
                        <b>{ingestResponse.metrics.persist_duration_ms} ms</b>
                      </div>
                      <div className="metric-box">
                        <small>Throughput</small>
                        <b>{ingestResponse.metrics.throughput_packets_per_sec} pkt/s</b>
                      </div>
                    </div>

                    <div className="prob-breakdown">
                      <h4>
                        Aggregated Flow Classifications (Persisted to PostgreSQL)
                        {ingestResponse.results_omitted_count && ingestResponse.results_omitted_count > 0 ? (
                          <span style={{ fontSize: '0.8rem', opacity: 0.8, marginLeft: '0.5rem', fontWeight: 'normal' }}>
                            (Top {ingestResponse.results.length} of {ingestResponse.flows_evaluated} evaluated flows shown)
                          </span>
                        ) : null}
                      </h4>
                      <table className="ingest-flow-table">
                        <thead>
                          <tr>
                            <th>Flow ID</th>
                            <th>Endpoints</th>
                            <th>Dst Port</th>
                            <th>Packets</th>
                            <th>Risk Score</th>
                            <th>Attack Type</th>
                            <th>Policy Action</th>
                          </tr>
                        </thead>
                        <tbody>
                          {ingestResponse.results.slice(0, 10).map((r) => (
                            <tr key={r.flow_id}>
                              <td><code>{r.flow_id.split('-')[1] || r.flow_id}</code></td>
                              <td>{r.flow_features.source_ip} → {r.flow_features.destination_ip}</td>
                              <td>{r.flow_features.dst_port}</td>
                              <td>{r.flow_features.packet_count}</td>
                              <td>
                                <b className={r.prediction.risk_score >= 70 ? 'r-high' : r.prediction.risk_score >= 40 ? 'r-med' : 'r-low'}>
                                  {r.prediction.risk_score}
                                </b>
                              </td>
                              <td>{r.prediction.attack_type}</td>
                              <td>{r.prediction.action_recommendation}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
              </>
            ) : (
              <>
                <div className="preset-container">
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <label>1. Standard AWS VPC Flow Log Fixtures (Deterministic / Offline)</label>
                    <span className="topology-badge" style={{ fontSize: '11px' }}>Mode: {topology?.telemetry_mode || 'AWS_FIXTURE'}</span>
                  </div>
                  <div className="pcap-sample-grid">
                    {awsVpcSamples.map((sample) => (
                      <div
                        key={sample.sample_id}
                        className="pcap-sample-card"
                        onClick={() => handleIngestAwsSample(sample.sample_id)}
                      >
                        <div>
                          <h4>{sample.name}</h4>
                          <p>{sample.description}</p>
                        </div>
                        <div className="pcap-sample-footer">
                          <span>{sample.record_count} records</span>
                          <span className={`badge ${sample.expected_threat}`}>{sample.expected_threat}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="preset-container">
                  <label>2. Or Paste Raw AWS VPC Flow Log Lines (Version 2 Format)</label>
                  <textarea
                    className="raw-log-input"
                    rows={4}
                    placeholder="2 123456789012 eni-0a1b2c3d4e5f67890 198.51.100.25 10.100.1.10 49152 443 6 25 15000 1620000000 1620000060 ACCEPT OK"
                    value={rawVpcText}
                    onChange={(e) => setRawVpcText(e.target.value)}
                  />
                  <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '8px' }}>
                    <button
                      className="chip active"
                      style={{ padding: '8px 16px', fontWeight: 600 }}
                      disabled={ingestingVpc || !rawVpcText.trim()}
                      onClick={handleIngestRawVpcLogs}
                    >
                      {ingestingVpc ? 'Parsing & Evaluating AWS Flows...' : '⚡ Ingest & Evaluate Raw Flow Logs'}
                    </button>
                  </div>
                </div>

                {awsVpcResponse && (
                  <div className="prediction-result-panel">
                    <div className="result-header">
                      <h3>Ingestion Telemetry: {awsVpcResponse.source_label}</h3>
                      <span className={`threat-tag ${awsVpcResponse.high_risk_flows_count > 0 ? 'HIGH' : 'LOW'}`}>
                        {awsVpcResponse.total_flows_aggregated} Flows ({awsVpcResponse.high_risk_flows_count} High Risk)
                      </span>
                    </div>

                    <div className="metrics-strip">
                      <div className="metric-box">
                        <small>Lines Parsed</small>
                        <b>{awsVpcResponse.total_records_parsed}</b>
                      </div>
                      <div className="metric-box">
                        <small>Flows Created</small>
                        <b>{awsVpcResponse.total_flows_aggregated}</b>
                      </div>
                      <div className="metric-box">
                        <small>Telemetry Source</small>
                        <b style={{ fontSize: '11px', color: 'var(--terracotta)' }}>{awsVpcResponse.telemetry_source}</b>
                      </div>
                      <div className="metric-box">
                        <small>Parse Time</small>
                        <b>{awsVpcResponse.parse_duration_ms} ms</b>
                      </div>
                      <div className="metric-box">
                        <small>ML Inference</small>
                        <b>{awsVpcResponse.inference_duration_ms} ms</b>
                      </div>
                      <div className="metric-box">
                        <small>Total Duration</small>
                        <b>{awsVpcResponse.total_duration_ms} ms</b>
                      </div>
                    </div>

                    <div className="prob-breakdown">
                      <h4>Zone-Classified Flow Ingestion Results (Persisted to PostgreSQL)</h4>
                      <table className="ingest-flow-table">
                        <thead>
                          <tr>
                            <th>Flow ID</th>
                            <th>Source Zone</th>
                            <th>Dest Zone</th>
                            <th>Direction</th>
                            <th>Dst Port</th>
                            <th>Risk Score</th>
                            <th>Attack Type</th>
                            <th>Policy Action</th>
                            <th>Enforcement</th>
                          </tr>
                        </thead>
                        <tbody>
                          {awsVpcResponse.results.slice(0, 10).map((r) => (
                            <tr key={r.flow_id}>
                              <td><code>{r.flow_id.split('-')[1] || r.flow_id}</code></td>
                              <td>
                                <span className={`zone-tag ${r.source_zone}`}>
                                  {r.source_zone}
                                </span>
                                <br />
                                <small style={{ color: 'var(--muted-cream)' }}>{r.source_ip}</small>
                              </td>
                              <td>
                                <span className={`zone-tag ${r.destination_zone}`}>
                                  {r.destination_zone}
                                </span>
                                <br />
                                <small style={{ color: 'var(--muted-cream)' }}>{r.destination_ip}</small>
                              </td>
                              <td>
                                <code style={{ fontSize: '11px', color: 'var(--warm-cream)' }}>
                                  {r.traffic_direction}
                                </code>
                              </td>
                              <td>{r.dst_port}</td>
                              <td>
                                <b className={r.prediction.risk_score >= 70 ? 'r-high' : r.prediction.risk_score >= 40 ? 'r-med' : 'r-low'}>
                                  {r.prediction.risk_score}
                                </b>
                              </td>
                              <td>{r.prediction.attack_type}</td>
                              <td>{r.prediction.action_recommendation}</td>
                              <td>
                                <span className="enforce-status-tag">
                                  {r.policy_decision?.policy_action || 'Permit'}
                                </span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
              </>
            )}
          </section>
        </div>
      )}

      {showRulesModal && (
        <div className="backdrop" onClick={() => setShowRulesModal(false)}>
          <section className="analyzer-modal" onClick={(e) => e.stopPropagation()}>
            <button className="close-btn" onClick={() => setShowRulesModal(false)}>
              ×
            </button>
            <div className="modal-badge-row">
              <span className="api-badge">Phase 5 Enforcement Layer</span>
              <span className="model-badge">
                Mode: {enforcementConfig?.active_mode || 'DRY_RUN'} (Zero Host Modifications)
              </span>
            </div>
            <h2>Active Containment Policies & Enforcements</h2>
            <p className="analyzer-sub">
              Live containment rules applied by the Adaptive Policy Engine. Rules operate in isolated
              DRY_RUN or in-memory SANDBOX modes with automatic TTL expiration.
            </p>

            <div className="mode-toggle-bar">
              <div>
                <small style={{ color: 'var(--muted-cream)', display: 'block' }}>Operating Mode</small>
                <b style={{ color: 'var(--warm-cream)' }}>{enforcementConfig?.active_mode || 'DRY_RUN'}</b>
              </div>
              <div style={{ display: 'flex', gap: '8px' }}>
                <button
                  className={`chip ${enforcementConfig?.active_mode === 'DRY_RUN' ? 'active' : ''}`}
                  onClick={() => handleToggleMode('DRY_RUN')}
                >
                  Dry-Run (Simulation)
                </button>
                <button
                  className={`chip ${enforcementConfig?.active_mode === 'SANDBOX' ? 'active' : ''}`}
                  onClick={() => handleToggleMode('SANDBOX')}
                >
                  Sandbox (Lab Filter)
                </button>
              </div>
            </div>

            <div className="preset-container">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <label>Active Rules ({activeRules.length})</label>
                <button className="chip" onClick={refreshRules} style={{ fontSize: '11px', padding: '3px 8px' }}>
                  ↻ Refresh
                </button>
              </div>

              {activeRules.length === 0 ? (
                <div style={{ textAlign: 'center', padding: '24px', color: 'var(--muted-cream)', background: 'var(--panel-secondary)', borderRadius: '8px' }}>
                  No active containment rules currently enforced.
                </div>
              ) : (
                <div className="rules-list-container">
                  {activeRules.map((rule) => (
                    <div className="rule-card" key={rule.rule_id}>
                      <div className="rule-info">
                        <h4>{rule.target_ip} ({rule.action})</h4>
                        <p>{rule.reason}</p>
                        <small style={{ fontSize: '10px', color: 'var(--muted-cream)' }}>
                          ID: <code>{rule.rule_id}</code> | Port: {rule.target_port || 'ALL'} | Protocol: {rule.protocol}
                        </small>
                      </div>
                      <div className="rule-meta">
                        <span className="ttl-badge" title="Remaining TTL before automatic expiration">
                          ⏱ {Math.floor(rule.remaining_ttl_seconds / 60)}:{(rule.remaining_ttl_seconds % 60).toString().padStart(2, '0')}
                        </span>
                        <button
                          className="revoke-btn"
                          onClick={() => handleRevokeRule(rule.rule_id)}
                        >
                          Revoke
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </section>
        </div>
      )}

      {toast && (
        <button className="toast" onClick={() => setToast('')}>
          {toast} ×
        </button>
      )}
    </div>
  )
}
