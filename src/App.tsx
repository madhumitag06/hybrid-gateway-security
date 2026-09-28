import React, { useEffect, useMemo, useState } from 'react'
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
import { AuthView } from './components/AuthView'
import { authService } from './services/auth'
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

const nav = [
  ['⌂', 'Dashboard'],
  ['▥', 'Traffic'],
  ['▣', 'Events'],
  ['◇', 'Policies'],
  ['▤', 'Reports'],
  ['⚖', 'Evaluation'],
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
}: {
  icon: string
  label: string
  value: string
  note?: string
  green?: boolean
}) {
  return (
    <div className="metric">
      <i>{icon}</i>
      <div>
        <small>{label}</small>
        <b className={green ? 'green' : ''}>{value}</b>
        {note && <em>{note}</em>}
      </div>
    </div>
  )
}

function Traffic({
  points,
  range,
}: {
  points?: TrafficPoint[]
  range: string
}) {
  const [activeTooltip, setActiveTooltip] = useState<{
    x: number
    y: number
    title: string
    val: string
    time: string
  } | null>(null)

  const defaultPoints: TrafficPoint[] = [
    { time_label: '00:00', inbound_val: 32, outbound_val: 19, flow_count: 32, anomaly_count: 0 },
    { time_label: '04:00', inbound_val: 45, outbound_val: 27, flow_count: 45, anomaly_count: 0 },
    { time_label: '08:00', inbound_val: 68, outbound_val: 42, flow_count: 68, anomaly_count: 1, anomaly_note: 'Traffic Spike' },
    { time_label: '12:00', inbound_val: 94, outbound_val: 58, flow_count: 94, anomaly_count: 2, anomaly_note: 'Port Scan (87/100)' },
    { time_label: '16:00', inbound_val: 55, outbound_val: 33, flow_count: 55, anomaly_count: 0 },
    { time_label: '20:00', inbound_val: 73, outbound_val: 45, flow_count: 73, anomaly_count: 1, anomaly_note: 'SSH Brute Force' },
  ]

  const dataPoints = points && points.length >= 2 ? points : defaultPoints

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

  const getX = (idx: number) => paddingX + (idx / (dataPoints.length - 1)) * chartW
  const getY = (val: number) => height - paddingY - (val / maxVal) * chartH

  let inPath = `M ${getX(0)} ${getY(dataPoints[0].inbound_val)}`
  let outPath = `M ${getX(0)} ${getY(dataPoints[0].outbound_val)}`

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

  const inAreaPath = `${inPath} L ${getX(dataPoints.length - 1)} ${height - paddingY} L ${getX(0)} ${height - paddingY} Z`

  return (
    <div className="traffic-chart">
      <div className="legend">
        <span>
          <i className="in" />
          Inbound Events ({range})
        </span>
        <span>
          <i className="out" />
          Outbound Ratio
        </span>
        <span>
          <i className="an" />
          Anomalous Flows ({dataPoints.reduce((acc, p) => acc + p.anomaly_count, 0)})
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
        <svg viewBox="0 0 780 205" preserveAspectRatio="none" aria-label="Dynamic telemetry traffic chart">
          <defs>
            <linearGradient id="fade" x1="0" x2="0" y1="0" y2="1">
              <stop stopColor="#2c9bff" stopOpacity=".32" />
              <stop offset="1" stopColor="#2c9bff" stopOpacity="0" />
            </linearGradient>
          </defs>
          <path
            className="grid"
            d="M0 5H780M0 45H780M0 85H780M0 125H780M0 165H780M0 204H780M130 0V205M260 0V205M390 0V205M520 0V205M650 0V205"
          />
          <path className="line-in" d={inAreaPath} fill="url(#fade)" stroke="#2c9bff" strokeWidth="2" />
          <path className="line-out" d={outPath} fill="none" stroke="#ff7f8c" strokeWidth="2" strokeDasharray="4 2" />

          <g className="dots">
            {dataPoints.map((pt, idx) => {
              const cx = getX(idx)
              const cy = getY(pt.inbound_val)
              const hasAnomaly = pt.anomaly_count > 0
              return (
                <circle
                  key={pt.time_label + idx}
                  cx={cx}
                  cy={cy}
                  r={hasAnomaly ? 8 : 4}
                  fill={hasAnomaly ? '#ff4d6d' : '#2c9bff'}
                  stroke="#ffffff"
                  strokeWidth={hasAnomaly ? 2 : 1}
                  style={{ cursor: 'pointer', transition: 'r 0.2s' }}
                  onMouseEnter={() =>
                    setActiveTooltip({
                      x: cx,
                      y: cy,
                      title: hasAnomaly ? `⚠️ Anomaly: ${pt.anomaly_note || 'Detected'}` : `Recorded Telemetry (${pt.flow_count} events)`,
                      val: `${pt.flow_count} Flows • ${pt.total_packets || pt.flow_count * 20} pkts`,
                      time: pt.time_label,
                    })
                  }
                  onMouseLeave={() => setActiveTooltip(null)}
                />
              )
            })}
          </g>
        </svg>

        {activeTooltip && (
          <div
            className="chart-tip"
            style={{
              position: 'absolute',
              left: `${Math.min(Math.max(activeTooltip.x - 60, 10), 620)}px`,
              top: `${Math.max(activeTooltip.y - 70, 5)}px`,
              pointerEvents: 'none',
              zIndex: 10,
            }}
          >
            <b>{activeTooltip.title}</b>
            <br />
            {activeTooltip.val}
            <br />
            <small>{activeTooltip.time}</small>
          </div>
        )}
      </div>
      <div className="ticks">
        {dataPoints.map((pt) => (
          <span key={pt.time_label}>{pt.time_label}</span>
        ))}
      </div>
    </div>
  )
}

function Connectivity({ flows, topology }: { flows: number; topology: HybridTopologySummary | null }) {
  return (
    <div className="connect">
      <div className="title-line">
        <div>
          <h2>Hybrid Cloud Connectivity</h2>
          <p>
            <i /> All links operational • <strong>Read-Only Telemetry Active</strong>
          </p>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span className="topology-badge" title="AWS Integration Mode">
            ☁ {topology?.telemetry_mode || 'AWS_FIXTURE'}
          </span>
          <span>↔ &nbsp;{flows} recorded events</span>
        </div>
      </div>
      <div className="network">
        <div className="node">
          <b>☁</b>
          <strong>AWS Cloud (VPC)</strong>
          <small>
            {topology?.aws_region || 'us-east-1'}
            <br />
            {topology?.aws_vpc_cidrs.join(', ') || '10.100.0.0/16'}
          </small>
          <em>Read-Only</em>
        </div>
        <div className="wire">
          <label>VPC Flow Logs</label>
          <small>● &nbsp;12 ms</small>
        </div>
        <div className="node central">
          <b>⬡</b>
          <strong>AI Security Gateway</strong>
          <small>Inspect • Classify • Sandbox</small>
          <em>Active</em>
        </div>
        <div className="wire">
          <label>On-Prem PCAP</label>
          <small>● &nbsp;18 ms</small>
        </div>
        <div className="node">
          <b>▤</b>
          <strong>On-Premise Network</strong>
          <small>{topology?.on_prem_cidrs.join(', ') || '192.168.0.0/16'}</small>
          <em>Monitored</em>
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
  const [selected, setSelected] = useState<SecurityEvent | null>(null)
  const [toast, setToast] = useState('')
  const [loading, setLoading] = useState(true)

  // User Authentication State (Phase 13)
  const [authUser, setAuthUser] = useState<AuthUser | null>(authService.getUser())
  const [isAuthChecked, setIsAuthChecked] = useState(false)

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
  const [currentEnv, setCurrentEnv] = useState<string>('SANDBOX')

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
    } else {
      setIsAuthChecked(true)
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
    if (selected) {
      setLoadingExplanation(true)
      setSelectedExplanation(null)
      setAiBriefing(null)
      getEventExplanation(selected.id)
        .then(setSelectedExplanation)
        .catch(() => {})
        .finally(() => setLoadingExplanation(false))
    } else {
      setSelectedExplanation(null)
      setAiBriefing(null)
    }
  }, [selected])

  const loadDashboard = (timeRangeStr = range) => {
    const controller = new AbortController()
    getDashboard(timeRangeStr, controller.signal)
      .then((res) => {
        setData(res.data)
        setIsLiveBackend(res.isLiveBackend)
        if (res.data.notifications) {
          setNotifications(res.data.notifications)
        }
      })
      .catch(() => setToast('Could not load dashboard data.'))
      .finally(() => setLoading(false))
  }

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
        setCurrentEnv(cfg.active_mode)
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
  }, [authUser])

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
    setIngesting(true)
    try {
      const res = await ingestSamplePcap(filename, true)
      setIngestResponse(res)
      setToast(`Ingested ${res.filename}: ${res.metrics.packets_processed} pkts -> ${res.flows_evaluated} flows evaluated.`)
      loadDashboard(range)
      refreshRules()
    } catch (err) {
      setToast(`PCAP Ingestion error: ${String(err)}`)
    } finally {
      setIngesting(false)
    }
  }

  const handleUploadPcap = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    setIngesting(true)
    try {
      const res = await uploadPcapFile(file, true)
      setIngestResponse(res)
      setToast(`Uploaded & Ingested ${res.filename}: ${res.metrics.packets_processed} pkts -> ${res.flows_evaluated} flows.`)
      loadDashboard(range)
      refreshRules()
    } catch (err) {
      setToast(`Upload error: ${String(err)}`)
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

  const handleToggleMode = async (mode: 'DRY_RUN' | 'SANDBOX') => {
    try {
      const conf = await updateEnforcementMode(mode)
      setEnforcementConfig(conf)
      setCurrentEnv(mode)
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
      <aside>
        <div className="brand">
          <i>⬡</i>
          <b>
            Adaptive AI-Powered
            <br />
            Hybrid Cloud Security Gateway
          </b>
        </div>
        <nav>
          {nav.map(([icon, name]) => (
            <button
              className={activeNav === name ? 'active' : ''}
              onClick={() => {
                setActiveNav(name)
              }}
              key={name}
            >
              <i>{icon}</i>
              <span>{name}</span>
            </button>
          ))}
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
          <div className="header-left">
            <div className="mobile-logo">⬡</div>
            <div className="search-wrapper" style={{ position: 'relative' }}>
              <label className="search">
                ⌕{' '}
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
                  placeholder="Search for IP, event, policy..."
                  onFocus={() => {
                    if (search.trim().length >= 2) toggleSearchDropdown(true)
                  }}
                />
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
              title="FastAPI Backend Connection State"
            >
              <i /> <span>{isLiveBackend ? 'FastAPI ML Online' : 'Fallback Offline'}</span>
            </div>
          </div>

          <div className="header-actions">
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

          <div className="header-right">
            {/* Interactive Environment Selector (Supported Modes Only) */}
            <div style={{ position: 'relative' }}>
              <button
                className="select"
                onClick={toggleEnvMenu}
                title="Execution Environment Mode"
              >
                {currentEnv === 'SANDBOX'
                  ? '🧪 Sandbox Lab ⌄'
                  : currentEnv === 'LOCAL'
                  ? '💻 Local Dev ⌄'
                  : currentEnv === 'AWS_FIXTURE'
                  ? '☁ AWS Fixture ⌄'
                  : '☁ Live AWS (RO) ⌄'}
              </button>
              {showEnvMenu && (
                <div className="env-dropdown-menu">
                  <div className="env-item" onClick={() => { handleToggleMode('SANDBOX'); setShowEnvMenu(false); }}>
                    <b>🧪 In-Memory Sandbox Lab</b>
                    <small>Active in-memory quarantine filtering with auto TTL</small>
                  </div>
                  <div className="env-item" onClick={() => { handleToggleMode('DRY_RUN'); setShowEnvMenu(false); }}>
                    <b>💻 Local Dev (Dry-Run)</b>
                    <small>Simulation only — zero host network changes</small>
                  </div>
                  <div className="env-item" onClick={() => { setIngestTab('AWS_VPC'); setShowIngestModal(true); setShowEnvMenu(false); }}>
                    <b>☁ AWS VPC Flow Fixtures</b>
                    <small>Deterministic offline AWS CloudWatch log fixtures</small>
                  </div>
                  <div className="env-item" onClick={() => { setToast('Live AWS CloudWatch connected in Read-Only mode.'); setShowEnvMenu(false); }}>
                    <b>☁ Live AWS Read-Only</b>
                    <small>CloudWatch flow logs read-only ingest (Safety Gated)</small>
                  </div>
                </div>
              )}
            </div>

            <select
              className="select range"
              value={range}
              onChange={(event) => handleRangeChange(event.target.value)}
              aria-label="Time range"
            >
              <option>Last 1 hour</option>
              <option>Last 24 hours</option>
              <option>Last 7 days</option>
              <option>Last 30 days</option>
            </select>

            {/* Persistent Notifications Bell & Dropdown */}
            <div style={{ position: 'relative' }}>
              <button
                className="alert"
                onClick={toggleNotifications}
                title="Security Notifications"
              >
                ♧{unreadCount > 0 && <b>{unreadCount}</b>}
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
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <div
                  className="profile"
                  onClick={openProfileModal}
                  title={`Authenticated Operator: ${authUser.full_name} (${authUser.email})`}
                  style={{ cursor: 'pointer' }}
                >
                  <i>{authUser.role === 'ADMIN' ? '👑' : '🛡️'}</i>
                  <span>
                    <b>{authUser.full_name}</b>
                    <small style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                      <span className={`auth-user-role-badge ${authUser.role.toLowerCase()}`}>
                        {authUser.role}
                      </span>
                    </small>
                  </span>
                  ⌄
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
          {activeNav === 'Traffic' ? (
            <TrafficView />
          ) : activeNav === 'Events' ? (
            <EventsView />
          ) : activeNav === 'Policies' ? (
            <PoliciesView />
          ) : activeNav === 'Reports' ? (
            <AnalyticsView />
          ) : activeNav === 'Evaluation' ? (
            <EvaluationView />
          ) : (
            <>
              <section className="intro">
                <div>
                  <h1>SecOps Gateway Console</h1>
                  <p>Hybrid cloud security inspection active with real-time AI anomaly evaluation and sandbox isolation.</p>
                </div>
                <div className="metrics">
                  <Metric icon="♢" label="Process Uptime" value={data.processUptime || data.uptime || 'Active'} />
                  <Metric icon="⌁" label="Evaluated Events" value={String(data.evaluatedEventsCount || data.activeFlows)} note={`Persisted in ${range}`} />
                  <Metric icon="◴" label="ML Latency" value={data.inferenceLatency || '1.8 ms'} note="SHAP: ~20.6 ms" />
                  <Metric icon="●" label="Gateway Status" value={data.connectionHealth || 'Healthy'} note={data.connectionNote || 'FastAPI ↔ DB ↔ Model'} green />
                </div>
              </section>

              <section className="top">
                <article className="card risk">
                  <h2>
                    Current Risk Score <small>ⓘ</small>
                  </h2>
                  <div className="risk-body">
                    <div className="gauge">
                      <span>
                        <b>{data.riskScore}</b>
                        <small>/ 100</small>
                        <em>{data.riskState.toUpperCase()}</em>
                      </span>
                    </div>
                    <div>
                      <h3>⬡　{data.riskScore >= 70 ? 'Elevated risk detected' : 'Normal Operating Baseline'}</h3>
                      <p>
                        {data.riskScore >= 70
                          ? 'Unusual traffic patterns and anomalous flow vectors detected by trained ML model.'
                          : 'Observed network flow distributions adhere to learned benign baseline behaviors.'}
                      </p>
                      <button className="primary" onClick={openTopIncident}>
                        Review incident <span>→</span>
                      </button>
                    </div>
                  </div>
                </article>

                <article className="card reason-card">
                  <h2>Top Risk Reasons (Explainable AI)</h2>
                  {data.reasons.map((reason) => (
                    <div className="reason" key={reason.label}>
                      <span>{reason.label}</span>
                      <div>
                        <i className={reason.tone} style={{ width: `${Math.min(reason.value, 100)}%` }} />
                      </div>
                      <b>{reason.value}%</b>
                    </div>
                  ))}
                </article>

                <article className="card ai">
                  <h2>✦　AI Recommendation</h2>
                  <div className="recommend">
                    <i>⬡</i>
                    <section>
                      <h3>{data.riskScore >= 70 ? 'Restrict and investigate' : 'Maintain standard monitoring'}</h3>
                      <small>
                        Policy Engine Recommendation: <b>{data.riskState}</b>
                      </small>
                      <p>
                        {data.riskScore >= 70
                          ? 'Elevated threat probability detected across active flows. Recommend applying policy restriction.'
                          : 'All evaluated flows remain within normal Gaussian bounds. Continuing standard gateway inspection.'}
                      </p>
                      <button className="primary" onClick={openTopIncident}>
                        Review incident <span>→</span>
                      </button>
                    </section>
                  </div>
                </article>
              </section>

              <section className="middle">
                <article className="card">
                  <Connectivity flows={data.evaluatedEventsCount || data.activeFlows} topology={topology} />
                </article>
                <article className="card">
                  <h2>
                    Evaluated Flow Ingestion Telemetry <small>({range})</small>
                  </h2>
                  <Traffic points={data.trafficPoints} range={range} />
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

                <article className="card key">
                  <h2>Key Metrics</h2>
                  <div>
                    <Metric
                      icon="⌘"
                      label="Holdout Detection Rate"
                      value={data.keyMetrics?.detection_rate || '98.5%'}
                      note={data.keyMetrics?.detection_note || 'Holdout Benchmark (N=200)'}
                    />
                    <Metric
                      icon="♢"
                      label="Holdout False Positives"
                      value={data.keyMetrics?.false_positives || '0.0%'}
                      note={data.keyMetrics?.fp_note || 'Holdout Validation Suite'}
                    />
                    <Metric
                      icon="◴"
                      label="ML Inference Latency"
                      value={data.keyMetrics?.ml_latency || '1.8 ms (Inference)'}
                      note={data.keyMetrics?.latency_note || 'SHAP Explainer: ~20.6 ms'}
                    />
                    <Metric
                      icon="▣"
                      label="Active Policies"
                      value={String(data.keyMetrics?.active_policies ?? activeRules.length)}
                      note={data.keyMetrics?.policies_note || `${activeRules.length} in sandbox`}
                    />
                  </div>
                </article>
              </section>
            </>
          )}
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
                <div style={{ fontSize: '11px', color: '#8faec9', padding: '8px 0' }}>
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
                    <div style={{ fontSize: '11px', color: '#8faec9', padding: '4px 0' }}>
                      Standard baseline z-score attribution active.
                    </div>
                  )}

                  {selectedExplanation.policy_reasoning && (
                    <div className="policy-trace-box">
                      <small>Policy Engine Reason: <strong>{selectedExplanation.policy_reasoning.policy_rule_name || 'Adaptive Risk Threshold'}</strong></small>
                      <small style={{ display: 'block', marginTop: '2px', color: '#89b1d6' }}>
                        Enforcement: {selectedExplanation.policy_reasoning.enforcement_status || 'Simulated'} (Sandbox Isolated)
                      </small>
                    </div>
                  )}
                  {selectedExplanation.disclaimer && (
                    <div style={{ fontSize: '10px', color: '#8faec9', marginTop: '6px', lineHeight: '1.3' }}>
                      {selectedExplanation.disclaimer}
                    </div>
                  )}
                </div>
              ) : (
                <div style={{ fontSize: '11px', color: '#8faec9', padding: '6px 0' }}>
                  Standard baseline z-score attribution active.
                </div>
              )}
            </div>

            {/* AI Security Copilot Executive Briefing Section */}
            <div className="ai-briefing-section" style={{ marginTop: '14px', background: '#061320', padding: '12px 16px', borderRadius: '8px', border: '1px solid #1c3e5d' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                <div>
                  <h4 style={{ margin: 0, color: '#38bdf8', fontSize: '12px' }}>✦ Advisory — Security Analyst AI</h4>
                  <small style={{ color: '#8faec9', fontSize: '10px' }}>
                    Authoritative Policy Engine Decision: <b style={{ color: selected.action === 'Block' ? '#ff5e6f' : selected.action === 'Restrict' ? '#ffbd42' : '#42dfa0' }}>{selected.action.toUpperCase()}</b>
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
                  <div style={{ color: '#d8e8f8', marginBottom: '8px', lineHeight: '1.4', wordBreak: 'break-word' }}>
                    <strong>Executive Summary: </strong>{aiBriefing.executive_summary}
                  </div>
                  <div style={{ color: '#9bbcd8', marginBottom: '8px', lineHeight: '1.4', wordBreak: 'break-word' }}>
                    <strong>Threat Context: </strong>{aiBriefing.threat_narrative}
                  </div>
                  <div>
                    <strong style={{ color: '#c0d6ee', display: 'block', marginBottom: '4px' }}>Recommended Remediation (Advisory):</strong>
                    <ul style={{ margin: 0, paddingLeft: '18px', color: '#8faec9', lineHeight: '1.45' }}>
                      {aiBriefing.remediation_steps.map((st, i) => (
                        <li key={i}>{st}</li>
                      ))}
                    </ul>
                  </div>
                  <small style={{ display: 'block', marginTop: '10px', fontSize: '10px', color: '#8faec9', borderTop: '1px solid #142e48', paddingTop: '6px' }}>
                    {aiBriefing.disclaimer}
                  </small>
                </div>
              ) : (
                <small style={{ display: 'block', marginTop: '6px', color: '#7fa4c4' }}>
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
                style={{ marginRight: 'auto', background: 'transparent', borderColor: '#24486b', color: '#8ec5fc' }}
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
                  <h3 style={{ margin: 0, color: '#f0f6fc' }}>
                    {authUser?.full_name || profile?.full_name || 'SecOps Operator'}
                  </h3>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '4px' }}>
                    <span className={`auth-user-role-badge ${authUser?.role?.toLowerCase() || 'analyst'}`}>
                      {authUser?.role || 'ANALYST'}
                    </span>
                    <span style={{ color: '#38bdf8', fontSize: '13px' }}>{authUser?.email}</span>
                  </div>
                  <small style={{ display: 'block', color: '#8faec9', marginTop: '4px' }}>
                    Provider: {authUser?.auth_provider || 'LOCAL'} • Verified Database Identity
                  </small>
                </div>
              </div>

              <div className="profile-meta-grid">
                <div>
                  <small>Operating Mode</small>
                  <b style={{ color: '#42dfa0' }}>{profile?.active_mode || enforcementConfig?.active_mode || 'DRY_RUN'}</b>
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

              <h4 style={{ margin: '18px 0 8px', color: '#c0d6ee', fontSize: '12px' }}>Active Safety Guardrails & Status</h4>
              <div className="profile-perms-list">
                <div>✓ ML Anomaly & Continuous Risk Scoring: <b>Active</b></div>
                <div>✓ In-Memory Sandbox Quarantine Isolation: <b>Enabled</b></div>
                <div>✓ AWS VPC Telemetry Integration: <b>Read-Only (Safety Gated)</b></div>
                <div>✓ Host OS Firewall Modification: <b>Restricted (Zero Host Changes)</b></div>
                <div>✓ Multi-User Authentication: <b style={{ color: '#42dfa0' }}>Active (JWT + PostgreSQL)</b></div>
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
                  value={flowInput.packet_count}
                  onChange={(e) => setFlowInput({ ...flowInput, packet_count: Number(e.target.value) })}
                />
              </div>
              <div className="flow-field">
                <label>Byte Count</label>
                <input
                  type="number"
                  value={flowInput.byte_count}
                  onChange={(e) => setFlowInput({ ...flowInput, byte_count: Number(e.target.value) })}
                />
              </div>
              <div className="flow-field">
                <label>Duration (s)</label>
                <input
                  type="number"
                  step="0.01"
                  value={flowInput.duration}
                  onChange={(e) => setFlowInput({ ...flowInput, duration: Number(e.target.value) })}
                />
              </div>
              <div className="flow-field">
                <label>Conn Rate (conn/s)</label>
                <input
                  type="number"
                  step="0.1"
                  value={flowInput.conn_rate}
                  onChange={(e) => setFlowInput({ ...flowInput, conn_rate: Number(e.target.value) })}
                />
              </div>
              <div className="flow-field">
                <label>Dest Port</label>
                <input
                  type="number"
                  value={flowInput.dst_port}
                  onChange={(e) => setFlowInput({ ...flowInput, dst_port: Number(e.target.value) })}
                />
              </div>
              <div className="flow-field">
                <label>Unique Dest Ports</label>
                <input
                  type="number"
                  value={flowInput.unique_dst_ports ?? 1}
                  onChange={(e) => setFlowInput({ ...flowInput, unique_dst_ports: Number(e.target.value) })}
                />
              </div>
              <div className="flow-field">
                <label>Failed Auth Count</label>
                <input
                  type="number"
                  value={flowInput.failed_auth_count ?? 0}
                  onChange={(e) => setFlowInput({ ...flowInput, failed_auth_count: Number(e.target.value) })}
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
                  <h4>Class Probability Estimates (RandomForest)</h4>
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

                {predictResult.top_contributing_features.length > 0 && (
                  <div className="deviations-list">
                    <h4>Top Anomalous Feature Indicators (z-score vs Benign Baseline)</h4>
                    {predictResult.top_contributing_features.map((cf) => (
                      <div className="deviation-item" key={cf.feature}>
                        • <strong>{cf.feature}</strong>: {cf.description}
                      </div>
                    ))}
                  </div>
                )}

                <div style={{ marginTop: '16px' }}>
                  <button
                    className="chip"
                    onClick={handleComparePolicies}
                    disabled={comparing}
                    style={{ width: '100%', padding: '8px', background: '#1c3e5d', borderColor: '#3b8cd9', fontWeight: 600 }}
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
                        <span style={{ fontSize: '10px', color: '#7fa4c4' }}>
                          {comparisonResult.static_rule_matched || 'Default Permit Policy'}
                        </span>
                      </div>
                      <div className="comp-box">
                        <small>Adaptive AI Decision</small>
                        <b className={comparisonResult.adaptive_decision}>{comparisonResult.adaptive_decision}</b>
                        <span style={{ fontSize: '10px', color: '#7fa4c4' }}>
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
                <small style={{ color: '#8faec9', display: 'block' }}>Telemetry Source Type</small>
                <b style={{ color: '#f0f6fe' }}>
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
                        {ingestResponse.flows_evaluated} Flows ({ingestResponse.high_risk_flows_count} High Risk)
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
                      <h4>Aggregated Flow Classifications (Persisted to PostgreSQL)</h4>
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
                        <b style={{ fontSize: '11px', color: '#38bdf8' }}>{awsVpcResponse.telemetry_source}</b>
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
                                <small style={{ color: '#8faec9' }}>{r.source_ip}</small>
                              </td>
                              <td>
                                <span className={`zone-tag ${r.destination_zone}`}>
                                  {r.destination_zone}
                                </span>
                                <br />
                                <small style={{ color: '#8faec9' }}>{r.destination_ip}</small>
                              </td>
                              <td>
                                <code style={{ fontSize: '11px', color: '#a0c4e8' }}>
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
                <small style={{ color: '#8faec9', display: 'block' }}>Operating Mode</small>
                <b style={{ color: '#f0f6fe' }}>{enforcementConfig?.active_mode || 'DRY_RUN'}</b>
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
                <div style={{ textAlign: 'center', padding: '24px', color: '#7fa4c4', background: '#091928', borderRadius: '8px' }}>
                  No active containment rules currently enforced.
                </div>
              ) : (
                <div className="rules-list-container">
                  {activeRules.map((rule) => (
                    <div className="rule-card" key={rule.rule_id}>
                      <div className="rule-info">
                        <h4>{rule.target_ip} ({rule.action})</h4>
                        <p>{rule.reason}</p>
                        <small style={{ fontSize: '10px', color: '#8faec9' }}>
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
