import { useEffect, useMemo, useState } from 'react'
import './App.css'
import { applyAction, getDashboard } from './services/dashboard'
import { getPresets, predictFlow } from './services/predictor'
import type {
  DashboardData,
  FlowPredictionRequest,
  FlowPredictionResponse,
  PolicyAction,
  SecurityEvent,
} from './types'

const nav = [
  ['⌂', 'Dashboard'],
  ['▥', 'Traffic'],
  ['▣', 'Events'],
  ['◇', 'Policies'],
  ['▤', 'Reports'],
]

const timeline = [
  ['14:32:07', 'Anomaly detected', 'Unusual traffic on port 8443', '◈'],
  ['14:32:09', 'Traffic restricted', 'Applied temporary restrict policy (confidence 87%)', '✹'],
  ['14:32:12', 'Security team notified', 'Alert sent to #sec-ops', '♟'],
  ['14:33:01', 'Monitoring', 'Continuing to monitor for further activity', '✓'],
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

function Traffic() {
  return (
    <div className="traffic-chart">
      <div className="legend">
        <span>
          <i className="in" />
          Inbound
        </span>
        <span>
          <i className="out" />
          Outbound
        </span>
        <span>
          <i className="an" />
          Anomalies
        </span>
      </div>
      <div className="chart">
        <div className="axis">
          <span>5 Gbps</span>
          <span>4 Gbps</span>
          <span>3 Gbps</span>
          <span>2 Gbps</span>
          <span>1 Gbps</span>
          <span>0</span>
        </div>
        <svg viewBox="0 0 780 205" preserveAspectRatio="none" aria-label="24 hour traffic chart">
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
          <path
            className="line-in"
            d="M0 156C27 143 47 153 74 132S112 113 143 137 179 153 205 132 240 140 268 122 307 137 340 117 385 127 407 91 435 39 458 61 476 102 517 109 544 92 588 112 628 120 657 101 703 113 747 94 780 100L780 205H0Z"
          />
          <path
            className="line-out"
            d="M0 173C35 151 68 169 99 147S139 149 171 169 211 176 250 163 296 162 330 174 370 150 408 145 444 139 477 165 516 176 554 163 600 159 635 174 683 178 722 160 760 167 780 162"
          />
          <g className="dots">
            <circle cx="102" cy="125" r="7" />
            <circle cx="282" cy="123" r="7" />
            <circle cx="431" cy="53" r="8" />
            <circle cx="475" cy="100" r="7" />
            <circle cx="610" cy="112" r="7" />
          </g>
        </svg>
        <div className="chart-tip">
          <b>Anomaly detected</b>
          <br />
          4.2 Gbps
          <br />
          <small>14:32</small>
        </div>
      </div>
      <div className="ticks">
        <span>00:00</span>
        <span>04:00</span>
        <span>08:00</span>
        <span>12:00</span>
        <span>16:00</span>
        <span>20:00</span>
      </div>
    </div>
  )
}

function Connectivity({ flows }: { flows: number }) {
  return (
    <div className="connect">
      <div className="title-line">
        <div>
          <h2>Hybrid Cloud Connectivity</h2>
          <p>
            <i /> All links operational
          </p>
        </div>
        <span>↔ &nbsp;{flows} active flows</span>
      </div>
      <div className="network">
        <div className="node">
          <b>☁</b>
          <strong>AWS Cloud</strong>
          <small>
            us-east-1
            <br />
            10.100.0.0/16
          </small>
          <em>Healthy</em>
        </div>
        <div className="wire">
          <label>Secure VPN</label>
          <small>● &nbsp;12 ms</small>
        </div>
        <div className="node central">
          <b>⬡</b>
          <strong>AI Security Gateway</strong>
          <small>Inspect • Analyze • Protect</small>
          <em>Active</em>
        </div>
        <div className="wire">
          <label>Transit Gateway</label>
          <small>● &nbsp;18 ms</small>
        </div>
        <div className="node">
          <b>▤</b>
          <strong>On-Premise Data Center</strong>
          <small>192.168.1.0/24</small>
          <em>Healthy</em>
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

  // Live Threat Analyzer State
  const [showAnalyzer, setShowAnalyzer] = useState(false)
  const [flowInput, setFlowInput] = useState<FlowPredictionRequest>(DEFAULT_FLOW_INPUT)
  const [predictResult, setPredictResult] = useState<FlowPredictionResponse | null>(null)
  const [predicting, setPredicting] = useState(false)
  const [presets, setPresets] = useState<Record<string, FlowPredictionRequest>>({})

  useEffect(() => {
    const controller = new AbortController()
    getDashboard(controller.signal)
      .then((res) => {
        setData(res.data)
        setIsLiveBackend(res.isLiveBackend)
      })
      .catch(() => setToast('Could not load dashboard data.'))
      .finally(() => setLoading(false))

    // Preload test presets from FastAPI backend
    getPresets(controller.signal)
      .then(setPresets)
      .catch(() => {
        // Fallback local presets if offline
        setPresets({
          BENIGN_HTTPS: { packet_count: 25, byte_count: 15000, duration: 2.5, conn_rate: 2.0, dst_port: 443, unique_dst_ports: 1, failed_auth_count: 0 },
          PORT_SCAN: { packet_count: 2, byte_count: 120, duration: 0.08, conn_rate: 120.0, dst_port: 8080, unique_dst_ports: 75, failed_auth_count: 0 },
          BRUTE_FORCE_SSH: { packet_count: 35, byte_count: 8500, duration: 1.8, conn_rate: 18.0, dst_port: 22, unique_dst_ports: 1, failed_auth_count: 12 },
          TRAFFIC_SPIKE: { packet_count: 4500, byte_count: 4500000, duration: 4.0, conn_rate: 60.0, dst_port: 80, unique_dst_ports: 1, failed_auth_count: 0 },
          BORDERLINE_FLOW: { packet_count: 8, byte_count: 600, duration: 0.8, conn_rate: 15.0, dst_port: 8080, unique_dst_ports: 5, failed_auth_count: 0 },
        })
      })

    return () => controller.abort()
  }, [])

  const filtered = useMemo(
    () =>
      data?.events.filter((event) =>
        Object.values(event).join(' ').toLowerCase().includes(search.toLowerCase())
      ) ?? [],
    [data, search]
  )

  const updateAction = async (action: PolicyAction) => {
    if (!selected || action === 'Allow') return
    await applyAction(selected.id, action)
    setData((previous) =>
      previous
        ? {
            ...previous,
            events: previous.events.map((event) =>
              event.id === selected.id
                ? { ...event, action, status: action === 'Monitor' ? 'Monitoring' : 'Applied' }
                : event
            ),
          }
        : previous
    )
    setToast(`${action} policy applied to ${selected.source}.`)
    setSelected(null)
  }

  const runLiveInference = async () => {
    setPredicting(true)
    try {
      const res = await predictFlow(flowInput)
      setPredictResult(res)
      setToast(`ML Inference Complete: ${res.attack_type} (Risk: ${res.risk_score})`)
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

  if (loading || !data) return <div className="loading">Loading security overview…</div>

  return (
    <div className="app">
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
                if (name !== 'Dashboard') setToast(`${name} is ready to connect to its backend endpoint.`)
              }}
              key={name}
            >
              <i>{icon}</i>
              <span>{name}</span>
            </button>
          ))}
        </nav>
        <div className="health">
          <i /> <b>System Healthy</b>
          <span>
            {isLiveBackend ? 'FastAPI ML Engine Connected' : 'Local Fallback Mode'}
            <br />
            Uptime 99.98%
          </span>
        </div>
      </aside>

      <main>
        <header>
          <div className="mobile-logo">⬡</div>
          <label className="search">
            ⌕{' '}
            <input
              value={search}
              onChange={(event) => setSearch(event.target.value)}
              placeholder="Search for IP, domain, event, or policy..."
            />
          </label>
          <div
            className={`backend-status-tag ${isLiveBackend ? 'online' : 'offline'}`}
            title="FastAPI Backend Connection State"
          >
            <i /> {isLiveBackend ? 'FastAPI ML Online' : 'Fallback Offline'}
          </div>
          <button className="analyzer-btn" onClick={() => setShowAnalyzer(true)}>
            ⚡ Test Live Flow (ML API)
          </button>
          <button className="select">Production ⌄</button>
          <select
            className="select range"
            value={range}
            onChange={(event) => setRange(event.target.value)}
            aria-label="Time range"
          >
            <option>Last 24 hours</option>
            <option>Last 7 days</option>
            <option>Last 30 days</option>
          </select>
          <button className="alert" onClick={() => setToast('3 unread security notifications.')}>
            ♧<b>3</b>
          </button>
          <div className="profile">
            <i>K</i>
            <span>
              <b>Krishna</b>
              <small>Security Analyst</small>
            </span>
            ⌄
          </div>
        </header>

        <div className="content">
          <section className="intro">
            <div>
              <h1>{activeNav === 'Dashboard' ? 'Good evening, Krishna' : activeNav}</h1>
              <p>Your hybrid cloud environment is secure, with real-time AI anomaly evaluation active.</p>
            </div>
            <div className="metrics">
              <Metric icon="♢" label="Uptime" value="99.98%" />
              <Metric icon="⌁" label="Active Flows" value={String(data.activeFlows)} note="+12% vs. prev" />
              <Metric icon="◴" label="Avg. Latency" value="18 ms" />
              <Metric icon="●" label="Connection Health" value="Healthy" note="AWS ↔ On-Prem" green />
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
                  <button className="primary" onClick={() => data.events[0] && setSelected(data.events[0])}>
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
                  <button className="primary" onClick={() => data.events[0] && setSelected(data.events[0])}>
                    Review incident <span>→</span>
                  </button>
                </section>
              </div>
            </article>
          </section>

          <section className="middle">
            <article className="card">
              <Connectivity flows={data.activeFlows} />
            </article>
            <article className="card">
              <h2>
                Inbound / Outbound Traffic <small>({range})</small>
              </h2>
              <Traffic />
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
              {timeline.map(([time, title, sub, icon]) => (
                <div className="step" key={time}>
                  <i>{icon}</i>
                  <div>
                    <span>{time}</span>
                    <b>{title}</b>
                    <small>{sub}</small>
                  </div>
                </div>
              ))}
            </article>

            <article className="card key">
              <h2>Key Metrics</h2>
              <div>
                <Metric icon="⌘" label="Detection Rate" value="98.5%" note="Trained RF Classifier" />
                <Metric icon="♢" label="False Positives" value="0.0%" note="Holdout validation" />
                <Metric icon="◴" label="ML Latency" value="< 2 ms" note="Inference speed" />
                <Metric icon="▣" label="Active Policies" value="12" note="2 in monitor mode" />
              </div>
            </article>
          </section>
        </div>
      </main>

      {/* Incident Review Modal */}
      {selected && (
        <div className="modal-backdrop" role="presentation" onMouseDown={() => setSelected(null)}>
          <section
            className="incident-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="incident-title"
            onMouseDown={(event) => event.stopPropagation()}
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
            <div className="modal-actions">
              <button onClick={() => updateAction('Monitor')}>Monitor</button>
              <button onClick={() => updateAction('Restrict')}>Restrict</button>
              <button className="danger-button" onClick={() => updateAction('Block')}>
                Block traffic
              </button>
            </div>
          </section>
        </div>
      )}

      {/* Phase 2: Live Threat Analyzer Modal */}
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
            <span className="eyebrow">Phase 2 — Real ML Inference Gateway</span>
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
              </div>
            )}
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
