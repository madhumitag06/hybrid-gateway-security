/**
 * Traffic View Component — Live Network Flow & Anomaly Analyzer
 * =============================================================
 * Allows analysts to inject real-time network flow vectors, evaluate
 * RandomForest threat predictions, inspect 5-class probability distributions,
 * view SHAP waterfall attributions, inspect policy engine decisions, and
 * review interactive analysis history.
 */

import React, { useEffect, useState } from 'react'
import { getPresets, predictFlow } from '../services/predictor'
import { comparePolicies, evaluateFlowPolicy } from '../services/enforcement'
import { listSecurityEvents } from '../services/events'
import type {
  FlowPredictionRequest,
  FlowPredictionResponse,
  PolicyComparisonResult,
  PolicyDecision,
} from '../types'

const DEFAULT_FLOW: FlowPredictionRequest = {
  packet_count: 2,
  byte_count: 120,
  duration: 0.08,
  conn_rate: 120.0,
  dst_port: 8080,
  unique_dst_ports: 75,
  failed_auth_count: 0,
}

// Verified baseline and anomaly flow vectors (all 6 standard scenarios)
const FALLBACK_PRESETS: Record<string, FlowPredictionRequest> = {
  BENIGN_HTTPS: {
    packet_count: 25,
    byte_count: 15000,
    duration: 2.5,
    conn_rate: 2.0,
    dst_port: 443,
    unique_dst_ports: 1,
    failed_auth_count: 0,
  },
  PORT_SCAN: {
    packet_count: 2,
    byte_count: 120,
    duration: 0.08,
    conn_rate: 120.0,
    dst_port: 8080,
    unique_dst_ports: 75,
    failed_auth_count: 0,
  },
  BRUTE_FORCE_SSH: {
    packet_count: 35,
    byte_count: 8500,
    duration: 1.8,
    conn_rate: 18.0,
    dst_port: 22,
    unique_dst_ports: 1,
    failed_auth_count: 12,
  },
  TRAFFIC_SPIKE: {
    packet_count: 4500,
    byte_count: 4500000,
    duration: 4.0,
    conn_rate: 60.0,
    dst_port: 80,
    unique_dst_ports: 1,
    failed_auth_count: 0,
  },
  BORDERLINE_FLOW: {
    packet_count: 8,
    byte_count: 600,
    duration: 0.8,
    conn_rate: 15.0,
    dst_port: 8080,
    unique_dst_ports: 5,
    failed_auth_count: 0,
  },
  SUSPICIOUS_TRANSFER: {
    packet_count: 1200,
    byte_count: 1600000,
    duration: 120.0,
    conn_rate: 3.0,
    dst_port: 8443,
    unique_dst_ports: 1,
    failed_auth_count: 0,
  },
}

export interface AnalysisHistoryItem {
  id: string
  runNumber: number
  timestamp: string
  presetName: string
  flowSummary: string
  attack_type: string
  risk_score: number
  confidence: number
  policy_action: string
  is_anomaly: boolean
  shap_status: string
  flow: FlowPredictionRequest
}

export const TrafficView: React.FC = () => {
  const [flow, setFlow] = useState<FlowPredictionRequest>(DEFAULT_FLOW)
  const [inputValues, setInputValues] = useState<Record<string, string>>({
    packet_count: String(DEFAULT_FLOW.packet_count),
    byte_count: String(DEFAULT_FLOW.byte_count),
    duration: String(DEFAULT_FLOW.duration),
    conn_rate: String(DEFAULT_FLOW.conn_rate),
    dst_port: String(DEFAULT_FLOW.dst_port),
    unique_dst_ports: String(DEFAULT_FLOW.unique_dst_ports || 1),
    failed_auth_count: String(DEFAULT_FLOW.failed_auth_count || 0),
  })
  const [validationErrors, setValidationErrors] = useState<Record<string, string>>({})
  const [presets, setPresets] = useState<Record<string, FlowPredictionRequest>>(FALLBACK_PRESETS)
  const [activePreset, setActivePreset] = useState<string>('PORT_SCAN')
  const [predictResult, setPredictResult] = useState<FlowPredictionResponse | null>(null)
  const [policyDecision, setPolicyDecision] = useState<PolicyDecision | null>(null)
  const [comparisonResult, setComparisonResult] = useState<PolicyComparisonResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Execution tracking & dynamic feedback state
  const [analysisRunCount, setAnalysisRunCount] = useState<number>(0)
  const [lastExecution, setLastExecution] = useState<{
    runNumber: number
    timestamp: string
    latencyMs: number
    presetName: string
  } | null>(null)
  const [showFreshBanner, setShowFreshBanner] = useState<boolean>(false)
  const [analysisHistory, setAnalysisHistory] = useState<AnalysisHistoryItem[]>([])

  const handlePredict = async (
    flowInput: FlowPredictionRequest = flow,
    presetLabel?: string
  ) => {
    setLoading(true)
    setError(null)
    const startTime = performance.now()

    try {
      const [res, dec, comp] = await Promise.all([
        predictFlow(flowInput),
        evaluateFlowPolicy(flowInput).catch(() => null),
        comparePolicies(flowInput).catch(() => null),
      ])

      const latencyMs = Math.max(1, Math.round(performance.now() - startTime))
      const nextRun = analysisRunCount + 1
      const nowStr = new Date().toLocaleTimeString()
      const label = presetLabel || activePreset || 'CUSTOM'

      setPredictResult(res)
      setPolicyDecision(dec)
      setComparisonResult(comp)
      setAnalysisRunCount(nextRun)
      setLastExecution({
        runNumber: nextRun,
        timestamp: nowStr,
        latencyMs,
        presetName: label,
      })
      setShowFreshBanner(true)

      // Prepend to interactive session history
      const historyEntry: AnalysisHistoryItem = {
        id: `run-${Date.now()}-${nextRun}`,
        runNumber: nextRun,
        timestamp: nowStr,
        presetName: label,
        flowSummary: `Port ${flowInput.dst_port} • ${flowInput.packet_count} pkts • ${flowInput.duration}s`,
        attack_type: res.attack_type,
        risk_score: res.risk_score,
        confidence: res.confidence,
        policy_action: dec?.policy_action || res.action_recommendation,
        is_anomaly: res.is_anomaly,
        shap_status:
          res.explanation_status ||
          (res.top_contributing_features && res.top_contributing_features.length > 0
            ? 'CALCULATED'
            : 'SKIPPED_LOW_RISK'),
        flow: { ...flowInput },
      }

      setAnalysisHistory((prev) => [historyEntry, ...prev.slice(0, 9)])
    } catch (err) {
      setError(String(err))
    } finally {
      setLoading(false)
    }
  }

  // Preload presets and seed initial session history from persisted database events
  useEffect(() => {
    getPresets()
      .then((p) => {
        const merged = { ...FALLBACK_PRESETS, ...p }
        setPresets(merged)
        const initial = merged.PORT_SCAN || DEFAULT_FLOW
        setFlow(initial)
        setInputValues({
          packet_count: String(initial.packet_count),
          byte_count: String(initial.byte_count),
          duration: String(initial.duration),
          conn_rate: String(initial.conn_rate),
          dst_port: String(initial.dst_port),
          unique_dst_ports: String(initial.unique_dst_ports ?? 1),
          failed_auth_count: String(initial.failed_auth_count ?? 0),
        })
        handlePredict(initial, 'PORT_SCAN')
      })
      .catch(() => {
        setPresets(FALLBACK_PRESETS)
        handlePredict(FALLBACK_PRESETS.PORT_SCAN, 'PORT_SCAN')
      })

    // Preload recent backend events to populate history baseline
    listSecurityEvents({ limit: 5 })
      .then((res) => {
        if (res && res.events && res.events.length > 0) {
          const preloaded: AnalysisHistoryItem[] = res.events.map((evt) => ({
            id: evt.id,
            runNumber: 0,
            timestamp: evt.time || 'Persisted',
            presetName: evt.attack_type || evt.event || 'SECURITY_EVENT',
            flowSummary: `${evt.source} → ${evt.destination}`,
            attack_type: evt.attack_type || evt.event || 'UNKNOWN',
            risk_score: evt.risk ?? 0,
            confidence: evt.confidence ?? 0.99,
            policy_action: evt.action || 'Allow',
            is_anomaly: evt.severity !== 'low',
            shap_status: evt.severity === 'low' ? 'SKIPPED_LOW_RISK' : 'CALCULATED',
            flow: {
              packet_count: 10,
              byte_count: 500,
              duration: 1.0,
              conn_rate: 10.0,
              dst_port: 80,
              unique_dst_ports: 1,
              failed_auth_count: 0,
            },
          }))
          setAnalysisHistory((prev) => (prev.length === 0 ? preloaded : prev))
        }
      })
      .catch(() => {})
  }, [])

  // Auto-dismiss fresh analysis flash banner after 4.5 seconds
  useEffect(() => {
    if (!showFreshBanner) return
    const timer = setTimeout(() => setShowFreshBanner(false), 4500)
    return () => clearTimeout(timer)
  }, [showFreshBanner, analysisRunCount])

  const selectPreset = (key: string) => {
    setActivePreset(key)
    const p = presets[key]
    if (p) {
      setFlow({ ...p })
      setInputValues({
        packet_count: String(p.packet_count),
        byte_count: String(p.byte_count),
        duration: String(p.duration),
        conn_rate: String(p.conn_rate),
        dst_port: String(p.dst_port),
        unique_dst_ports: String(p.unique_dst_ports ?? 1),
        failed_auth_count: String(p.failed_auth_count ?? 0),
      })
      setValidationErrors({})
      handlePredict(p, key)
    }
  }

  const reloadFromHistory = (item: AnalysisHistoryItem) => {
    setActivePreset(item.presetName)
    setFlow({ ...item.flow })
    setInputValues({
      packet_count: String(item.flow.packet_count),
      byte_count: String(item.flow.byte_count),
      duration: String(item.flow.duration),
      conn_rate: String(item.flow.conn_rate),
      dst_port: String(item.flow.dst_port),
      unique_dst_ports: String(item.flow.unique_dst_ports ?? 1),
      failed_auth_count: String(item.flow.failed_auth_count ?? 0),
    })
    setValidationErrors({})
    handlePredict(item.flow, item.presetName)
  }

  const handleInputChange = (field: string, val: string) => {
    setInputValues((prev) => ({ ...prev, [field]: val }))
    setValidationErrors((prev) => {
      if (!prev[field]) return prev
      const updated = { ...prev }
      delete updated[field]
      return updated
    })
  }

  const handleFormSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    const errors: Record<string, string> = {}

    // 1. Duration (float >= 0.0)
    const durRaw = inputValues.duration.trim()
    const durationNum = parseFloat(durRaw)
    if (durRaw === '' || isNaN(durationNum) || durationNum < 0) {
      errors.duration = 'Duration must be a valid number ≥ 0.0s (e.g. 0.08, 0.10, 1.5)'
    }

    // 2. Packet Count (int >= 1)
    const pktRaw = inputValues.packet_count.trim()
    const pktNum = parseInt(pktRaw, 10)
    if (pktRaw === '' || isNaN(pktNum) || pktNum < 1 || !/^\d+$/.test(pktRaw)) {
      errors.packet_count = 'Packet count must be an integer ≥ 1'
    }

    // 3. Byte Count (int >= 0)
    const byteRaw = inputValues.byte_count.trim()
    const byteNum = parseInt(byteRaw, 10)
    if (byteRaw === '' || isNaN(byteNum) || byteNum < 0 || !/^\d+$/.test(byteRaw)) {
      errors.byte_count = 'Byte count must be an integer ≥ 0'
    }

    // 4. Connection Rate (float >= 0.0)
    const connRaw = inputValues.conn_rate.trim()
    const connNum = parseFloat(connRaw)
    if (connRaw === '' || isNaN(connNum) || connNum < 0) {
      errors.conn_rate = 'Connection rate must be a valid number ≥ 0.0'
    }

    // 5. Destination Port (1 <= int <= 65535)
    const portRaw = inputValues.dst_port.trim()
    const portNum = parseInt(portRaw, 10)
    if (
      portRaw === '' ||
      isNaN(portNum) ||
      portNum < 1 ||
      portNum > 65535 ||
      !/^\d+$/.test(portRaw)
    ) {
      errors.dst_port = 'Port must be an integer between 1 and 65535'
    }

    // 6. Unique Destination Ports (int >= 1)
    const uniqRaw = inputValues.unique_dst_ports.trim()
    const uniqNum = parseInt(uniqRaw, 10)
    if (uniqRaw === '' || isNaN(uniqNum) || uniqNum < 1 || !/^\d+$/.test(uniqRaw)) {
      errors.unique_dst_ports = 'Unique ports must be an integer ≥ 1'
    }

    // 7. Failed Authentication Count (int >= 0)
    const authRaw = inputValues.failed_auth_count.trim()
    const authNum = parseInt(authRaw, 10)
    if (authRaw === '' || isNaN(authNum) || authNum < 0 || !/^\d+$/.test(authRaw)) {
      errors.failed_auth_count = 'Failed auth count must be an integer ≥ 0'
    }

    if (Object.keys(errors).length > 0) {
      setValidationErrors(errors)
      return
    }

    setValidationErrors({})
    const validatedFlow: FlowPredictionRequest = {
      packet_count: pktNum,
      byte_count: byteNum,
      duration: durationNum,
      conn_rate: connNum,
      dst_port: portNum,
      unique_dst_ports: uniqNum,
      failed_auth_count: authNum,
    }
    setFlow(validatedFlow)
    handlePredict(validatedFlow, activePreset || 'CUSTOM')
  }

  // Determine strongest risk-increasing and risk-reducing features
  const shapFeatures = predictResult?.top_contributing_features || []
  const hasShapValues = shapFeatures.some((f) => f.shap_value !== undefined && f.shap_value !== null)
  let strongestIncreaseFeature: string | null = null
  let strongestDecreaseFeature: string | null = null

  if (hasShapValues) {
    let maxInc = -Infinity
    let minDec = Infinity
    shapFeatures.forEach((f) => {
      const val = f.shap_value ?? 0
      if (val > 0 && val > maxInc) {
        maxInc = val
        strongestIncreaseFeature = f.feature
      }
      if (val < 0 && val < minDec) {
        minDec = val
        strongestDecreaseFeature = f.feature
      }
    })
  }

  const isShapSkipped =
    predictResult &&
    (predictResult.explanation_status === 'SKIPPED_LOW_RISK' ||
      (!hasShapValues && predictResult.risk_score < 50 && !predictResult.is_anomaly))

  return (
    <div className="traffic-view-container">
      <section className="intro">
        <div>
          <h1>⚡ Live Flow Inspector & Threat Classifier</h1>
          <p>
            Evaluate raw network flow vectors in real-time through the trained RandomForest model,
            view exact multi-class probabilities, SHAP feature attributions, and adaptive policy decisions.
          </p>
        </div>
      </section>

      {error && (
        <div
          className="card error-banner"
          style={{
            marginBottom: '16px',
            color: 'var(--muted-red)',
            borderColor: 'var(--muted-red)',
            background: 'rgba(217, 83, 79, 0.12)',
            padding: '12px 16px',
            borderRadius: '4px',
          }}
        >
          <b>Inference Error:</b> {error}
        </div>
      )}

      <div className="traffic-layout-grid">
        {/* Left Column: Flow Vector Form & Presets */}
        <div className="card traffic-input-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <h2>1. Select Flow Scenario or Enter Parameters</h2>
            {analysisRunCount > 0 && (
              <span
                style={{
                  fontSize: '11px',
                  color: 'var(--muted-cream)',
                  fontFamily: 'var(--font-mono)',
                  background: 'var(--panel-inset)',
                  padding: '2px 8px',
                  borderRadius: '10px',
                  border: '1px solid var(--line)',
                }}
              >
                Inferences: {analysisRunCount}
              </span>
            )}
          </div>

          <div className="preset-container" style={{ marginTop: '12px' }}>
            <label>Standard Test Scenarios</label>
            <div className="preset-chips">
              {Object.keys(presets).map((key) => (
                <button
                  key={key}
                  type="button"
                  className={`chip ${activePreset === key ? 'active' : ''}`}
                  onClick={() => selectPreset(key)}
                  disabled={loading}
                >
                  {key.replace(/_/g, ' ')}
                </button>
              ))}
            </div>
          </div>

          <form onSubmit={handleFormSubmit} style={{ marginTop: '16px' }} noValidate>
            <div className="flow-form-grid">
              <div className="flow-field">
                <label>Packet Count</label>
                <input
                  type="number"
                  min="1"
                  step="1"
                  required
                  autoComplete="off"
                  value={inputValues.packet_count}
                  onChange={(e) => handleInputChange('packet_count', e.target.value)}
                />
                {validationErrors.packet_count && (
                  <span style={{ color: 'var(--muted-red)', fontSize: '10.5px', marginTop: '3px' }}>
                    {validationErrors.packet_count}
                  </span>
                )}
              </div>
              <div className="flow-field">
                <label>Byte Count</label>
                <input
                  type="number"
                  min="0"
                  step="1"
                  required
                  autoComplete="off"
                  value={inputValues.byte_count}
                  onChange={(e) => handleInputChange('byte_count', e.target.value)}
                />
                {validationErrors.byte_count && (
                  <span style={{ color: 'var(--muted-red)', fontSize: '10.5px', marginTop: '3px' }}>
                    {validationErrors.byte_count}
                  </span>
                )}
              </div>
              <div className="flow-field">
                <label>Duration (s)</label>
                <input
                  type="number"
                  min="0"
                  step="any"
                  required
                  autoComplete="off"
                  value={inputValues.duration}
                  onChange={(e) => handleInputChange('duration', e.target.value)}
                />
                {validationErrors.duration && (
                  <span style={{ color: 'var(--muted-red)', fontSize: '10.5px', marginTop: '3px' }}>
                    {validationErrors.duration}
                  </span>
                )}
              </div>
              <div className="flow-field">
                <label>Connection Rate (pkts/s)</label>
                <input
                  type="number"
                  min="0"
                  step="any"
                  required
                  autoComplete="off"
                  value={inputValues.conn_rate}
                  onChange={(e) => handleInputChange('conn_rate', e.target.value)}
                />
                {validationErrors.conn_rate && (
                  <span style={{ color: 'var(--muted-red)', fontSize: '10.5px', marginTop: '3px' }}>
                    {validationErrors.conn_rate}
                  </span>
                )}
              </div>
              <div className="flow-field">
                <label>Destination Port</label>
                <input
                  type="number"
                  min="1"
                  max="65535"
                  step="1"
                  required
                  autoComplete="off"
                  value={inputValues.dst_port}
                  onChange={(e) => handleInputChange('dst_port', e.target.value)}
                />
                {validationErrors.dst_port && (
                  <span style={{ color: 'var(--muted-red)', fontSize: '10.5px', marginTop: '3px' }}>
                    {validationErrors.dst_port}
                  </span>
                )}
              </div>
              <div className="flow-field">
                <label>Unique Dest Ports</label>
                <input
                  type="number"
                  min="1"
                  step="1"
                  required
                  autoComplete="off"
                  value={inputValues.unique_dst_ports}
                  onChange={(e) => handleInputChange('unique_dst_ports', e.target.value)}
                />
                {validationErrors.unique_dst_ports && (
                  <span style={{ color: 'var(--muted-red)', fontSize: '10.5px', marginTop: '3px' }}>
                    {validationErrors.unique_dst_ports}
                  </span>
                )}
              </div>
              <div className="flow-field">
                <label>Failed Auth Count</label>
                <input
                  type="number"
                  min="0"
                  step="1"
                  required
                  autoComplete="off"
                  value={inputValues.failed_auth_count}
                  onChange={(e) => handleInputChange('failed_auth_count', e.target.value)}
                />
                {validationErrors.failed_auth_count && (
                  <span style={{ color: 'var(--muted-red)', fontSize: '10.5px', marginTop: '3px' }}>
                    {validationErrors.failed_auth_count}
                  </span>
                )}
              </div>
            </div>

            <button
              type="submit"
              className="primary run-predict-btn"
              disabled={loading}
              style={{
                marginTop: '16px',
                display: 'flex',
                justifyContent: 'center',
                alignItems: 'center',
                gap: '8px',
                width: '100%',
                fontWeight: 600,
              }}
            >
              {loading ? (
                <>
                  <span className="spinner" style={{ display: 'inline-block', width: '12px', height: '12px', border: '2px solid rgba(255,255,255,0.3)', borderTopColor: '#fff', borderRadius: '50%', animation: 'spin 0.6s linear infinite' }} />
                  Analyzing flow features...
                </>
              ) : (
                '⚡ Run ML Anomaly Inference & Policy Trace'
              )}
            </button>
          </form>
        </div>

        {/* Right Column: Real-time ML Prediction & Probabilities */}
        {predictResult && (
          <div className="traffic-results-container">
            {/* Visual Flash Banner on new inference completion */}
            {showFreshBanner && lastExecution && (
              <div className="analysis-success-banner">
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <span style={{ fontSize: '14px' }}>✨</span>
                  <span>
                    <strong>Analysis #{lastExecution.runNumber} Complete:</strong> {lastExecution.presetName} evaluated in <strong>{lastExecution.latencyMs} ms</strong> at {lastExecution.timestamp}.
                  </span>
                </div>
                <button
                  type="button"
                  onClick={() => setShowFreshBanner(false)}
                  style={{ background: 'transparent', border: 'none', color: 'var(--muted-cream)', cursor: 'pointer', fontSize: '14px' }}
                >
                  ✕
                </button>
              </div>
            )}

            <div key={`scorecard-${analysisRunCount}`} className="card traffic-scorecard analysis-pulse-card">
              <div className="title-line">
                <div>
                  <h2>2. ML Threat Classification & Risk Assessment</h2>
                  {lastExecution && (
                    <span style={{ fontSize: '11px', color: 'var(--muted-cream)', fontFamily: 'var(--font-mono)' }}>
                      Run #{lastExecution.runNumber} • Completed at {lastExecution.timestamp} • Latency: {lastExecution.latencyMs}ms
                    </span>
                  )}
                </div>
                <span className={`threat-tag ${predictResult.threat_level}`}>
                  {predictResult.threat_level} THREAT
                </span>
              </div>

              <div className="result-summary-grid" style={{ marginTop: '14px' }}>
                <div className="res-stat">
                  <small>Predicted Threat</small>
                  <b>{predictResult.attack_type}</b>
                </div>
                <div className="res-stat">
                  <small>Continuous Risk Score</small>
                  <b
                    className={`risk-val ${
                      predictResult.risk_score >= 70 ? 'r-high' : predictResult.risk_score >= 40 ? 'r-med' : 'r-low'
                    }`}
                  >
                    {predictResult.risk_score} / 100
                  </b>
                </div>
                <div className="res-stat">
                  <small>Model Confidence</small>
                  <b>{(predictResult.confidence * 100).toFixed(1)}%</b>
                </div>
                <div className="res-stat">
                  <small>Anomaly Detected</small>
                  <b style={{ color: predictResult.is_anomaly ? 'var(--muted-red)' : 'var(--desaturated-eucalyptus)' }}>
                    {predictResult.is_anomaly ? 'YES (ANOMALY)' : 'NO (BENIGN)'}
                  </b>
                </div>
              </div>

              {/* Class Probability Distribution across all 5 classes */}
              <div className="prob-breakdown" style={{ marginTop: '14px' }}>
                <h4>Multi-Class Probability Distribution (RandomForest)</h4>
                {['BENIGN', 'PORT_SCAN', 'BRUTE_FORCE', 'TRAFFIC_SPIKE', 'SUSPICIOUS_TRANSFER'].map((cls) => {
                  const prob = predictResult.class_probabilities[cls] ?? 0.0
                  const isWinner = cls === predictResult.attack_type
                  return (
                    <div className="prob-row" key={cls}>
                      <span style={{ fontWeight: isWinner ? 700 : 400, color: isWinner ? 'var(--warm-cream)' : 'var(--muted-cream)' }}>
                        {cls.replace(/_/g, ' ')} {isWinner && '★'}
                      </span>
                      <div className="prob-bar-track">
                        <div
                          className={`prob-bar-fill ${cls}`}
                          style={{ width: `${Math.max(prob * 100, 2)}%` }}
                        />
                      </div>
                      <span style={{ fontWeight: isWinner ? 700 : 400 }}>{(prob * 100).toFixed(1)}%</span>
                    </div>
                  )
                })}
              </div>

              {/* SHAP Feature Attributions or Transparent Skip Card */}
              {isShapSkipped ? (
                <div className="shap-skipped-box">
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <span style={{ fontSize: '13px' }}>🛡️</span>
                    <strong style={{ color: 'var(--desaturated-eucalyptus)', fontSize: '12px' }}>
                      SHAP explanation skipped: flow risk below configured threshold.
                    </strong>
                  </div>
                  <p style={{ margin: '6px 0 0', fontSize: '11px', color: 'var(--muted-cream)', lineHeight: '1.4' }}>
                    TreeExplainer feature attribution is conditionally triggered only when flow risk exceeds the activation threshold (≥ 50/100) or an anomaly is detected. For low-risk benign baseline flows (Risk: {predictResult.risk_score}/100), expensive SHAP calculations are skipped to preserve real-time gateway throughput.
                  </p>
                </div>
              ) : shapFeatures.length > 0 ? (
                <div className="prob-breakdown" style={{ marginTop: '14px' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                    <h4>Top Feature Attributions (SHAP TreeExplainer)</h4>
                    <span style={{ fontSize: '10.5px', color: 'var(--muted-cream)', fontFamily: 'var(--font-mono)' }}>
                      Status: {predictResult.explanation_status || 'CALCULATED'}
                    </span>
                  </div>
                  {shapFeatures.map((fa) => {
                    const isStrongestInc = fa.feature === strongestIncreaseFeature
                    const isStrongestDec = fa.feature === strongestDecreaseFeature
                    return (
                      <div className="shap-bar-row" key={fa.feature} style={{ margin: '6px 0' }}>
                        <span className="shap-bar-feat" title={`${fa.feature} = ${fa.value}`}>
                          {fa.feature} ({fa.value})
                          {isStrongestInc && <span className="shap-strongest-badge increase">MAX RISK</span>}
                          {isStrongestDec && <span className="shap-strongest-badge decrease">REDUCES</span>}
                        </span>
                        <div className="shap-track">
                          <div
                            className={`shap-fill ${fa.contribution_direction || 'INCREASES_RISK'}`}
                            style={{
                              width: `${Math.min(Math.abs(fa.shap_value || fa.deviation_z_score || 0.5) * 150, 100)}%`,
                            }}
                          />
                        </div>
                        <span className={`shap-val-text ${fa.contribution_direction || 'INCREASES_RISK'}`}>
                          {fa.shap_value !== undefined && fa.shap_value !== null
                            ? `${fa.shap_value > 0 ? '+' : ''}${(fa.shap_value * 100).toFixed(1)}%`
                            : `z=${fa.deviation_z_score.toFixed(1)}`}
                        </span>
                      </div>
                    )
                  })}
                </div>
              ) : null}

              {/* Policy Decision Trace — 3-Tier Explanation */}
              <div className="policy-trace-box" style={{ marginTop: '14px' }}>
                <h4>Adaptive Policy Engine Decision Trace</h4>
                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: 'repeat(3, 1fr)',
                    gap: '10px',
                    marginBottom: '12px',
                  }}
                >
                  <div style={{ background: 'var(--panel-inset)', padding: '10px', borderRadius: '4px', border: '1px solid var(--line)' }}>
                    <small style={{ color: 'var(--muted-cream)', fontSize: '10px', display: 'block' }}>1. ML Recommendation</small>
                    <b className={`action ${predictResult.action_recommendation.toLowerCase()}`} style={{ fontSize: '13px', display: 'block', marginTop: '2px' }}>
                      {predictResult.action_recommendation}
                    </b>
                    <span style={{ fontSize: '10px', color: 'var(--muted-cream)' }}>Threat Score: {predictResult.risk_score}/100</span>
                  </div>
                  <div style={{ background: 'var(--panel-inset)', padding: '10px', borderRadius: '4px', border: '1px solid var(--line)' }}>
                    <small style={{ color: 'var(--muted-cream)', fontSize: '10px', display: 'block' }}>2. Policy Decision</small>
                    <b
                      className={`action ${(policyDecision?.policy_action || predictResult.action_recommendation).toLowerCase()}`}
                      style={{ fontSize: '13px', display: 'block', marginTop: '2px' }}
                    >
                      {policyDecision?.policy_action || predictResult.action_recommendation}
                    </b>
                    <span style={{ fontSize: '10px', color: 'var(--muted-cream)' }}>Rule: {policyDecision?.rule_name || 'DEFAULT_EVAL'}</span>
                  </div>
                  <div style={{ background: 'var(--panel-inset)', padding: '10px', borderRadius: '4px', border: '1px solid var(--line)' }}>
                    <small style={{ color: 'var(--muted-cream)', fontSize: '10px', display: 'block' }}>3. Router Enforcement</small>
                    <b style={{ fontSize: '13px', display: 'block', marginTop: '2px', color: 'var(--oxidized-copper)' }}>
                      Simulated / Trace
                    </b>
                    <span style={{ fontSize: '10px', color: 'var(--muted-cream)' }}>Flow Inspector Mode</span>
                  </div>
                </div>

                <p style={{ margin: '0 0 8px', fontSize: '11.5px', color: 'var(--muted-cream)' }}>
                  <b>Policy Rationale:</b> {policyDecision?.reason || 'Evaluated against active security policy baseline rules.'}
                </p>

                <div
                  style={{
                    padding: '8px 10px',
                    background: 'rgba(217, 119, 54, 0.08)',
                    borderRadius: '4px',
                    border: '1px solid rgba(217, 119, 54, 0.25)',
                    fontSize: '10.5px',
                    color: 'var(--muted-cream)',
                  }}
                >
                  ⚠️ <strong>Enforcement Notice:</strong> A 'Block' or 'Restrict' decision in this interactive Flow Inspector demonstrates policy engine evaluation. Real iptables packet dropping requires live container traffic crossing router interfaces via <em>Attack Simulation</em> or <em>Hybrid Topology</em>.
                </div>
              </div>

              {/* Static vs Adaptive Comparison */}
              {comparisonResult && (
                <div className="comparison-card" style={{ marginTop: '14px' }}>
                  <h4>Traditional Static Baseline vs Adaptive AI Divergence</h4>
                  <div className="comparison-grid">
                    <div className="comp-box">
                      <small>Traditional Static Baseline</small>
                      <b className={comparisonResult.static_decision}>{comparisonResult.static_decision}</b>
                      <span style={{ fontSize: '11px', color: 'var(--muted-cream)' }}>Rule: {comparisonResult.static_rule_matched || 'DEFAULT_ALLOW'}</span>
                    </div>
                    <div className="comp-box">
                      <small>Adaptive AI Decision</small>
                      <b className={comparisonResult.adaptive_decision}>{comparisonResult.adaptive_decision}</b>
                      <span style={{ fontSize: '11px', color: 'var(--muted-cream)' }}>Risk: {comparisonResult.adaptive_risk_score}/100</span>
                    </div>
                  </div>
                  <div className="divergence-note">
                    <strong>Divergence:</strong> {comparisonResult.decision_divergence ? 'YES (Policy Divergence)' : 'NO (Same Action)'} — {comparisonResult.divergence_rationale}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Section 3: Recent Analysis History */}
      <div className="card traffic-history-card">
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
          <div>
            <h2 style={{ margin: 0 }}>3. Recent Analysis History</h2>
            <p style={{ margin: '4px 0 0', fontSize: '11.5px', color: 'var(--muted-cream)' }}>
              Complete record of flow vectors inspected in this session and recent security events. Click 'Load Flow' to repopulate any vector.
            </p>
          </div>
          <span style={{ fontSize: '11px', color: 'var(--muted-cream)', fontFamily: 'var(--font-mono)' }}>
            {analysisHistory.length} Record{analysisHistory.length === 1 ? '' : 's'}
          </span>
        </div>

        {analysisHistory.length === 0 ? (
          <div style={{ padding: '24px', textAlign: 'center', color: 'var(--muted-cream)', fontSize: '12px' }}>
            No flow inspections executed yet in this session. Run an analysis above to populate history.
          </div>
        ) : (
          <div style={{ overflowX: 'auto' }}>
            <table className="traffic-history-table">
              <thead>
                <tr>
                  <th>#</th>
                  <th>Timestamp</th>
                  <th>Scenario / Target</th>
                  <th>Classification</th>
                  <th>Risk Score</th>
                  <th>Confidence</th>
                  <th>Policy Action</th>
                  <th>SHAP Status</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {analysisHistory.map((item, index) => (
                  <tr key={item.id || index}>
                    <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--muted-cream)' }}>
                      {item.runNumber > 0 ? `#${item.runNumber}` : 'DB'}
                    </td>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '11px' }}>
                      {item.timestamp}
                    </td>
                    <td>
                      <strong>{item.presetName.replace(/_/g, ' ')}</strong>
                      <span style={{ display: 'block', fontSize: '10px', color: 'var(--muted-cream)', fontFamily: 'var(--font-mono)' }}>
                        {item.flowSummary}
                      </span>
                    </td>
                    <td>
                      <span className={`threat-tag ${item.is_anomaly ? 'HIGH' : 'LOW'}`} style={{ fontSize: '10px', padding: '2px 6px' }}>
                        {item.attack_type}
                      </span>
                    </td>
                    <td>
                      <b
                        className={`risk-val ${
                          item.risk_score >= 70 ? 'r-high' : item.risk_score >= 40 ? 'r-med' : 'r-low'
                        }`}
                        style={{ fontSize: '12px' }}
                      >
                        {item.risk_score}/100
                      </b>
                    </td>
                    <td>{(item.confidence * 100).toFixed(1)}%</td>
                    <td>
                      <b className={`action ${item.policy_action.toLowerCase()}`} style={{ fontSize: '11.5px' }}>
                        {item.policy_action}
                      </b>
                    </td>
                    <td>
                      <span
                        style={{
                          fontSize: '10px',
                          color: item.shap_status === 'CALCULATED' ? 'var(--muted-clay)' : 'var(--desaturated-eucalyptus)',
                        }}
                      >
                        {item.shap_status === 'CALCULATED' ? '✓ Calculated' : '⊘ Skipped (Low Risk)'}
                      </span>
                    </td>
                    <td>
                      <button
                        type="button"
                        className="chip"
                        style={{ padding: '3px 8px', fontSize: '10px' }}
                        onClick={() => reloadFromHistory(item)}
                      >
                        Load Flow
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
