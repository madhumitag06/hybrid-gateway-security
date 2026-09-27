/**
 * Traffic View Component — Live Network Flow & Anomaly Analyzer
 * =============================================================
 * Allows analysts to inject real-time network flow vectors, evaluate
 * RandomForest threat predictions, inspect 5-class probability distributions,
 * view SHAP waterfall attributions, and simulate policy engine actions.
 */

import React, { useEffect, useState } from 'react'
import { getPresets, predictFlow } from '../services/predictor'
import { comparePolicies, evaluateFlowPolicy } from '../services/enforcement'
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

export const TrafficView: React.FC = () => {
  const [flow, setFlow] = useState<FlowPredictionRequest>(DEFAULT_FLOW)
  const [presets, setPresets] = useState<Record<string, FlowPredictionRequest>>({})
  const [activePreset, setActivePreset] = useState<string>('PORT_SCAN')
  const [predictResult, setPredictResult] = useState<FlowPredictionResponse | null>(null)
  const [policyDecision, setPolicyDecision] = useState<PolicyDecision | null>(null)
  const [comparisonResult, setComparisonResult] = useState<PolicyComparisonResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    getPresets()
      .then((p) => {
        setPresets(p)
        if (p.PORT_SCAN) {
          setFlow(p.PORT_SCAN)
          handlePredict(p.PORT_SCAN)
        }
      })
      .catch(() => {
        // Fallback standard presets
        const defaultPresets: Record<string, FlowPredictionRequest> = {
          BENIGN_HTTPS: { packet_count: 25, byte_count: 15000, duration: 2.5, conn_rate: 2.0, dst_port: 443, unique_dst_ports: 1, failed_auth_count: 0 },
          PORT_SCAN: { packet_count: 2, byte_count: 120, duration: 0.08, conn_rate: 120.0, dst_port: 8080, unique_dst_ports: 75, failed_auth_count: 0 },
          BRUTE_FORCE_SSH: { packet_count: 35, byte_count: 8500, duration: 1.8, conn_rate: 18.0, dst_port: 22, unique_dst_ports: 1, failed_auth_count: 12 },
          TRAFFIC_SPIKE: { packet_count: 4500, byte_count: 4500000, duration: 4.0, conn_rate: 60.0, dst_port: 80, unique_dst_ports: 1, failed_auth_count: 0 },
          BORDERLINE_FLOW: { packet_count: 12, byte_count: 1200, duration: 0.8, conn_rate: 35.0, dst_port: 8080, unique_dst_ports: 12, failed_auth_count: 2 },
        }
        setPresets(defaultPresets)
        handlePredict(defaultPresets.PORT_SCAN)
      })
  }, [])

  const handlePredict = async (flowInput: FlowPredictionRequest = flow) => {
    setLoading(true)
    setError(null)
    try {
      const [res, dec, comp] = await Promise.all([
        predictFlow(flowInput),
        evaluateFlowPolicy(flowInput).catch(() => null),
        comparePolicies(flowInput).catch(() => null),
      ])
      setPredictResult(res)
      setPolicyDecision(dec)
      setComparisonResult(comp)
    } catch (err) {
      setError(String(err))
    } finally {
      setLoading(false)
    }
  }

  const selectPreset = (key: string) => {
    setActivePreset(key)
    const p = presets[key]
    if (p) {
      setFlow({ ...p })
      handlePredict(p)
    }
  }

  const handleChange = (field: keyof FlowPredictionRequest, val: string) => {
    const num = parseFloat(val) || 0
    setFlow((prev) => ({ ...prev, [field]: num }))
  }

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
        <div className="card error-banner" style={{ marginBottom: '16px', color: '#ff7f8c', borderColor: '#9b3746' }}>
          <b>Inference Error:</b> {error}
        </div>
      )}

      <div className="traffic-layout-grid">
        {/* Left Column: Flow Vector Form & Presets */}
        <div className="card traffic-input-card">
          <h2>1. Select Flow Scenario or Enter Parameters</h2>
          
          <div className="preset-container" style={{ marginTop: '12px' }}>
            <label>Standard Test Scenarios</label>
            <div className="preset-chips">
              {Object.keys(presets).map((key) => (
                <button
                  key={key}
                  type="button"
                  className={`chip ${activePreset === key ? 'active' : ''}`}
                  onClick={() => selectPreset(key)}
                >
                  {key.replace(/_/g, ' ')}
                </button>
              ))}
            </div>
          </div>

          <form
            onSubmit={(e) => {
              e.preventDefault()
              handlePredict(flow)
            }}
            style={{ marginTop: '16px' }}
          >
            <div className="flow-form-grid">
              <div className="flow-field">
                <label>Packet Count</label>
                <input
                  type="number"
                  value={flow.packet_count}
                  onChange={(e) => handleChange('packet_count', e.target.value)}
                  min={1}
                />
              </div>
              <div className="flow-field">
                <label>Byte Count</label>
                <input
                  type="number"
                  value={flow.byte_count}
                  onChange={(e) => handleChange('byte_count', e.target.value)}
                  min={1}
                />
              </div>
              <div className="flow-field">
                <label>Duration (s)</label>
                <input
                  type="number"
                  step="0.01"
                  value={flow.duration}
                  onChange={(e) => handleChange('duration', e.target.value)}
                  min={0.001}
                />
              </div>
              <div className="flow-field">
                <label>Connection Rate (pkts/s)</label>
                <input
                  type="number"
                  step="0.1"
                  value={flow.conn_rate}
                  onChange={(e) => handleChange('conn_rate', e.target.value)}
                />
              </div>
              <div className="flow-field">
                <label>Destination Port</label>
                <input
                  type="number"
                  value={flow.dst_port}
                  onChange={(e) => handleChange('dst_port', e.target.value)}
                  min={1}
                  max={65535}
                />
              </div>
              <div className="flow-field">
                <label>Unique Dst Ports Probed</label>
                <input
                  type="number"
                  value={flow.unique_dst_ports || 1}
                  onChange={(e) => handleChange('unique_dst_ports', e.target.value)}
                  min={1}
                />
              </div>
              <div className="flow-field">
                <label>Failed Auth Count</label>
                <input
                  type="number"
                  value={flow.failed_auth_count || 0}
                  onChange={(e) => handleChange('failed_auth_count', e.target.value)}
                  min={0}
                />
              </div>
            </div>

            <button
              type="submit"
              className="primary run-predict-btn"
              disabled={loading}
              style={{ marginTop: '16px', display: 'flex', justifyContent: 'center', alignItems: 'center', gap: '8px' }}
            >
              {loading ? 'Executing ML Inference…' : '⚡ Run ML Anomaly Inference & Policy Trace'}
            </button>
          </form>
        </div>

        {/* Right Column: Real-time ML Prediction & Probabilities */}
        {predictResult && (
          <div className="traffic-results-container">
            <div className="card traffic-scorecard">
              <div className="title-line">
                <h2>ML Threat Classification & Risk Assessment</h2>
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
                  <b style={{ color: predictResult.is_anomaly ? '#ff5e6f' : '#42dfa0' }}>
                    {predictResult.is_anomaly ? 'YES (ANOMALY)' : 'NO (BENIGN)'}
                  </b>
                </div>
              </div>

              {/* Class Probability Distribution */}
              <div className="prob-breakdown" style={{ marginTop: '14px' }}>
                <h4>Multi-Class Probability Distribution (RandomForest)</h4>
                {Object.entries(predictResult.class_probabilities || {}).map(([cls, prob]) => (
                  <div className="prob-row" key={cls}>
                    <span style={{ fontWeight: cls === predictResult.attack_type ? 700 : 400 }}>{cls}</span>
                    <div className="prob-bar-track">
                      <div
                        className={`prob-bar-fill ${cls}`}
                        style={{ width: `${Math.max(prob * 100, 2)}%` }}
                      />
                    </div>
                    <span>{(prob * 100).toFixed(1)}%</span>
                  </div>
                ))}
              </div>

              {/* SHAP Feature Attributions */}
              {predictResult.top_contributing_features && predictResult.top_contributing_features.length > 0 && (
                <div className="prob-breakdown" style={{ marginTop: '14px' }}>
                  <h4>Top Feature Attributions (SHAP TreeExplainer)</h4>
                  {predictResult.top_contributing_features.map((fa) => (
                    <div className="shap-bar-row" key={fa.feature} style={{ margin: '6px 0' }}>
                      <span className="shap-bar-feat">{fa.feature} ({fa.value})</span>
                      <div className="shap-track">
                        <div
                          className={`shap-fill ${fa.contribution_direction || 'INCREASES_RISK'}`}
                          style={{
                            width: `${Math.min(Math.abs(fa.shap_value || fa.deviation_z_score || 0.5) * 150, 100)}%`,
                          }}
                        />
                      </div>
                      <span className="shap-val-text">
                        {fa.shap_value !== undefined
                          ? `${fa.shap_value > 0 ? '+' : ''}${(fa.shap_value * 100).toFixed(1)}%`
                          : `z=${fa.deviation_z_score.toFixed(1)}`}
                      </span>
                    </div>
                  ))}
                </div>
              )}

              {/* Policy Decision Trace */}
              {policyDecision && (
                <div className="policy-trace-box" style={{ marginTop: '14px' }}>
                  <h4>Adaptive Policy Engine Decision</h4>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                    <span>Enacted Action: <b className={`action ${policyDecision.policy_action.toLowerCase()}`}>{policyDecision.policy_action}</b></span>
                    <span style={{ color: '#8faec9', fontSize: '11px' }}>Rule: <b>{policyDecision.rule_name}</b></span>
                  </div>
                  <p style={{ margin: 0, fontSize: '12px', color: '#b6c9de' }}>{policyDecision.reason}</p>
                </div>
              )}

              {/* Static vs Adaptive Comparison */}
              {comparisonResult && (
                <div className="comparison-card" style={{ marginTop: '14px' }}>
                  <h4>Traditional Static Baseline vs Adaptive AI Divergence</h4>
                  <div className="comparison-grid">
                    <div className="comp-box">
                      <small>Traditional Static Baseline</small>
                      <b className={comparisonResult.static_decision}>{comparisonResult.static_decision}</b>
                      <span style={{ fontSize: '11px', color: '#8ba4bf' }}>Rule: {comparisonResult.static_rule_matched || 'DEFAULT_ALLOW'}</span>
                    </div>
                    <div className="comp-box">
                      <small>Adaptive AI Decision</small>
                      <b className={comparisonResult.adaptive_decision}>{comparisonResult.adaptive_decision}</b>
                      <span style={{ fontSize: '11px', color: '#8ba4bf' }}>Risk: {comparisonResult.adaptive_risk_score}/100</span>
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
    </div>
  )
}
