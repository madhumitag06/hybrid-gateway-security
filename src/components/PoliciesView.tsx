/**
 * Policies View Component — Containment Rules & Policy Engine Manager
 * ===================================================================
 * Manages active containment rules, enforcement mode switching (DRY_RUN vs SANDBOX),
 * manual rule revocation, and static vs. adaptive policy comparison matrices.
 */

import React, { useEffect, useState } from 'react'
import {
  comparePolicies,
  getEnforcementConfig,
  listEnforcementRules,
  revokeEnforcementRule,
  updateEnforcementMode,
} from '../services/enforcement'
import type {
  ActiveEnforcementRule,
  EnforcementConfig,
  FlowPredictionRequest,
  PolicyComparisonResult,
} from '../types'

export const PoliciesView: React.FC = () => {
  const [config, setConfig] = useState<EnforcementConfig | null>(null)
  const [rules, setRules] = useState<ActiveEnforcementRule[]>([])
  const [statusFilter, setStatusFilter] = useState<string>('ACTIVE')
  const [loading, setLoading] = useState<boolean>(true)
  const [error, setError] = useState<string | null>(null)
  const [toast, setToast] = useState<string>('')

  // Policy Comparator State
  const [compFlow, setCompFlow] = useState<FlowPredictionRequest>({
    packet_count: 2,
    byte_count: 120,
    duration: 0.08,
    conn_rate: 120.0,
    dst_port: 8080,
    unique_dst_ports: 75,
    failed_auth_count: 0,
  })
  const [compResult, setCompResult] = useState<PolicyComparisonResult | null>(null)
  const [comparing, setComparing] = useState<boolean>(false)

  const loadData = () => {
    setLoading(true)
    setError(null)
    Promise.all([
      getEnforcementConfig(),
      listEnforcementRules(statusFilter || undefined),
    ])
      .then(([cfg, r]) => {
        setConfig(cfg)
        setRules(r)
      })
      .catch((err) => setError(String(err)))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    loadData()
  }, [statusFilter])

  const handleToggleMode = async (mode: 'DRY_RUN' | 'SANDBOX') => {
    try {
      const updated = await updateEnforcementMode(mode)
      setConfig(updated)
      setToast(`Enforcement mode switched to ${mode}.`)
      loadData()
    } catch (err) {
      setToast(`Mode switch error: ${String(err)}`)
    }
  }

  const handleRevoke = async (ruleId: string) => {
    try {
      await revokeEnforcementRule(ruleId)
      setToast(`Revoked containment rule '${ruleId}'.`)
      loadData()
    } catch (err) {
      setToast(`Failed to revoke rule: ${String(err)}`)
    }
  }

  const handleRunComparison = async () => {
    setComparing(true)
    try {
      const res = await comparePolicies(compFlow)
      setCompResult(res)
    } catch (err) {
      setToast(`Comparison error: ${String(err)}`)
    } finally {
      setComparing(false)
    }
  }

  return (
    <div className="policies-view-container">
      <section className="intro">
        <div>
          <h1>◇ Active Containment & Policy Engine Manager</h1>
          <p>
            Monitor live containment rules, toggle sandbox enforcement adapter modes,
            and benchmark dynamic AI decisions against the traditional static baseline.
          </p>
        </div>
      </section>

      {toast && (
        <div className="toast" onClick={() => setToast('')}>
          {toast}
        </div>
      )}

      {error && (
        <div className="card error-banner" style={{ marginBottom: '16px', color: '#ff7f8c', borderColor: '#9b3746' }}>
          <b>Policy Engine Error:</b> {error}
        </div>
      )}

      {/* Enforcement Mode & Controls */}
      <div className="card mode-toggle-bar" style={{ marginBottom: '16px' }}>
        <div>
          <span style={{ fontSize: '12px', color: '#8faec9' }}>Enforcement Adapter Mode</span>
          <h3 style={{ margin: '2px 0 0', color: '#f0f6fc' }}>
            {config?.active_mode === 'SANDBOX' ? '🧪 SANDBOX ISOLATION' : '🛡️ DRY_RUN (SIMULATION)'}
          </h3>
          <small style={{ color: '#9bb2cb' }}>
            {config?.active_mode === 'SANDBOX'
              ? 'Active in-memory quarantine filtering enabled with automatic TTL expiration.'
              : 'Audit simulation only; all traffic is logged without dropped packets.'}
          </small>
        </div>

        <div style={{ display: 'flex', gap: '8px' }}>
          <button
            type="button"
            className={`chip ${config?.active_mode === 'DRY_RUN' ? 'active' : ''}`}
            onClick={() => handleToggleMode('DRY_RUN')}
          >
            DRY_RUN
          </button>
          <button
            type="button"
            className={`chip ${config?.active_mode === 'SANDBOX' ? 'active' : ''}`}
            onClick={() => handleToggleMode('SANDBOX')}
          >
            SANDBOX
          </button>
        </div>
      </div>

      <div className="policies-layout-grid" style={{ display: 'grid', gridTemplateColumns: '1.2fr 0.8fr', gap: '16px' }}>
        {/* Left Column: Active Rules Table */}
        <div className="card" style={{ padding: '16px' }}>
          <div className="title-line" style={{ marginBottom: '12px' }}>
            <h2>Containment Rules Table ({rules.length})</h2>
            <select
              className="select"
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              style={{ height: '32px', fontSize: '12px' }}
            >
              <option value="">All Statuses</option>
              <option value="ACTIVE">ACTIVE</option>
              <option value="SIMULATED">SIMULATED</option>
              <option value="EXPIRED">EXPIRED</option>
              <option value="REVOKED">REVOKED</option>
            </select>
          </div>

          {loading ? (
            <div style={{ padding: '30px', textAlign: 'center', color: '#8faec9' }}>
              Loading containment rules…
            </div>
          ) : rules.length === 0 ? (
            <div className="empty" style={{ padding: '30px' }}>
              No containment rules found with status “{statusFilter || 'ALL'}”.
            </div>
          ) : (
            <div className="rules-list-container" style={{ maxHeight: '550px' }}>
              {rules.map((r) => (
                <div className="rule-card" key={r.rule_id}>
                  <div className="rule-info">
                    <h4>
                      <span className={`pill ${r.action === 'Block' ? 'r87' : 'r76'}`} style={{ marginRight: '8px' }}>
                        {r.action}
                      </span>
                      {r.target_ip} {r.target_port ? `:${r.target_port}` : ''}
                    </h4>
                    <p>{r.reason}</p>
                    <small style={{ color: '#8faec9', fontSize: '11px', display: 'block', marginTop: '4px' }}>
                      ID: {r.rule_id} • Created: {new Date(r.created_at).toLocaleTimeString()}
                    </small>
                  </div>

                  <div className="rule-meta">
                    <div className="ttl-badge" title="Remaining TTL">
                      ⏱ {Math.max(r.remaining_ttl_seconds, 0)}s
                    </div>
                    {r.status === 'ACTIVE' || r.status === 'SIMULATED' ? (
                      <button
                        className="rule-card revoke-btn"
                        onClick={() => handleRevoke(r.rule_id)}
                        type="button"
                      >
                        Revoke
                      </button>
                    ) : (
                      <span className="prov-badge" style={{ background: '#1c2e42', color: '#8faec9' }}>
                        {r.status}
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Right Column: Interactive Static vs Adaptive Policy Comparator */}
        <div className="card" style={{ padding: '16px' }}>
          <h2>⚖ Policy Engine Comparator</h2>
          <p style={{ fontSize: '12px', color: '#9bb2cb', margin: '4px 0 14px' }}>
            Compare decisions between the <strong>Traditional Static Policy Baseline</strong> and the{' '}
            <strong>Adaptive AI Policy Engine</strong>.
          </p>

          <div className="flow-form-grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
            <div className="flow-field">
              <label>Dst Port</label>
              <input
                type="number"
                value={compFlow.dst_port}
                onChange={(e) => setCompFlow({ ...compFlow, dst_port: parseInt(e.target.value) || 80 })}
              />
            </div>
            <div className="flow-field">
              <label>Unique Ports</label>
              <input
                type="number"
                value={compFlow.unique_dst_ports || 1}
                onChange={(e) => setCompFlow({ ...compFlow, unique_dst_ports: parseInt(e.target.value) || 1 })}
              />
            </div>
            <div className="flow-field">
              <label>Conn Rate</label>
              <input
                type="number"
                value={compFlow.conn_rate}
                onChange={(e) => setCompFlow({ ...compFlow, conn_rate: parseFloat(e.target.value) || 1.0 })}
              />
            </div>
            <div className="flow-field">
              <label>Failed Auth</label>
              <input
                type="number"
                value={compFlow.failed_auth_count || 0}
                onChange={(e) => setCompFlow({ ...compFlow, failed_auth_count: parseInt(e.target.value) || 0 })}
              />
            </div>
          </div>

          <button
            type="button"
            className="primary"
            onClick={handleRunComparison}
            disabled={comparing}
            style={{ marginTop: '12px' }}
          >
            {comparing ? 'Comparing Decisions…' : 'Compare Policies'}
          </button>

          {compResult && (
            <div className="comparison-card" style={{ marginTop: '16px' }}>
              <h4>Comparison Output</h4>
              <div className="comparison-grid">
                <div className="comp-box">
                  <small>Traditional Static Baseline</small>
                  <b className={compResult.static_decision}>{compResult.static_decision}</b>
                  <span style={{ fontSize: '11px', color: '#8ba4bf' }}>Rule: {compResult.static_rule_matched || 'DEFAULT_ALLOW'}</span>
                </div>
                <div className="comp-box">
                  <small>Adaptive AI Decision</small>
                  <b className={compResult.adaptive_decision}>{compResult.adaptive_decision}</b>
                  <span style={{ fontSize: '11px', color: '#8ba4bf' }}>Risk: {compResult.adaptive_risk_score}/100</span>
                </div>
              </div>
              <div className="divergence-note">
                <strong>Divergence:</strong> {compResult.decision_divergence ? 'YES (Policy Diverged)' : 'NO (Same Action)'}
                <p style={{ margin: '4px 0 0', fontSize: '11px' }}>{compResult.divergence_rationale}</p>
              </div>
            </div>
          )}

          {config?.management_allowlist && (
            <div style={{ marginTop: '16px', background: '#091c2d', padding: '10px 12px', borderRadius: '6px', border: '1px solid #1a3c58' }}>
              <small style={{ display: 'block', color: '#8faec9', fontSize: '11px', marginBottom: '4px' }}>
                Protected Management Allowlist CIDRs
              </small>
              <div style={{ display: 'flex', gap: '6px', flexWrap: 'wrap' }}>
                {config.management_allowlist.map((cidr) => (
                  <span key={cidr} className="chip" style={{ fontSize: '11px', padding: '2px 8px' }}>
                    🔒 {cidr}
                  </span>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
