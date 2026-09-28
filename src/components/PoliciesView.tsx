/**
 * Policies View Component — Containment Rules & Policy Engine Manager
 * ===================================================================
 * Partitioned sub-navigation architecture:
 * 1. Overview
 * 2. Active Rules
 * 3. Policy Comparator
 * 4. Policy Rules (Phase 5 Deterministic Rule Catalog)
 * 5. Audit History (PostgreSQL Persisted Policy Audit Trail)
 */

import React, { useEffect, useState } from 'react'
import {
  comparePolicies,
  getEnforcementConfig,
  getPolicyAuditLogs,
  listEnforcementRules,
  revokeEnforcementRule,
  updateEnforcementMode,
} from '../services/enforcement'
import type {
  ActiveEnforcementRule,
  EnforcementConfig,
  FlowPredictionRequest,
  PolicyAuditLog,
  PolicyComparisonResult,
} from '../types'

type PoliciesSubTab = 'overview' | 'rules' | 'comparator' | 'catalog' | 'audit'

interface PolicyCatalogRule {
  id: string
  name: string
  precedence: number
  trigger: string
  action: 'Allow' | 'Monitor' | 'Restrict' | 'Block'
  ttl: string
  description: string
}

const PHASE_5_POLICY_RULES: PolicyCatalogRule[] = [
  {
    id: 'RULE-01',
    name: 'MANAGEMENT_ALLOWLIST_PROTECTION',
    precedence: 1,
    trigger: 'Source IP matches CIDR in management allowlist (127.0.0.1/32, 192.168.1.1/32, 8.8.8.8/32, 1.1.1.1/32)',
    action: 'Allow',
    ttl: '0s (Bypass)',
    description: 'Highest precedence safeguard protecting internal management networks and administrative subnets from automated quarantine.',
  },
  {
    id: 'RULE-02',
    name: 'CONFIDENCE_GATING_MONITOR',
    precedence: 2,
    trigger: 'Threat prediction confidence < 0.60 on anomalous/non-benign flows',
    action: 'Monitor',
    ttl: '180s',
    description: 'Prevents false-positive disruptions on low-confidence anomalies by placing traffic in non-blocking observation mode.',
  },
  {
    id: 'RULE-03',
    name: 'BASELINE_TRAFFIC_ALLOW',
    precedence: 3,
    trigger: 'Threat Level == LOW or Attack Type == BENIGN',
    action: 'Allow',
    ttl: '0s (Pass-through)',
    description: 'Normal verified operational baseline traffic is permitted without latency overhead or containment restrictions.',
  },
  {
    id: 'RULE-04',
    name: 'GRADUATED_SERVICE_RESTRICTION',
    precedence: 4,
    trigger: 'Threat Level == MEDIUM (moderate anomaly signature)',
    action: 'Restrict',
    ttl: '180s',
    description: 'Applies targeted rate-limiting and port-level throttling to suspicious medium-risk flows while preserving service availability.',
  },
  {
    id: 'RULE-05',
    name: 'RECON_PORT_SCAN_QUARANTINE',
    precedence: 5,
    trigger: 'Attack Type == PORT_SCAN with Threat Level >= HIGH (multi-destination port sweep)',
    action: 'Block',
    ttl: '300s',
    description: 'Quarantines aggressive reconnaissance and network sweep actors across all ports to halt lateral discovery.',
  },
  {
    id: 'RULE-06',
    name: 'BRUTE_FORCE_AUTHENTICATION_QUARANTINE',
    precedence: 6,
    trigger: 'Attack Type == BRUTE_FORCE with Threat Level >= HIGH (repeated failed auth surges)',
    action: 'Block',
    ttl: '600s',
    description: 'Imposes an extended 10-minute isolation quarantine on sources attempting credential stuffing or authentication brute-forcing.',
  },
  {
    id: 'RULE-07',
    name: 'VOLUMETRIC_SPIKE_RATE_LIMIT',
    precedence: 7,
    trigger: 'Attack Type == TRAFFIC_SPIKE with Threat Level >= HIGH (volumetric packet/byte surge)',
    action: 'Restrict',
    ttl: '300s',
    description: 'Enforces high-priority rate limiting to prevent bandwidth saturation while maintaining connection state.',
  },
  {
    id: 'RULE-08',
    name: 'HIGH_RISK_ANOMALY_QUARANTINE',
    precedence: 8,
    trigger: 'Threat Level == HIGH / CRITICAL (Risk Score >= 75)',
    action: 'Block',
    ttl: '300s',
    description: 'Full sandbox quarantine isolation for high-severity behavioral deviations and confirmed attack patterns.',
  },
]

export const PoliciesView: React.FC = () => {
  const [activeSubTab, setActiveSubTab] = useState<PoliciesSubTab>('overview')
  const [config, setConfig] = useState<EnforcementConfig | null>(null)
  const [rules, setRules] = useState<ActiveEnforcementRule[]>([])
  const [auditLogs, setAuditLogs] = useState<PolicyAuditLog[]>([])
  const [statusFilter, setStatusFilter] = useState<string>('ACTIVE')
  const [loading, setLoading] = useState<boolean>(true)
  const [auditLoading, setAuditLoading] = useState<boolean>(false)
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

  const loadAuditLogs = () => {
    setAuditLoading(true)
    getPolicyAuditLogs(50)
      .then((logs) => setAuditLogs(logs))
      .catch((err) => setToast(`Failed to load audit history: ${String(err)}`))
      .finally(() => setAuditLoading(false))
  }

  useEffect(() => {
    loadData()
  }, [statusFilter])

  useEffect(() => {
    if (activeSubTab === 'audit') {
      loadAuditLogs()
    }
  }, [activeSubTab])

  const handleToggleMode = async (mode: 'DRY_RUN' | 'SANDBOX') => {
    try {
      const updated = await updateEnforcementMode(mode)
      setConfig(updated)
      setToast(`Enforcement adapter mode switched to ${mode}.`)
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
      if (activeSubTab === 'audit') {
        loadAuditLogs()
      }
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

  const activeRulesCount = rules.filter((r) => r.status === 'ACTIVE' || r.status === 'SIMULATED').length

  return (
    <div className="policies-view-container">
      {/* Header & Sub-navigation */}
      <section className="intro" style={{ marginBottom: '14px' }}>
        <div>
          <h1>🛡️ Policy Engine & Active Containment Console</h1>
          <p>
            Authoritative deterministic policy management, graduated isolation rules,
            comparative static baseline auditing, and PostgreSQL-persisted enforcement history.
          </p>
        </div>
      </section>

      {/* Policies Contextual Sub-navigation */}
      <div className="sub-nav-bar" style={{ marginBottom: '16px', display: 'flex', gap: '8px', borderBottom: '1px solid #1a3c58', paddingBottom: '8px' }}>
        <button
          type="button"
          className={`sub-nav-btn ${activeSubTab === 'overview' ? 'active' : ''}`}
          onClick={() => setActiveSubTab('overview')}
        >
          📊 Overview
        </button>
        <button
          type="button"
          className={`sub-nav-btn ${activeSubTab === 'rules' ? 'active' : ''}`}
          onClick={() => setActiveSubTab('rules')}
        >
          ⚡ Active Rules ({rules.length})
        </button>
        <button
          type="button"
          className={`sub-nav-btn ${activeSubTab === 'comparator' ? 'active' : ''}`}
          onClick={() => setActiveSubTab('comparator')}
        >
          ⚖️ Policy Comparator
        </button>
        <button
          type="button"
          className={`sub-nav-btn ${activeSubTab === 'catalog' ? 'active' : ''}`}
          onClick={() => setActiveSubTab('catalog')}
        >
          📜 Policy Rules Catalog (8)
        </button>
        <button
          type="button"
          className={`sub-nav-btn ${activeSubTab === 'audit' ? 'active' : ''}`}
          onClick={() => setActiveSubTab('audit')}
        >
          📋 Audit History
        </button>
      </div>

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

      {/* ====================================================================
          SUBVIEW 1: OVERVIEW
         ==================================================================== */}
      {activeSubTab === 'overview' && (
        <div className="subview-overview">
          {/* Enforcement Mode Switcher Card */}
          <div className="card mode-toggle-bar" style={{ marginBottom: '16px' }}>
            <div>
              <span style={{ fontSize: '12px', color: '#8faec9' }}>Authoritative Enforcement Mode</span>
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

          {/* High-Level Policy Metrics Grid */}
          <div className="grid4" style={{ marginBottom: '16px' }}>
            <div className="card stat-card">
              <span className="stat-label">Active Containment Rules</span>
              <div className="stat-value" style={{ color: activeRulesCount > 0 ? '#f39c12' : '#2ecc71' }}>
                {activeRulesCount}
              </div>
              <span className="stat-sub">Managed by in-memory adapter</span>
            </div>

            <div className="card stat-card">
              <span className="stat-label">Default Rule TTL</span>
              <div className="stat-value" style={{ color: '#58a6ff' }}>
                {config?.default_ttl_seconds ?? 300}s
              </div>
              <span className="stat-sub">Automatic expiry window</span>
            </div>

            <div className="card stat-card">
              <span className="stat-label">Protected CIDRs</span>
              <div className="stat-value" style={{ color: '#58a6ff' }}>
                {config?.management_allowlist?.length ?? 3}
              </div>
              <span className="stat-sub">Management allowlist subnets</span>
            </div>

            <div className="card stat-card">
              <span className="stat-label">Authoritative Engine</span>
              <div className="stat-value" style={{ color: '#2ecc71', fontSize: '18px' }}>
                Deterministic
              </div>
              <span className="stat-sub">Zero LLM policy modification</span>
            </div>
          </div>

          {/* Protected CIDR Subnets Card */}
          <div className="card" style={{ marginBottom: '16px', padding: '16px' }}>
            <h3 style={{ margin: '0 0 8px', fontSize: '14px', color: '#f0f6fc' }}>
              🔒 Protected Management Allowlist Subnets
            </h3>
            <p style={{ fontSize: '12px', color: '#9bb2cb', margin: '0 0 12px' }}>
              Traffic originating from these CIDR ranges is explicitly protected by Rule 01 (MANAGEMENT_ALLOWLIST_PROTECTION)
              and cannot be blocked or quarantined by automated ML predictions.
            </p>
            <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
              {config?.management_allowlist?.map((cidr) => (
                <span key={cidr} className="chip" style={{ fontSize: '12px', padding: '4px 10px', background: '#0d2137' }}>
                  🛡️ {cidr}
                </span>
              )) ?? (
                <>
                  <span className="chip" style={{ fontSize: '12px', padding: '4px 10px', background: '#0d2137' }}>🛡️ 127.0.0.1/32</span>
                  <span className="chip" style={{ fontSize: '12px', padding: '4px 10px', background: '#0d2137' }}>🛡️ 192.168.1.1/32</span>
                  <span className="chip" style={{ fontSize: '12px', padding: '4px 10px', background: '#0d2137' }}>🛡️ 8.8.8.8/32</span>
                  <span className="chip" style={{ fontSize: '12px', padding: '4px 10px', background: '#0d2137' }}>🛡️ 1.1.1.1/32</span>
                </>
              )}
            </div>
          </div>

          {/* Quick Recent Activity Snapshot */}
          <div className="card" style={{ padding: '16px' }}>
            <div className="title-line" style={{ marginBottom: '10px' }}>
              <h3 style={{ margin: 0, fontSize: '14px' }}>⚡ Active Containment Snapshot</h3>
              <button type="button" className="btn-secondary" style={{ fontSize: '12px', padding: '2px 8px' }} onClick={() => setActiveSubTab('rules')}>
                View All Rules →
              </button>
            </div>
            {rules.length === 0 ? (
              <p style={{ color: '#8faec9', fontSize: '13px', margin: 0 }}>
                No active containment rules currently enforced. Gateway is operating in nominal pass-through state.
              </p>
            ) : (
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))', gap: '10px' }}>
                {rules.slice(0, 4).map((r) => (
                  <div key={r.rule_id} style={{ background: '#0a192f', border: '1px solid #1a3c58', borderRadius: '6px', padding: '10px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '4px' }}>
                      <span className={`pill ${r.action === 'Block' ? 'r87' : 'r76'}`} style={{ fontSize: '10px' }}>
                        {r.action}
                      </span>
                      <span style={{ fontSize: '11px', color: '#8faec9' }}>⏱ {Math.max(r.remaining_ttl_seconds, 0)}s</span>
                    </div>
                    <b style={{ color: '#f0f6fc', fontSize: '13px' }}>{r.target_ip} {r.target_port ? `:${r.target_port}` : ''}</b>
                    <p style={{ fontSize: '11px', color: '#9bb2cb', margin: '4px 0 0', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {r.reason}
                    </p>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ====================================================================
          SUBVIEW 2: ACTIVE RULES
         ==================================================================== */}
      {activeSubTab === 'rules' && (
        <div className="subview-rules">
          <div className="card" style={{ padding: '16px' }}>
            <div className="title-line" style={{ marginBottom: '14px' }}>
              <div>
                <h2 style={{ margin: 0 }}>Active Containment Rules ({rules.length})</h2>
                <span style={{ fontSize: '12px', color: '#8faec9' }}>
                  Live in-memory adapter containment rules with real-time TTL expiration counters.
                </span>
              </div>
              <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
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
                <button type="button" className="btn-secondary" onClick={loadData} style={{ height: '32px', fontSize: '12px' }}>
                  🔄 Refresh
                </button>
              </div>
            </div>

            {loading ? (
              <div style={{ padding: '40px', textAlign: 'center', color: '#8faec9' }}>
                Loading containment rules…
              </div>
            ) : rules.length === 0 ? (
              <div className="empty" style={{ padding: '40px', textAlign: 'center' }}>
                No containment rules found matching status filter “{statusFilter || 'ALL'}”.
              </div>
            ) : (
              <div className="rules-list-container" style={{ maxHeight: '600px', overflowY: 'auto' }}>
                {rules.map((r) => (
                  <div className="rule-card" key={r.rule_id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '12px', borderBottom: '1px solid #1a3c58' }}>
                    <div className="rule-info" style={{ flex: 1, paddingRight: '16px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                        <span className={`pill ${r.action === 'Block' ? 'r87' : 'r76'}`}>
                          {r.action}
                        </span>
                        <b style={{ color: '#f0f6fc', fontSize: '14px' }}>
                          {r.target_ip} {r.target_port ? `:${r.target_port}` : ''}
                        </b>
                        <span className="prov-badge" style={{ fontSize: '10px' }}>
                          {r.mode}
                        </span>
                      </div>
                      <p style={{ margin: '2px 0 4px', fontSize: '12px', color: '#c9d1d9' }}>{r.reason}</p>
                      <small style={{ color: '#8faec9', fontSize: '11px' }}>
                        ID: <span style={{ fontFamily: 'monospace' }}>{r.rule_id}</span> • Created: {new Date(r.created_at).toLocaleTimeString()} • TTL: {r.ttl_seconds}s
                      </small>
                    </div>

                    <div className="rule-meta" style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      <div className="ttl-badge" title="Remaining TTL" style={{ background: '#091c2d', border: '1px solid #1a3c58', padding: '4px 8px', borderRadius: '4px', fontSize: '12px' }}>
                        ⏱ {Math.max(r.remaining_ttl_seconds, 0)}s
                      </div>
                      {r.status === 'ACTIVE' || r.status === 'SIMULATED' ? (
                        <button
                          className="rule-card revoke-btn"
                          onClick={() => handleRevoke(r.rule_id)}
                          type="button"
                          style={{ background: '#9b3746', color: '#fff', border: 'none', padding: '6px 12px', borderRadius: '4px', cursor: 'pointer', fontSize: '12px' }}
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
        </div>
      )}

      {/* ====================================================================
          SUBVIEW 3: POLICY COMPARATOR
         ==================================================================== */}
      {activeSubTab === 'comparator' && (
        <div className="subview-comparator">
          <div className="card" style={{ padding: '16px' }}>
            <h2>⚖️ Policy Engine Comparative Benchmark</h2>
            <p style={{ fontSize: '12px', color: '#9bb2cb', margin: '4px 0 16px' }}>
              Evaluate live network flow features simultaneously against the <strong>Static Rule Baseline</strong> and the <strong>Adaptive AI Policy Engine</strong> to observe divergence and context-aware policy decisions.
            </p>

            <div className="policy-comparator-grid">
              {/* Left Column: Input Vector */}
              <div style={{ background: '#081726', padding: '14px', borderRadius: '6px', border: '1px solid #1a3c58', minWidth: 0 }}>
                <h4 style={{ margin: '0 0 12px', fontSize: '13px', color: '#58a6ff' }}>Input Flow Feature Vector</h4>
                <div className="flow-form-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: '10px' }}>
                  <div className="flow-field">
                    <label style={{ fontSize: '11px', color: '#8faec9', display: 'block', marginBottom: '2px' }}>Dst Port</label>
                    <input
                      type="number"
                      className="input"
                      value={compFlow.dst_port}
                      onChange={(e) => setCompFlow({ ...compFlow, dst_port: parseInt(e.target.value) || 80 })}
                    />
                  </div>
                  <div className="flow-field">
                    <label style={{ fontSize: '11px', color: '#8faec9', display: 'block', marginBottom: '2px' }}>Unique Ports</label>
                    <input
                      type="number"
                      className="input"
                      value={compFlow.unique_dst_ports || 1}
                      onChange={(e) => setCompFlow({ ...compFlow, unique_dst_ports: parseInt(e.target.value) || 1 })}
                    />
                  </div>
                  <div className="flow-field">
                    <label style={{ fontSize: '11px', color: '#8faec9', display: 'block', marginBottom: '2px' }}>Connection Rate (conn/s)</label>
                    <input
                      type="number"
                      className="input"
                      value={compFlow.conn_rate}
                      onChange={(e) => setCompFlow({ ...compFlow, conn_rate: parseFloat(e.target.value) || 1.0 })}
                    />
                  </div>
                  <div className="flow-field">
                    <label style={{ fontSize: '11px', color: '#8faec9', display: 'block', marginBottom: '2px' }}>Failed Auth Count</label>
                    <input
                      type="number"
                      className="input"
                      value={compFlow.failed_auth_count || 0}
                      onChange={(e) => setCompFlow({ ...compFlow, failed_auth_count: parseInt(e.target.value) || 0 })}
                    />
                  </div>
                  <div className="flow-field">
                    <label style={{ fontSize: '11px', color: '#8faec9', display: 'block', marginBottom: '2px' }}>Packet Count</label>
                    <input
                      type="number"
                      className="input"
                      value={compFlow.packet_count}
                      onChange={(e) => setCompFlow({ ...compFlow, packet_count: parseInt(e.target.value) || 1 })}
                    />
                  </div>
                  <div className="flow-field">
                    <label style={{ fontSize: '11px', color: '#8faec9', display: 'block', marginBottom: '2px' }}>Duration (s)</label>
                    <input
                      type="number"
                      step="0.01"
                      className="input"
                      value={compFlow.duration}
                      onChange={(e) => setCompFlow({ ...compFlow, duration: parseFloat(e.target.value) || 0.1 })}
                    />
                  </div>
                </div>

                <button
                  type="button"
                  className="primary btn-stable"
                  onClick={handleRunComparison}
                  disabled={comparing}
                  style={{ marginTop: '14px', width: '100%', height: '36px' }}
                >
                  {comparing ? 'Comparing Decisions…' : '⚖️ Compare Policies'}
                </button>
              </div>

              {/* Right Column: Comparison Result */}
              <div style={{ minWidth: 0 }}>
                {compResult ? (
                  <div className="comparison-card" style={{ background: '#091c2d', border: '1px solid #1a3c58', borderRadius: '6px', padding: '14px' }}>
                    <h4 style={{ margin: '0 0 10px', fontSize: '13px', color: '#f0f6fc' }}>Comparison Output</h4>
                    <div className="comparison-grid" style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px', marginBottom: '12px' }}>
                      <div className="comp-box" style={{ background: '#0c1f33', padding: '10px', borderRadius: '4px', border: '1px solid #1a3c58' }}>
                        <small style={{ color: '#8faec9', fontSize: '11px', display: 'block' }}>Traditional Static Baseline</small>
                        <b className={compResult.static_decision} style={{ fontSize: '18px', display: 'block', margin: '4px 0' }}>
                          {compResult.static_decision}
                        </b>
                        <span style={{ fontSize: '11px', color: '#8ba4bf' }}>Rule: {compResult.static_rule_matched || 'DEFAULT_ALLOW'}</span>
                      </div>
                      <div className="comp-box" style={{ background: '#0c1f33', padding: '10px', borderRadius: '4px', border: '1px solid #1a3c58' }}>
                        <small style={{ color: '#8faec9', fontSize: '11px', display: 'block' }}>Adaptive AI Decision</small>
                        <b className={compResult.adaptive_decision} style={{ fontSize: '18px', display: 'block', margin: '4px 0' }}>
                          {compResult.adaptive_decision}
                        </b>
                        <span style={{ fontSize: '11px', color: '#8ba4bf' }}>Risk: {compResult.adaptive_risk_score}/100</span>
                      </div>
                    </div>
                    <div className="divergence-note" style={{ background: compResult.decision_divergence ? 'rgba(230, 126, 34, 0.15)' : 'rgba(46, 204, 113, 0.15)', border: `1px solid ${compResult.decision_divergence ? '#e67e22' : '#2ecc71'}`, borderRadius: '4px', padding: '10px' }}>
                      <strong style={{ color: compResult.decision_divergence ? '#f39c12' : '#2ecc71', fontSize: '12px' }}>
                        {compResult.decision_divergence ? '⚠️ Policy Divergence Detected' : '✓ Congruent Policy Decisions'}
                      </strong>
                      <p style={{ margin: '4px 0 0', fontSize: '12px', color: '#c9d1d9' }}>{compResult.divergence_rationale}</p>
                    </div>
                  </div>
                ) : (
                  <div style={{ background: '#091c2d', border: '1px dashed #1a3c58', borderRadius: '6px', padding: '30px', textAlign: 'center', color: '#8faec9', fontSize: '13px' }}>
                    Adjust the flow parameters on the left and click <b>Compare Policies</b> to evaluate the static rule baseline against the adaptive engine.
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ====================================================================
          SUBVIEW 4: POLICY RULES CATALOG (Phase 5)
         ==================================================================== */}
      {activeSubTab === 'catalog' && (
        <div className="subview-catalog">
          <div className="card" style={{ padding: '16px' }}>
            <div style={{ marginBottom: '14px' }}>
              <h2 style={{ margin: 0 }}>📜 Phase 5 Policy Rules Catalog</h2>
              <span style={{ fontSize: '12px', color: '#8faec9' }}>
                Deterministic, hierarchical policy rules executed in strict precedence order by the PolicyEngine.
              </span>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
              {PHASE_5_POLICY_RULES.map((rule) => (
                <div
                  key={rule.id}
                  className="policy-catalog-row"
                >
                  <div>
                    <span style={{ fontSize: '11px', color: '#58a6ff', fontFamily: 'monospace', fontWeight: 'bold' }}>
                      #{rule.precedence}
                    </span>
                  </div>

                  <div>
                    <b style={{ color: '#f0f6fc', fontSize: '13px', display: 'block' }}>{rule.name}</b>
                    <span style={{ fontSize: '11px', color: '#9bb2cb' }}>{rule.description}</span>
                  </div>

                  <div style={{ fontSize: '11px', color: '#8faec9', background: '#061320', padding: '6px 8px', borderRadius: '4px' }}>
                    <strong>Trigger:</strong> {rule.trigger}
                  </div>

                  <div style={{ textAlign: 'center' }}>
                    <span className={`pill ${rule.action === 'Block' ? 'r87' : rule.action === 'Restrict' ? 'r76' : 'r35'}`}>
                      {rule.action}
                    </span>
                  </div>

                  <div style={{ textAlign: 'right', fontSize: '11px', color: '#8faec9' }}>
                    ⏱ {rule.ttl}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ====================================================================
          SUBVIEW 5: AUDIT HISTORY (PostgreSQL Persisted)
         ==================================================================== */}
      {activeSubTab === 'audit' && (
        <div className="subview-audit">
          <div className="card" style={{ padding: '16px' }}>
            <div className="title-line" style={{ marginBottom: '14px' }}>
              <div>
                <h2 style={{ margin: 0 }}>📋 Policy Enforcement Audit History</h2>
                <span style={{ fontSize: '12px', color: '#8faec9' }}>
                  Real PostgreSQL-persisted security policy audit log entries tracking policy evaluation and manual revocation actions.
                </span>
              </div>
              <button type="button" className="btn-secondary" onClick={loadAuditLogs} disabled={auditLoading} style={{ height: '32px', fontSize: '12px' }}>
                {auditLoading ? 'Loading…' : '🔄 Refresh Audit Log'}
              </button>
            </div>

            {auditLoading ? (
              <div style={{ padding: '40px', textAlign: 'center', color: '#8faec9' }}>
                Fetching audit records from PostgreSQL database…
              </div>
            ) : auditLogs.length === 0 ? (
              <div className="empty" style={{ padding: '40px', textAlign: 'center' }}>
                No policy audit logs recorded yet in database.
              </div>
            ) : (
              <div style={{ overflowX: 'auto', maxHeight: '550px', overflowY: 'auto' }}>
                <table className="table" style={{ width: '100%', fontSize: '12px', borderCollapse: 'collapse' }}>
                  <thead>
                    <tr style={{ background: '#0a1d30', textAlign: 'left', borderBottom: '1px solid #1a3c58' }}>
                      <th style={{ padding: '8px 10px' }}>ID</th>
                      <th style={{ padding: '8px 10px' }}>Timestamp</th>
                      <th style={{ padding: '8px 10px' }}>Event ID</th>
                      <th style={{ padding: '8px 10px' }}>Requested Action</th>
                      <th style={{ padding: '8px 10px' }}>Previous Action</th>
                      <th style={{ padding: '8px 10px' }}>Resulting Status</th>
                      <th style={{ padding: '8px 10px' }}>Actor</th>
                    </tr>
                  </thead>
                  <tbody>
                    {auditLogs.map((log) => (
                      <tr key={log.id} style={{ borderBottom: '1px solid #11263c' }}>
                        <td style={{ padding: '8px 10px', fontFamily: 'monospace', color: '#58a6ff' }}>#{log.id}</td>
                        <td style={{ padding: '8px 10px', color: '#8faec9' }}>{new Date(log.timestamp).toLocaleString()}</td>
                        <td style={{ padding: '8px 10px', fontFamily: 'monospace', color: '#c9d1d9' }}>{log.event_id}</td>
                        <td style={{ padding: '8px 10px' }}>
                          <span className={`pill ${log.requested_action === 'Block' ? 'r87' : log.requested_action === 'Restrict' ? 'r76' : 'r35'}`}>
                            {log.requested_action}
                          </span>
                        </td>
                        <td style={{ padding: '8px 10px', color: '#8faec9' }}>{log.previous_action || '—'}</td>
                        <td style={{ padding: '8px 10px' }}>
                          <span className="prov-badge" style={{ fontSize: '10px' }}>{log.resulting_status}</span>
                        </td>
                        <td style={{ padding: '8px 10px', color: '#f0f6fc' }}>{log.actor}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
