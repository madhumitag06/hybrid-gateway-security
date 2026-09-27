/**
 * Events View Component — PostgreSQL Security Events Ledger
 * =========================================================
 * Displays real-time and historical security events persisted in PostgreSQL.
 * Supports filtering by threat level, attack type, policy action, risk score range,
 * text search, and deep inspection with SHAP feature attributions.
 */

import React, { useEffect, useState } from 'react'
import { listSecurityEvents } from '../services/events'
import { applyAction } from '../services/dashboard'
import { getEventExplanation } from '../services/analytics'
import type { EventExplanationResponse, PolicyAction, SecurityEvent } from '../types'

const riskClass = (risk: number) =>
  risk >= 80 ? 'r87' : risk >= 70 ? 'r76' : risk >= 60 ? 'r64' : 'r52'

export const EventsView: React.FC = () => {
  const [events, setEvents] = useState<SecurityEvent[]>([])
  const [total, setTotal] = useState<number>(0)
  const [loading, setLoading] = useState<boolean>(true)
  const [error, setError] = useState<string | null>(null)

  // Filter States
  const [threatLevel, setThreatLevel] = useState<string>('')
  const [attackType, setAttackType] = useState<string>('')
  const [actionFilter, setActionFilter] = useState<string>('')
  const [search, setSearch] = useState<string>('')
  const [page, setPage] = useState<number>(0)
  const limit = 25

  // Selected Event & SHAP Modal
  const [selected, setSelected] = useState<SecurityEvent | null>(null)
  const [explanation, setExplanation] = useState<EventExplanationResponse | null>(null)
  const [loadingExplanation, setLoadingExplanation] = useState<boolean>(false)
  const [toast, setToast] = useState<string>('')

  const fetchEvents = () => {
    setLoading(true)
    setError(null)
    listSecurityEvents({
      threat_level: threatLevel || undefined,
      attack_type: attackType || undefined,
      action: actionFilter || undefined,
      search: search || undefined,
      limit,
      offset: page * limit,
    })
      .then((res) => {
        setEvents(res.events)
        setTotal(res.total)
      })
      .catch((err) => setError(String(err)))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    fetchEvents()
  }, [threatLevel, attackType, actionFilter, page])

  useEffect(() => {
    if (selected) {
      setLoadingExplanation(true)
      setExplanation(null)
      getEventExplanation(selected.id)
        .then(setExplanation)
        .catch(() => {})
        .finally(() => setLoadingExplanation(false))
    } else {
      setExplanation(null)
    }
  }, [selected])

  const handleUpdateAction = async (action: PolicyAction) => {
    if (!selected) return
    try {
      await applyAction(selected.id, action)
      setToast(`Applied '${action}' policy to event ${selected.id}.`)
      setEvents((prev) =>
        prev.map((e) =>
          e.id === selected.id
            ? { ...e, action, status: action === 'Monitor' ? 'Monitoring' : 'Applied' }
            : e
        )
      )
      setSelected(null)
    } catch (err) {
      setToast(`Action error: ${String(err)}`)
    }
  }

  const handleSearchSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    setPage(0)
    fetchEvents()
  }

  const totalPages = Math.ceil(total / limit) || 1

  return (
    <div className="events-view-container">
      <section className="intro">
        <div>
          <h1>▣ Security Events Explorer (PostgreSQL Ledger)</h1>
          <p>
            Audit log of real-time and ingested security events evaluated by the AI Gateway and
            stored in the PostgreSQL relational datastore.
          </p>
        </div>
      </section>

      {toast && (
        <div className="toast" onClick={() => setToast('')}>
          {toast}
        </div>
      )}

      {/* Filter Control Bar */}
      <div className="card events-filter-bar" style={{ marginBottom: '16px', padding: '14px 18px' }}>
        <form onSubmit={handleSearchSubmit} style={{ display: 'flex', gap: '12px', flexWrap: 'wrap', alignItems: 'center' }}>
          <div style={{ flex: 1, minWidth: '220px' }}>
            <input
              type="text"
              className="raw-log-input"
              style={{ height: '36px', padding: '6px 12px' }}
              placeholder="Search by IP, event ID, description..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
            />
          </div>

          <select
            className="select"
            value={threatLevel}
            onChange={(e) => {
              setThreatLevel(e.target.value)
              setPage(0)
            }}
          >
            <option value="">All Threat Levels</option>
            <option value="LOW">LOW</option>
            <option value="MEDIUM">MEDIUM</option>
            <option value="HIGH">HIGH</option>
          </select>

          <select
            className="select"
            value={attackType}
            onChange={(e) => {
              setAttackType(e.target.value)
              setPage(0)
            }}
          >
            <option value="">All Threat Types</option>
            <option value="BENIGN">BENIGN</option>
            <option value="PORT_SCAN">PORT SCAN</option>
            <option value="BRUTE_FORCE">BRUTE FORCE</option>
            <option value="TRAFFIC_SPIKE">TRAFFIC SPIKE</option>
            <option value="SUSPICIOUS_TRANSFER">SUSPICIOUS TRANSFER</option>
          </select>

          <select
            className="select"
            value={actionFilter}
            onChange={(e) => {
              setActionFilter(e.target.value)
              setPage(0)
            }}
          >
            <option value="">All Policy Actions</option>
            <option value="Allow">Allow</option>
            <option value="Monitor">Monitor</option>
            <option value="Restrict">Restrict</option>
            <option value="Block">Block</option>
          </select>

          <button type="submit" className="primary" style={{ marginTop: 0, padding: '8px 16px', width: 'auto' }}>
            ⌕ Filter
          </button>
          <button
            type="button"
            className="chip"
            onClick={() => {
              setSearch('')
              setThreatLevel('')
              setAttackType('')
              setActionFilter('')
              setPage(0)
              fetchEvents()
            }}
          >
            Reset
          </button>
        </form>
      </div>

      {error && (
        <div className="card error-banner" style={{ marginBottom: '16px', color: '#ff7f8c', borderColor: '#9b3746' }}>
          <b>Query Error:</b> {error}
        </div>
      )}

      {/* Events Table */}
      <div className="card" style={{ padding: '16px' }}>
        <div className="title-line" style={{ marginBottom: '12px' }}>
          <h2>Persisted Security Events ({total} total)</h2>
          <div style={{ fontSize: '12px', color: '#8faec9' }}>
            Page {page + 1} of {totalPages}
          </div>
        </div>

        {loading ? (
          <div style={{ padding: '30px', textAlign: 'center', color: '#8faec9' }}>
            Loading security events from PostgreSQL…
          </div>
        ) : events.length === 0 ? (
          <div className="empty" style={{ padding: '40px' }}>
            No security events found matching the specified filters.
          </div>
        ) : (
          <div className="table">
            <div className="row head">
              <span>Time</span>
              <span>Event / Threat</span>
              <span>Source IP</span>
              <span>Destination IP</span>
              <span>Risk</span>
              <span>Policy Action</span>
              <span>Status</span>
            </div>
            {events.map((event) => (
              <button
                className="row event-row"
                onClick={() => setSelected(event)}
                key={event.id}
                type="button"
              >
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
          </div>
        )}

        {/* Pagination Controls */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '16px' }}>
          <button
            className="chip"
            disabled={page === 0}
            onClick={() => setPage((p) => Math.max(0, p - 1))}
            style={{ opacity: page === 0 ? 0.5 : 1 }}
          >
            ← Previous Page
          </button>
          <span style={{ fontSize: '12px', color: '#8faec9' }}>
            Showing {events.length > 0 ? page * limit + 1 : 0} – {Math.min((page + 1) * limit, total)} of {total}
          </span>
          <button
            className="chip"
            disabled={page >= totalPages - 1}
            onClick={() => setPage((p) => Math.min(totalPages - 1, p + 1))}
            style={{ opacity: page >= totalPages - 1 ? 0.5 : 1 }}
          >
            Next Page →
          </button>
        </div>
      </div>

      {/* Incident Review Modal */}
      {selected && (
        <div className="modal-backdrop" role="presentation" onMouseDown={() => setSelected(null)}>
          <section
            className="incident-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="incident-title"
            onMouseDown={(e) => e.stopPropagation()}
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
                <dt>Source IP</dt>
                <dd>{selected.source}</dd>
              </div>
              <div>
                <dt>Destination IP</dt>
                <dd>{selected.destination}</dd>
              </div>
              <div>
                <dt>Risk score</dt>
                <dd>
                  <b className={`pill ${riskClass(selected.risk)}`}>{selected.risk} / 100</b>
                </dd>
              </div>
              <div>
                <dt>Current Action</dt>
                <dd>
                  <b className={`action ${selected.action.toLowerCase()}`}>{selected.action}</b>
                </dd>
              </div>
            </dl>

            {/* Deep SHAP Feature Attribution Section */}
            <div className="shap-modal-section">
              <h4>✦ Transparent XAI Feature Attributions (SHAP)</h4>
              {loadingExplanation ? (
                <div style={{ fontSize: '11px', color: '#8faec9', padding: '8px 0' }}>
                  Calculating Shapley feature attributions via TreeExplainer…
                </div>
              ) : explanation ? (
                <div className="shap-breakdown-box">
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '8px', fontSize: '11px' }}>
                    <span>Model Base Expected Prior: <b>{(explanation.expected_base_probability * 100).toFixed(1)}%</b></span>
                    <span>Threat: <b>{explanation.attack_type}</b></span>
                  </div>

                  <div className="shap-bars-list">
                    {explanation.feature_attributions.slice(0, 6).map((fa) => (
                      <div className="shap-bar-row" key={fa.feature}>
                        <span className="shap-bar-feat">{fa.feature} ({fa.value})</span>
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

                  {explanation.policy_reasoning && (
                    <div className="policy-trace-box" style={{ marginTop: '10px' }}>
                      <h4>Policy Decision Reasoning</h4>
                      <div className="policy-trace-steps">
                        <span className="trace-step">Model: {explanation.attack_type} ({selected.risk}/100)</span>
                        <span className="trace-arrow">→</span>
                        <span className="trace-step">Rule: {explanation.policy_reasoning.policy_rule_name}</span>
                        <span className="trace-arrow">→</span>
                        <span className="trace-step">Action: {explanation.policy_reasoning.enacted_policy_action}</span>
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                <p style={{ fontSize: '12px', color: '#9bb2cb' }}>
                  Standard baseline z-score attribution active.
                </p>
              )}
            </div>

            <div className="modal-actions" style={{ marginTop: '16px' }}>
              <button onClick={() => handleUpdateAction('Monitor')}>
                👁️ Monitor Flow
              </button>
              <button onClick={() => handleUpdateAction('Restrict')}>
                ⚠️ Restrict Flow
              </button>
              <button className="danger-button" onClick={() => handleUpdateAction('Block')}>
                🛑 Block / Quarantine
              </button>
            </div>
          </section>
        </div>
      )}
    </div>
  )
}
