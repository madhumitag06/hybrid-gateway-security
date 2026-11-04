/**
 * Infrastructure & Gateway Health Console
 * =======================================
 * Live inspection of all 13 Docker containers across the Virtual Hybrid Cloud Lab,
 * verifying Linux Router forwarding, iptables agent status, PostgreSQL persistence,
 * and ML anomaly inference pipeline health.
 */

import React, { useEffect, useState } from 'react'
import { getInfrastructureHealth, type InfrastructureHealthResponse } from '../services/hybrid'

export const SystemHealthView: React.FC = () => {
  const [healthData, setHealthData] = useState<InfrastructureHealthResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [refreshing, setRefreshing] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const fetchHealth = (isRefresh = false) => {
    if (isRefresh) setRefreshing(true)
    else setLoading(true)
    setError(null)

    getInfrastructureHealth()
      .then((data) => {
        setHealthData(data)
        setLoading(false)
        setRefreshing(false)
      })
      .catch((err) => {
        setError(String(err))
        setLoading(false)
        setRefreshing(false)
      })
  }

  useEffect(() => {
    fetchHealth()
    const timer = setInterval(() => fetchHealth(true), 15000)
    return () => clearInterval(timer)
  }, [])

  return (
    <div className="system-health-view-container" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      <section className="intro">
        <div>
          <h1>🖥️ Infrastructure & Gateway Health</h1>
          <p>
            Real-time status of all 13 Docker containers across On-Premises, Transit Router, and Cloud VPC networks.
          </p>
        </div>
        <div style={{ display: 'flex', gap: '8px' }}>
          <button
            type="button"
            className="btn-secondary"
            disabled={loading || refreshing}
            onClick={() => fetchHealth(true)}
            style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
          >
            <span>🔄</span> {refreshing ? 'Refreshing...' : 'Refresh Health'}
          </button>
        </div>
      </section>

      {error && (
        <div className="auth-alert error" style={{ margin: 0 }}>
          <span>⚠️ {error}</span>
        </div>
      )}

      {healthData && (
        <>
          {/* Top Health Summaries */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))',
              gap: '12px',
            }}
          >
            <div className="card" style={{ padding: '14px', background: 'var(--panel)', border: '1px solid var(--line)' }}>
              <small style={{ color: 'var(--muted-cream)', display: 'block', fontSize: '11px' }}>Overall Cluster Health</small>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '4px' }}>
                <span
                  style={{
                    width: '10px',
                    height: '10px',
                    borderRadius: '50%',
                    background: healthData.overall_status === 'OPERATIONAL' ? 'var(--olive-green)' : 'var(--muted-red)',
                    display: 'inline-block',
                  }}
                />
                <b style={{ color: 'var(--warm-cream)', fontSize: '18px' }}>{healthData.overall_status}</b>
              </div>
              <small style={{ color: 'var(--muted)', fontSize: '11px', marginTop: '4px', display: 'block' }}>
                {healthData.healthy_containers} of {healthData.containers_count} containers healthy
              </small>
            </div>

            <div className="card" style={{ padding: '14px', background: 'var(--panel)', border: '1px solid var(--line)' }}>
              <small style={{ color: 'var(--muted-cream)', display: 'block', fontSize: '11px' }}>Linux Transit Router (10.30.10.2)</small>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '4px' }}>
                <span
                  style={{
                    width: '10px',
                    height: '10px',
                    borderRadius: '50%',
                    background: healthData.router.status === 'HEALTHY' ? 'var(--olive-green)' : 'var(--muted-red)',
                    display: 'inline-block',
                  }}
                />
                <b style={{ color: 'var(--warm-cream)', fontSize: '18px' }}>{healthData.router.status}</b>
              </div>
              <small style={{ color: 'var(--muted)', fontSize: '11px', marginTop: '4px', display: 'block' }}>
                IPv4 Forwarding: {healthData.router.ip_forward_active ? 'ACTIVE (1)' : 'DISABLED (0)'}
              </small>
            </div>

            <div className="card" style={{ padding: '14px', background: 'var(--panel)', border: '1px solid var(--line)' }}>
              <small style={{ color: 'var(--muted-cream)', display: 'block', fontSize: '11px' }}>Database Persistence</small>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '4px' }}>
                <span
                  style={{
                    width: '10px',
                    height: '10px',
                    borderRadius: '50%',
                    background: 'var(--olive-green)',
                    display: 'inline-block',
                  }}
                />
                <b style={{ color: 'var(--warm-cream)', fontSize: '18px' }}>{healthData.database.status}</b>
              </div>
              <small style={{ color: 'var(--muted)', fontSize: '11px', marginTop: '4px', display: 'block' }}>
                {healthData.database.engine} • Pool size: {healthData.database.pool_size}
              </small>
            </div>

            <div className="card" style={{ padding: '14px', background: 'var(--panel)', border: '1px solid var(--line)' }}>
              <small style={{ color: 'var(--muted-cream)', display: 'block', fontSize: '11px' }}>ML Threat Predictor</small>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '4px' }}>
                <span
                  style={{
                    width: '10px',
                    height: '10px',
                    borderRadius: '50%',
                    background: 'var(--terracotta)',
                    display: 'inline-block',
                  }}
                />
                <b style={{ color: 'var(--warm-cream)', fontSize: '18px' }}>RandomForest</b>
              </div>
              <small style={{ color: 'var(--muted)', fontSize: '11px', marginTop: '4px', display: 'block' }}>
                SHAP Explainer: Threshold ≥ {healthData.ml_engine.shap_threshold}
              </small>
            </div>
          </div>

          {/* 13 Containers Roster Table */}
          <div className="card" style={{ padding: '16px', background: 'var(--panel)', border: '1px solid var(--line)' }}>
            <div className="title-line" style={{ marginBottom: '14px' }}>
              <h2 style={{ margin: 0, fontSize: '15px' }}>Docker Container Fleet (13 Services)</h2>
              <span style={{ fontSize: '11px', color: 'var(--muted-cream)', fontFamily: 'var(--font-mono)' }}>
                Last checked: {new Date(healthData.checked_at).toLocaleTimeString()}
              </span>
            </div>

            <div className="table-wrapper" style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px', textAlign: 'left' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--line-strong)', color: 'var(--muted-cream)' }}>
                    <th style={{ padding: '8px 10px' }}>Container Name</th>
                    <th style={{ padding: '8px 10px' }}>Network Zone</th>
                    <th style={{ padding: '8px 10px' }}>Role / Description</th>
                    <th style={{ padding: '8px 10px' }}>IP / Interface Binding</th>
                    <th style={{ padding: '8px 10px' }}>Health Status</th>
                  </tr>
                </thead>
                <tbody>
                  {healthData.containers.map((c) => (
                    <tr
                      key={c.name}
                      style={{
                        borderBottom: '1px solid var(--line-subtle)',
                        color: 'var(--warm-cream)',
                      }}
                    >
                      <td style={{ padding: '8px 10px', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
                        {c.name}
                      </td>
                      <td style={{ padding: '8px 10px' }}>
                        <span
                          className="prov-badge"
                          style={{
                            fontSize: '9.5px',
                            background:
                              c.zone === 'ON_PREMISE'
                                ? 'var(--dark-olive)'
                                : c.zone === 'AWS_VPC'
                                ? 'var(--panel-elevated)'
                                : 'var(--muted-charcoal)',
                            color:
                              c.zone === 'ON_PREMISE'
                                ? 'var(--olive-green)'
                                : c.zone === 'AWS_VPC'
                                ? 'var(--pale-sand)'
                                : 'var(--terracotta)',
                          }}
                        >
                          {c.zone}
                        </span>
                      </td>
                      <td style={{ padding: '8px 10px', color: 'var(--text-secondary)' }}>{c.role}</td>
                      <td style={{ padding: '8px 10px', fontFamily: 'var(--font-mono)', fontSize: '11px', color: 'var(--muted-cream)' }}>
                        {c.ip}
                      </td>
                      <td style={{ padding: '8px 10px' }}>
                        <span
                          style={{
                            display: 'inline-flex',
                            alignItems: 'center',
                            gap: '5px',
                            color: c.health === 'HEALTHY' ? 'var(--olive-green)' : 'var(--muted-red)',
                            fontWeight: 600,
                            fontSize: '11px',
                          }}
                        >
                          ● {c.health}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
    </div>
  )
}

