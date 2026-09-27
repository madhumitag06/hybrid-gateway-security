/**
 * Security Analytics & Transparent XAI Dashboard Component
 * ========================================================
 * Visualizes historical risk score histogram buckets, threat classifications,
 * hybrid zone transit flows, telemetry provenance, and global SHAP sensitivity.
 */

import React, { useEffect, useState } from 'react'
import { getAnalyticsSummary } from '../services/analytics'
import type { AnalyticsSummaryResponse } from '../types'

export const AnalyticsView: React.FC = () => {
  const [analytics, setAnalytics] = useState<AnalyticsSummaryResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    getAnalyticsSummary()
      .then((data) => {
        setAnalytics(data)
        setLoading(false)
      })
      .catch((err) => {
        setError(String(err))
        setLoading(false)
      })
  }, [])

  if (loading) {
    return <div className="loading">Loading Security Analytics & XAI Distributions…</div>
  }

  if (error || !analytics) {
    return (
      <div className="card" style={{ padding: '24px', textAlign: 'center', color: '#ff7f8c' }}>
        <h3>Unable to load analytics</h3>
        <p>{error || 'No analytics data available.'}</p>
      </div>
    )
  }

  return (
    <div className="analytics-container">
      {/* Top Metrics Banner */}
      <section className="analytics-metrics-strip">
        <div className="analytics-stat-card">
          <small>Total Events Evaluated</small>
          <b>{analytics.total_events_evaluated}</b>
          <span>PostgreSQL Records</span>
        </div>
        <div className="analytics-stat-card">
          <small>Live Telemetry Events</small>
          <b style={{ color: '#38bdf8' }}>{analytics.real_telemetry_events}</b>
          <span>Live CloudWatch / Socket</span>
        </div>
        <div className="analytics-stat-card">
          <small>Synthetic Fixtures & Demo Seeds</small>
          <b style={{ color: '#ffd166' }}>{analytics.fixture_demo_events}</b>
          <span>Synthetic PCAPs / AWS Fixtures / Seeds</span>
        </div>
        <div className="analytics-stat-card">
          <small>Active Containment Rules</small>
          <b style={{ color: '#c084fc' }}>{analytics.active_sandbox_rules_count}</b>
          <span>Sandbox Isolation Filter</span>
        </div>
      </section>

      {/* Grid Row 1: Histogram Buckets & Threat Classification */}
      <div className="analytics-grid">
        <article className="card analytics-card">
          <div className="title-line">
            <h2>Analytics Histogram Buckets (Risk Spectrum)</h2>
            <small style={{ color: '#8faec9' }}>Standardized 20-Point Bins</small>
          </div>
          <p className="analytics-sub">
            Distribution of continuous risk scores (0–100) across historical flows.
            (Policy tiers: 0–39 LOW, 40–69 MEDIUM, 70–100 HIGH).
          </p>
          <div className="histogram-bars-container">
            {analytics.histogram_buckets.map((b) => (
              <div key={b.bin_label} className="histogram-row">
                <div className="hist-meta">
                  <span>Bucket {b.bin_label}</span>
                  <b>{b.count} events ({b.percentage}%)</b>
                </div>
                <div className="hist-track">
                  <div
                    className={`hist-fill ${
                      b.min_score >= 60 ? 'high' : b.min_score >= 40 ? 'med' : 'low'
                    }`}
                    style={{ width: `${Math.max(b.percentage, 3)}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </article>

        <article className="card analytics-card">
          <div className="title-line">
            <h2>Threat Classification Distribution</h2>
            <small style={{ color: '#8faec9' }}>RandomForest Predictions</small>
          </div>
          <p className="analytics-sub">
            Proportion of evaluated network flows classified into learned threat categories.
          </p>
          <div className="histogram-bars-container">
            {analytics.attack_type_distribution.map((atk) => (
              <div key={atk.attack_type} className="histogram-row">
                <div className="hist-meta">
                  <span className={`atk-label ${atk.attack_type}`}>{atk.attack_type}</span>
                  <b>{atk.count} ({atk.percentage}%)</b>
                </div>
                <div className="hist-track">
                  <div
                    className={`prob-bar-fill ${atk.attack_type}`}
                    style={{ width: `${Math.max(atk.percentage, 3)}%` }}
                  />
                </div>
              </div>
            ))}
          </div>
        </article>
      </div>

      {/* Grid Row 2: Hybrid Zone Traffic & Telemetry Provenance */}
      <div className="analytics-grid">
        <article className="card analytics-card">
          <div className="title-line">
            <h2>Hybrid Zone Transit Matrix</h2>
            <small style={{ color: '#8faec9' }}>CIDR Cross-Zone Routing</small>
          </div>
          <p className="analytics-sub">
            Evaluated traffic directions classified across On-Premise, AWS VPC, and External boundaries.
          </p>
          <div className="zone-grid-list">
            {analytics.zone_traffic_distribution.map((z) => (
              <div key={z.traffic_direction} className="zone-stat-row">
                <code>{z.traffic_direction}</code>
                <span className="zone-count-badge">{z.count} flows ({z.percentage}%)</span>
              </div>
            ))}
          </div>
        </article>

        <article className="card analytics-card">
          <div className="title-line">
            <h2>Telemetry Provenance Ledger</h2>
            <small style={{ color: '#8faec9' }}>Audit Provenance</small>
          </div>
          <p className="analytics-sub">
            Strict provenance segregation ensuring benchmarks are never labeled as live telemetry.
          </p>
          <div className="provenance-cards-list">
            {analytics.telemetry_provenance_distribution.map((p) => (
              <div key={p.telemetry_source} className="provenance-item-card">
                <div>
                  <strong>{p.telemetry_source}</strong>
                  <small style={{ display: 'block', color: p.is_real_telemetry ? '#34d399' : '#ffd166' }}>
                    {p.is_real_telemetry ? '● Real Capture / Telemetry' : '○ Deterministic Fixture / Demo Seed'}
                  </small>
                </div>
                <b>{p.count} events ({p.percentage}%)</b>
              </div>
            ))}
          </div>
        </article>
      </div>

      {/* Row 3: Global SHAP Feature Sensitivity Ranking */}
      <article className="card analytics-card">
        <div className="title-line">
          <h2>Global Model Sensitivity Ranking (Mean Absolute SHAP)</h2>
          <span className="topology-badge">TreeExplainer Attribution</span>
        </div>
        <p className="analytics-sub">
          Mean absolute Shapley value contribution across historical traffic, measuring statistical feature influence on model classification decisions.
        </p>
        <div className="shap-ranking-grid">
          {analytics.top_sensitive_features.map((f) => (
            <div key={f.feature} className="shap-ranking-row">
              <span className="rank-num">#{f.importance_rank}</span>
              <span className="rank-name">{f.feature}</span>
              <div className="rank-track">
                <div
                  className="rank-fill"
                  style={{ width: `${Math.min(f.mean_abs_shap * 300, 100)}%` }}
                />
              </div>
              <b className="rank-val">{f.mean_abs_shap.toFixed(4)}</b>
            </div>
          ))}
        </div>
      </article>

      {/* Non-Causal Framing Disclaimer */}
      <div className="non-causal-disclaimer">
        <strong>⚠️ Non-Causal Transparency Notice: </strong>
        SHAP feature attributions quantify the mathematical sensitivity of the trained Random Forest decision trees to specific input values. They explain the statistical basis of model predictions and do not constitute physical or legal proof of malicious causality.
      </div>
    </div>
  )
}
