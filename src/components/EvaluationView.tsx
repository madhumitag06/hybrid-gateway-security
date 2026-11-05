/**
 * Evaluation & Benchmarking View Component
 * =========================================
 * Provides interactive benchmarking controls, empirical ML performance metrics,
 * Traditional Static Policy Baseline vs Adaptive AI comparative scorecards,
 * confusion matrix heatmaps, policy divergence ledger, and report export.
 */

import React, { useEffect, useState } from 'react'
import { fetchEvaluationSuites, getExportUrl, runEvaluation } from '../services/evaluation'
import type { EvaluationRunResponse, EvaluationSuiteInfo } from '../types'

export const EvaluationView: React.FC = () => {
  const [suites, setSuites] = useState<EvaluationSuiteInfo[]>([])
  const [selectedSuite, setSelectedSuite] = useState<string>('FULL_BENCHMARK')
  const [sampleCount, setSampleCount] = useState<number>(200)
  const [includeShap, setIncludeShap] = useState<boolean>(true)
  const [evaluation, setEvaluation] = useState<EvaluationRunResponse | null>(null)
  const [loading, setLoading] = useState<boolean>(false)
  const [error, setError] = useState<string | null>(null)

  const handleRunBenchmark = (suite = selectedSuite, count = sampleCount, shap = includeShap) => {
    setLoading(true)
    setError(null)
    runEvaluation(suite, count, shap)
      .then((res) => {
        setEvaluation(res)
        setLoading(false)
      })
      .catch((err) => {
        setError(String(err))
        setLoading(false)
      })
  }

  useEffect(() => {
    fetchEvaluationSuites()
      .then((data) => {
        setSuites(data)
      })
      .catch((err) => console.error('Failed to load suites:', err))

    // Automatically trigger initial default benchmark
    handleRunBenchmark('FULL_BENCHMARK', 200, true)
  }, [])

  return (
    <div className="analytics-container evaluation-view-container">
      {/* 1. Benchmark Execution Control Panel */}
      <section className="card" style={{ padding: '18px 22px', border: '1px solid var(--line)' }}>
        <div className="title-line" style={{ marginBottom: '14px' }}>
          <div>
            <h2 style={{ fontSize: '18px', color: 'var(--warm-cream)' }}>
              ⚡ Experimental Gateway Benchmark & Policy Comparative Suite
            </h2>
            <p style={{ margin: '4px 0 0', color: 'var(--muted-cream)', fontSize: '12px' }}>
              Dual-path empirical evaluation comparing the <strong>Adaptive AI Policy Engine</strong> against the <strong>Traditional Static Policy Baseline</strong> across controlled synthetic scenario suites.
            </p>
          </div>
          <div style={{ display: 'flex', gap: '8px' }}>
            <a
              href={getExportUrl(selectedSuite, sampleCount, 'json')}
              download={`evaluation_${selectedSuite.toLowerCase()}.json`}
              className="chip"
              style={{ textDecoration: 'none', color: 'var(--terracotta)', border: '1px solid var(--terracotta)' }}
            >
              ⬇ Export JSON
            </a>
            <a
              href={getExportUrl(selectedSuite, sampleCount, 'csv')}
              download={`evaluation_${selectedSuite.toLowerCase()}.csv`}
              className="chip"
              style={{ textDecoration: 'none', color: 'var(--olive-green)', border: '1px solid var(--olive-green)' }}
            >
              ⬇ Export CSV
            </a>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '14px', alignItems: 'center', flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <label style={{ fontSize: '11px', color: 'var(--muted-cream)' }}>Benchmark Suite</label>
            <select
              value={selectedSuite}
              onChange={(e) => setSelectedSuite(e.target.value)}
              className="select"
              style={{ height: '36px' }}
            >
              {suites.map((s) => (
                <option key={s.suite_name} value={s.suite_name}>
                  {s.title}
                </option>
              ))}
            </select>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '4px' }}>
            <label style={{ fontSize: '11px', color: 'var(--muted-cream)' }}>Sample Size (N)</label>
            <select
              value={sampleCount}
              onChange={(e) => setSampleCount(Number(e.target.value))}
              className="select"
              style={{ height: '36px', minWidth: '100px' }}
            >
              <option value={50}>N = 50</option>
              <option value={100}>N = 100</option>
              <option value={200}>N = 200</option>
              <option value={500}>N = 500</option>
            </select>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginTop: '16px' }}>
            <input
              type="checkbox"
              id="includeShapToggle"
              checked={includeShap}
              onChange={(e) => setIncludeShap(e.target.checked)}
            />
            <label htmlFor="includeShapToggle" style={{ fontSize: '12px', color: 'var(--warm-cream)', cursor: 'pointer' }}>
              Profile SHAP Attribution Latency
            </label>
          </div>

          <button
            onClick={() => handleRunBenchmark()}
            disabled={loading}
            className="analyzer-btn"
            style={{ marginTop: '16px', height: '36px', marginLeft: 'auto' }}
          >
            {loading ? 'Executing Dual Pipeline Evaluation…' : '▶ Run Evaluation Benchmark'}
          </button>
        </div>
      </section>

      {error && (
        <div className="card" style={{ padding: '16px', color: 'var(--muted-red)', textAlign: 'center' }}>
          {error}
        </div>
      )}

      {evaluation && (
        <>
          {/* 2. Top Summary Scorecard Strip */}
          <section className="analytics-metrics-strip">
            <div className="analytics-stat-card">
              <small>Overall ML Accuracy</small>
              <b style={{ color: 'var(--olive-green)' }}>
                {(evaluation.ml_classification_metrics.overall_accuracy * 100).toFixed(1)}%
              </b>
              <em>Macro F1: {(evaluation.ml_classification_metrics.macro_f1 * 100).toFixed(1)}%</em>
            </div>

            <div className="analytics-stat-card">
              <small>Over-Blocking (False Alarms)</small>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '4px' }}>
                <span style={{ fontSize: '12px', color: 'var(--muted-cream)' }}>
                  Static: <strong style={{ color: 'var(--muted-red)' }}>{(evaluation.policy_comparison_metrics.static_over_blocking_rate * 100).toFixed(1)}%</strong>
                </span>
                <span style={{ fontSize: '12px', color: 'var(--muted-cream)' }}>
                  Adaptive: <strong style={{ color: 'var(--olive-green)' }}>{(evaluation.policy_comparison_metrics.adaptive_over_blocking_rate * 100).toFixed(1)}%</strong>
                </span>
              </div>
              <em>Ground Truth Benign Contained</em>
            </div>

            <div className="analytics-stat-card">
              <small>Under-Blocking (Missed Threats)</small>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '4px' }}>
                <span style={{ fontSize: '12px', color: 'var(--muted-cream)' }}>
                  Static: <strong style={{ color: 'var(--muted-red)' }}>{(evaluation.policy_comparison_metrics.static_under_blocking_rate * 100).toFixed(1)}%</strong>
                </span>
                <span style={{ fontSize: '12px', color: 'var(--muted-cream)' }}>
                  Adaptive: <strong style={{ color: 'var(--olive-green)' }}>{(evaluation.policy_comparison_metrics.adaptive_under_blocking_rate * 100).toFixed(1)}%</strong>
                </span>
              </div>
              <em>Ground Truth Malicious Allowed</em>
            </div>

            <div className="analytics-stat-card">
              <small>Decision Divergence</small>
              <b style={{ color: 'var(--terracotta)' }}>
                {(evaluation.policy_comparison_metrics.divergence_rate * 100).toFixed(1)}%
              </b>
              <em>{evaluation.policy_comparison_metrics.total_divergent_decisions} of {evaluation.total_flows_evaluated} scenarios differed</em>
            </div>

            <div className="analytics-stat-card">
              <small>Gateway Throughput</small>
              <b style={{ color: 'var(--pale-sand)' }}>
                {evaluation.latency_metrics.throughput_flows_per_sec}
              </b>
              <em>flows/sec (Mean: {evaluation.latency_metrics.total_pipeline_latency_ms.mean.toFixed(2)} ms)</em>
            </div>
          </section>

          {/* 3. Confusion Matrix & Per-Class Table */}
          <div className="analytics-grid">
            {/* Confusion Matrix Card */}
            <article className="card analytics-card">
              <div className="title-line">
                <h2>Multi-Class Confusion Matrix</h2>
                <span className="topology-badge">Ground Truth vs Predicted</span>
              </div>
              <p className="analytics-sub">
                Rows represent ground-truth synthetic scenario labels; columns represent Phase 1 Random Forest predictions.
              </p>

              <div style={{ overflowX: 'auto', marginTop: '12px' }}>
                <table className="ingest-flow-table" style={{ textAlign: 'center' }}>
                  <thead>
                    <tr>
                      <th style={{ textAlign: 'left' }}>Actual \ Predicted</th>
                      {evaluation.ml_classification_metrics.confusion_matrix.classes.map((c) => (
                        <th key={c} style={{ fontSize: '10px' }}>{c}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {evaluation.ml_classification_metrics.confusion_matrix.matrix.map((row, rIdx) => {
                      const actualClass = evaluation.ml_classification_metrics.confusion_matrix.classes[rIdx]
                      return (
                        <tr key={actualClass}>
                          <td style={{ textAlign: 'left', fontWeight: 'bold', color: 'var(--terracotta)' }}>
                            {actualClass}
                          </td>
                          {row.map((cellVal, cIdx) => {
                            const isDiagonal = rIdx === cIdx
                            const bg = isDiagonal
                              ? cellVal > 0 ? 'var(--panel-secondary)' : 'var(--panel-secondary)'
                              : cellVal > 0 ? 'var(--panel-secondary)' : 'transparent'
                            const fg = isDiagonal
                              ? cellVal > 0 ? 'var(--olive-green)' : 'var(--muted-cream)'
                              : cellVal > 0 ? 'var(--muted-red)' : 'var(--muted-cream)'
                            return (
                              <td key={cIdx} style={{ background: bg, color: fg, fontWeight: isDiagonal ? 'bold' : 'normal' }}>
                                {cellVal}
                              </td>
                            )
                          })}
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            </article>

            {/* Per-Class Metrics Table */}
            <article className="card analytics-card">
              <div className="title-line">
                <h2>Classification Efficacy (Per Class)</h2>
                <small style={{ color: 'var(--muted-cream)' }}>Standard Evaluation Metrics</small>
              </div>
              <p className="analytics-sub">
                Mathematical detection performance computed against known ground-truth holdout test vectors.
              </p>

              <div style={{ overflowX: 'auto', marginTop: '12px' }}>
                <table className="ingest-flow-table">
                  <thead>
                    <tr>
                      <th>Class</th>
                      <th>TP / FP</th>
                      <th>Precision</th>
                      <th>Recall</th>
                      <th>F1-Score</th>
                    </tr>
                  </thead>
                  <tbody>
                    {evaluation.ml_classification_metrics.per_class_metrics.map((pcm) => (
                      <tr key={pcm.class_name}>
                        <td style={{ fontWeight: 'bold', color: 'var(--warm-cream)' }}>{pcm.class_name}</td>
                        <td style={{ fontSize: '11px', color: 'var(--muted-cream)' }}>{pcm.tp} / {pcm.fp}</td>
                        <td style={{ color: pcm.precision >= 0.9 ? 'var(--olive-green)' : 'var(--pale-sand)' }}>
                          {(pcm.precision * 100).toFixed(1)}%
                        </td>
                        <td style={{ color: pcm.recall >= 0.9 ? 'var(--olive-green)' : 'var(--pale-sand)' }}>
                          {(pcm.recall * 100).toFixed(1)}%
                        </td>
                        <td style={{ fontWeight: 'bold', color: pcm.f1_score >= 0.9 ? 'var(--olive-green)' : 'var(--pale-sand)' }}>
                          {(pcm.f1_score * 100).toFixed(1)}%
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </article>
          </div>

          {/* 4. Policy Comparison & Latency Breakdown */}
          <div className="analytics-grid">
            {/* Policy Comparison Details */}
            <article className="card analytics-card">
              <div className="title-line">
                <h2>Policy Action Distributions & Gating</h2>
                <small style={{ color: 'var(--muted-cream)' }}>Static Baseline vs Adaptive AI</small>
              </div>
              <p className="analytics-sub">
                Comparing containment decisions between rigid static heuristic rules and context-aware adaptive policies.
              </p>

              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px', marginTop: '12px' }}>
                <div style={{ background: 'var(--panel-secondary)', padding: '10px', borderRadius: '6px', border: '1px solid var(--line)' }}>
                  <small style={{ color: 'var(--muted-cream)', textTransform: 'uppercase' }}>Traditional Static Policy</small>
                  <div style={{ marginTop: '6px', fontSize: '12px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span>Allow:</span> <b>{evaluation.policy_comparison_metrics.static_action_distribution.Allow || 0}</b>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span>Block:</span> <b>{evaluation.policy_comparison_metrics.static_action_distribution.Block || 0}</b>
                    </div>
                  </div>
                </div>

                <div style={{ background: 'var(--panel-secondary)', padding: '10px', borderRadius: '6px', border: '1px solid var(--line)' }}>
                  <small style={{ color: 'var(--muted-cream)', textTransform: 'uppercase' }}>Adaptive Policy Engine</small>
                  <div style={{ marginTop: '6px', fontSize: '12px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span>Allow:</span> <b>{evaluation.policy_comparison_metrics.adaptive_action_distribution.Allow || 0}</b>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span>Monitor:</span> <b style={{ color: 'var(--pale-sand)' }}>{evaluation.policy_comparison_metrics.adaptive_action_distribution.Monitor || 0}</b>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span>Restrict:</span> <b style={{ color: 'var(--pale-sand)' }}>{evaluation.policy_comparison_metrics.adaptive_action_distribution.Restrict || 0}</b>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                      <span>Block:</span> <b style={{ color: 'var(--muted-red)' }}>{evaluation.policy_comparison_metrics.adaptive_action_distribution.Block || 0}</b>
                    </div>
                  </div>
                </div>
              </div>

              <div style={{ marginTop: '12px', background: 'var(--panel-secondary)', padding: '10px 12px', borderRadius: '6px', fontSize: '12px' }}>
                <span style={{ color: 'var(--terracotta)' }}>Borderline Confidence Gating Effectiveness: </span>
                <strong>{(evaluation.policy_comparison_metrics.borderline_gating_effectiveness * 100).toFixed(1)}%</strong>
                <span style={{ display: 'block', color: 'var(--muted-cream)', fontSize: '11px', marginTop: '2px' }}>
                  ({evaluation.policy_comparison_metrics.borderline_gated_to_monitor_count} of {evaluation.policy_comparison_metrics.borderline_scenarios_count} ambiguous flows safely placed into observation mode).
                </span>
              </div>
            </article>

            {/* Empirical Latency Breakdown */}
            <article className="card analytics-card">
              <div className="title-line">
                <h2>Empirical Latency & Throughput Profile</h2>
                <span className="topology-badge">Host Measurements</span>
              </div>
              <p className="analytics-sub">
                Actual measured latency percentiles across the full gateway execution pipeline.
              </p>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '12px' }}>
                <div className="zone-stat-row">
                  <span>Total End-to-End Pipeline</span>
                  <span style={{ color: 'var(--terracotta)', fontWeight: 'bold' }}>
                    Mean: {evaluation.latency_metrics.total_pipeline_latency_ms.mean.toFixed(2)} ms | p95: {evaluation.latency_metrics.total_pipeline_latency_ms.p95.toFixed(2)} ms
                  </span>
                </div>

                <div className="zone-stat-row">
                  <span>ML Inference Latency</span>
                  <span>Mean: {evaluation.latency_metrics.ml_inference_latency_ms.mean.toFixed(2)} ms | p95: {evaluation.latency_metrics.ml_inference_latency_ms.p95.toFixed(2)} ms</span>
                </div>

                {evaluation.latency_metrics.shap_attribution_latency_ms && (
                  <div className="zone-stat-row">
                    <span>SHAP TreeExplainer Attribution</span>
                    <span>Mean: {evaluation.latency_metrics.shap_attribution_latency_ms.mean.toFixed(2)} ms | p95: {evaluation.latency_metrics.shap_attribution_latency_ms.p95.toFixed(2)} ms</span>
                  </div>
                )}

                <div className="zone-stat-row">
                  <span>Context-Aware Policy Engine</span>
                  <span>Mean: {evaluation.latency_metrics.policy_evaluation_latency_ms.mean.toFixed(3)} ms</span>
                </div>
              </div>
            </article>
          </div>

          {/* 5. Policy Divergence Ledger Table */}
          <article className="card analytics-card">
            <div className="title-line">
              <h2>Policy Decision Divergence Ledger (Sample Flows)</h2>
              <span className="topology-badge">Cross-Engine Discrepancy Analysis</span>
            </div>
            <p className="analytics-sub">
              Detailed audit of flows where the Traditional Static Policy Baseline and Adaptive AI Policy Engine reached different containment decisions.
            </p>

            <div style={{ overflowX: 'auto', marginTop: '12px', maxHeight: '360px' }}>
              <table className="ingest-flow-table">
                <thead>
                  <tr>
                    <th>Scenario ID</th>
                    <th>Ground Truth</th>
                    <th>Flow Vector</th>
                    <th>Static Decision</th>
                    <th>Adaptive Decision</th>
                    <th>Rationale</th>
                  </tr>
                </thead>
                <tbody>
                  {evaluation.divergent_scenarios_sample.map((d) => (
                    <tr key={d.scenario_id}>
                      <td style={{ fontFamily: 'monospace', fontSize: '11px', color: 'var(--terracotta)' }}>{d.scenario_id}</td>
                      <td>
                        <span className={`zone-tag ${d.ground_truth_class === 'BENIGN' ? 'ON_PREMISE' : 'INTERNET'}`}>
                          {d.ground_truth_class}
                        </span>
                      </td>
                      <td style={{ fontSize: '11px', color: 'var(--muted-cream)' }}>
                        port:{d.dst_port} | pkts:{d.packet_count} | rate:{d.conn_rate.toFixed(1)}
                      </td>
                      <td>
                        <span className={`action ${d.static_action.toLowerCase()}`}>{d.static_action}</span>
                      </td>
                      <td>
                        <span className={`action ${d.adaptive_action.toLowerCase()}`}>{d.adaptive_action}</span>
                      </td>
                      <td style={{ fontSize: '11px', color: 'var(--muted-cream)', maxWidth: '320px' }}>
                        {d.divergence_rationale}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </article>

          {/* Disclaimer */}
          <div className="non-causal-disclaimer">
            <strong>⚠️ Evaluation Methodology Notice: </strong>
            {evaluation.disclaimer} The Traditional Static Policy Baseline represents fixed heuristic port/rate threshold rules and does not represent all possible hardware firewall configurations.
          </div>
        </>
      )}
    </div>
  )
}
