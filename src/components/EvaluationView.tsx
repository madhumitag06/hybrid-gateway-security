/**
 * Evaluation & Benchmarking View Component
 * =========================================
 * Provides interactive benchmarking controls, empirical ML performance metrics,
 * Traditional Static Policy Baseline vs Adaptive AI comparative scorecards,
 * confusion matrix heatmaps, policy divergence ledger, and report export.
 */

import React, { useEffect, useState } from 'react'
import {
  fetchEvaluationSuites,
  fetchShadowComparison,
  getExportUrl,
  runEvaluation,
  type ShadowComparisonResponse,
} from '../services/evaluation'
import {
  getAdaptiveTelemetry,
  listFeedbacks,
  submitFlowFeedback,
  prepareTrainingDataset,
  triggerRetraining,
  listTrainingRuns,
  approveCandidatePromotion,
  rollbackAdaptiveModel,
  type AdaptiveTelemetry,
  type FeedbackRecord,
} from '../services/adaptive'
import type { EvaluationRunResponse, EvaluationSuiteInfo } from '../types'

export const EvaluationView: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'BENCHMARK' | 'SHADOW_MODE' | 'ADAPTIVE_LEARNING'>('BENCHMARK')
  const [suites, setSuites] = useState<EvaluationSuiteInfo[]>([])
  const [selectedSuite, setSelectedSuite] = useState<string>('FULL_BENCHMARK')
  const [sampleCount, setSampleCount] = useState<number>(200)
  const [includeShap, setIncludeShap] = useState<boolean>(true)
  const [evaluation, setEvaluation] = useState<EvaluationRunResponse | null>(null)
  const [loading, setLoading] = useState<boolean>(false)
  const [error, setError] = useState<string | null>(null)

  // Shadow Mode state
  const [shadowData, setShadowData] = useState<ShadowComparisonResponse | null>(null)
  const [loadingShadow, setLoadingShadow] = useState<boolean>(false)
  const [shadowError, setShadowError] = useState<string | null>(null)

  // Adaptive Learning & Feedback state
  const [adaptiveTelemetry, setAdaptiveTelemetry] = useState<AdaptiveTelemetry | null>(null)
  const [feedbacks, setFeedbacks] = useState<FeedbackRecord[]>([])
  const [feedbackTotal, setFeedbackTotal] = useState<number>(0)
  const [feedbackFilter, setFeedbackFilter] = useState<string>('ALL')
  const [trainingRuns, setTrainingRuns] = useState<any[]>([])
  const [candidateVersionName, setCandidateVersionName] = useState<string>('')
  const [loadingAdaptive, setLoadingAdaptive] = useState<boolean>(false)
  const [adaptiveMessage, setAdaptiveMessage] = useState<string | null>(null)
  const [correctingRecordId, setCorrectingRecordId] = useState<string | null>(null)
  const [correctionTargetLabel, setCorrectionTargetLabel] = useState<string>('BENIGN')
  const [datasetPrepInfo, setDatasetPrepInfo] = useState<any | null>(null)
  const [isRetraining, setIsRetraining] = useState<boolean>(false)

  const loadShadowData = () => {
    setLoadingShadow(true)
    setShadowError(null)
    fetchShadowComparison(50)
      .then((data) => {
        setShadowData(data)
        setLoadingShadow(false)
      })
      .catch((err) => {
        setShadowError(String(err))
        setLoadingShadow(false)
      })
  }

  const loadAdaptiveData = async (filter = feedbackFilter) => {
    setLoadingAdaptive(true)
    try {
      const [tel, fbRes, runs] = await Promise.all([
        getAdaptiveTelemetry().catch(() => null),
        listFeedbacks(1, 25, filter === 'ALL' ? undefined : filter).catch(() => ({ total: 0, records: [] })),
        listTrainingRuns(10).catch(() => []),
      ])
      if (tel) setAdaptiveTelemetry(tel)
      if (fbRes) {
        setFeedbacks(fbRes.records || [])
        setFeedbackTotal(fbRes.total || 0)
      }
      if (runs) setTrainingRuns(runs)
    } catch (err: any) {
      setAdaptiveMessage(`Adaptive loading error: ${err.message || String(err)}`)
    } finally {
      setLoadingAdaptive(false)
    }
  }

  const handleFeedbackSubmit = async (
    feedbackId: string,
    action: 'CONFIRM' | 'CORRECT' | 'EXCLUDE' | 'RESET',
    verifiedLabel?: string
  ) => {
    try {
      await submitFlowFeedback(feedbackId, action, verifiedLabel)
      setAdaptiveMessage(`Feedback updated successfully (${action}${verifiedLabel ? `: ${verifiedLabel}` : ''})`)
      setCorrectingRecordId(null)
      loadAdaptiveData(feedbackFilter)
    } catch (err: any) {
      setAdaptiveMessage(`Feedback submission failed: ${err.message || String(err)}`)
    }
  }

  const handlePrepareDataset = async () => {
    try {
      setLoadingAdaptive(true)
      const res = await prepareTrainingDataset(5)
      setDatasetPrepInfo(res)
      setAdaptiveMessage(`Prepared versioned training dataset: ${res.total_samples} samples (${res.feature_count} features verified)`)
      loadAdaptiveData(feedbackFilter)
    } catch (err: any) {
      setAdaptiveMessage(`Dataset prep failed: ${err.message || String(err)}`)
    } finally {
      setLoadingAdaptive(false)
    }
  }

  const handleTriggerRetraining = async () => {
    setIsRetraining(true)
    setAdaptiveMessage('Retraining candidate model in isolated directory...')
    try {
      const res = await triggerRetraining(candidateVersionName.trim() || undefined)
      setAdaptiveMessage(
        `Retraining complete for ${res.candidate_version}: Accuracy ${((res.metrics?.accuracy || 0) * 100).toFixed(1)}%, F1 ${((res.metrics?.f1_macro || 0) * 100).toFixed(1)}%. Model is isolated and awaiting promotion approval.`
      )
      setCandidateVersionName('')
      loadAdaptiveData(feedbackFilter)
    } catch (err: any) {
      setAdaptiveMessage(`Retraining failed: ${err.message || String(err)}`)
    } finally {
      setIsRetraining(false)
    }
  }

  const handleApprovePromotion = async (runId: string, candidateVer: string) => {
    if (!window.confirm(`Are you sure you want to promote candidate model '${candidateVer}' to production authoritative? The current active model will be moved to standby rollback.`)) {
      return
    }
    try {
      setLoadingAdaptive(true)
      await approveCandidatePromotion(runId)
      setAdaptiveMessage(`Model ${candidateVer} successfully PROMOTED to active production model!`)
      loadAdaptiveData(feedbackFilter)
    } catch (err: any) {
      setAdaptiveMessage(`Promotion failed: ${err.message || String(err)}`)
    } finally {
      setLoadingAdaptive(false)
    }
  }

  const handleRollbackModel = async () => {
    if (!window.confirm('Are you sure you want to rollback to the standby model? Active traffic decisions will immediately revert to the standby model.')) {
      return
    }
    try {
      setLoadingAdaptive(true)
      const res = await rollbackAdaptiveModel('Manual analyst safety rollback')
      setAdaptiveMessage(`Gateway model successfully ROLLED BACK to standby: ${res.active_model_version}`)
      loadAdaptiveData(feedbackFilter)
    } catch (err: any) {
      setAdaptiveMessage(`Rollback failed: ${err.message || String(err)}`)
    } finally {
      setLoadingAdaptive(false)
    }
  }

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
    loadShadowData()
  }, [])

  return (
    <div className="analytics-container evaluation-view-container">
      {/* Sub-View Switcher: Benchmark Suite vs Candidate Shadow Mode */}
      <div style={{ display: 'flex', gap: '10px', marginBottom: '16px' }}>
        <button
          className="chip"
          onClick={() => setActiveTab('BENCHMARK')}
          style={{
            padding: '8px 18px',
            fontSize: '13px',
            cursor: 'pointer',
            backgroundColor: activeTab === 'BENCHMARK' ? 'var(--terracotta)' : 'var(--card-bg)',
            color: activeTab === 'BENCHMARK' ? '#ffffff' : 'var(--muted-cream)',
            border: activeTab === 'BENCHMARK' ? '1px solid var(--terracotta)' : '1px solid var(--line)',
            borderRadius: '6px',
            fontWeight: 600,
          }}
        >
          ⚡ Experimental Benchmark Suite
        </button>
        <button
          className="chip"
          onClick={() => {
            setActiveTab('SHADOW_MODE')
            loadShadowData()
          }}
          style={{
            padding: '8px 18px',
            fontSize: '13px',
            cursor: 'pointer',
            backgroundColor: activeTab === 'SHADOW_MODE' ? 'var(--terracotta)' : 'var(--card-bg)',
            color: activeTab === 'SHADOW_MODE' ? '#ffffff' : 'var(--muted-cream)',
            border: activeTab === 'SHADOW_MODE' ? '1px solid var(--terracotta)' : '1px solid var(--line)',
            borderRadius: '6px',
            fontWeight: 600,
          }}
        >
          🛡️ Candidate Model Shadow Mode (XGBoost V2 — Advisory Only)
        </button>
        <button
          className="chip"
          onClick={() => {
            setActiveTab('ADAPTIVE_LEARNING')
            loadAdaptiveData()
          }}
          style={{
            padding: '8px 18px',
            fontSize: '13px',
            cursor: 'pointer',
            backgroundColor: activeTab === 'ADAPTIVE_LEARNING' ? 'var(--terracotta)' : 'var(--card-bg)',
            color: activeTab === 'ADAPTIVE_LEARNING' ? '#ffffff' : 'var(--muted-cream)',
            border: activeTab === 'ADAPTIVE_LEARNING' ? '1px solid var(--terracotta)' : '1px solid var(--line)',
            borderRadius: '6px',
            fontWeight: 600,
          }}
        >
          🧠 Adaptive ML Learning & Feedback
        </button>
      </div>

      {activeTab === 'BENCHMARK' ? (
        <>
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
          {/* Active Model Benchmark Metadata Banner */}
          <div
            className="card"
            style={{
              padding: '12px 16px',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              background: 'var(--panel-secondary)',
              border: '1px solid var(--line-strong)',
              marginBottom: '12px',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', flexWrap: 'wrap' }}>
              <span className="topology-badge" style={{ background: 'var(--terracotta)', color: '#fff' }}>
                ACTIVE MODEL: {evaluation.model_name || 'Big Data XGBoost V2'} ({evaluation.model_version || 'candidate_xgboost_v2'})
              </span>
              <span style={{ fontSize: '12px', color: 'var(--muted-cream)' }}>
                Dataset: <strong>{evaluation.dataset_type || 'Representative Multi-Dataset Benchmark'}</strong> • Evaluated: <strong>N = {evaluation.total_flows_evaluated}</strong>
              </span>
            </div>
            <div style={{ fontSize: '11px', color: 'var(--muted-cream)' }}>
              Authority: <strong style={{ color: 'var(--olive-green)' }}>{evaluation.active_role || 'ACTIVE_PRIMARY'}</strong>
            </div>
          </div>

          {/* Single-Class Scenario Warning Banner */}
          {evaluation.is_single_class_suite && (
            <div
              className="auth-alert"
              style={{
                background: 'rgba(217, 119, 6, 0.15)',
                border: '1px solid rgba(217, 119, 6, 0.5)',
                color: 'var(--warm-cream)',
                padding: '12px 16px',
                borderRadius: 'var(--radius-sm)',
                fontSize: '12px',
                marginBottom: '14px',
              }}
            >
              <strong>⚠️ Single-Class Scenario Suite Notice: </strong>
              The selected evaluation suite ({evaluation.suite_name}) only contains samples for class <strong>{evaluation.represented_classes?.join(', ')}</strong>.
              Macro F1 across all 5 classes is naturally deflated ({(evaluation.ml_classification_metrics.macro_f1 * 100).toFixed(1)}%) because unrepresented classes have 0 true positives.
              For an authoritative, balanced 5-class evaluation, select <strong>"Full Synthetic Evaluation Suite"</strong>.
            </div>
          )}

          {/* 2. Top Summary Scorecard Strip */}
          <section className="analytics-metrics-strip">
            <div className="analytics-stat-card">
              <small>Overall ML Accuracy</small>
              <b style={{ color: 'var(--olive-green)' }}>
                {(evaluation.ml_classification_metrics.overall_accuracy * 100).toFixed(1)}%
              </b>
              <em>
                Macro F1: {(evaluation.ml_classification_metrics.macro_f1 * 100).toFixed(1)}%
                {evaluation.ml_classification_metrics.weighted_f1 !== undefined && (
                  <> • W-F1: {(evaluation.ml_classification_metrics.weighted_f1 * 100).toFixed(1)}%</>
                )}
              </em>
            </div>

            <div className="analytics-stat-card">
              <small>Error Rates (FPR / FNR)</small>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '4px' }}>
                <span style={{ fontSize: '12px', color: 'var(--muted-cream)' }}>
                  FPR: <strong style={{ color: 'var(--terracotta)' }}>{((evaluation.ml_classification_metrics.overall_fpr || 0) * 100).toFixed(1)}%</strong>
                </span>
                <span style={{ fontSize: '12px', color: 'var(--muted-cream)' }}>
                  FNR: <strong style={{ color: 'var(--muted-red)' }}>{((evaluation.ml_classification_metrics.overall_fnr || 0) * 100).toFixed(1)}%</strong>
                </span>
              </div>
              <em>False Positive vs False Negative</em>
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
                Rows represent ground-truth scenario labels; columns represent {evaluation.model_name || 'authoritative model'} predictions.
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
    </>
  ) : (
    /* Shadow Mode Candidate Evaluation Panel */
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {/* Header Card */}
          <section className="card" style={{ padding: '18px 22px', border: '1px solid var(--line)' }}>
            <div className="title-line" style={{ marginBottom: '10px' }}>
              <div>
                <h2 style={{ fontSize: '18px', color: 'var(--warm-cream)' }}>
                  🛡️ Candidate Model Telemetry: Big Data XGBoost V2 (Shadow Mode)
                </h2>
                <p style={{ margin: '4px 0 0', color: 'var(--muted-cream)', fontSize: '12px' }}>
                  Parallel advisory evaluation across live hybrid gateway network flows.
                </p>
              </div>
              <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                <span
                  style={{
                    backgroundColor: 'rgba(235, 94, 40, 0.15)',
                    color: 'var(--terracotta)',
                    border: '1px solid var(--terracotta)',
                    padding: '4px 10px',
                    borderRadius: '4px',
                    fontSize: '11px',
                    fontWeight: 700,
                  }}
                >
                  AUTHORITY: ADVISORY ONLY (NON-ENFORCING)
                </span>
                <button
                  className="chip"
                  onClick={loadShadowData}
                  disabled={loadingShadow}
                  style={{
                    padding: '6px 14px',
                    fontSize: '12px',
                    cursor: 'pointer',
                    border: '1px solid var(--line)',
                    backgroundColor: 'var(--card-bg)',
                    color: 'var(--warm-cream)',
                  }}
                >
                  {loadingShadow ? 'Refreshing...' : '🔄 Refresh Live Telemetry'}
                </button>
              </div>
            </div>

            {shadowData && (
              <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap', marginTop: '12px' }}>
                <span className="zone-tag ON_PREMISE">Model: {shadowData.candidate_status.candidate_model}</span>
                <span className="zone-tag CLOUD">Version: {shadowData.candidate_status.candidate_version}</span>
                <span className="zone-tag MANAGEMENT">Features: {shadowData.candidate_status.feature_count} (Clean V2)</span>
                <span className="zone-tag ON_PREMISE">Status: {shadowData.candidate_status.status}</span>
              </div>
            )}
            {shadowError && (
              <div style={{ color: 'var(--terracotta)', fontSize: '12px', marginTop: '8px' }}>
                ⚠️ Notice: {shadowError}
              </div>
            )}
          </section>

          {/* Metric Summary Grid */}
          {shadowData && (
            <div className="metrics-row" style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '14px' }}>
              <div className="card" style={{ padding: '16px', border: '1px solid var(--line)' }}>
                <div style={{ fontSize: '11px', color: 'var(--muted-cream)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                  Total Evaluated Flows
                </div>
                <div style={{ fontSize: '24px', fontWeight: 700, color: 'var(--warm-cream)', marginTop: '4px' }}>
                  {shadowData.summary.total_evaluated.toLocaleString()}
                </div>
                <div style={{ fontSize: '11px', color: 'var(--muted-cream)', marginTop: '2px' }}>
                  Parallel shadow evaluation
                </div>
              </div>

              <div className="card" style={{ padding: '16px', border: '1px solid var(--line)' }}>
                <div style={{ fontSize: '11px', color: 'var(--muted-cream)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                  Model Agreement Rate
                </div>
                <div
                  style={{
                    fontSize: '24px',
                    fontWeight: 700,
                    color: shadowData.summary.agreement_rate_pct >= 85 ? 'var(--olive-green)' : 'var(--terracotta)',
                    marginTop: '4px',
                  }}
                >
                  {shadowData.summary.agreement_rate_pct.toFixed(1)}%
                </div>
                <div style={{ fontSize: '11px', color: 'var(--muted-cream)', marginTop: '2px' }}>
                  {shadowData.summary.agreement_count} / {shadowData.summary.total_evaluated} concordant
                </div>
              </div>

              <div className="card" style={{ padding: '16px', border: '1px solid var(--line)' }}>
                <div style={{ fontSize: '11px', color: 'var(--muted-cream)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                  Inference Latency
                </div>
                <div style={{ fontSize: '24px', fontWeight: 700, color: 'var(--olive-green)', marginTop: '4px' }}>
                  {shadowData.summary.avg_candidate_latency_ms.toFixed(2)} ms
                </div>
                <div style={{ fontSize: '11px', color: 'var(--muted-cream)', marginTop: '2px' }}>
                  Prod RF: {shadowData.summary.avg_prod_latency_ms.toFixed(2)} ms (speedup)
                </div>
              </div>

              <div className="card" style={{ padding: '16px', border: '1px solid var(--line)' }}>
                <div style={{ fontSize: '11px', color: 'var(--muted-cream)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                  Total Disagreements
                </div>
                <div style={{ fontSize: '24px', fontWeight: 700, color: 'var(--terracotta)', marginTop: '4px' }}>
                  {shadowData.summary.disagreement_count}
                </div>
                <div style={{ fontSize: '11px', color: 'var(--muted-cream)', marginTop: '2px' }}>
                  Audited advisory divergence
                </div>
              </div>
            </div>
          )}

          {/* Comparison Ledger Table */}
          <article className="card analytics-card">
            <div className="title-line">
              <h2>Dual-Model Comparison & Telemetry Ledger</h2>
              <span className="topology-badge">Shadow & Multi-Model Audit Trail</span>
            </div>
            <p className="analytics-sub">
              Dual-model telemetry tracking authoritative XGBoost V2 policy classifications alongside standby Random Forest baseline evaluations.
            </p>

            <div style={{ overflowX: 'auto', marginTop: '12px', maxHeight: '420px' }}>
              <table className="ingest-flow-table">
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>Endpoints</th>
                    <th>Port/Proto</th>
                    <th>Active XGBoost V2 (Authoritative)</th>
                    <th>Standby RF Baseline (Rollback)</th>
                    <th>Agreement</th>
                    <th>SHAP Attributions</th>
                  </tr>
                </thead>
                <tbody>
                  {shadowData && shadowData.recent_comparisons.length > 0 ? (
                    shadowData.recent_comparisons.map((item) => (
                      <tr key={item.id}>
                        <td style={{ fontSize: '11px', color: 'var(--muted-cream)', whiteSpace: 'nowrap' }}>
                          {item.timestamp.split('T')[1]?.slice(0, 8) || item.timestamp}
                        </td>
                        <td style={{ fontSize: '11px', fontFamily: 'monospace' }}>
                          {item.source_ip} → {item.destination_ip}
                        </td>
                        <td style={{ fontSize: '11px', color: 'var(--muted-cream)' }}>
                          {item.dst_port}/{item.protocol}
                        </td>
                        <td>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                            <span className={`zone-tag ${item.prod_attack_type === 'BENIGN' ? 'ON_PREMISE' : 'INTERNET'}`}>
                              {item.prod_attack_type}
                            </span>
                            <span style={{ fontSize: '10px', color: 'var(--muted-cream)' }}>
                              Risk:{item.prod_risk_score} | {item.prod_latency_ms.toFixed(1)}ms
                            </span>
                          </div>
                        </td>
                        <td>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                            <span className={`zone-tag ${item.candidate_attack_type === 'BENIGN' ? 'ON_PREMISE' : 'INTERNET'}`}>
                              {item.candidate_attack_type}
                            </span>
                            <span style={{ fontSize: '10px', color: 'var(--muted-cream)' }}>
                              Risk:{item.candidate_risk_score} | {item.candidate_latency_ms.toFixed(1)}ms
                            </span>
                          </div>
                        </td>
                        <td>
                          {item.agreement ? (
                            <span
                              style={{
                                color: 'var(--olive-green)',
                                fontSize: '11px',
                                fontWeight: 700,
                                backgroundColor: 'rgba(74, 124, 89, 0.15)',
                                padding: '2px 8px',
                                borderRadius: '4px',
                              }}
                            >
                              AGREED
                            </span>
                          ) : (
                            <span
                              style={{
                                color: 'var(--terracotta)',
                                fontSize: '11px',
                                fontWeight: 700,
                                backgroundColor: 'rgba(235, 94, 40, 0.15)',
                                padding: '2px 8px',
                                borderRadius: '4px',
                              }}
                              title={item.disagreement_type || 'Discrepancy'}
                            >
                              DISAGREEMENT
                            </span>
                          )}
                        </td>
                        <td style={{ fontSize: '10px', color: 'var(--muted-cream)', maxWidth: '260px' }}>
                          {item.shap_attributions && item.shap_attributions.length > 0 ? (
                            item.shap_attributions.map((sa, sidx) => (
                              <span key={sidx} style={{ display: 'inline-block', marginRight: '4px' }}>
                                <strong>{sa.feature}</strong>: {sa.shap_value > 0 ? `+${sa.shap_value}` : sa.shap_value}
                              </span>
                            ))
                          ) : (
                            <span style={{ color: 'var(--muted-cream)', fontStyle: 'italic' }}>Baseline</span>
                          )}
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={7} style={{ textAlign: 'center', color: 'var(--muted-cream)', padding: '20px' }}>
                        No shadow evaluations recorded yet. Run hybrid lab scenarios or ingest traffic to populate telemetry.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </article>

          {/* Safety Notice */}
          <div className="non-causal-disclaimer">
            <strong>🛡️ Model Authority Guarantee: </strong>
            Big Data XGBoost V2 is the active authoritative model governing live hybrid gateway and router policy enforcements. Random Forest V1 is preserved as the standby model for instant zero-downtime rollback without traffic interruption.
          </div>
        </div>
      )}

      {activeTab === 'ADAPTIVE_LEARNING' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
          {/* Toast / Message Banner */}
          {adaptiveMessage && (
            <div
              className="auth-alert"
              style={{
                background: 'var(--panel-elevated)',
                border: '1px solid var(--line-strong)',
                color: 'var(--warm-cream)',
                padding: '10px 14px',
                borderRadius: 'var(--radius-sm)',
                fontSize: '12px',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
              }}
            >
              <span>ℹ️ {adaptiveMessage}</span>
              <button
                type="button"
                onClick={() => setAdaptiveMessage(null)}
                style={{ background: 'none', border: 'none', color: 'var(--muted-cream)', cursor: 'pointer' }}
              >
                ✕
              </button>
            </div>
          )}

          {/* 1. Telemetry and Model State Strip */}
          <section className="card" style={{ padding: '16px 20px', border: '1px solid var(--line)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px', flexWrap: 'wrap', gap: '10px' }}>
              <div>
                <h2 style={{ margin: 0, fontSize: '15px', color: 'var(--warm-cream)' }}>
                  🧠 Adaptive ML Pipeline Telemetry
                </h2>
                <span style={{ fontSize: '11.5px', color: 'var(--muted-cream)' }}>
                  Closed-loop feedback collection, verified label management, isolated candidate retraining, and safe promotion gates.
                </span>
              </div>
              <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                <button
                  type="button"
                  className="chip"
                  onClick={() => loadAdaptiveData()}
                  disabled={loadingAdaptive}
                  style={{ fontSize: '11px', padding: '4px 10px' }}
                >
                  ↻ Refresh
                </button>
                {adaptiveTelemetry?.standby_model_version && (
                  <button
                    type="button"
                    className="chip"
                    onClick={handleRollbackModel}
                    disabled={loadingAdaptive}
                    style={{ fontSize: '11px', padding: '4px 10px', borderColor: 'var(--terracotta)', color: 'var(--terracotta)' }}
                  >
                    🛡️ Safety Rollback to Standby
                  </button>
                )}
              </div>
            </div>

            <div className="metrics-strip">
              <div className="metric-box">
                <small>Ingested PCAPs</small>
                <b>{adaptiveTelemetry?.total_ingested_pcaps ?? 0}</b>
              </div>
              <div className="metric-box">
                <small>Extracted Flows</small>
                <b>{adaptiveTelemetry?.total_extracted_flows ?? 0}</b>
              </div>
              <div className="metric-box">
                <small>Verified Labels</small>
                <b style={{ color: 'var(--olive-green)' }}>{adaptiveTelemetry?.verified_feedback_count ?? 0}</b>
              </div>
              <div className="metric-box">
                <small>Unverified Inflow</small>
                <b style={{ color: 'var(--terracotta)' }}>{adaptiveTelemetry?.unverified_flow_count ?? 0}</b>
              </div>
              <div className="metric-box">
                <small>Active Authoritative Model</small>
                <b style={{ fontSize: '11.5px', color: 'var(--warm-cream)' }}>
                  {adaptiveTelemetry?.active_model_version || 'Loading...'}
                </b>
              </div>
              <div className="metric-box">
                <small>Retraining Readiness</small>
                <b>
                  {adaptiveTelemetry?.is_retraining_eligible ? (
                    <span style={{ color: 'var(--olive-green)' }}>Eligible (≥ {adaptiveTelemetry?.training_threshold_min_samples || 5})</span>
                  ) : (
                    <span style={{ color: 'var(--muted-cream)' }}>Need {Math.max(0, (adaptiveTelemetry?.training_threshold_min_samples || 5) - (adaptiveTelemetry?.verified_feedback_count || 0))} more</span>
                  )}
                </b>
              </div>
            </div>
          </section>

          {/* 2. Flow Feedback Review Ledger */}
          <section className="card" style={{ padding: '16px 20px', border: '1px solid var(--line)' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px', flexWrap: 'wrap', gap: '8px' }}>
              <div>
                <h3 style={{ margin: 0, fontSize: '14px', color: 'var(--warm-cream)' }}>
                  1. Analyst Feedback & Label Verification Ledger ({feedbackTotal} total)
                </h3>
                <small style={{ color: 'var(--muted-cream)', fontSize: '11px' }}>
                  Review live/ingested flow vectors, verify ground-truth labels, or exclude noisy samples.
                </small>
              </div>
              <div style={{ display: 'flex', gap: '6px' }}>
                {['ALL', 'UNVERIFIED', 'CONFIRMED', 'CORRECTED', 'EXCLUDED'].map((f) => (
                  <button
                    key={f}
                    type="button"
                    className={`chip ${feedbackFilter === f ? 'active' : ''}`}
                    onClick={() => {
                      setFeedbackFilter(f)
                      loadAdaptiveData(f)
                    }}
                    style={{ fontSize: '10.5px', padding: '3px 8px' }}
                  >
                    {f}
                  </button>
                ))}
              </div>
            </div>

            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '11.5px', textAlign: 'left' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--line-strong)', color: 'var(--muted-cream)' }}>
                    <th style={{ padding: '8px' }}>Flow / Protocol</th>
                    <th style={{ padding: '8px' }}>Model Prediction</th>
                    <th style={{ padding: '8px' }}>Key Flow Features</th>
                    <th style={{ padding: '8px' }}>Verified Label</th>
                    <th style={{ padding: '8px' }}>Status</th>
                    <th style={{ padding: '8px' }}>Analyst Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {feedbacks.length > 0 ? (
                    feedbacks.map((fb) => (
                      <tr key={fb.id} style={{ borderBottom: '1px solid var(--line-subtle)', color: 'var(--warm-cream)' }}>
                        <td style={{ padding: '8px', fontFamily: 'var(--font-mono)' }}>
                          <div>{fb.source_ip} → {fb.destination_ip}:{fb.dst_port}</div>
                          <small style={{ color: 'var(--muted-cream)', fontSize: '10px' }}>{fb.protocol} • {fb.timestamp ? new Date(fb.timestamp).toLocaleTimeString() : ''}</small>
                        </td>
                        <td style={{ padding: '8px' }}>
                          <b>{fb.predicted_class}</b>
                          <small style={{ display: 'block', color: 'var(--muted-cream)', fontSize: '10px' }}>
                            {((fb.prediction_confidence || 0) * 100).toFixed(1)}% conf ({fb.model_version})
                          </small>
                        </td>
                        <td style={{ padding: '8px', fontSize: '10.5px', color: 'var(--muted-cream)' }}>
                          pkts: {fb.flow_features?.packet_count ?? '-'}, bytes: {fb.flow_features?.byte_count ?? '-'}, dur: {fb.flow_features?.duration ?? '-'}s, rate: {fb.flow_features?.conn_rate ?? '-'}
                        </td>
                        <td style={{ padding: '8px' }}>
                          {fb.verified_label ? (
                            <span style={{ fontWeight: 600, color: 'var(--olive-green)' }}>{fb.verified_label}</span>
                          ) : (
                            <span style={{ color: 'var(--muted-cream)', fontStyle: 'italic' }}>Pending</span>
                          )}
                        </td>
                        <td style={{ padding: '8px' }}>
                          <span
                            className="pill"
                            style={{
                              fontSize: '10px',
                              padding: '2px 6px',
                              background:
                                fb.feedback_status === 'CONFIRMED'
                                  ? 'var(--olive-green-muted)'
                                  : fb.feedback_status === 'CORRECTED'
                                  ? 'rgba(235, 94, 40, 0.2)'
                                  : fb.feedback_status === 'EXCLUDED'
                                  ? 'rgba(150, 150, 150, 0.2)'
                                  : 'var(--panel-elevated)',
                              color:
                                fb.feedback_status === 'CONFIRMED'
                                  ? 'var(--olive-green)'
                                  : fb.feedback_status === 'CORRECTED'
                                  ? 'var(--terracotta)'
                                  : 'var(--warm-cream)',
                            }}
                          >
                            {fb.feedback_status}
                          </span>
                        </td>
                        <td style={{ padding: '8px' }}>
                          {correctingRecordId === fb.id ? (
                            <div style={{ display: 'flex', gap: '4px', alignItems: 'center' }}>
                              <select
                                value={correctionTargetLabel}
                                onChange={(e) => setCorrectionTargetLabel(e.target.value)}
                                style={{ background: 'var(--panel-inset)', color: 'var(--warm-cream)', border: '1px solid var(--line)', padding: '2px 4px', fontSize: '11px', borderRadius: '4px' }}
                              >
                                <option value="BENIGN">BENIGN</option>
                                <option value="BRUTE_FORCE">BRUTE_FORCE</option>
                                <option value="PORT_SCAN">PORT_SCAN</option>
                                <option value="SUSPICIOUS_TRANSFER">SUSPICIOUS_TRANSFER</option>
                                <option value="TRAFFIC_SPIKE">TRAFFIC_SPIKE</option>
                              </select>
                              <button
                                type="button"
                                className="primary"
                                onClick={() => handleFeedbackSubmit(fb.id, 'CORRECT', correctionTargetLabel)}
                                style={{ padding: '2px 6px', fontSize: '10.5px' }}
                              >
                                Save
                              </button>
                              <button
                                type="button"
                                className="btn-secondary"
                                onClick={() => setCorrectingRecordId(null)}
                                style={{ padding: '2px 6px', fontSize: '10.5px' }}
                              >
                                Cancel
                              </button>
                            </div>
                          ) : (
                            <div style={{ display: 'flex', gap: '4px' }}>
                              <button
                                type="button"
                                className="btn-secondary"
                                onClick={() => handleFeedbackSubmit(fb.id, 'CONFIRM')}
                                title="Confirm predicted class as correct"
                                style={{ padding: '2px 6px', fontSize: '10.5px' }}
                              >
                                ✓ Confirm
                              </button>
                              <button
                                type="button"
                                className="btn-secondary"
                                onClick={() => {
                                  setCorrectingRecordId(fb.id)
                                  setCorrectionTargetLabel(fb.predicted_class || 'BENIGN')
                                }}
                                title="Correct label"
                                style={{ padding: '2px 6px', fontSize: '10.5px' }}
                              >
                                ✏ Correct
                              </button>
                              <button
                                type="button"
                                className="btn-secondary"
                                onClick={() => handleFeedbackSubmit(fb.id, 'EXCLUDE')}
                                title="Exclude from training"
                                style={{ padding: '2px 6px', fontSize: '10.5px' }}
                              >
                                ✕ Exclude
                              </button>
                              {fb.feedback_status !== 'UNVERIFIED' && (
                                <button
                                  type="button"
                                  className="btn-secondary"
                                  onClick={() => handleFeedbackSubmit(fb.id, 'RESET')}
                                  title="Reset to unverified"
                                  style={{ padding: '2px 4px', fontSize: '10px' }}
                                >
                                  ↩
                                </button>
                              )}
                            </div>
                          )}
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={6} style={{ textAlign: 'center', color: 'var(--muted-cream)', padding: '20px' }}>
                        No feedback records found for this filter. Ingest PCAP captures to stream unverified flows into the ledger.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </section>

          {/* 3. Retraining Sandbox & Dataset Panel */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '16px' }}>
            {/* Dataset Preparation Card */}
            <section className="card" style={{ padding: '16px 20px', border: '1px solid var(--line)' }}>
              <h3 style={{ margin: '0 0 10px', fontSize: '14px', color: 'var(--warm-cream)' }}>
                2. Versioned Training Dataset
              </h3>
              <p style={{ fontSize: '11.5px', color: 'var(--muted-cream)', margin: '0 0 12px' }}>
                Combines verified analyst feedback with baseline datasets. Enforces 9-feature schema parity, deduplication, and NaN/Inf validation.
              </p>
              <div style={{ marginBottom: '12px' }}>
                <button
                  type="button"
                  className="primary"
                  onClick={handlePrepareDataset}
                  disabled={loadingAdaptive || !adaptiveTelemetry?.is_retraining_eligible}
                  style={{ padding: '6px 12px', fontSize: '11.5px' }}
                >
                  📦 Prepare Versioned Dataset
                </button>
                {!adaptiveTelemetry?.is_retraining_eligible && (
                  <small style={{ display: 'block', color: 'var(--muted-cream)', marginTop: '4px', fontSize: '10.5px' }}>
                    Requires at least {adaptiveTelemetry?.training_threshold_min_samples || 5} verified feedback samples.
                  </small>
                )}
              </div>
              {datasetPrepInfo && (
                <div style={{ background: 'var(--panel-inset)', padding: '10px 12px', borderRadius: '4px', fontSize: '11px', color: 'var(--warm-cream)' }}>
                  <div><strong>Dataset Version:</strong> <code>{datasetPrepInfo.dataset_version}</code></div>
                  <div><strong>Total Samples:</strong> {datasetPrepInfo.total_samples} (Feedback: {datasetPrepInfo.feedback_samples_included})</div>
                  <div><strong>Schema Parity:</strong> {datasetPrepInfo.feature_count} features verified (NaN/Inf checked)</div>
                </div>
              )}
            </section>

            {/* Candidate Retraining Card */}
            <section className="card" style={{ padding: '16px 20px', border: '1px solid var(--line)' }}>
              <h3 style={{ margin: '0 0 10px', fontSize: '14px', color: 'var(--warm-cream)' }}>
                3. Isolated Candidate Retraining
              </h3>
              <p style={{ fontSize: '11.5px', color: 'var(--muted-cream)', margin: '0 0 12px' }}>
                Trains an isolated candidate model in <code>ml/models/candidates/</code>. The active production model is never modified during training.
              </p>
              <div style={{ display: 'flex', gap: '8px', marginBottom: '12px' }}>
                <input
                  type="text"
                  placeholder="Candidate Version (optional, auto-generated)"
                  value={candidateVersionName}
                  onChange={(e) => setCandidateVersionName(e.target.value)}
                  style={{ flex: 1, padding: '6px 10px', fontSize: '11.5px', background: 'var(--panel-inset)', border: '1px solid var(--line)', color: 'var(--warm-cream)', borderRadius: '4px' }}
                />
                <button
                  type="button"
                  className="primary"
                  onClick={handleTriggerRetraining}
                  disabled={isRetraining || !adaptiveTelemetry?.is_retraining_eligible}
                  style={{ padding: '6px 14px', fontSize: '11.5px' }}
                >
                  {isRetraining ? 'Retraining...' : '🚀 Retrain Candidate'}
                </button>
              </div>
              <small style={{ color: 'var(--muted-cream)', fontSize: '10.5px', display: 'block' }}>
                🛡️ Safety Guarantee: New candidate model remains inactive until evaluation and explicit analyst promotion approval.
              </small>
            </section>
          </div>

          {/* 4. Candidate Runs & Promotion Acceptance Gate */}
          <section className="card" style={{ padding: '16px 20px', border: '1px solid var(--line)' }}>
            <h3 style={{ margin: '0 0 10px', fontSize: '14px', color: 'var(--warm-cream)' }}>
              4. Candidate Evaluation & Promotion Gate
            </h3>
            <p style={{ fontSize: '11.5px', color: 'var(--muted-cream)', margin: '0 0 12px' }}>
              Historical candidate training runs. Evaluate accuracy, F1 score, and false positive rates before approving promotion.
            </p>
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '11.5px', textAlign: 'left' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--line-strong)', color: 'var(--muted-cream)' }}>
                    <th style={{ padding: '8px' }}>Candidate Version</th>
                    <th style={{ padding: '8px' }}>Created</th>
                    <th style={{ padding: '8px' }}>Training Samples</th>
                    <th style={{ padding: '8px' }}>Accuracy</th>
                    <th style={{ padding: '8px' }}>F1 Macro</th>
                    <th style={{ padding: '8px' }}>False Positive Rate</th>
                    <th style={{ padding: '8px' }}>Status</th>
                    <th style={{ padding: '8px' }}>Promotion Action</th>
                  </tr>
                </thead>
                <tbody>
                  {trainingRuns.length > 0 ? (
                    trainingRuns.map((run) => (
                      <tr key={run.id} style={{ borderBottom: '1px solid var(--line-subtle)', color: 'var(--warm-cream)' }}>
                        <td style={{ padding: '8px', fontFamily: 'var(--font-mono)' }}>
                          <b>{run.candidate_version}</b>
                          <small style={{ display: 'block', color: 'var(--muted-cream)', fontSize: '10px' }}>
                            Base: {run.base_model_version}
                          </small>
                        </td>
                        <td style={{ padding: '8px', color: 'var(--muted-cream)' }}>
                          {run.created_at ? new Date(run.created_at).toLocaleString() : 'N/A'}
                        </td>
                        <td style={{ padding: '8px' }}>{run.retrain_samples_count}</td>
                        <td style={{ padding: '8px' }}>
                          {run.validation_accuracy !== null ? `${((run.validation_accuracy || 0) * 100).toFixed(1)}%` : 'N/A'}
                        </td>
                        <td style={{ padding: '8px' }}>
                          {run.validation_f1 !== null ? `${((run.validation_f1 || 0) * 100).toFixed(1)}%` : 'N/A'}
                        </td>
                        <td style={{ padding: '8px' }}>
                          {run.validation_fpr !== null ? `${((run.validation_fpr || 0) * 100).toFixed(2)}%` : 'N/A'}
                        </td>
                        <td style={{ padding: '8px' }}>
                          <span
                            className="pill"
                            style={{
                              fontSize: '10px',
                              padding: '2px 6px',
                              background:
                                run.status === 'PROMOTED'
                                  ? 'var(--olive-green-muted)'
                                  : run.status === 'TRAINED'
                                  ? 'rgba(235, 94, 40, 0.2)'
                                  : 'var(--panel-elevated)',
                              color:
                                run.status === 'PROMOTED'
                                  ? 'var(--olive-green)'
                                  : run.status === 'TRAINED'
                                  ? 'var(--terracotta)'
                                  : 'var(--warm-cream)',
                            }}
                          >
                            {run.status}
                          </span>
                        </td>
                        <td style={{ padding: '8px' }}>
                          {run.status === 'TRAINED' ? (
                            <button
                              type="button"
                              className="primary"
                              onClick={() => handleApprovePromotion(run.id, run.candidate_version)}
                              style={{ padding: '3px 8px', fontSize: '10.5px' }}
                            >
                              👑 Approve Promotion
                            </button>
                          ) : run.status === 'PROMOTED' ? (
                            <span style={{ color: 'var(--olive-green)', fontWeight: 600, fontSize: '11px' }}>
                              ✓ Active Production
                            </span>
                          ) : (
                            <span style={{ color: 'var(--muted-cream)', fontSize: '10.5px' }}>{run.status}</span>
                          )}
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={8} style={{ textAlign: 'center', color: 'var(--muted-cream)', padding: '20px' }}>
                        No candidate training runs yet. Trigger retraining when sufficient verified feedback has accumulated.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </section>
        </div>
      )}
    </div>
  )
}
