/**
 * Attack Simulation Control Center
 * ================================
 * Enables security analysts to trigger 6 real cross-network traffic scenarios
 * from On-Premises (10.10.10.0/24) through lab-router (10.10.10.2 <-> 10.20.10.2)
 * to Cloud VPC (10.20.10.0/24) with live execution telemetry and response inspection.
 */

import React, { useEffect, useState } from 'react'
import {
  getHybridScenarios,
  runHybridScenario,
  type HybridScenarioInfo,
  type ScenarioRunResult,
} from '../services/hybrid'

export const SimulationView: React.FC = () => {
  const [scenarios, setScenarios] = useState<HybridScenarioInfo[]>([])
  const [loadingScenarios, setLoadingScenarios] = useState(true)
  const [activeRunningId, setActiveRunningId] = useState<string | null>(null)
  const [lastResult, setLastResult] = useState<ScenarioRunResult | null>(null)
  const [toastMessage, setToastMessage] = useState<string | null>(null)
  const [executionHistory, setExecutionHistory] = useState<ScenarioRunResult[]>([])

  useEffect(() => {
    let mounted = true
    getHybridScenarios()
      .then((data) => {
        if (mounted) {
          setScenarios(data)
          setLoadingScenarios(false)
        }
      })
      .catch((err) => {
        console.error('Failed to load scenarios:', err)
        if (mounted) setLoadingScenarios(false)
      })
    return () => {
      mounted = false
    }
  }, [])

  const handleExecuteScenario = async (scenarioId: string) => {
    setActiveRunningId(scenarioId)
    setToastMessage(`Dispatching scenario '${scenarioId}' to traffic-generator container...`)
    try {
      const res = await runHybridScenario(scenarioId)
      setLastResult(res)
      setExecutionHistory((prev) => [res, ...prev.slice(0, 9)])
      setToastMessage(
        `Scenario '${scenarioId}' completed in ${res.duration_ms} ms. Traffic generated across lab-router.`
      )
    } catch (err: any) {
      setToastMessage(`Scenario dispatch error: ${err.message || String(err)}`)
    } finally {
      setActiveRunningId(null)
    }
  }

  const getActionBadgeClass = (action: string) => {
    switch (action.toLowerCase()) {
      case 'block':
      case 'verify quarantine':
        return 'r87'
      case 'restrict':
        return 'r76'
      case 'monitor':
        return 'r64'
      default:
        return 'r52'
    }
  }

  return (
    <div className="simulation-view-container" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      <section className="intro">
        <div>
          <h1>⚔️ Attack Simulation Control Center</h1>
          <p>
            Trigger controlled, reproducible cyber threat vectors across the virtual hybrid-cloud boundary
            (On-Premises 10.10.10.0/24 ↔ Central Linux Router ↔ Cloud VPC 10.20.10.0/24) to evaluate gateway AI detection and live containment.
          </p>
        </div>
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
          <button
            type="button"
            className="primary"
            disabled={activeRunningId !== null}
            onClick={() => handleExecuteScenario('all')}
            style={{ display: 'flex', alignItems: 'center', gap: '6px' }}
          >
            <span>▶</span> Run Full Benchmark Suite (All 6 Scenarios)
          </button>
        </div>
      </section>

      {toastMessage && (
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
          <span>ℹ️ {toastMessage}</span>
          <button
            type="button"
            onClick={() => setToastMessage(null)}
            style={{ background: 'none', border: 'none', color: 'var(--muted-cream)', cursor: 'pointer' }}
          >
            ✕
          </button>
        </div>
      )}

      {/* 6 Scenarios Interactive Grid */}
      {loadingScenarios ? (
        <div className="card" style={{ padding: '24px', textAlign: 'center', color: 'var(--muted-cream)' }}>
          Loading hybrid cloud traffic scenarios...
        </div>
      ) : (
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
            gap: '14px',
          }}
        >
          {scenarios.map((sc) => {
          const isRunning = activeRunningId === sc.id
          return (
            <div
              key={sc.id}
              className="card"
              style={{
                display: 'flex',
                flexDirection: 'column',
                justifyContent: 'space-between',
                padding: '16px',
                background: 'var(--panel)',
                border: '1px solid var(--line)',
                borderRadius: 'var(--radius-md)',
              }}
            >
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                  <span
                    className={`pill ${getActionBadgeClass(sc.expected_action)}`}
                    style={{ fontSize: '10px', textTransform: 'uppercase' }}
                  >
                    Expected: {sc.expected_action}
                  </span>
                  <span style={{ fontSize: '11px', color: 'var(--muted)', fontFamily: 'var(--font-mono)' }}>
                    {sc.protocol} • {sc.packets} pkts
                  </span>
                </div>

                <h3 style={{ margin: '0 0 6px', fontSize: '14px', color: 'var(--warm-cream)' }}>
                  {sc.name}
                </h3>
                <p style={{ margin: '0 0 12px', fontSize: '11.5px', color: 'var(--text-secondary)', lineHeight: '1.4' }}>
                  {sc.description}
                </p>

                <div
                  style={{
                    background: 'var(--panel-inset)',
                    padding: '8px 10px',
                    borderRadius: 'var(--radius-xs)',
                    border: '1px solid var(--line-subtle)',
                    fontSize: '11px',
                    fontFamily: 'var(--font-mono)',
                    marginBottom: '14px',
                    display: 'flex',
                    flexDirection: 'column',
                    gap: '4px',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: 'var(--muted-cream)' }}>Source:</span>
                    <span style={{ color: 'var(--warm-cream)' }}>
                      {sc.source_name} (<code>{sc.source_ip}</code>)
                    </span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: 'var(--muted-cream)' }}>Target:</span>
                    <span style={{ color: 'var(--terracotta)' }}>
                      {sc.destination_name} (<code>{sc.destination_ip}:{sc.port}</code>)
                    </span>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                    <span style={{ color: 'var(--muted-cream)' }}>Transit:</span>
                    <span style={{ color: 'var(--olive-green)' }}>lab-router (10.10.10.2 ↔ 10.20.10.2)</span>
                  </div>
                </div>
              </div>

              <button
                type="button"
                className="primary"
                disabled={activeRunningId !== null}
                onClick={() => handleExecuteScenario(sc.id)}
                style={{
                  width: '100%',
                  padding: '8px 12px',
                  fontSize: '12px',
                  display: 'flex',
                  justifyContent: 'center',
                  alignItems: 'center',
                  gap: '6px',
                  background: isRunning ? 'var(--panel-elevated)' : 'var(--terracotta)',
                  borderColor: 'var(--terracotta)',
                }}
              >
                {isRunning ? (
                  <>
                    <span className="auth-spinner" /> Generating Real Traffic...
                  </>
                ) : (
                  <>
                    <span>⚡</span> Launch Scenario
                  </>
                )}
              </button>
            </div>
          )
        })}
      </div>
      )}

      {/* Latest Execution Details */}
      {lastResult && (
        <section className="card" style={{ padding: '16px', background: 'var(--panel)', border: '1px solid var(--line)' }}>
          <div className="title-line" style={{ marginBottom: '10px' }}>
            <h2 style={{ margin: 0, fontSize: '15px' }}>
              Execution Telemetry: <code style={{ color: 'var(--terracotta)' }}>{lastResult.scenario}</code>
            </h2>
            <span style={{ fontSize: '11px', color: 'var(--muted)', fontFamily: 'var(--font-mono)' }}>
              Run ID: {lastResult.run_id} • Duration: {lastResult.duration_ms} ms
            </span>
          </div>
          <pre
            style={{
              background: 'var(--panel-inset)',
              border: '1px solid var(--line-subtle)',
              borderRadius: 'var(--radius-xs)',
              padding: '12px',
              fontSize: '11px',
              fontFamily: 'var(--font-mono)',
              color: 'var(--warm-cream)',
              maxHeight: '220px',
              overflowY: 'auto',
              margin: 0,
            }}
          >
            {JSON.stringify(lastResult.output || lastResult, null, 2)}
          </pre>
        </section>
      )}

      {/* Recent Simulation Executions Ledger */}
      {executionHistory.length > 0 && (
        <section className="card" style={{ padding: '16px', background: 'var(--panel)', border: '1px solid var(--line)' }}>
          <h2 style={{ margin: '0 0 10px', fontSize: '14px', color: 'var(--warm-cream)' }}>
            Recent Simulation Runs ({executionHistory.length})
          </h2>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {executionHistory.map((item) => (
              <div
                key={item.run_id}
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  background: 'var(--panel-inset)',
                  padding: '6px 10px',
                  borderRadius: 'var(--radius-xs)',
                  fontSize: '11px',
                  fontFamily: 'var(--font-mono)',
                }}
              >
                <span style={{ color: 'var(--warm-cream)' }}>
                  <b>{item.scenario}</b> ({item.run_id})
                </span>
                <span style={{ color: 'var(--olive-green)' }}>
                  {item.status} in {item.duration_ms} ms
                </span>
              </div>
            ))}
          </div>
        </section>
      )}
    </div>
  )
}
