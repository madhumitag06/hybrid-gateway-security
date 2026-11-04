/**
 * Simulated AWS VPC Flow Logs Console
 * ===================================
 * Dedicated inspection and evaluation view for AWS VPC Flow Log records (Format v2).
 * Clearly marked as simulated cloud telemetry generated within the virtual hybrid lab.
 */

import React, { useEffect, useState } from 'react'
import {
  getAwsVpcSamples,
  ingestAwsVpcSample,
  ingestRawVpcLogs,
} from '../services/hybrid'
import type { AwsVpcIngestionResponse, AwsVpcSampleFixtureInfo } from '../types'

export const AwsVpcView: React.FC = () => {
  const [samples, setSamples] = useState<AwsVpcSampleFixtureInfo[]>([])
  const [loadingSamples, setLoadingSamples] = useState(true)
  const [ingesting, setIngesting] = useState(false)
  const [activeSampleId, setActiveSampleId] = useState<string | null>(null)
  const [ingestResponse, setIngestResponse] = useState<AwsVpcIngestionResponse | null>(null)
  const [rawVpcText, setRawVpcText] = useState('')
  const [toast, setToast] = useState<string | null>(null)

  useEffect(() => {
    let mounted = true
    getAwsVpcSamples()
      .then((data) => {
        if (mounted) {
          setSamples(data)
          setLoadingSamples(false)
        }
      })
      .catch((err) => {
        console.error('Failed to load AWS VPC samples:', err)
        if (mounted) setLoadingSamples(false)
      })
    return () => {
      mounted = false
    }
  }, [])

  const handleIngestSample = async (sampleId: string) => {
    setActiveSampleId(sampleId)
    setIngesting(true)
    setToast(`Ingesting benchmark AWS VPC flow fixture '${sampleId}'...`)
    try {
      const res = await ingestAwsVpcSample(sampleId, true)
      setIngestResponse(res)
      setToast(
        `Successfully evaluated ${res.total_flows_aggregated} flows (${res.high_risk_flows_count} high risk) from '${sampleId}'.`
      )
    } catch (err: any) {
      setToast(`Ingestion error: ${err.message || String(err)}`)
    } finally {
      setIngesting(false)
      setActiveSampleId(null)
    }
  }

  const handleIngestRaw = async () => {
    if (!rawVpcText.trim()) return
    setIngesting(true)
    setToast('Parsing and evaluating raw AWS VPC flow log records...')
    try {
      const res = await ingestRawVpcLogs(rawVpcText, false, 'operator_custom_vpc_input')
      setIngestResponse(res)
      setToast(
        `Ingested ${res.total_records_parsed} records into ${res.total_flows_aggregated} flow vectors.`
      )
    } catch (err: any) {
      setToast(`Error parsing raw VPC logs: ${err.message || String(err)}`)
    } finally {
      setIngesting(false)
    }
  }

  return (
    <div className="aws-vpc-view-container" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      <section className="intro">
        <div>
          <h1>☁️ Simulated AWS VPC Flow Logs</h1>
          <p>
            Inspect and evaluate standard AWS VPC Flow Log lines (v2 schema) crossing the hybrid cloud boundary.
          </p>
        </div>
      </section>

      {/* Mandatory Transparency Banner */}
      <div
        className="card"
        style={{
          background: 'var(--panel-muted)',
          border: '1px solid var(--line)',
          borderRadius: 'var(--radius-sm)',
          padding: '12px 16px',
          display: 'flex',
          alignItems: 'center',
          gap: '12px',
        }}
      >
        <span style={{ fontSize: '20px' }}>⚠️</span>
        <div style={{ fontSize: '12px', color: 'var(--text-secondary)' }}>
          <b style={{ color: 'var(--warm-cream)' }}>Simulated Cloud Telemetry Notice:</b> VPC flow logs shown here represent synthetic telemetry generated in the virtual hybrid lab (10.20.10.0/24, region us-east-1). No actual AWS credentials, billable cloud resources, or production security groups are modified.
        </div>
      </div>

      {toast && (
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
          <span>ℹ️ {toast}</span>
          <button
            type="button"
            onClick={() => setToast(null)}
            style={{ background: 'none', border: 'none', color: 'var(--muted-cream)', cursor: 'pointer' }}
          >
            ✕
          </button>
        </div>
      )}

      {/* Dual Ingestion Columns */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '16px' }}>
        {/* Column 1: Built-in Benchmark Fixtures */}
        <div className="card" style={{ padding: '16px', background: 'var(--panel)', border: '1px solid var(--line)' }}>
          <h2 style={{ fontSize: '14px', margin: '0 0 10px', color: 'var(--warm-cream)' }}>
            1. Pre-Configured Benchmark Fixtures
          </h2>
          <p style={{ fontSize: '11.5px', color: 'var(--text-secondary)', margin: '0 0 14px' }}>
            Click any fixture to trigger deterministic flow log parsing and AI threat evaluation:
          </p>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            {loadingSamples ? (
              <small style={{ color: 'var(--muted-cream)' }}>Loading benchmark fixtures...</small>
            ) : samples.map((s) => {
              const isSelected = activeSampleId === s.sample_id
              return (
                <div
                  key={s.sample_id}
                  style={{
                    background: 'var(--panel-inset)',
                    border: '1px solid var(--line-subtle)',
                    borderRadius: 'var(--radius-sm)',
                    padding: '10px 12px',
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                  }}
                >
                  <div>
                    <b style={{ color: 'var(--warm-cream)', fontSize: '12.5px' }}>{s.name}</b>
                    <small style={{ color: 'var(--muted-cream)', display: 'block', fontSize: '11px', marginTop: '2px' }}>
                      {s.record_count} records • {s.description}
                    </small>
                  </div>
                  <button
                    type="button"
                    className="primary"
                    disabled={ingesting}
                    onClick={() => handleIngestSample(s.sample_id)}
                    style={{ fontSize: '11px', padding: '5px 10px', whiteSpace: 'nowrap' }}
                  >
                    {isSelected ? 'Evaluating...' : 'Ingest Fixture'}
                  </button>
                </div>
              )
            })}
          </div>
        </div>

        {/* Column 2: Raw Custom Log Input */}
        <div className="card" style={{ padding: '16px', background: 'var(--panel)', border: '1px solid var(--line)' }}>
          <h2 style={{ fontSize: '14px', margin: '0 0 10px', color: 'var(--warm-cream)' }}>
            2. Raw AWS VPC Flow Log Input (Version 2 Format)
          </h2>
          <p style={{ fontSize: '11.5px', color: 'var(--text-secondary)', margin: '0 0 10px' }}>
            Paste space-separated VPC flow log records (e.g. <code>2 123456789012 eni-sim01 10.10.10.10 10.20.10.20 443 8080 6 25 15000 ...</code>):
          </p>

          <textarea
            value={rawVpcText}
            onChange={(e) => setRawVpcText(e.target.value)}
            placeholder="2 123456789012 eni-0123456789abcdef0 10.10.10.50 10.20.10.40 49152 80 6 75 4500 1620000000 1620000060 ACCEPT OK"
            rows={7}
            style={{
              width: '100%',
              background: 'var(--panel-inset)',
              border: '1px solid var(--line)',
              borderRadius: 'var(--radius-xs)',
              padding: '8px 10px',
              fontFamily: 'var(--font-mono)',
              fontSize: '11px',
              color: 'var(--warm-cream)',
              boxSizing: 'border-box',
              resize: 'vertical',
              marginBottom: '10px',
            }}
          />

          <button
            type="button"
            className="primary"
            disabled={ingesting || !rawVpcText.trim()}
            onClick={handleIngestRaw}
            style={{ width: '100%', padding: '8px 12px', fontSize: '12px' }}
          >
            {ingesting ? 'Evaluating...' : 'Ingest & Evaluate Raw Lines'}
          </button>
        </div>
      </div>

      {/* Ingestion Results Display */}
      {ingestResponse && (
        <section className="card" style={{ padding: '16px', background: 'var(--panel)', border: '1px solid var(--line)' }}>
          <div className="title-line" style={{ marginBottom: '12px' }}>
            <div>
              <h2 style={{ margin: 0, fontSize: '15px' }}>
                VPC Ingestion Telemetry: <code style={{ color: 'var(--terracotta)' }}>{ingestResponse.source_label}</code>
              </h2>
              <span style={{ fontSize: '11px', color: 'var(--muted-cream)' }}>
                {ingestResponse.total_records_parsed} records parsed into {ingestResponse.total_flows_aggregated} flows in {ingestResponse.total_duration_ms} ms
              </span>
            </div>
            <span
              className={`threat-tag ${ingestResponse.high_risk_flows_count > 0 ? 'HIGH' : 'LOW'}`}
              style={{ fontSize: '11px' }}
            >
              {ingestResponse.high_risk_flows_count} High Risk Flows
            </span>
          </div>

          <div className="table-wrapper" style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '12px', textAlign: 'left' }}>
              <thead>
                <tr style={{ borderBottom: '1px solid var(--line-strong)', color: 'var(--muted-cream)' }}>
                  <th style={{ padding: '8px 10px' }}>Flow Direction</th>
                  <th style={{ padding: '8px 10px' }}>Source IP</th>
                  <th style={{ padding: '8px 10px' }}>Dest IP:Port</th>
                  <th style={{ padding: '8px 10px' }}>Packets</th>
                  <th style={{ padding: '8px 10px' }}>Bytes</th>
                  <th style={{ padding: '8px 10px' }}>ML Prediction</th>
                  <th style={{ padding: '8px 10px' }}>Risk Score</th>
                  <th style={{ padding: '8px 10px' }}>Policy Action</th>
                </tr>
              </thead>
              <tbody>
                {ingestResponse.results.slice(0, 15).map((r: any, i: number) => (
                  <tr key={i} style={{ borderBottom: '1px solid var(--line-subtle)', color: 'var(--warm-cream)' }}>
                    <td style={{ padding: '8px 10px', fontSize: '11px' }}>
                      <span className="prov-badge" style={{ fontSize: '9.5px' }}>
                        {r.transit_zone || 'TRANSIT'}
                      </span>
                    </td>
                    <td style={{ padding: '8px 10px', fontFamily: 'var(--font-mono)' }}>{r.source_ip}</td>
                    <td style={{ padding: '8px 10px', fontFamily: 'var(--font-mono)', color: 'var(--terracotta)' }}>
                      {r.destination_ip}:{r.destination_port}
                    </td>
                    <td style={{ padding: '8px 10px' }}>{r.packet_count}</td>
                    <td style={{ padding: '8px 10px' }}>{r.byte_count}</td>
                    <td style={{ padding: '8px 10px', fontWeight: 600 }}>{r.predicted_class}</td>
                    <td style={{ padding: '8px 10px' }}>
                      <span
                        className="pill"
                        style={{
                          fontSize: '10.5px',
                          background: r.risk_score >= 70 ? 'var(--muted-red-muted)' : 'var(--olive-green-muted)',
                          color: r.risk_score >= 70 ? 'var(--muted-red)' : 'var(--olive-green)',
                        }}
                      >
                        {r.risk_score}/100
                      </span>
                    </td>
                    <td style={{ padding: '8px 10px', fontWeight: 600 }}>{r.policy_action}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  )
}
