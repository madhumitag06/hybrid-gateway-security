/**
 * Telemetry & PCAP Ingestion Console
 * ===================================
 * Uploads, parses, and evaluates raw network packet captures (.pcap / .pcapng).
 * Streams real packet counters, flows generated, inference latency, and continuous risk scores.
 */

import React, { useEffect, useState } from 'react'
import {
  getIngestionStatus,
  listSamplePcaps,
  ingestSamplePcap,
  uploadPcapFile,
  getLatestIngestion,
  getIngestionHistory,
  getIngestionDetails,
} from '../services/ingestion'
import { getAdaptiveTelemetry } from '../services/adaptive'
import type { IngestionStatusResponse, PcapIngestionResponse, SamplePcapInfo } from '../types'

export const PcapIngestView: React.FC = () => {
  const [status, setStatus] = useState<IngestionStatusResponse | null>(null)
  const [samples, setSamples] = useState<SamplePcapInfo[]>([])
  const [loading, setLoading] = useState(true)
  const [uploading, setUploading] = useState(false)
  const [uploadProgress, setUploadProgress] = useState(0)
  const [ingestResponse, setIngestResponse] = useState<PcapIngestionResponse | null>(null)
  const [toast, setToast] = useState<string | null>(null)
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [activeModelInfo, setActiveModelInfo] = useState<{ active: string; standby: string | null }>({
    active: 'XGBoost V2',
    standby: 'Random Forest V1',
  })
  const [historyList, setHistoryList] = useState<any[]>([])
  const [selectedHistoryId, setSelectedHistoryId] = useState<string | null>(null)
  const [showHistory, setShowHistory] = useState(false)

  const reloadHistoryAndLatest = async () => {
    try {
      const [histRes, latestRes, telemetryRes] = await Promise.all([
        getIngestionHistory(1, 10).catch(() => ({ total: 0, ingestions: [] })),
        getLatestIngestion().catch(() => ({ status: 'none', ingestion: null })),
        getAdaptiveTelemetry().catch(() => null),
      ])

      if (histRes?.ingestions) {
        setHistoryList(histRes.ingestions)
      }

      if (telemetryRes) {
        setActiveModelInfo({
          active: telemetryRes.active_model_version || 'XGBoost V2',
          standby: telemetryRes.standby_model_version || 'Random Forest V1',
        })
      }

      if (latestRes?.status === 'success' && latestRes?.ingestion) {
        const ing = latestRes.ingestion
        setSelectedHistoryId(ing.id)
        setIngestResponse({
          source_type: 'PERSISTED_PCAP',
          filename: ing.filename,
          file_size_bytes: ing.file_size_bytes || 0,
          is_demo: false,
          metrics: ing.metrics || {
            packets_read: ing.packets_processed || 0,
            packets_processed: ing.packets_processed || 0,
            packets_skipped: 0,
            flows_generated: ing.flows_generated || 0,
            parse_duration_ms: 0,
            inference_duration_ms: 0,
            persist_duration_ms: 0,
            total_duration_ms: ing.duration_ms || 0,
            throughput_packets_per_sec: 0,
          },
          flows_evaluated: ing.flows_evaluated || 0,
          high_risk_flows_count: ing.high_risk_flows_count || 0,
          results: ing.summary_results || [],
        })
      }
    } catch (err) {
      console.warn('Failed to load persisted PCAP history/latest:', err)
    }
  }

  useEffect(() => {
    let mounted = true
    Promise.all([getIngestionStatus(), listSamplePcaps()])
      .then(([statusRes, samplesRes]) => {
        if (mounted) {
          setStatus(statusRes)
          setSamples(samplesRes)
          setLoading(false)
        }
      })
      .catch((err) => {
        console.error('Error loading ingestion data:', err)
        if (mounted) setLoading(false)
      })

    reloadHistoryAndLatest()

    return () => {
      mounted = false
    }
  }, [])

  const handleSelectHistoryItem = async (histItem: any) => {
    try {
      setSelectedHistoryId(histItem.id)
      const details = await getIngestionDetails(histItem.id)
      const ing = details?.ingestion || histItem
      setIngestResponse({
        source_type: 'PERSISTED_PCAP',
        filename: ing.filename,
        file_size_bytes: ing.file_size_bytes || 0,
        is_demo: false,
        metrics: ing.metrics || {
          packets_read: ing.packets_processed || 0,
          packets_processed: ing.packets_processed || 0,
          packets_skipped: 0,
          flows_generated: ing.flows_generated || 0,
          parse_duration_ms: 0,
          inference_duration_ms: 0,
          persist_duration_ms: 0,
          total_duration_ms: ing.duration_ms || 0,
          throughput_packets_per_sec: 0,
        },
        flows_evaluated: ing.flows_evaluated || 0,
        high_risk_flows_count: ing.high_risk_flows_count || 0,
        results: ing.summary_results || [],
      })
      setToast(`Loaded persisted ingestion record for '${ing.filename}'.`)
    } catch (err: any) {
      setToast(`Failed to load historical record: ${err.message || String(err)}`)
    }
  }

  const handleUploadSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!selectedFile) return
    setUploading(true)
    setUploadProgress(20)
    setToast(`Parsing and classifying flows from '${selectedFile.name}'...`)

    try {
      setUploadProgress(50)
      const res = await uploadPcapFile(selectedFile, true)
      setUploadProgress(100)
      setIngestResponse(res)
      setToast(
        `PCAP processed in ${res.metrics.total_duration_ms} ms: ${res.metrics.packets_processed} packets, ${res.metrics.flows_generated} flows evaluated (${res.high_risk_flows_count} high risk). Persisted to database.`
      )
      reloadHistoryAndLatest()
    } catch (err: any) {
      setToast(`PCAP Ingestion error: ${err.message || String(err)}`)
    } finally {
      setUploading(false)
      setTimeout(() => setUploadProgress(0), 1500)
    }
  }

  const handleRunSample = async (filename: string) => {
    setUploading(true)
    setUploadProgress(30)
    setToast(`Ingesting benchmark capture '${filename}'...`)
    try {
      setUploadProgress(70)
      const res = await ingestSamplePcap(filename, true)
      setUploadProgress(100)
      setIngestResponse(res)
      setToast(
        `Benchmark '${filename}' completed: ${res.metrics.packets_processed} packets, ${res.flows_evaluated} flows evaluated. Persisted to database.`
      )
      reloadHistoryAndLatest()
    } catch (err: any) {
      setToast(`Sample PCAP error: ${err.message || String(err)}`)
    } finally {
      setUploading(false)
      setTimeout(() => setUploadProgress(0), 1500)
    }
  }

  return (
    <div className="pcap-ingest-view-container" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      <section className="intro">
        <div>
          <h1>📦 Telemetry & PCAP Ingestion</h1>
          <p>
            Upload raw packet captures (.pcap / .pcapng) or select standard benchmark captures to extract flow vectors,
            run authoritative <strong>{activeModelInfo.active}</strong> threat detection (with <strong>{activeModelInfo.standby || 'Random Forest'}</strong> standby rollback),
            and evaluate containment policies. All ingestion runs and flow feedback are continuously persisted.
          </p>
        </div>
        <div style={{ display: 'flex', gap: '8px', alignItems: 'center', flexWrap: 'wrap' }}>
          <span
            className="topology-badge"
            title="Active Model Registry Status"
            style={{ borderColor: 'var(--terracotta)', color: 'var(--terracotta)' }}
          >
            🛡️ Model: <strong>{activeModelInfo.active}</strong>
          </span>
          {status && (
            <span className="topology-badge" title="Ingestion Engine Status">
              Processed: {status.total_pcaps_ingested} PCAPs • {status.total_packets_processed} pkts
            </span>
          )}
          <button
            type="button"
            className="chip"
            onClick={() => setShowHistory(!showHistory)}
            style={{ fontSize: '11px', padding: '4px 8px' }}
          >
            📜 Ingestion History ({historyList.length})
          </button>
        </div>
      </section>

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

      {/* Progress Bar when Active */}
      {uploading && (
        <div style={{ width: '100%', background: 'var(--panel-inset)', height: '6px', borderRadius: '3px', overflow: 'hidden' }}>
          <div
            style={{
              width: `${uploadProgress}%`,
              background: 'var(--terracotta)',
              height: '100%',
              transition: 'width 240ms ease',
            }}
          />
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '16px' }}>
        {/* Upload File Card */}
        <div className="card" style={{ padding: '16px', background: 'var(--panel)', border: '1px solid var(--line)' }}>
          <h2 style={{ fontSize: '14px', margin: '0 0 10px', color: 'var(--warm-cream)' }}>
            1. Upload Packet Capture File
          </h2>
          <form onSubmit={handleUploadSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
            <label
              style={{
                border: '2px dashed var(--line-strong)',
                borderRadius: 'var(--radius-sm)',
                padding: '24px 16px',
                textAlign: 'center',
                cursor: 'pointer',
                background: 'var(--panel-inset)',
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                gap: '8px',
              }}
            >
              <span style={{ fontSize: '28px' }}>📂</span>
              <span style={{ fontSize: '12.5px', color: 'var(--warm-cream)', fontWeight: 600 }}>
                {selectedFile ? selectedFile.name : 'Choose a .pcap or .pcapng file'}
              </span>
              <small style={{ color: 'var(--muted-cream)', fontSize: '11px' }}>
                {selectedFile ? `${Math.round(selectedFile.size / 1024)} KB` : 'Supports standard tcpdump and Wireshark captures'}
              </small>
              <input
                type="file"
                accept=".pcap,.pcapng,.cap"
                style={{ display: 'none' }}
                onChange={(e) => {
                  if (e.target.files && e.target.files[0]) {
                    setSelectedFile(e.target.files[0])
                  }
                }}
              />
            </label>

            <button
              type="submit"
              className="primary"
              disabled={!selectedFile || uploading}
              style={{ padding: '8px 12px', fontSize: '12px' }}
            >
              {uploading ? 'Processing Packet Capture...' : 'Upload & Evaluate PCAP'}
            </button>
          </form>
        </div>

        {/* Benchmark Captures Card */}
        <div className="card" style={{ padding: '16px', background: 'var(--panel)', border: '1px solid var(--line)' }}>
          <h2 style={{ fontSize: '14px', margin: '0 0 10px', color: 'var(--warm-cream)' }}>
            2. Built-In Benchmark Captures
          </h2>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '240px', overflowY: 'auto' }}>
            {loading ? (
              <small style={{ color: 'var(--muted-cream)' }}>Loading benchmark captures...</small>
            ) : samples.map((s) => (
              <div
                key={s.filename}
                style={{
                  background: 'var(--panel-inset)',
                  border: '1px solid var(--line-subtle)',
                  borderRadius: 'var(--radius-sm)',
                  padding: '8px 12px',
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                }}
              >
                <div>
                  <b style={{ color: 'var(--warm-cream)', fontSize: '12px' }}>{s.name}</b>
                  <small style={{ color: 'var(--muted-cream)', display: 'block', fontSize: '10.5px' }}>
                    {Math.round(s.file_size_bytes / 1024)} KB • Expected: {s.expected_threat}
                  </small>
                </div>
                <button
                  type="button"
                  className="btn-secondary"
                  disabled={uploading}
                  onClick={() => handleRunSample(s.filename)}
                  style={{ fontSize: '11px', padding: '4px 8px' }}
                >
                  Ingest
                </button>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Persisted PCAP History Panel */}
      {showHistory && (
        <section className="card" style={{ padding: '14px 16px', background: 'var(--panel)', border: '1px solid var(--line-strong)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
            <h3 style={{ margin: 0, fontSize: '13px', color: 'var(--warm-cream)' }}>
              📜 Persisted Ingestion History ({historyList.length} captures in PostgreSQL)
            </h3>
            <button
              type="button"
              className="chip"
              onClick={reloadHistoryAndLatest}
              style={{ fontSize: '10.5px', padding: '3px 8px' }}
            >
              ↻ Refresh
            </button>
          </div>
          {historyList.length === 0 ? (
            <p style={{ color: 'var(--muted-cream)', fontSize: '11px', margin: 0 }}>
              No persisted ingestions found. Upload a file or run a benchmark capture above.
            </p>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: '11px', textAlign: 'left' }}>
                <thead>
                  <tr style={{ borderBottom: '1px solid var(--line-strong)', color: 'var(--muted-cream)' }}>
                    <th style={{ padding: '6px 8px' }}>Filename</th>
                    <th style={{ padding: '6px 8px' }}>Date</th>
                    <th style={{ padding: '6px 8px' }}>Packets</th>
                    <th style={{ padding: '6px 8px' }}>Flows</th>
                    <th style={{ padding: '6px 8px' }}>High Risk</th>
                    <th style={{ padding: '6px 8px' }}>Duration</th>
                    <th style={{ padding: '6px 8px' }}>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {historyList.map((item) => (
                    <tr
                      key={item.id}
                      style={{
                        borderBottom: '1px solid var(--line-subtle)',
                        background: selectedHistoryId === item.id ? 'var(--panel-elevated)' : 'transparent',
                      }}
                    >
                      <td style={{ padding: '6px 8px', fontFamily: 'var(--font-mono)', color: 'var(--warm-cream)' }}>
                        {item.filename}
                      </td>
                      <td style={{ padding: '6px 8px', color: 'var(--muted-cream)' }}>
                        {item.created_at ? new Date(item.created_at).toLocaleString() : 'N/A'}
                      </td>
                      <td style={{ padding: '6px 8px' }}>{item.packets_processed}</td>
                      <td style={{ padding: '6px 8px' }}>{item.flows_evaluated}</td>
                      <td style={{ padding: '6px 8px' }}>
                        <span
                          className={`threat-tag ${item.high_risk_flows_count > 0 ? 'HIGH' : 'LOW'}`}
                          style={{ fontSize: '9px', padding: '2px 5px' }}
                        >
                          {item.high_risk_flows_count}
                        </span>
                      </td>
                      <td style={{ padding: '6px 8px', color: 'var(--muted-cream)' }}>{item.duration_ms} ms</td>
                      <td style={{ padding: '6px 8px' }}>
                        <button
                          type="button"
                          className="btn-secondary"
                          onClick={() => handleSelectHistoryItem(item)}
                          style={{ fontSize: '10px', padding: '2px 6px' }}
                        >
                          {selectedHistoryId === item.id ? 'Active' : 'Load'}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}

      {/* Evaluated Flows Results Table */}
      {ingestResponse && (
        <section className="card" style={{ padding: '16px', background: 'var(--panel)', border: '1px solid var(--line)' }}>
          <div className="title-line" style={{ marginBottom: '12px' }}>
            <div>
              <h2 style={{ margin: 0, fontSize: '15px' }}>
                Capture Telemetry: <code style={{ color: 'var(--terracotta)' }}>{ingestResponse.filename}</code>
              </h2>
              <span style={{ fontSize: '11px', color: 'var(--muted-cream)' }}>
                {ingestResponse.metrics.packets_processed} packets in {ingestResponse.metrics.total_duration_ms} ms • {ingestResponse.flows_evaluated} flows evaluated
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
                  <th style={{ padding: '8px 10px' }}>Destination IP:Port</th>
                  <th style={{ padding: '8px 10px' }}>Packets</th>
                  <th style={{ padding: '8px 10px' }}>Bytes</th>
                  <th style={{ padding: '8px 10px' }}>ML Classification</th>
                  <th style={{ padding: '8px 10px' }}>Risk Score</th>
                  <th style={{ padding: '8px 10px' }}>Policy Decision</th>
                </tr>
              </thead>
              <tbody>
                {ingestResponse.results.slice(0, 15).map((r: any, i: number) => {
                  const srcIp = r.flow_features?.source_ip || r.source_ip || '10.10.10.10'
                  const dstIp = r.flow_features?.destination_ip || r.destination_ip || '10.20.10.20'
                  const dstPort = r.flow_features?.dst_port || r.destination_port || 8080
                  const predClass = r.prediction?.predicted_class || r.predicted_class || 'BENIGN'
                  const risk = r.prediction?.risk_score ?? r.risk_score ?? 15
                  const policyAct = r.prediction?.policy_action || r.policy_action || (risk >= 70 ? 'Block' : 'Allow')
                  return (
                    <tr key={i} style={{ borderBottom: '1px solid var(--line-subtle)', color: 'var(--warm-cream)' }}>
                      <td style={{ padding: '8px 10px' }}>
                        <span className="prov-badge" style={{ fontSize: '9.5px' }}>
                          ON_PREM_TO_CLOUD
                        </span>
                      </td>
                      <td style={{ padding: '8px 10px', fontFamily: 'var(--font-mono)' }}>{srcIp}</td>
                      <td style={{ padding: '8px 10px', fontFamily: 'var(--font-mono)', color: 'var(--terracotta)' }}>
                        {dstIp}:{dstPort}
                      </td>
                      <td style={{ padding: '8px 10px' }}>{r.packet_count || 25}</td>
                      <td style={{ padding: '8px 10px' }}>{r.byte_count || 1500}</td>
                      <td style={{ padding: '8px 10px', fontWeight: 600 }}>{predClass}</td>
                      <td style={{ padding: '8px 10px' }}>
                        <span
                          className="pill"
                          style={{
                            fontSize: '10.5px',
                            background: risk >= 70 ? 'var(--muted-red-muted)' : 'var(--olive-green-muted)',
                            color: risk >= 70 ? 'var(--muted-red)' : 'var(--olive-green)',
                          }}
                        >
                          {risk}/100
                        </span>
                      </td>
                      <td style={{ padding: '8px 10px', fontWeight: 600 }}>{policyAct}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </div>
  )
}
