/**
 * PCAP Traffic Ingestion API Client Service
 */

import type {
  IngestionStatusResponse,
  PcapIngestionResponse,
  SamplePcapInfo,
} from '../types'

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'

export async function getIngestionStatus(): Promise<IngestionStatusResponse> {
  const response = await fetch(`${API_BASE_URL}/api/v1/ingest/status`)
  if (!response.ok) {
    throw new Error(`Failed to fetch ingestion status (${response.status})`)
  }
  return response.json()
}

export async function listSamplePcaps(): Promise<SamplePcapInfo[]> {
  const response = await fetch(`${API_BASE_URL}/api/v1/ingest/samples`)
  if (!response.ok) {
    throw new Error(`Failed to list sample PCAPs (${response.status})`)
  }
  return response.json()
}

export async function ingestSamplePcap(
  filename: string,
  persist: boolean = true
): Promise<PcapIngestionResponse> {
  const response = await fetch(
    `${API_BASE_URL}/api/v1/ingest/samples/${encodeURIComponent(filename)}?persist=${persist}`,
    {
      method: 'POST',
    }
  )
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}))
    throw new Error(errorData.detail || `Failed to ingest sample PCAP (${response.status})`)
  }
  return response.json()
}

export async function uploadPcapFile(
  file: File,
  persist: boolean = true
): Promise<PcapIngestionResponse> {
  const formData = new FormData()
  formData.append('file', file)
  formData.append('persist', String(persist))

  const response = await fetch(`${API_BASE_URL}/api/v1/ingest/pcap`, {
    method: 'POST',
    body: formData,
  })
  if (!response.ok) {
    const errorData = await response.json().catch(() => ({}))
    throw new Error(errorData.detail || `Failed to upload and ingest PCAP (${response.status})`)
  }
  return response.json()
}
