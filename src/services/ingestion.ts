/**
 * PCAP Traffic Ingestion API Client Service
 * =========================================
 * Manages PCAP file streaming, sample fixture execution, and upload parsing.
 */

import { getApiUrl, request } from './api'
import type {
  IngestionStatusResponse,
  PcapIngestionResponse,
  SamplePcapInfo,
} from '../types'

export async function getIngestionStatus(): Promise<IngestionStatusResponse> {
  return request<IngestionStatusResponse>('v1/ingest/status')
}

export async function listSamplePcaps(): Promise<SamplePcapInfo[]> {
  return request<SamplePcapInfo[]>('v1/ingest/samples')
}

export async function ingestSamplePcap(
  filename: string,
  persist: boolean = true
): Promise<PcapIngestionResponse> {
  return request<PcapIngestionResponse>(
    `v1/ingest/samples/${encodeURIComponent(filename)}?persist=${persist}`,
    {
      method: 'POST',
    }
  )
}

export async function uploadPcapFile(
  file: File,
  persist: boolean = true
): Promise<PcapIngestionResponse> {
  const formData = new FormData()
  formData.append('file', file)
  formData.append('persist', String(persist))

  const url = getApiUrl('v1/ingest/pcap')
  const response = await fetch(url, {
    method: 'POST',
    body: formData,
  })

  if (!response.ok) {
    let errorDetail = `Failed to upload and ingest PCAP (HTTP ${response.status})`
    try {
      const errorData = await response.json()
      if (errorData.detail) errorDetail = errorData.detail
    } catch {
      // ignore
    }
    throw new Error(errorDetail)
  }

  return response.json()
}
