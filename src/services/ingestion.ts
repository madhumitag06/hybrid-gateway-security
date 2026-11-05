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
  persist: boolean = true,
  timeoutMs: number = 60000
): Promise<PcapIngestionResponse> {
  const controller = new AbortController()
  const timeoutId = setTimeout(() => {
    controller.abort()
  }, timeoutMs)

  try {
    return await request<PcapIngestionResponse>(
      `v1/ingest/samples/${encodeURIComponent(filename)}?persist=${persist}`,
      {
        method: 'POST',
        signal: controller.signal,
      }
    )
  } catch (err: any) {
    if (err?.name === 'AbortError' || controller.signal.aborted) {
      throw new Error(`Sample PCAP ingestion timed out after ${Math.round(timeoutMs / 1000)}s.`)
    }
    throw err
  } finally {
    clearTimeout(timeoutId)
  }
}

export async function uploadPcapFile(
  file: File,
  persist: boolean = true,
  timeoutMs: number = 60000
): Promise<PcapIngestionResponse> {
  const formData = new FormData()
  formData.append('file', file)
  formData.append('persist', String(persist))

  const controller = new AbortController()
  const timeoutId = setTimeout(() => {
    controller.abort()
  }, timeoutMs)

  try {
    const url = getApiUrl('v1/ingest/pcap')
    const response = await fetch(url, {
      method: 'POST',
      body: formData,
      signal: controller.signal,
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

    return await response.json()
  } catch (err: any) {
    if (err?.name === 'AbortError' || controller.signal.aborted) {
      throw new Error(`PCAP upload and ingestion timed out after ${Math.round(timeoutMs / 1000)}s: the capture may be very large or the server is busy.`)
    }
    throw err
  } finally {
    clearTimeout(timeoutId)
  }
}

export interface IngestionHistoryResponse {
  total: number
  page: number
  page_size: number
  ingestions: any[]
}

export async function getLatestIngestion(): Promise<{ status: string; ingestion: any }> {
  return request<{ status: string; ingestion: any }>('v1/ingest/latest')
}

export async function getIngestionHistory(page: number = 1, pageSize: number = 10): Promise<IngestionHistoryResponse> {
  return request<IngestionHistoryResponse>(`v1/ingest/history?page=${page}&page_size=${pageSize}`)
}

export async function getIngestionDetails(ingestionId: string): Promise<any> {
  return request<any>(`v1/ingest/history/${encodeURIComponent(ingestionId)}`)
}
