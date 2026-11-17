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
  timeoutMs: number = 180000,
  onProgress?: (progress: { loaded: number; total: number; percent: number }) => void
): Promise<PcapIngestionResponse> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest()
    const url = getApiUrl('v1/ingest/pcap')
    xhr.open('POST', url)
    xhr.timeout = timeoutMs

    try {
      const rawTokens = localStorage.getItem('hgs_auth_tokens')
      if (rawTokens) {
        const parsed = JSON.parse(rawTokens)
        if (parsed?.access_token) {
          xhr.setRequestHeader('Authorization', `Bearer ${parsed.access_token}`)
        }
      }
    } catch {
      // ignore
    }

    if (xhr.upload && onProgress) {
      xhr.upload.onprogress = (e) => {
        if (e.lengthComputable && e.total > 0) {
          const percent = Math.min(100, Math.round((e.loaded / e.total) * 100))
          onProgress({ loaded: e.loaded, total: e.total, percent })
        }
      }
    }

    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) {
        try {
          const data = JSON.parse(xhr.responseText)
          resolve(data as PcapIngestionResponse)
        } catch (jsonErr: any) {
          reject(new Error(`Failed to parse server response as JSON: ${jsonErr.message}`))
        }
      } else {
        let detail = `Failed to upload and ingest PCAP (HTTP ${xhr.status})`
        try {
          const errData = JSON.parse(xhr.responseText)
          if (errData.detail) detail = errData.detail
        } catch {
          // ignore
        }
        reject(new Error(detail))
      }
    }

    xhr.onerror = () => {
      reject(new Error('Network error or connection refusal during PCAP upload.'))
    }

    xhr.ontimeout = () => {
      reject(new Error(`PCAP upload and ingestion timed out after ${Math.round(timeoutMs / 1000)}s: the capture may be very large or server is busy.`))
    }

    const formData = new FormData()
    formData.append('file', file)
    formData.append('persist', String(persist))
    xhr.send(formData)
  })
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
