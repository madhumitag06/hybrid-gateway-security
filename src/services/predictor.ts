/**
 * ML Predictor API Service Client
 */

import { request } from './api'
import type { BackendHealth, FlowPredictionRequest, FlowPredictionResponse } from '../types'

export async function predictFlow(
  flow: FlowPredictionRequest,
  signal?: AbortSignal
): Promise<FlowPredictionResponse> {
  return request<FlowPredictionResponse>('v1/predict', {
    method: 'POST',
    body: JSON.stringify(flow),
    signal,
  })
}

export async function getPresets(
  signal?: AbortSignal
): Promise<Record<string, FlowPredictionRequest>> {
  return request<Record<string, FlowPredictionRequest>>('v1/predict/presets', {
    method: 'GET',
    signal,
  })
}

export async function getBackendHealth(
  signal?: AbortSignal
): Promise<BackendHealth> {
  return request<BackendHealth>('health', {
    method: 'GET',
    signal,
  })
}
