/**
 * Unified API Client for FastAPI Gateway Communication
 * ====================================================
 * Centralizes endpoint routing, environment configuration, error parsing,
 * and content-type verification to prevent HTML/Vite fallback JSON syntax errors.
 */

// Fallback to relative /api or configured environment base URL
const ENV_URL = import.meta.env.VITE_API_URL || import.meta.env.VITE_API_BASE_URL
const API_BASE_URL = ENV_URL ? ENV_URL.replace(/\/$/, '') : 'http://localhost:8000'

export function getApiUrl(endpoint: string): string {
  const cleanEndpoint = endpoint.startsWith('/') ? endpoint : `/${endpoint}`
  
  // If endpoint already starts with /api and API_BASE_URL ends with /api, avoid duplication
  if (API_BASE_URL.endsWith('/api') && cleanEndpoint.startsWith('/api/')) {
    return `${API_BASE_URL.slice(0, -4)}${cleanEndpoint}`
  }
  
  // If endpoint starts with /api and API_BASE_URL is root (e.g. http://localhost:8000)
  if (cleanEndpoint.startsWith('/api')) {
    return `${API_BASE_URL}${cleanEndpoint}`
  }
  
  // Otherwise append /api prefix if not present
  if (API_BASE_URL.endsWith('/api')) {
    return `${API_BASE_URL}${cleanEndpoint}`
  }
  
  return `${API_BASE_URL}/api${cleanEndpoint}`
}

export async function request<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const url = getApiUrl(endpoint)
  
  // Extract stored auth token if present
  let authHeader: Record<string, string> = {}
  try {
    const rawTokens = localStorage.getItem('hgs_auth_tokens')
    if (rawTokens) {
      const parsed = JSON.parse(rawTokens)
      if (parsed?.access_token) {
        authHeader = { Authorization: `Bearer ${parsed.access_token}` }
      }
    }
  } catch {
    // ignore
  }

  let response: Response
  try {
    response = await fetch(url, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        ...authHeader,
        ...options.headers,
      },
    })
  } catch (netErr) {
    throw new Error(`Network error connecting to Gateway API at ${url}: ${String(netErr)}`)
  }

  // Handle non-2xx responses
  if (!response.ok) {
    let errorDetail = `Request failed: HTTP ${response.status} ${response.statusText}`
    try {
      const contentType = response.headers.get('content-type') || ''
      if (contentType.includes('application/json')) {
        const errJson = await response.json()
        if (errJson.detail) {
          errorDetail = typeof errJson.detail === 'string' ? errJson.detail : JSON.stringify(errJson.detail)
        }
      } else {
        const errText = await response.text()
        if (errText && !errText.includes('<!doctype') && !errText.includes('<html')) {
          errorDetail = errText.slice(0, 300)
        }
      }
    } catch {
      // ignore parse failure
    }
    throw new Error(errorDetail)
  }

  // Check content type before parsing json
  const contentType = response.headers.get('content-type') || ''
  if (!contentType.includes('application/json')) {
    const rawText = await response.text()
    if (rawText.includes('<!doctype') || rawText.includes('<html')) {
      throw new Error(`Expected JSON response from ${url}, but received HTML page (HTTP ${response.status}). Verify backend route exists.`)
    }
    try {
      return JSON.parse(rawText) as T
    } catch {
      throw new Error(`Invalid JSON received from ${url}: ${rawText.slice(0, 100)}`)
    }
  }

  return response.json() as Promise<T>
}

export { API_BASE_URL }
