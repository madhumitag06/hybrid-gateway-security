/**
 * Authentication Service
 * ======================
 * Manages JWT tokens, authentication state, login, signup, logout,
 * password changes, and Google OAuth 2.0 flow for the Security Gateway.
 */

import type {
  AuthResponse,
  AuthTokens,
  AuthUser,
  GoogleOAuthInitResponse,
  LoginPayload,
  PasswordChangePayload,
  SignUpPayload,
} from '../types'
import { getApiUrl } from './api'

const TOKEN_STORAGE_KEY = 'hgs_auth_tokens'
const USER_STORAGE_KEY = 'hgs_auth_user'

class AuthService {
  private tokens: AuthTokens | null = null
  private user: AuthUser | null = null
  private listeners: Array<(user: AuthUser | null) => void> = []

  constructor() {
    this.loadStoredSession()
  }

  /**
   * Load stored authentication credentials from localStorage if valid.
   */
  private loadStoredSession(): void {
    try {
      const storedTokens = localStorage.getItem(TOKEN_STORAGE_KEY)
      const storedUser = localStorage.getItem(USER_STORAGE_KEY)
      if (storedTokens && storedUser) {
        this.tokens = JSON.parse(storedTokens)
        this.user = JSON.parse(storedUser)
      }
    } catch (e) {
      console.warn('Failed to parse stored auth session:', e)
      this.clearSession()
    }
  }

  /**
   * Persist current session into localStorage and memory.
   */
  private saveSession(tokens: AuthTokens, user: AuthUser): void {
    this.tokens = tokens
    this.user = user
    try {
      localStorage.setItem(TOKEN_STORAGE_KEY, JSON.stringify(tokens))
      localStorage.setItem(USER_STORAGE_KEY, JSON.stringify(user))
    } catch (e) {
      console.error('Failed to save auth session to storage:', e)
    }
    this.notifyListeners()
  }

  /**
   * Clear session state and localStorage.
   */
  public clearSession(): void {
    this.tokens = null
    this.user = null
    try {
      localStorage.removeItem(TOKEN_STORAGE_KEY)
      localStorage.removeItem(USER_STORAGE_KEY)
    } catch (e) {
      console.error('Failed to clear storage:', e)
    }
    this.notifyListeners()
  }

  /**
   * Get current authenticated user or null.
   */
  public getUser(): AuthUser | null {
    return this.user
  }

  /**
   * Get current valid access token.
   */
  public getAccessToken(): string | null {
    return this.tokens?.access_token || null
  }

  /**
   * Check if user is currently authenticated.
   */
  public isAuthenticated(): boolean {
    return !!this.tokens?.access_token && !!this.user
  }

  /**
   * Check if current user has ADMIN role.
   */
  public isAdmin(): boolean {
    return this.user?.role === 'ADMIN'
  }

  /**
   * Subscribe to authentication state changes.
   */
  public subscribe(callback: (user: AuthUser | null) => void): () => void {
    this.listeners.push(callback)
    callback(this.user)
    return () => {
      this.listeners = this.listeners.filter((cb) => cb !== callback)
    }
  }

  private notifyListeners(): void {
    for (const listener of this.listeners) {
      try {
        listener(this.user)
      } catch (e) {
        console.error('Error in auth listener:', e)
      }
    }
  }

  /**
   * Helper to perform authenticated fetch requests.
   */
  public async fetchWithAuth(url: string, options: RequestInit = {}): Promise<Response> {
    const headers = new Headers(options.headers || {})
    if (this.tokens?.access_token) {
      headers.set('Authorization', `Bearer ${this.tokens.access_token}`)
    }
    if (!headers.has('Content-Type') && !(options.body instanceof FormData)) {
      headers.set('Content-Type', 'application/json')
    }

    let response = await fetch(url, { ...options, headers })

    // If 401 Unauthorized, attempt refresh once
    if (response.status === 401 && this.tokens?.refresh_token) {
      const refreshed = await this.refreshToken()
      if (refreshed) {
        headers.set('Authorization', `Bearer ${this.tokens!.access_token}`)
        response = await fetch(url, { ...options, headers })
      } else {
        this.clearSession()
      }
    }

    return response
  }

  /**
   * Helper to normalize token response from backend.
   */
  private extractSessionFromResponse(data: any): { tokens: AuthTokens; user: AuthUser } {
    const tokens: AuthTokens = data.tokens
      ? data.tokens
      : {
          access_token: data.access_token,
          refresh_token: data.refresh_token,
          token_type: data.token_type || 'bearer',
          expires_in_seconds: data.expires_in || 1800,
        }
    const user: AuthUser = data.user
    return { tokens, user }
  }

  /**
   * Sign up a new user account.
   */
  public async signup(payload: SignUpPayload): Promise<AuthResponse> {
    const url = getApiUrl('/auth/signup')
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    })

    const data = await response.json()
    if (!response.ok) {
      throw new Error(data.detail || 'Sign up failed. Please check your credentials.')
    }

    const { tokens, user } = this.extractSessionFromResponse(data)
    this.saveSession(tokens, user)
    return { tokens, user, message: data.message }
  }

  /**
   * Authenticate with email and password.
   */
  public async login(payload: LoginPayload): Promise<AuthResponse> {
    const url = getApiUrl('/auth/login')
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    })

    const data = await response.json()
    if (!response.ok) {
      throw new Error(data.detail || 'Invalid email or password.')
    }

    const { tokens, user } = this.extractSessionFromResponse(data)
    this.saveSession(tokens, user)
    return { tokens, user, message: data.message }
  }

  /**
   * Attempt token refresh using refresh_token.
   */
  public async refreshToken(): Promise<boolean> {
    if (!this.tokens?.refresh_token) {
      return false
    }

    try {
      const url = getApiUrl('/auth/refresh')
      const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: this.tokens.refresh_token }),
      })

      if (!response.ok) {
        this.clearSession()
        return false
      }

      const data = await response.json()
      const { tokens, user } = this.extractSessionFromResponse(data)
      this.saveSession(tokens, user)
      return true
    } catch (e) {
      console.warn('Failed to refresh auth token:', e)
      this.clearSession()
      return false
    }
  }

  /**
   * Fetch latest profile data for current user.
   */
  public async getMe(): Promise<AuthUser> {
    const url = getApiUrl('/auth/me')
    const response = await this.fetchWithAuth(url)
    const data = await response.json()

    if (!response.ok) {
      this.clearSession()
      throw new Error(data.detail || 'Session expired. Please log in again.')
    }

    const user = data as AuthUser
    if (this.tokens) {
      this.saveSession(this.tokens, user)
    }
    return user
  }

  /**
   * Change user password.
   */
  public async changePassword(payload: PasswordChangePayload): Promise<{ message: string }> {
    const url = getApiUrl('/auth/password/change')
    const response = await this.fetchWithAuth(url, {
      method: 'POST',
      body: JSON.stringify(payload),
    })

    const data = await response.json()
    if (!response.ok) {
      throw new Error(data.detail || 'Failed to update password.')
    }

    return data
  }

  /**
   * Logout user, revoke refresh token on backend, and clear local state.
   */
  public async logout(): Promise<void> {
    const currentRefreshToken = this.tokens?.refresh_token
    const currentAccessToken = this.tokens?.access_token

    // Attempt backend token revocation
    if (currentRefreshToken || currentAccessToken) {
      try {
        const url = getApiUrl('/auth/logout')
        await fetch(url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            ...(currentAccessToken ? { Authorization: `Bearer ${currentAccessToken}` } : {}),
          },
          body: JSON.stringify({ refresh_token: currentRefreshToken || '' }),
        })
      } catch (e) {
        console.warn('Logout notification to backend failed:', e)
      }
    }

    this.clearSession()
  }

  /**
   * Initialize Google OAuth flow.
   */
  public async getGoogleAuthUrl(): Promise<GoogleOAuthInitResponse> {
    const url = getApiUrl('/auth/google/login')
    const response = await fetch(url)
    const data = await response.json()
    return data as GoogleOAuthInitResponse
  }

  /**
   * Complete Google OAuth callback with auth code.
   */
  public async handleGoogleCallback(code: string, state?: string): Promise<AuthResponse> {
    const params = new URLSearchParams({ code })
    if (state) params.set('state', state)
    const url = getApiUrl(`/auth/google/callback?${params.toString()}`)
    const response = await fetch(url)
    const data = await response.json()

    if (!response.ok) {
      throw new Error(data.detail || 'Google authentication failed.')
    }

    const { tokens, user } = this.extractSessionFromResponse(data)
    this.saveSession(tokens, user)
    return { tokens, user, message: data.message }
  }

  /**
   * Admin-only: list all registered accounts.
   */
  public async listAdminUsers(): Promise<{ users: AuthUser[]; total: number }> {
    const url = getApiUrl('/auth/admin/users')
    const response = await this.fetchWithAuth(url)
    const data = await response.json()

    if (!response.ok) {
      throw new Error(data.detail || 'Admin access required.')
    }

    return data
  }
}

export const authService = new AuthService()
