import React, { useState, useEffect } from 'react'
import { authService } from '../services/auth'
import type { AuthUser, LoginPayload, SignUpPayload, UserRole } from '../types'

interface AuthViewProps {
  onAuthSuccess: (user: AuthUser) => void
}

export const AuthView: React.FC<AuthViewProps> = ({ onAuthSuccess }) => {
  const [activeTab, setActiveTab] = useState<'signin' | 'signup'>('signin')
  const [loading, setLoading] = useState(false)
  const [errorMessage, setErrorMessage] = useState<string | null>(null)
  const [successMessage, setSuccessMessage] = useState<string | null>(null)

  // Sign In Form State
  const [loginEmail, setLoginEmail] = useState('')
  const [loginPassword, setLoginPassword] = useState('')
  const [showLoginPassword, setShowLoginPassword] = useState(false)

  // Sign Up Form State
  const [signupFullName, setSignupFullName] = useState('')
  const [signupEmail, setSignupEmail] = useState('')
  const [signupPassword, setSignupPassword] = useState('')
  const [signupConfirmPassword, setSignupConfirmPassword] = useState('')
  const [signupRole, setSignupRole] = useState<UserRole>('ANALYST')
  const [showSignupPassword, setShowSignupPassword] = useState(false)

  // Google OAuth Status
  const [googleOAuthEnabled, setGoogleOAuthEnabled] = useState(false)
  const [googleLoading, setGoogleLoading] = useState(false)

  // Check Google OAuth status on mount
  useEffect(() => {
    let mounted = true
    authService
      .getGoogleAuthUrl()
      .then((res) => {
        if (mounted && res.enabled && res.client_id_configured) {
          setGoogleOAuthEnabled(true)
        }
      })
      .catch(() => {
        // OAuth unavailable or disabled; local auth remains 100% functional
      })
    return () => {
      mounted = false
    }
  }, [])

  // Check URL parameters for OAuth callbacks (e.g. ?code=... or ?auth_error=...)
  useEffect(() => {
    const params = new URLSearchParams(window.location.search)
    const code = params.get('code')
    const state = params.get('state')
    const authError = params.get('auth_error')

    if (authError) {
      setErrorMessage(decodeURIComponent(authError))
      window.history.replaceState({}, document.title, window.location.pathname)
    } else if (code) {
      setGoogleLoading(true)
      authService
        .handleGoogleCallback(code, state || undefined)
        .then((res) => {
          window.history.replaceState({}, document.title, window.location.pathname)
          onAuthSuccess(res.user)
        })
        .catch((err) => {
          setErrorMessage(err.message || 'Google OAuth authentication failed.')
          setGoogleLoading(false)
          window.history.replaceState({}, document.title, window.location.pathname)
        })
    }
  }, [onAuthSuccess])

  const handleLoginSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setErrorMessage(null)
    setSuccessMessage(null)

    if (!loginEmail.trim() || !loginPassword) {
      setErrorMessage('Please provide both email address and password.')
      return
    }

    setLoading(true)
    try {
      const payload: LoginPayload = {
        email: loginEmail.trim().toLowerCase(),
        password: loginPassword,
      }
      const response = await authService.login(payload)
      onAuthSuccess(response.user)
    } catch (err: any) {
      setErrorMessage(err.message || 'Authentication failed. Please verify your credentials.')
    } finally {
      setLoading(false)
    }
  }

  const handleSignUpSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setErrorMessage(null)
    setSuccessMessage(null)

    if (!signupFullName.trim()) {
      setErrorMessage('Please enter your full name.')
      return
    }
    if (!signupEmail.trim() || !signupEmail.includes('@')) {
      setErrorMessage('Please enter a valid email address.')
      return
    }
    if (signupPassword.length < 8) {
      setErrorMessage('Password must be at least 8 characters long.')
      return
    }
    if (signupPassword !== signupConfirmPassword) {
      setErrorMessage('Passwords do not match. Please re-enter matching passwords.')
      return
    }

    setLoading(true)
    try {
      const payload: SignUpPayload = {
        email: signupEmail.trim().toLowerCase(),
        password: signupPassword,
        confirm_password: signupConfirmPassword,
        full_name: signupFullName.trim(),
        role: signupRole,
      }
      const response = await authService.signup(payload)
      setSuccessMessage('Account created successfully! Authenticating...')
      setTimeout(() => {
        onAuthSuccess(response.user)
      }, 600)
    } catch (err: any) {
      setErrorMessage(err.message || 'Registration failed. Email might already be registered.')
    } finally {
      setLoading(false)
    }
  }

  const handleGoogleOAuthClick = async () => {
    setErrorMessage(null)
    setGoogleLoading(true)
    try {
      const res = await authService.getGoogleAuthUrl()
      if (res.authorization_url) {
        window.location.href = res.authorization_url
      } else {
        setErrorMessage(
          'Google OAuth is not configured in backend environment (GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET). Local email/password authentication is active.'
        )
        setGoogleLoading(false)
      }
    } catch (err: any) {
      setErrorMessage(err.message || 'Failed to initiate Google OAuth.')
      setGoogleLoading(false)
    }
  }

  const handleQuickAdminFill = () => {
    setLoginEmail('admin@gateway.local')
    setLoginPassword('AdminSecOps2026!')
    setErrorMessage(null)
    setSuccessMessage('Loaded Default Admin Bootstrap Credentials')
  }

  return (
    <div className="auth-container">
      {/* Background Cyber Glow & Grid Elements */}
      <div className="auth-background-glow" />
      <div className="auth-grid-overlay" />

      <div className="auth-card-wrapper">
        {/* Header Branding */}
        <div className="auth-header">
          <div className="auth-logo-badge">
            <span className="auth-shield-icon">🛡️</span>
            <span className="auth-live-pulse" />
          </div>
          <h1 className="auth-title">Adaptive AI Security Gateway</h1>
          <p className="auth-subtitle">Hybrid Cloud Threat Intelligence & Policy Enforcement Platform</p>
          <div className="auth-status-chip">
            <span className="auth-status-dot" />
            <span>Zero-Trust Enterprise Access Control</span>
          </div>
        </div>

        {/* Auth Mode Tabs */}
        <div className="auth-tabs" role="tablist">
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === 'signin'}
            className={`auth-tab-btn ${activeTab === 'signin' ? 'active' : ''}`}
            onClick={() => {
              setActiveTab('signin')
              setErrorMessage(null)
              setSuccessMessage(null)
            }}
          >
            Sign In
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={activeTab === 'signup'}
            className={`auth-tab-btn ${activeTab === 'signup' ? 'active' : ''}`}
            onClick={() => {
              setActiveTab('signup')
              setErrorMessage(null)
              setSuccessMessage(null)
            }}
          >
            Create Account
          </button>
        </div>

        {/* Notifications & Feedback */}
        {errorMessage && (
          <div className="auth-alert error" role="alert">
            <span className="auth-alert-icon">⚠️</span>
            <div className="auth-alert-text">{errorMessage}</div>
            <button
              type="button"
              className="auth-alert-close"
              onClick={() => setErrorMessage(null)}
              aria-label="Dismiss error"
            >
              ×
            </button>
          </div>
        )}

        {successMessage && (
          <div className="auth-alert success" role="alert">
            <span className="auth-alert-icon">✅</span>
            <div className="auth-alert-text">{successMessage}</div>
          </div>
        )}

        {/* SIGN IN VIEW */}
        {activeTab === 'signin' && (
          <form className="auth-form" onSubmit={handleLoginSubmit} noValidate>
            <div className="auth-field">
              <label htmlFor="login-email">Corporate / Operator Email</label>
              <div className="auth-input-wrapper">
                <span className="auth-input-icon">✉️</span>
                <input
                  id="login-email"
                  type="email"
                  placeholder="analyst@enterprise.internal"
                  value={loginEmail}
                  onChange={(e) => setLoginEmail(e.target.value)}
                  disabled={loading || googleLoading}
                  required
                  autoComplete="email"
                />
              </div>
            </div>

            <div className="auth-field">
              <div className="auth-field-header">
                <label htmlFor="login-password">Password</label>
              </div>
              <div className="auth-input-wrapper">
                <span className="auth-input-icon">🔒</span>
                <input
                  id="login-password"
                  type={showLoginPassword ? 'text' : 'password'}
                  placeholder="••••••••••••"
                  value={loginPassword}
                  onChange={(e) => setLoginPassword(e.target.value)}
                  disabled={loading || googleLoading}
                  required
                  autoComplete="current-password"
                />
                <button
                  type="button"
                  className="auth-pwd-toggle"
                  onClick={() => setShowLoginPassword(!showLoginPassword)}
                  title={showLoginPassword ? 'Hide password' : 'Show password'}
                  tabIndex={-1}
                >
                  {showLoginPassword ? '👁️' : '👁️‍🗨️'}
                </button>
              </div>
            </div>

            <button
              type="submit"
              className="auth-btn primary"
              disabled={loading || googleLoading}
            >
              {loading ? (
                <span className="auth-spinner-label">
                  <span className="auth-spinner" /> Authenticating...
                </span>
              ) : (
                'Sign In to Console'
              )}
            </button>

            {/* Quick Admin Access Preset */}
            <div className="auth-quick-admin">
              <button
                type="button"
                className="auth-btn outline admin-quick-btn"
                onClick={handleQuickAdminFill}
                disabled={loading || googleLoading}
                title="Populates initial bootstrap administrator credentials for rapid testing"
              >
                <span>👑 Quick Admin Access Preset</span>
                <small>(admin@gateway.local)</small>
              </button>
            </div>

            <div className="auth-divider">
              <span>OR CONTINUE WITH</span>
            </div>

            {/* Google OAuth Button */}
            <button
              type="button"
              className={`auth-btn google-btn ${!googleOAuthEnabled ? 'oauth-disabled' : ''}`}
              onClick={handleGoogleOAuthClick}
              disabled={googleLoading || loading}
              title={
                googleOAuthEnabled
                  ? 'Sign in using Google Workspace / OAuth 2.0'
                  : 'Google OAuth not configured in backend .env (Local authentication active)'
              }
            >
              <svg className="google-icon" viewBox="0 0 24 24" width="18" height="18">
                <path
                  fill="#4285F4"
                  d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"
                />
                <path
                  fill="#34A853"
                  d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"
                />
                <path
                  fill="#FBBC05"
                  d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.06H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.94l2.85-2.22.81-.63z"
                />
                <path
                  fill="#EA4335"
                  d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.06l3.66 2.84c.87-2.6 3.3-4.52 6.16-4.52z"
                />
              </svg>
              {googleLoading ? (
                'Connecting to Google...'
              ) : (
                <span>Continue with Google</span>
              )}
            </button>
            {!googleOAuthEnabled && (
              <p className="auth-notice-muted">
                Google OAuth is optional. Ready to use with local email & password authentication.
              </p>
            )}
          </form>
        )}

        {/* SIGN UP VIEW */}
        {activeTab === 'signup' && (
          <form className="auth-form" onSubmit={handleSignUpSubmit} noValidate>
            <div className="auth-field">
              <label htmlFor="signup-name">Full Operator Name</label>
              <div className="auth-input-wrapper">
                <span className="auth-input-icon">👤</span>
                <input
                  id="signup-name"
                  type="text"
                  placeholder="Jane Analyst"
                  value={signupFullName}
                  onChange={(e) => setSignupFullName(e.target.value)}
                  disabled={loading}
                  required
                />
              </div>
            </div>

            <div className="auth-field">
              <label htmlFor="signup-email">Work Email</label>
              <div className="auth-input-wrapper">
                <span className="auth-input-icon">✉️</span>
                <input
                  id="signup-email"
                  type="email"
                  placeholder="jane.analyst@gateway.local"
                  value={signupEmail}
                  onChange={(e) => setSignupEmail(e.target.value)}
                  disabled={loading}
                  required
                  autoComplete="email"
                />
              </div>
            </div>

            <div className="auth-field">
              <label htmlFor="signup-role">Gateway Role</label>
              <div className="auth-input-wrapper">
                <span className="auth-input-icon">🏷️</span>
                <select
                  id="signup-role"
                  value={signupRole}
                  onChange={(e) => setSignupRole(e.target.value as UserRole)}
                  disabled={loading}
                  className="auth-select"
                >
                  <option value="ANALYST">Security Analyst (Telemetry, Incidents, ML Insights)</option>
                  <option value="ADMIN">Gateway Administrator (Full Access, Policy Enforcement, Rules)</option>
                  <option value="USER">Read-Only Observer (Metrics & Logs)</option>
                </select>
              </div>
            </div>

            <div className="auth-field-grid">
              <div className="auth-field">
                <label htmlFor="signup-password">Password (min 8 chars)</label>
                <div className="auth-input-wrapper">
                  <span className="auth-input-icon">🔒</span>
                  <input
                    id="signup-password"
                    type={showSignupPassword ? 'text' : 'password'}
                    placeholder="••••••••••••"
                    value={signupPassword}
                    onChange={(e) => setSignupPassword(e.target.value)}
                    disabled={loading}
                    required
                    autoComplete="new-password"
                  />
                  <button
                    type="button"
                    className="auth-pwd-toggle"
                    onClick={() => setShowSignupPassword(!showSignupPassword)}
                    tabIndex={-1}
                  >
                    {showSignupPassword ? '👁️' : '👁️‍🗨️'}
                  </button>
                </div>
              </div>

              <div className="auth-field">
                <label htmlFor="signup-confirm-pwd">Confirm Password</label>
                <div className="auth-input-wrapper">
                  <span className="auth-input-icon">🔒</span>
                  <input
                    id="signup-confirm-pwd"
                    type={showSignupPassword ? 'text' : 'password'}
                    placeholder="••••••••••••"
                    value={signupConfirmPassword}
                    onChange={(e) => setSignupConfirmPassword(e.target.value)}
                    disabled={loading}
                    required
                    autoComplete="new-password"
                  />
                </div>
              </div>
            </div>

            <button
              type="submit"
              className="auth-btn primary"
              disabled={loading}
            >
              {loading ? (
                <span className="auth-spinner-label">
                  <span className="auth-spinner" /> Registering Account...
                </span>
              ) : (
                'Create Secure Operator Account'
              )}
            </button>
          </form>
        )}

        {/* Footer Security Badges */}
        <div className="auth-footer">
          <div className="auth-footer-badges">
            <span>🔒 Argon2/Bcrypt Hash</span>
            <span>🛡️ JWT Session Protection</span>
            <span>⚡ Zero Telemetry Impact</span>
          </div>
          <p className="auth-footer-note">
            Authoritative ML pipeline and continuous risk scoring remain strictly decoupled from application access tokens.
          </p>
        </div>
      </div>
    </div>
  )
}
