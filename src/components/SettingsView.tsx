/**
 * Settings & Operator Profile View
 * =================================
 * Manages active operator profile, role authorization (ADMIN, OPERATOR, ANALYST, AUDITOR),
 * password modification, and JWT security credentials.
 */

import React, { useState } from 'react'
import { authService } from '../services/auth'
import type { AuthUser, PasswordChangePayload } from '../types'

interface SettingsViewProps {
  user: AuthUser | null
  onLogout: () => void
}

export const SettingsView: React.FC<SettingsViewProps> = ({ user, onLogout }) => {
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [statusMessage, setStatusMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null)

  const handlePasswordChange = async (e: React.FormEvent) => {
    e.preventDefault()
    setStatusMessage(null)

    if (!currentPassword) {
      setStatusMessage({ type: 'error', text: 'Please enter your current password.' })
      return
    }
    if (newPassword.length < 8) {
      setStatusMessage({ type: 'error', text: 'New password must be at least 8 characters long.' })
      return
    }
    if (newPassword !== confirmPassword) {
      setStatusMessage({ type: 'error', text: 'New passwords do not match.' })
      return
    }

    setLoading(true)
    try {
      const payload: PasswordChangePayload = {
        current_password: currentPassword,
        new_password: newPassword,
      }
      await authService.changePassword(payload)
      setStatusMessage({
        type: 'success',
        text: 'Password updated successfully. Existing sessions have been securely revoked.',
      })
      setCurrentPassword('')
      setNewPassword('')
      setConfirmPassword('')
    } catch (err: any) {
      setStatusMessage({
        type: 'error',
        text: err.message || 'Password update failed. Please check current password.',
      })
    } finally {
      setLoading(false)
    }
  }

  const getRoleBadgeColor = (role: string = 'ANALYST') => {
    switch (role.toUpperCase()) {
      case 'ADMIN':
        return { bg: 'var(--terracotta-muted)', text: 'var(--terracotta)' }
      case 'OPERATOR':
        return { bg: 'var(--pale-sand-muted)', text: 'var(--pale-sand)' }
      case 'AUDITOR':
        return { bg: 'var(--muted-charcoal)', text: 'var(--muted-cream)' }
      default:
        return { bg: 'var(--olive-green-muted)', text: 'var(--olive-green)' }
    }
  }

  const roleStyle = getRoleBadgeColor(user?.role)

  return (
    <div className="settings-view-container" style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
      <section className="intro">
        <div>
          <h1>⚙️ Settings & Operator Profile</h1>
          <p>
            Review active console operator identity, role permissions, and update authentication credentials.
          </p>
        </div>
        <div>
          <button
            type="button"
            className="btn-secondary"
            onClick={onLogout}
            style={{ borderColor: 'var(--muted-red)', color: 'var(--muted-red)' }}
          >
            Sign Out of Console
          </button>
        </div>
      </section>

      {statusMessage && (
        <div
          className={`auth-alert ${statusMessage.type}`}
          style={{
            background: statusMessage.type === 'success' ? 'var(--olive-green-muted)' : 'var(--muted-red-muted)',
            border: `1px solid ${statusMessage.type === 'success' ? 'var(--olive-green)' : 'var(--muted-red)'}`,
            color: 'var(--warm-cream)',
            padding: '10px 14px',
            borderRadius: 'var(--radius-sm)',
            fontSize: '12px',
          }}
        >
          {statusMessage.type === 'success' ? '✅' : '⚠️'} {statusMessage.text}
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '16px' }}>
        {/* Operator Profile Card */}
        <div className="card" style={{ padding: '16px', background: 'var(--panel)', border: '1px solid var(--line)' }}>
          <h2 style={{ fontSize: '14px', margin: '0 0 14px', color: 'var(--warm-cream)' }}>
            Active Operator Profile
          </h2>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', fontSize: '12px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--line-subtle)', paddingBottom: '8px' }}>
              <span style={{ color: 'var(--muted-cream)' }}>Full Name:</span>
              <b style={{ color: 'var(--warm-cream)' }}>{user?.full_name || 'Administrator'}</b>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--line-subtle)', paddingBottom: '8px' }}>
              <span style={{ color: 'var(--muted-cream)' }}>Email Address:</span>
              <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--warm-cream)' }}>
                {user?.email || 'test10@gmail.com'}
              </span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--line-subtle)', paddingBottom: '8px' }}>
              <span style={{ color: 'var(--muted-cream)' }}>Access Role (RBAC):</span>
              <span
                style={{
                  background: roleStyle.bg,
                  color: roleStyle.text,
                  padding: '2px 8px',
                  borderRadius: 'var(--radius-xs)',
                  fontWeight: 600,
                  fontSize: '11px',
                  fontFamily: 'var(--font-mono)',
                }}
              >
                {user?.role || 'ADMIN'}
              </span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--line-subtle)', paddingBottom: '8px' }}>
              <span style={{ color: 'var(--muted-cream)' }}>Auth Provider:</span>
              <span style={{ color: 'var(--warm-cream)' }}>{user?.auth_provider || 'LOCAL'}</span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <span style={{ color: 'var(--muted-cream)' }}>Operator ID:</span>
              <small style={{ fontFamily: 'var(--font-mono)', color: 'var(--muted)' }}>
                {user?.id || '2946f1e8-c44c-451d-86f4-2db121f97085'}
              </small>
            </div>
          </div>
        </div>

        {/* Change Password Card */}
        <div className="card" style={{ padding: '16px', background: 'var(--panel)', border: '1px solid var(--line)' }}>
          <h2 style={{ fontSize: '14px', margin: '0 0 14px', color: 'var(--warm-cream)' }}>
            Update Operator Password
          </h2>

          <form onSubmit={handlePasswordChange} style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
            <div className="flow-field">
              <label style={{ fontSize: '11px', color: 'var(--muted-cream)' }}>Current Password</label>
              <input
                type="password"
                className="input"
                placeholder="••••••••••••"
                value={currentPassword}
                onChange={(e) => setCurrentPassword(e.target.value)}
                disabled={loading}
                required
              />
            </div>

            <div className="flow-field">
              <label style={{ fontSize: '11px', color: 'var(--muted-cream)' }}>New Password (min 8 chars)</label>
              <input
                type="password"
                className="input"
                placeholder="••••••••••••"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                disabled={loading}
                required
              />
            </div>

            <div className="flow-field">
              <label style={{ fontSize: '11px', color: 'var(--muted-cream)' }}>Confirm New Password</label>
              <input
                type="password"
                className="input"
                placeholder="••••••••••••"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                disabled={loading}
                required
              />
            </div>

            <button
              type="submit"
              className="primary"
              disabled={loading || !currentPassword || !newPassword}
              style={{ marginTop: '4px', padding: '8px 12px', fontSize: '12px' }}
            >
              {loading ? 'Updating Password...' : 'Save New Password'}
            </button>
          </form>
        </div>
      </div>
    </div>
  )
}
