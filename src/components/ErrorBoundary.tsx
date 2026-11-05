import { Component, type ErrorInfo, type ReactNode } from 'react'

interface Props {
  children: ReactNode
  fallbackTitle?: string
  onReset?: () => void
}

interface State {
  hasError: boolean
  error: Error | null
}

export class ErrorBoundary extends Component<Props, State> {
  public state: State = {
    hasError: false,
    error: null,
  }

  public static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error }
  }

  public componentDidCatch(error: Error, errorInfo: ErrorInfo): void {
    console.error('ErrorBoundary caught an unhandled rendering error:', error, errorInfo)
  }

  private handleReset = (): void => {
    this.setState({ hasError: false, error: null })
    if (this.props.onReset) {
      this.props.onReset()
    }
  }

  public render(): ReactNode {
    if (this.state.hasError) {
      return (
        <div
          className="card error-boundary-card"
          style={{
            margin: '32px auto',
            maxWidth: '800px',
            padding: '24px',
            background: 'var(--panel)',
            border: '1px solid var(--muted-red)',
            borderRadius: '8px',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' }}>
            <span style={{ fontSize: '24px' }}>⚠️</span>
            <div>
              <h2 style={{ margin: 0, color: 'var(--warm-cream)', fontSize: '18px' }}>
                {this.props.fallbackTitle || 'Unable to display view component'}
              </h2>
              <small style={{ color: 'var(--muted-cream)' }}>
                A client rendering exception occurred in this view.
              </small>
            </div>
          </div>
          <div
            style={{
              background: 'var(--panel-inset)',
              padding: '12px',
              borderRadius: '4px',
              fontFamily: 'var(--font-mono)',
              fontSize: '12px',
              color: 'var(--terracotta)',
              marginBottom: '16px',
              overflowX: 'auto',
            }}
          >
            {this.state.error?.message || 'Unknown render exception'}
          </div>
          <div style={{ display: 'flex', gap: '12px' }}>
            <button
              className="primary"
              onClick={this.handleReset}
              style={{ padding: '8px 16px', fontSize: '13px' }}
            >
              ↻ Try Reloading Section
            </button>
            <button
              className="select"
              onClick={() => window.location.reload()}
              style={{ padding: '8px 16px', fontSize: '13px' }}
            >
              Full Page Refresh
            </button>
          </div>
        </div>
      )
    }

    return this.props.children
  }
}
