# AWS Live Mode Switching & State Persistence Fix Report

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**UI Components:** `src/App.tsx`, `src/components/AwsVpcView.tsx`  
**Execution Modes:** `SANDBOX`, `LOCAL`, `AWS_FIXTURE`, `LIVE_AWS`  
**Date:** November 15, 2026  
**Status:** FULLY IMPLEMENTED & VERIFIED  

---

## 1. Executive Summary

This report certifies the comprehensive resolution of the mode switching and state persistence defect that previously prevented the gateway console from visibly transitioning into **Live AWS Read-Only** mode.

The solution establishes a single consistent, mutually exclusive environment state (`SANDBOX`, `LOCAL`, `AWS_FIXTURE`, `LIVE_AWS`), binds the global navigation header and the `AwsVpcView` console through bidirectional synchronization, ensures persistent state retention via `sessionStorage`, removes synthetic disclaimer banners during live operations, and enforces that connection states reflect authentic backend health checks rather than fabricated static toasts.

---

## 2. Problem Diagnosis & Defect Profile

### 2.1 The Ghost Mode Defect
In prior builds, clicking `"Live AWS Read-Only"` in the top environment dropdown menu produced a toast notification (`"Live AWS CloudWatch connected in Read-Only mode."`), but:
1. `currentEnv` remained trapped at `'SANDBOX'`.
2. The top button continued to display `"🧪 Sandbox Lab ⌄"`.
3. The active navigation tab remained unchanged.
4. `AwsVpcView.tsx` was rendered with zero props, unaware of the operator's mode selection.
5. The view unconditionally presented the synthetic telemetry warning notice:
   > *"Simulated Cloud Telemetry Notice: VPC flow logs shown here represent synthetic telemetry generated in the virtual hybrid lab..."*
6. On page refresh, `getEnforcementConfig()` unconditionally reset `currentEnv` to the backend adapter mode (`'SANDBOX'` or `'DRY_RUN'`).

---

## 3. The 4-State Architectural Solution

### 3.1 First-Class Environment Enum (`src/App.tsx`)
The gateway establishes four distinct execution environments:
- **`SANDBOX`:** Virtual hybrid lab isolation with in-memory quarantine filtering and automated TTL.
- **`LOCAL`:** Local development dry-run simulation with zero host firewall or network interface alterations.
- **`AWS_FIXTURE`:** Offline deterministic CloudWatch flow log fixtures (`benign_web_browsing.log`, `brute_force_ssh.log`, etc.).
- **`LIVE_AWS`:** Live, read-only streaming ingestion from Amazon CloudWatch Logs group `/aws/vpc/flowlogs/ap-southeast-2-default` in AWS Account `698766075180`.

### 3.2 Persistent State Lifecycle
`src/App.tsx` initializes `currentEnv` from `sessionStorage` with safe fallback:

```tsx
const [currentEnv, setCurrentEnv] = useState<string>(() => {
  return sessionStorage.getItem('hgs_current_env') || 'SANDBOX'
})
```

When `getEnforcementConfig()` resolves during dashboard initialization, it respects any active operator environment override:

```tsx
getEnforcementConfig()
  .then((cfg) => {
    setEnforcementConfig(cfg)
    const savedEnv = sessionStorage.getItem('hgs_current_env')
    if (!savedEnv) {
      setCurrentEnv(cfg.active_mode === 'DRY_RUN' ? 'LOCAL' : cfg.active_mode)
    }
  })
  .catch(() => {})
```

### 3.3 Dynamic Mode Selector & Navigation Routing
The top menu dynamically synchronizes with `currentEnv`:

```tsx
<button className="select" onClick={toggleEnvMenu} title="Execution Environment Mode">
  {currentEnv === 'SANDBOX'
    ? '🧪 Sandbox Lab ⌄'
    : currentEnv === 'LOCAL' || currentEnv === 'DRY_RUN'
    ? '💻 Local Dev ⌄'
    : currentEnv === 'AWS_FIXTURE'
    ? '☁ AWS Fixture ⌄'
    : currentEnv === 'LIVE_AWS'
    ? '☁ Live AWS (RO) ⌄'
    : '🧪 Sandbox Lab ⌄'}
</button>
```

When an operator selects an environment:
1. `handleSelectEnv(env)` updates React state and saves to `sessionStorage.setItem('hgs_current_env', env)`.
2. If `env === 'LIVE_AWS'` or `'AWS_FIXTURE'`, it immediately switches `setActiveNav('AWS VPC Logs')`.
3. It passes `currentEnv` and `onSelectEnv={handleSelectEnv}` as props to `<AwsVpcView currentEnv={currentEnv} onSelectEnv={handleSelectEnv} />`.

---

## 4. UI Transformation in `AwsVpcView.tsx`

### 4.1 Conditional Header & Transparency Gating
- **When in `LIVE_AWS` Mode:**
  - The synthetic disclaimer banner is **hidden**.
  - Replaced by the **Live AWS CloudWatch Telemetry Header**:
    - Account ID: `698766075180`
    - Region: `ap-southeast-2`
    - VPC ID: `vpc-0fc9db63fecb34fad`
    - Flow Log ID: `fl-0d236b31b1fd0d13e`
    - Log Group: `/aws/vpc/flowlogs/ap-southeast-2-default`
    - Assumed IAM Role: `SecurityGatewayReadOnlyRole`
    - Safety Status: `STRICTLY READ-ONLY (Zero mutating permissions)`
- **When in `FIXTURES` or `RAW` Mode:**
  - The synthetic disclaimer notice is **cleanly restored**, informing the operator that data is generated within the deterministic offline lab.

### 4.2 Genuine, Non-Fabricated Telemetry Status
`telemetryStatus` initializes to `'CONNECTING'` and performs an authentic backend check via `cloudService.getAwsTelemetryStatus()`:
- If the backend returns valid connection telemetry $\to$ status is set to `● CONNECTED`.
- If the backend reports an authentication or connectivity failure $\to$ status is set to `● ERROR`, and the diagnostic error message is rendered in a dedicated alert box. Success is **never** fabricated.
- When polling returns zero new records $\to$ status is set to `● NO_NEW_EVENTS`.

### 4.3 Bidirectional View & Top Selector Synchronization
`AwsVpcView` provides tab controls:
- `☁️ Live AWS Read-Only`
- `📁 Benchmark Fixtures`
- `📝 Raw Log Input`

Clicking any tab invokes `onSelectEnv?.(newEnv)`, which instantly updates the top navigation selector in `App.tsx` and saves to `sessionStorage`, ensuring complete lockstep alignment across the application.
