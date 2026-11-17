# PHASE 8 TELEMETRY UX & STATE MACHINE REPORT

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Deliverable:** Telemetry User Experience, Mode Switching & State Machine Audit  
**Date:** November 15, 2026  
**Scope:** AWS VPC Flow Logs Dashboard (`AwsVpcView.tsx`), Mode Switcher, Telemetry Lifecycle  

---

## 1. Executive Summary

The AWS Telemetry interface previously suffered from ambiguous UI transitions:
1. When switching between "Sandbox (Simulated)" and "Live AWS Read-Only", a toast notification would appear, but the dashboard state did not visibly re-render or reflect the live AWS context.
2. If CloudWatch returned 0 events for a given time window, the UI would remain silent or show stale data, leading users to believe the operation had hung or failed.
3. Errors during STS assume-role or invalid log group specifications lacked structured feedback.

This report documents the overhauled state machine, explicit status indicators, and mode transition safeguards implemented in `src/components/AwsVpcView.tsx`.

---

## 2. Discrete Telemetry State Machine

The telemetry ingestion workflow is now managed through an explicit finite state machine with 5 discrete visual states:

```
[IDLE / READY]
      |
      v (Trigger Fetch / Poll)
[FETCHING_TELEMETRY] (Shows spinner & target log group)
      |
      +---> [NO_NEW_EVENTS] (Clear badge: "Connected. 0 new events in current window")
      |
      +---> [EVENTS_RETRIEVED] (Shows count, evaluation cards, flow table, policy actions)
      |
      +---> [INGESTION_FAILED] (Shows error banner: STS credentials, permission, or network failure)
      |
      +---> [PARSE_FAILED] (Shows corrupt record warning with raw line diagnostics)
```

### State Definitions & UI Representation:

| State | UI Representation | User Guidance |
|:---|:---|:---|
| **CONNECTED / READY** | Green pulse pill: `AWS Read-Only Active` | System is ready to query CloudWatch or S3. |
| **NO_NEW_EVENTS** | Yellow alert banner: `0 events in time window` | Informs user that VPC is idle; suggests widening query window. |
| **EVENTS_RETRIEVED** | Blue success card with record metrics | Displays total discovered, evaluated, benign vs threat breakdown. |
| **INGESTION_FAILED** | Red error card with copyable diagnostic trace | Points to IAM assume-role permission or CloudWatch log group mismatch. |
| **PARSE_FAILED** | Amber warning card showing dropped record count | Details unsupported custom flow log format fields. |

---

## 3. Mode Switching Architecture

The interface provides an unequivocal, persistent visual distinction between environments:

1. **Sandbox Mode**:
   - Amber banner: `SANDBOX SIMULATION ACTIVE`.
   - Data source: Synthetic hybrid-lab PCAP and simulated flow fixtures.
   - Allows threat injection testing (`PORT_SCAN`, `BRUTE_FORCE`, `TRAFFIC_SPIKE`).
2. **Live AWS Read-Only Mode**:
   - Blue banner with AWS badge: `LIVE AWS READ-ONLY TELEMETRY`.
   - Account: `698766075180` | Region: `ap-southeast-2` | Role: `SecurityGatewayReadOnlyRole`.
   - Data source: Amazon CloudWatch log group `/aws/vpc/flowlogs/ap-southeast-2-default`.
   - Read-only guard: All mutation/enforcement actions are visibly disabled or tagged `DRY-RUN / AUDIT ONLY`.

---

## 4. UI Testing Status

> [!IMPORTANT]
> **NOT TESTED — MANUAL USER VERIFICATION REQUIRED**  
> In accordance with strict development constraints, no browser automation, Puppeteer, Selenium, or localhost HTTP requests were executed against the running UI. The React component structures, TypeScript typings, state transitions, and unit tests have been fully compiled and validated through Vite build (`tsc -b && vite build`) and backend in-process test fixtures. Live visual verification must be conducted by the user in the browser.

---

## 5. Conclusion

The AWS Telemetry view now provides unambiguous visual feedback, resilient error boundaries, and clear operational state reporting across both simulated and live AWS operating modes.
