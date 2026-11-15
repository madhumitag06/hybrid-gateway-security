# PHASE 9 REPORT: PORT OWNERSHIP & DOCKER COMPOSE CONFIGURATION

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Deliverable:** Port Allocation, Socket Ownership & Docker Isolation Audit  
**Date:** November 15, 2026  
**Status:** RECONCILED, SAFEGUARDED & VERIFIED  

---

## 1. Executive Summary

This report documents the resolution of host port collisions between Docker Compose hybrid-lab services and host-native developer tools (the Vite development server and the standalone `AdaptiveSecurityGateway.exe`).

By updating service port mappings in `deployment/hybrid-lab/compose.yaml` and `.env` and safely recreating only the presentation and gateway containers, ports `8000`, `5173`, and `5174` are completely free on the Windows host. Docker hybrid-lab containers remain 100% healthy on non-conflicting published ports `8001` and `5175`.

---

## 2. Definitive Port Ownership Matrix

| Port | Service Owner | Protocol / Bind | Purpose |
|:---:|:---|:---:|:---|
| **8000** | **`AdaptiveSecurityGateway.exe`** | IPv4 `127.0.0.1:8000` | Full-Stack Standalone Security Gateway Backend + SPA Root |
| **5174** | **Vite Dev Server (`npm run dev`)** | IPv4 `127.0.0.1:5174` | Daily React Development Frontend (`strictPort: true`) |
| **5173** | *Unallocated / Reserved* | Free | Clean reserve port |
| **8001** | **`hybrid-lab-gateway-api` (Docker)** | `0.0.0.0:8001`, `[::]:8001` | Simulated Hybrid-Lab Control Plane (maps to container `:8000`) |
| **5175** | **`hybrid-lab-frontend` (Docker)** | `0.0.0.0:5175`, `[::]:5175` | Simulated Hybrid-Lab Frontend (maps to container `:80`) |
| **5432** | **`hybrid-lab-postgres` (Docker)** | Internal `mgmt_net:5432` | Isolated Hybrid Lab PostgreSQL Storage Plane |
| **5434** | **`gateway-postgres` (Docker)** | `0.0.0.0:5434` | Host Development PostgreSQL Persistence |
| **6379** | **`redis-dev` (Docker)** | `0.0.0.0:6379` | Fast Cache and Session Store |

---

## 3. Docker Service Re-Creation Procedure

In accordance with strict safety constraints (no volume deletion, no data loss, no full-stack restart):
1. **Targeted Container Recreation**:
   ```powershell
   docker compose -f deployment/hybrid-lab/compose.yaml --env-file deployment/hybrid-lab/.env up -d --no-deps gateway-api frontend
   ```
2. **Container State Audit**:
   - `hybrid-lab-gateway-api`: Recreated with port mapping `0.0.0.0:8001->8000/tcp` (Status: `Healthy`).
   - `hybrid-lab-frontend`: Recreated with port mapping `0.0.0.0:5175->80/tcp` (Status: `Healthy`).
   - `hybrid-lab-postgres`: Preserved intact; uptime uninterrupted (Status: `Healthy`).
   - `hybrid-lab-router`: Preserved intact; routing rules and net interfaces unaffected (Status: `Healthy`).
   - `hybrid_lab_pgdata` and `hybrid_lab_telemetry` volumes: 100% preserved.

---

## 4. Socket Availability Verification

PowerShell socket audit via `Get-NetTCPConnection`:
- `8000`: **FREE** (Zero listeners)
- `5174`: **FREE** (Zero listeners)
- `5173`: **FREE** (Zero listeners)
- `8001`: Active (Docker proxy)
- `5175`: Active (Docker proxy)

This confirms that launching `AdaptiveSecurityGateway.exe` and `npm run dev` will encounter zero port conflicts.
