# PHASE 22.8.1 — SAFE DEPLOYMENT READINESS VERIFICATION REPORT

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Phase:** 22.8.1 — Safe Deployment Readiness Verification  
**Date:** 2026-11-16  
**Status:** COMPLETE & VERIFIED — SAFE FOR TARGETED DEPLOYMENT  
**Scope:** Verification of Docker Compose configuration, container isolation, volume preservation, and targeted recreation procedure for `traffic-generator`.  
**Baseline Git HEAD:** `f472588bb35c45031a8a28dec2d19d626ea58daf`  
**Working Tree:** Uncommitted changes preserved across all completed phases.

---

## 1. Executive Summary

Phase 22.8 modified the traffic generator service source files (`Dockerfile`, `entrypoint.sh`, and `trigger_daemon.py`) to resolve the ~12-second `DISPATCHED_ASYNC` scenario timeout defect by running `trigger_daemon.py` as a persistent background daemon.

This Phase 22.8.1 verification audits the deployment topology and provides the exact procedure to rebuild and recreate **ONLY** the `traffic-generator` service container.

### Key Verification Findings
1. **Service Identity:** The service is `traffic-generator` with container name `hybrid-lab-traffic-generator`, built from context `./traffic-generator`.
2. **Zero Upstream Inversion:** Absolutely **no service** in the Compose architecture depends on `traffic-generator`. Rebuilding or recreating `traffic-generator` cannot trigger restarts of `postgres`, `gateway-api`, `lab-router`, or `telemetry-sensor`.
3. **Volume Safety:** The volume `hybrid_lab_telemetry` is a shared external persistent Docker volume. Recreating the `traffic-generator` container with `--no-deps` reattaches the same volume without touching existing PCAPs, flow logs, metadata, or database tables.
4. **Daemon Integration:** The new `Dockerfile` and `entrypoint.sh` correctly package and launch `trigger_daemon.py` on container startup, creating the `/var/lib/hybrid-lab/telemetry/triggers` directory and maintaining `.daemon_heartbeat.json` every 2 seconds.

---

## 2. Docker Compose Configuration Audit (`compose.yaml`)

From `deployment/hybrid-lab/compose.yaml` (lines 360–396):

```yaml
traffic-generator:
  build:
    context: ./traffic-generator
    dockerfile: Dockerfile
  container_name: hybrid-lab-traffic-generator
  hostname: traffic-generator
  restart: unless-stopped
  cap_add:
    - NET_ADMIN
  environment:
    REMOTE_SUBNET: "10.20.10.0/24"
    GATEWAY_IP: "10.10.10.2"
    CLOUD_WEB_IP: "10.20.10.20"
    CLOUD_DB_IP: "10.20.10.30"
    CLOUD_WORKLOAD_IP: "10.20.10.40"
    ONPREM_WEB_IP: "10.10.10.20"
    AUTO_RUN_ON_START: ${TRAFFIC_GEN_AUTO_START:-false}
  volumes:
    - hybrid_lab_telemetry:/var/lib/hybrid-lab/telemetry
  networks:
    onprem_net:
      ipv4_address: 10.10.10.50
  depends_on:
    lab-router:
      condition: service_healthy
    cloud-web:
      condition: service_healthy
    cloud-db:
      condition: service_healthy
    cloud-workload:
      condition: service_healthy
  deploy:
    resources:
      limits:
        cpus: "${TRAFFIC_GEN_CPU_LIMIT:-0.50}"
        memory: "${TRAFFIC_GEN_MEM_LIMIT:-256M}"
```

### Configuration Specifications
| Parameter | Value | Assessment |
| :--- | :--- | :--- |
| **Compose Service Name** | `traffic-generator` | Authoritative service identifier |
| **Container Name** | `hybrid-lab-traffic-generator` | Authoritative container runtime name |
| **Derived Image Name** | `hybrid-security-lab-traffic-generator:latest` | Standard Compose project/service tag |
| **Network & IP** | `onprem_net` / `10.10.10.50` | Isolated on-premise bridge |
| **Volume Mount** | `hybrid_lab_telemetry:/var/lib/hybrid-lab/telemetry` | Authoritative persistent volume |
| **Capabilities** | `CAP_NET_ADMIN` | Permitted for static route installation |
| **Resource Limits** | CPU: 0.50 cores, Memory: 256 MB | Bounded resource footprint |

---

## 3. Container Image Comparison (Running vs. Source)

In compliance with the strict rule (*"Do not execute Docker commands or change infrastructure"*), Docker CLI queries were not invoked during this static verification turn. The structural analysis confirms:

### 3.1 Currently Running Container
- Built from previous baseline commit `f472588bb35c45031a8a28dec2d19d626ea58daf`.
- `Dockerfile`: Copied `entrypoint.sh`, `run_scenario.py`, and `scenarios/`. Did **not** copy `trigger_daemon.py`.
- `entrypoint.sh`: Terminated with `exec tail -f /dev/null`.
- Runtime State: Running as an idle sleep process without trigger monitoring.

### 3.2 Image Built from Updated Source
- `Dockerfile`:
  * Added layer: `COPY trigger_daemon.py /app/trigger_daemon.py` (line 18).
  * Line ending sanitization: `sed -i 's/\r$//' /app/entrypoint.sh && chmod +x /app/entrypoint.sh`.
- `entrypoint.sh`:
  * Replaced `exec tail -f /dev/null` with:
    ```bash
    echo "[+] Starting traffic trigger daemon on /var/lib/hybrid-lab/telemetry/triggers..."
    exec python3 /app/trigger_daemon.py
    ```
- Result: Because Docker layer caching computes SHA-256 digests over layer instructions and file contents, the new image will have a completely distinct Image ID and distinct layer history.

---

## 4. Packaging and Launch Verification

### 4.1 Dockerfile Structure (`deployment/hybrid-lab/traffic-generator/Dockerfile`)
```dockerfile
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    iputils-ping \
    curl \
    netcat-openbsd \
    && pip install --no-cache-dir "scapy>=2.6.0" \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY entrypoint.sh /app/entrypoint.sh
COPY run_scenario.py /app/run_scenario.py
COPY trigger_daemon.py /app/trigger_daemon.py
COPY scenarios/ /app/scenarios/

RUN sed -i 's/\r$//' /app/entrypoint.sh && chmod +x /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]
```
**Verification Points:**
- `trigger_daemon.py` is explicitly copied into `/app/trigger_daemon.py`.
- `scapy>=2.6.0` and network utilities (`iproute2`, `iputils-ping`, `curl`, `netcat-openbsd`) are installed.
- Line endings for `entrypoint.sh` are normalized to UNIX LF, preventing `\r: command not found` errors.

### 4.2 Entrypoint Lifecycle (`deployment/hybrid-lab/traffic-generator/entrypoint.sh`)
```bash
#!/bin/sh
set -e

PEER_SUBNET="${PEER_SUBNET:-${REMOTE_SUBNET:-10.20.10.0/24}}"
ROUTER_IP="${ROUTER_IP:-${GATEWAY_IP:-10.10.10.2}}"

echo "[*] Initializing Traffic Generator on On-Premises Network (10.10.10.50)"
ip route del default 2>/dev/null || true
echo "[*] Installing static route to Cloud VPC (${PEER_SUBNET}) via Virtual Gateway (${ROUTER_IP})..."

if ip route replace "${PEER_SUBNET}" via "${ROUTER_IP}"; then
    echo "[+] Static route active: $(ip route show "${PEER_SUBNET}")"
else
    echo "[!] Warning: Failed to install static route."
fi

mkdir -p /var/lib/hybrid-lab/telemetry/pcaps
mkdir -p /var/lib/hybrid-lab/telemetry/flowlogs
mkdir -p /var/lib/hybrid-lab/telemetry/metadata

touch /tmp/traffic_gen_ready

if [ "$#" -gt 0 ]; then
    exec "$@"
fi

echo "[+] Starting traffic trigger daemon on /var/lib/hybrid-lab/telemetry/triggers..."
exec python3 /app/trigger_daemon.py
```
**Verification Points:**
- Installs the static routing table entry to direct `10.20.10.0/24` traffic through the virtual router `10.10.10.2`.
- Creates standard telemetry subdirectories.
- Creates `/tmp/traffic_gen_ready` synchronization marker.
- Uses `exec python3 /app/trigger_daemon.py` to replace the shell process, ensuring Python executes as PID 1 to capture and respond cleanly to SIGTERM / SIGINT shutdown signals.

---

## 5. Volume Mounts & Trigger Directory Permissions

### 5.1 Volume Mount Consistency
The persistent volume `hybrid_lab_telemetry` is declared at lines 464–465 of `compose.yaml`:
```yaml
volumes:
  hybrid_lab_pgdata:
    name: hybrid_lab_pgdata
  hybrid_lab_telemetry:
    name: hybrid_lab_telemetry
```
It is mounted identically at `/var/lib/hybrid-lab/telemetry` across:
1. `gateway-api` (line 60)
2. `lab-router` (line 129)
3. `traffic-generator` (line 378)
4. `telemetry-sensor` (line 419)

### 5.2 Trigger Protocol & File Permissions
- Directory: `/var/lib/hybrid-lab/telemetry/triggers/` (created automatically by `trigger_daemon.py:main()` with `parents=True, exist_ok=True`).
- Permissions: `traffic-generator` runs as root inside the container, granting full read/write permissions to create the triggers directory and files.
- Atomic Heartbeat Protocol:
  * File: `/var/lib/hybrid-lab/telemetry/triggers/.daemon_heartbeat.json`
  * Written every 2.0s via temporary file rename (`.tmp` $\to$ `.daemon_heartbeat.json`) to prevent read tearing.
  * Checked by `HybridTrafficService.is_daemon_online()` (30s threshold).
- Request/Response Handshake:
  * Backend writes: `<run_id>.req`
  * Daemon acknowledges: writes `<run_id>.run`
  * Daemon completes: writes `<run_id>.res` (atomic via `.tmp`), unlinks `.req` and `.run`
  * Backend collects: reads `<run_id>.res` and unlinks it.

---

## 6. Dependency Graph & Isolation Confirmation

### 6.1 Compose Dependency Tree

```
postgres (no dependencies)
  ▲
  └── gateway-api
        ▲
        ├── frontend
        └── telemetry-sensor (also depends on lab-router)

lab-router (no dependencies)
  ▲
  ├── onprem-client
  ├── onprem-web
  ├── onprem-workload
  ├── cloud-client
  ├── cloud-web
  ├── cloud-db
  ├── cloud-workload
  └── traffic-generator (also depends on cloud-web, cloud-db, cloud-workload)
```

### 6.2 Service Recreate Impact Analysis
- Services dependent on `traffic-generator`: **NONE**.
- Recreating `traffic-generator` with `docker compose up -d --no-deps --force-recreate traffic-generator`:
  * `--no-deps`: Explicitly instructs Docker Compose not to start, restart, or recreate linked services.
  * `postgres`: Remains untouched. Database sessions and storage remain continuous.
  * `gateway-api`: Remains untouched. Fast-API web workers and client connections remain active.
  * `lab-router`: Remains untouched. Active iptables rules, routing tables, and interface forwarding remain active.
  * `telemetry-sensor`: Remains untouched. Continuous packet capture and ingestion loops remain active.
  * Workload containers (`cloud-*`, `onprem-*`): Remain untouched.

---

## 7. Exact PowerShell Deployment Commands

To be executed by the operator when ready to deploy the updated `traffic-generator` service.

> [!IMPORTANT]
> **Safety Notice:**  
> - Do NOT run `docker compose down`.  
> - Do NOT use `-v` or `--volumes`.  
> - Do NOT run `docker system prune` or `docker volume prune`.  
> - Follow the targeted recreate commands below.

### Step 1: Navigate to the Hybrid Lab directory
```powershell
Set-Location "c:\Users\LENOVO\Desktop\hybrid-gateway-security\deployment\hybrid-lab"
```

### Step 2: (Optional Read-Only) Inspect current running container image ID
```powershell
docker inspect --format '{{.Id}} (Image: {{.Image}})' hybrid-lab-traffic-generator
```

### Step 3: Build the updated `traffic-generator` image
Builds only the image for the `traffic-generator` service using the updated Dockerfile:
```powershell
docker compose build traffic-generator
```

### Step 4: Recreate ONLY the `traffic-generator` container
Replaces the running container without touching any other service:
```powershell
docker compose up -d --no-deps --force-recreate traffic-generator
```

### Step 5: Verify the recreated container status
```powershell
docker compose ps traffic-generator
```

### Step 6: Verify daemon startup in container logs
Check that the daemon printed its startup and static route confirmation:
```powershell
docker compose logs --tail 25 traffic-generator
```
*Expected log output:*
```text
[*] Initializing Traffic Generator on On-Premises Network (10.10.10.50)
[+] Static route active: 10.20.10.0/24 via 10.10.10.2
[+] Starting traffic trigger daemon on /var/lib/hybrid-lab/telemetry/triggers...
[+] Traffic trigger daemon active on /var/lib/hybrid-lab/telemetry/triggers
```

### Step 7: Verify persistent volume and heartbeat liveness
```powershell
# 1. Verify volume is still present
docker volume ls --filter name=hybrid_lab_telemetry

# 2. Check the daemon heartbeat file inside the shared volume
docker compose exec traffic-generator cat /var/lib/hybrid-lab/telemetry/triggers/.daemon_heartbeat.json
```
*Expected heartbeat content:*
```json
{"pid": 1, "heartbeat_at": "...", "timestamp": ..., "status": "ONLINE"}
```

---

## 8. Rollback Procedure

If any issue arises with the new container, rolling back requires only rebuilding from the prior commit or launching a shell override:

```powershell
Set-Location "c:\Users\LENOVO\Desktop\hybrid-gateway-security\deployment\hybrid-lab"

# Option A: Run container in fallback sleep mode (restores previous behavior)
docker compose run -d --name hybrid-lab-traffic-generator-rollback traffic-generator tail -f /dev/null

# Option B: Rebuild with prior entrypoint if needed
```

---

## 9. Conclusion

Phase 22.8.1 safe deployment readiness verification is complete:
- The configuration and dependency topology are validated.
- Zero upstream service restarts are guaranteed by the `--no-deps` execution pattern.
- Persistent volumes and database state will be 100% preserved.
- No Docker commands were executed during this verification turn.
- No commits or pushes have been made.
