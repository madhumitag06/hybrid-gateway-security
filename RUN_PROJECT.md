# RUN GUIDE — Adaptive AI-Powered Security Gateway for Hybrid Cloud

This guide provides beginner-friendly, copy-paste instructions to run the consolidated project.

The authoritative project directory is:
`C:\Users\LENOVO\Desktop\hybrid-gateway-security` (also accessible via `C:\Users\LENOVO\Desktop\AdaptiveSecurityGateway_Final`)

---

## Quick Navigation

- [Option A: Run Standalone Executable (Recommended)](#option-a--run-the-standalone-executable-recommended)
- [Option B: Run in Development Mode](#option-b--run-in-development-mode)
- [Option C: Run in Docker (Full Hybrid Lab)](#option-c--run-with-docker-full-hybrid-cloud-lab)
- [Startup URL & Ports Reference](#startup-url--port-reference)
- [Troubleshooting & FAQs](#troubleshooting--faqs)

---

## Option A — Run the Standalone Executable (Recommended)

The standalone executable packages the complete React frontend, FastAPI backend, XGBoost V2 model, Random Forest standby model, and AES-256-GCM credential vault into one unified binary.

### Step 1: Ensure PostgreSQL Persistence is Running

Open PowerShell in the project directory and start the lightweight PostgreSQL database container:

```powershell
cd C:\Users\LENOVO\Desktop\hybrid-gateway-security
docker compose up -d db
```
*(Verify: `docker compose ps` shows `gateway-postgres` running on port 5434).*

### Step 2: Launch the Executable

You can launch the application in either of two ways:

#### Method 1: Double-Click (File Explorer)
Open File Explorer, navigate to:
```
C:\Users\LENOVO\Desktop\hybrid-gateway-security\dist\AdaptiveSecurityGateway
```
Double-click:
```
AdaptiveSecurityGateway.exe
```

#### Method 2: Command Line (PowerShell)
```powershell
cd C:\Users\LENOVO\Desktop\hybrid-gateway-security
.\dist\AdaptiveSecurityGateway\AdaptiveSecurityGateway.exe
```
*(Alternative shortcut wrapper: `.\backend\executable\AdaptiveSecurityGateway.cmd`)*

### Step 3: Observe Startup Output and Identify the URL

When the executable starts, a console window opens and prints the startup banner:

```text
==================================================================
 Adaptive Hybrid Cloud Security Gateway v2.2.0
==================================================================
[*] Binding host: 127.0.0.1:8000
[*] Environment file: C:\Users\LENOVO\Desktop\hybrid-gateway-security\.env
[*] Mode: Standalone Executable
[*] Database: 5434/hybrid_gateway_db
[*] ML Artifacts: ml/models
==================================================================
[+] Serving frontend distribution from: ...\dist
[*] Unified Gateway Dashboard: http://localhost:8000
==================================================================
INFO:     Started server process
INFO:     Waiting for application startup.
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)
```

Look for the line:
`[*] Unified Gateway Dashboard: http://localhost:8000`

### Step 4: Open in Your Browser

Open your web browser and navigate to:
```
http://localhost:8000
```
*(If port 8000 was busy, the launcher automatically selects fallback port `8080`, so navigate to `http://localhost:8080`).*

### Step 5: How to Stop the Application

In the console window where the executable is running, press:
```text
Ctrl + C
```
Or simply close the console window.

---

## Option B — Run in Development Mode

Run the backend and frontend separately in live development mode with hot-reloading.

### Step 1: Start PostgreSQL

```powershell
cd C:\Users\LENOVO\Desktop\hybrid-gateway-security
docker compose up -d db
```

### Step 2: Terminal 1 — Start the FastAPI Backend

Open a PowerShell terminal:

```powershell
cd C:\Users\LENOVO\Desktop\hybrid-gateway-security
.\ml\.venv\Scripts\Activate.ps1
python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```
Backend API will be active on `http://localhost:8000` (API Docs: `http://localhost:8000/docs`).

### Step 3: Terminal 2 — Start the React Frontend

Open a second PowerShell terminal:

```powershell
cd C:\Users\LENOVO\Desktop\hybrid-gateway-security
cmd.exe /c "npm run dev"
```
The Vite development server will print its URL, typically:
```text
  VITE v8.3.5  ready in 250 ms

  ➜  Local:   http://localhost:5174/
  ➜  Network: use --host to expose
```

### Step 4: Access Application in Dev Mode

Open your browser and navigate to:
```
http://localhost:5174
```
All API calls are automatically proxied from port `5174` to backend port `8000`.

### Step 5: Stopping Dev Mode

In each terminal window, press:
```text
Ctrl + C
```

---

## Option C — Run with Docker (Full Hybrid Cloud Lab)

Run the full simulated enterprise environment: Gateway API, React Frontend with Nginx reverse proxy, PostgreSQL, virtual network transit router with `iptables` FORWARD isolation, telemetry sensor, and traffic generator.

### Step 1: Prerequisite

Ensure **Docker Desktop** is open and running on Windows.

### Step 2: Navigate to Hybrid Lab Deployment Directory

```powershell
cd C:\Users\LENOVO\Desktop\hybrid-gateway-security\deployment\hybrid-lab
```

### Step 3: Start the Multi-Container Lab

```powershell
docker compose up -d
```

### Step 4: Check Container Status

```powershell
docker compose ps
```
You will observe all services running:
- `hybrid-lab-postgres` (PostgreSQL Database)
- `hybrid-lab-gateway-api` (Gateway FastAPI Backend on port `8001`)
- `hybrid-lab-frontend` (React + Nginx on port `5175`)
- `hybrid-lab-router` (Virtual Network Transit Router)
- `hybrid-lab-telemetry` (Telemetry Sensor)
- `hybrid-lab-traffic-gen` (Traffic Generator)

### Step 5: View Logs

```powershell
# View logs from all services:
docker compose logs -f

# Or inspect control plane logs specifically:
docker compose logs -f gateway-api frontend
```

### Step 6: Access the Application in Docker

Open your browser to:
- **Unified Frontend Dashboard**: `http://localhost:5175`
- **Gateway Backend API**: `http://localhost:8001`
- **Swagger API Docs**: `http://localhost:8001/docs`

### Step 7: How to Stop Docker Safely (Preserving Data)

```powershell
cd C:\Users\LENOVO\Desktop\hybrid-gateway-security\deployment\hybrid-lab
docker compose down
```

> [!CAUTION]
> NEVER run `docker compose down -v`. Running with `-v` destroys the PostgreSQL volume and deletes all historical security events and telemetry. Always use `docker compose down`.

---

## How to Interact with the Telemetry Chart

The **Evaluated Flow Ingestion Telemetry (Last 24 hours)** chart on the main dashboard provides complete interactive inspection:

### 1. Mouse Interaction
- **Hover**: Move pointer over any plotted circle on the area curve. A vertical crosshair appears along with an intelligent floating tooltip displaying:
  - Time bucket label and interval window (`08:00 → 12:00 UTC`).
  - Inbound flow volume and outbound ratio.
  - Anomaly status (`⚠️ Port Scan` or `✓ 0 Nominal`).
  - Total packets and formatted byte volume.
  - Telemetry source attribution (`AWS_VPC_FLOW`, `PCAP_INGEST`, or `GATEWAY_STREAM`).
- **Click**: Click any data point to open the **Detailed Telemetry Inspection Drawer** below the chart.

### 2. Touch Interaction (Mobile / Tablet)
- **Tap**: Tap any data point circle (equipped with $\ge 44\text{px}$ touch target) to immediately open the inspection drawer.
- **Switch Bucket**: Tap any other circle or time label to update the drawer.
- **Dismiss**: Tap the **✕ Close [Esc]** button or **← Return to Telemetry Overview** button.

### 3. Keyboard Navigation
- Use `Tab` to navigate focus to the chart.
- Press `ArrowRight` / `ArrowLeft` to navigate between time buckets.
- Press `Enter` or `Space` to open/close the inspection drawer for the focused bucket.
- Press `Escape` to close the inspection drawer and tooltip.

### 4. Detailed Inspection Drawer Features
- **5 Metric Chips**: Inbound flows, Outbound ratio, Anomaly status, Packet/Byte counts, and Source attribution with average and peak risk scores.
- **Correlated Security Incidents Table**: Lists real individual security events that occurred in that time bucket.
- **Filter Action**: Click **🔍 Filter Table by [Bucket]** to dynamically filter the Recent Security Events table to this time interval.
- **Honest Aggregated Notice**: If no discrete threat events were triggered during a window, an informative notice clarifies that all flows conformed to baseline gateway traffic policies.

---

## Motion Design & Interactive UI Guide

The platform integrates a restrained, enterprise-grade motion design system designed specifically for mission-critical hybrid cloud security operations. Animations are purposeful, low-latency, and physics-driven—never ornamental or distracting.

### 1. Motion Design Tokens & Timing System
All transitions leverage centralized CSS design tokens defined in `src/index.css`:
- `--ease-smooth`: `cubic-bezier(0.16, 1, 0.3, 1)` — for smooth camera and card elevations.
- `--ease-tactile`: `cubic-bezier(0.4, 0, 0.2, 1)` — for snappy button clicks and segment interactions.
- `--ease-ambient`: `ease-in-out` — for continuous background monitoring.
- `--duration-instant`: `100ms` — immediate micro-interactions.
- `--duration-fast`: `180ms` — hover and state transitions.
- `--duration-normal`: `280ms` — drawer entrances and dropdowns.
- `--duration-slow`: `420ms` — risk gauge transitions and status changes.
- `--duration-heartbeat`: `3.2s` — healthy telemetry pulse cycle.

### 2. Hybrid Network Topology Conduits & Segments
- **Directional Flow Conduits**: Directional connecting lines feature moving packet indicators (`.conduit-packet.p1` and `p2`) with staggered intervals (0s and 1.1s) moving from On-Premises to the Central Gateway, and from the Gateway to Hybrid Cloud VPCs.
- **Traffic-Aware States**: When no active flows or captured packets are detected (`flows === 0 && !packetsCaptured`), the topology gracefully transitions to an **idle state** (`.topology-stage.idle`), pausing moving packets and dimming conduit glow to conserve GPU overhead and provide honest status.
- **Interactive Enclave Inspector**: Clicking any enclave pod (On-Premises Corporate HQ, Central Gateway Core, or Hybrid Multi-Cloud VPC) highlights the segment and reveals the **Topology Segment Inspector** callout banner with instant live interface throughput, MTU, encryption cipher, and packet drop metrics.
- **Keyboard Navigation**: Press `Tab` to focus any segment, followed by `Enter` or `Space` to inspect; press `Escape` or click `✕` to dismiss.

### 3. Gateway Health & Service Heartbeats
- **Healthy Services (Nominal)**: Rhythmic, low-intensity green heartbeat pulse (`#858B59`, 3.2s cycle).
- **Degraded Services (Warning)**: Soft amber breathing glow (`#C87555`, 2.0s cycle).
- **Offline Services (Critical)**: Static muted red (`#E06C75`) with no pulsation, immediately signaling hard service failure.

### 4. Telemetry Anomaly Beacons & Dynamic Risk Gauge
- **Telemetry Anomaly Rings**: Plotted time buckets with detected security anomalies feature expanding radar beacon pulse rings (`.anomaly-pulse-ring`) behind the data point to draw operator attention without visual clutter.
- **Security Risk Gauge Arc**: The conic-gradient risk bezel transitions dynamically between Low (`#858B59`), Medium (`#C87555`), and High (`#E06C75`) tiers with smooth easing and contextual drop-shadow bloom.

### 5. Accessibility & Reduced Motion
In strict accordance with WCAG 2.2 AA accessibility guidelines:
- If the operating system or browser has **Reduced Motion** enabled (`prefers-reduced-motion: reduce`), all continuous animations (conduit packet movement, gateway pulse rings, anomaly beacons, and service heartbeats) are automatically disabled.
- Transitions drop to `0.001ms`, instantly displaying static terminal states without disorientation.

---

## Startup URL & Port Reference

| Mode | Component | URL | Port |
|---|---|---|---|
| **Option A (Standalone EXE)** | Unified Dashboard & API | `http://localhost:8000` | 8000 (auto-fallback to 8080 if busy) |
| **Option A (Standalone EXE)** | Swagger API Docs | `http://localhost:8000/docs` | 8000 |
| **Option B (Dev Mode)** | React Frontend (Vite) | `http://localhost:5174` | 5174 |
| **Option B (Dev Mode)** | FastAPI Backend | `http://localhost:8000` | 8000 |
| **Option C (Docker Lab)** | React Frontend (Nginx) | `http://localhost:5175` | 5175 |
| **Option C (Docker Lab)** | Gateway Backend API | `http://localhost:8001` | 8001 |
| **Database** | PostgreSQL Container | `localhost:5434` | 5434 (mapped to container 5432) |

---

## Troubleshooting & FAQs

### 1. Error: "Port 8000 is occupied"
- **Behavior**: Another application or container is listening on port 8000.
- **Resolution**: The standalone executable automatically detects this and binds to port `8080`. Check the console output:
  `[*] Launching on fallback port 8080 (http://127.0.0.1:8080)...`
  Then open `http://localhost:8080`.

### 2. Error: "Database connection failed / could not connect to server"
- **Behavior**: PostgreSQL container is not started.
- **Resolution**: Run `docker compose up -d db` in `C:\Users\LENOVO\Desktop\hybrid-gateway-security`. The database container listens on `localhost:5434` as configured in `.env`.

### 3. How to check application logs in EXE mode?
- Standard output and logs print directly to the console window where the executable runs.
- Log entries include Uvicorn HTTP access logs, XGBoost inference scoring, policy evaluations, and vault access notifications.

### 4. How do I configure AWS, GCP, or Azure credentials?
- See [SETUP_GUIDE.md](./SETUP_GUIDE.md) for step-by-step instructions.
- Or use the in-app **Onboarding Wizard** under **Multi-Cloud $\to$ Cloud Accounts $\to$ "+ Onboard Cloud Account"**. Credentials are encrypted using AES-256-GCM.
