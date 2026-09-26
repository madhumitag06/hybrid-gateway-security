# FastAPI Backend & Real ML API Subsystem (Phase 2)

> **Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
> **Subsystem:** FastAPI REST API & ML Inference Gateway  
> **Phase:** 2 — Backend & Frontend Integration

---

## 1. Overview & Architecture

The FastAPI backend exposes the trained Phase 1 machine learning model ([RandomForestClassifier](file:///c:/Users/LENOVO/Desktop/hybrid-gateway-security/ml/models/model.joblib)) to the React frontend dashboard.

```text
React Dashboard (:5173)
        ↓ HTTP REST (JSON)
FastAPI Server (:8000)
        ↓
MLService Singleton (backend/app/services/ml_service.py)
        ↓
Phase 1 ThreatPredictor (ml/models/predict.py)
        ↓
Trained RandomForestClassifier & StandardScaler (ml/models/*.joblib)
        ↓
Real Prediction, Class Probabilities, Continuous Risk Score (0–100)
```

---

## 2. API Endpoints

### Health Check
* **`GET /api/health`** (or `GET /health`): Returns system liveness, version, and verification that ML model artifacts are loaded in memory.

### Real ML Threat Prediction
* **`POST /api/v1/predict`**: Evaluates an individual network flow vector and returns:
  * `risk_score` (0–100 continuous score)
  * `threat_level` (`LOW`, `MEDIUM`, `HIGH`)
  * `attack_type` (`BENIGN`, `PORT_SCAN`, `BRUTE_FORCE`, `TRAFFIC_SPIKE`, `SUSPICIOUS_TRANSFER`)
  * `confidence` (float between 0.0 and 1.0)
  * `action_recommendation` (`Allow`, `Monitor`, `Restrict`, `Block`)
  * `class_probabilities` (class probability estimates across all 5 classes)
  * `top_contributing_features` ($z$-score deviations from learned benign baseline)
* **`POST /api/v1/predict/batch`**: Batch evaluation of multiple flow records.
* **`GET /api/v1/predict/presets`**: Returns verified test flow presets for interactive testing.

### Gateway Dashboard Telemetry
* **`GET /api/dashboard`**: Returns live dashboard state with events evaluated dynamically by the ML model.
* **`POST /api/events/{event_id}/action`**: Updates policy action (`Monitor`, `Restrict`, `Block`) for an incident.

---

## 3. How to Run Locally

### Prerequisites
* Dedicated Python virtual environment in `ml/.venv`

### Step 1: Start FastAPI Backend (Port 8000)
```powershell
# Windows PowerShell
.\ml\.venv\Scripts\Activate.ps1
uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```
* Interactive Swagger Docs: [http://localhost:8000/docs](http://localhost:8000/docs)
* Health Check: [http://localhost:8000/api/health](http://localhost:8000/api/health)

### Step 2: Start React Frontend (Port 5173)
```powershell
npm run dev
```
* Frontend Dashboard: [http://localhost:5173](http://localhost:5173)

---

## 4. Automated Tests
```powershell
.\ml\.venv\Scripts\python -m pytest -v
```
Runs all 19 unit and integration tests across ML training, inference, health check, prediction API, and dashboard aggregation.
