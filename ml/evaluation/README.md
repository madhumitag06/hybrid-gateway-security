# ML Evaluation & External Benchmark Validation

This directory provides a reproducible framework for evaluating the **Adaptive AI-Powered Security Gateway** machine learning models across synthetic benchmarks and public network intrusion datasets.

---

## Architecture & Workflows

```
ml/
├── data/
│   └── generator.py                 # Calibrated synthetic network-flow generator (CIC-IDS2017 inspired)
├── evaluation/
│   ├── evaluate.py                  # Standard multi-class classification evaluation metrics
│   ├── feature_mapping.py           # External public dataset to project schema translator
│   ├── external_dataset_loader.py   # Loader and calibrated benchmark generator for external schemas
│   ├── evaluate_external.py         # Evaluates Phase 11B production model on external data (Path A)
│   ├── train_external_model.py      # Trains experimental external model for academic comparison (Path B)
│   └── README.md                    # Reproducibility documentation
├── features/
│   └── extractor.py                 # 10-feature schema extractor & Pydantic flow validation
├── models/
│   ├── train.py                     # Production Random Forest training pipeline
│   ├── predict.py                   # ThreatPredictor inference engine
│   ├── model.joblib                 # Serialized production RandomForestClassifier
│   ├── scaler.joblib                # Serialized StandardScaler
│   ├── label_encoder.joblib         # Serialized LabelEncoder
│   └── metadata.json                # Production model training & evaluation metadata
```

---

## Feature Taxonomy & Mapping

The model operates on a standard 10-feature flow representation:

| Feature | Type | Source in Public Flow Logs (e.g. CIC-IDS2017 / UNSW-NB15) |
| :--- | :--- | :--- |
| `packet_count` | Observed | `Total Fwd Packets + Total Backward Packets` |
| `byte_count` | Observed | `Total Length of Fwd Packets + Total Length of Bwd Packets` |
| `duration` | Observed | `Flow Duration` (converted from microseconds to seconds) |
| `conn_rate` | Derived | Temporal connection frequency or normalized flow packet rate |
| `dst_port` | Observed | `Destination Port` |
| `unique_dst_ports` | Derived | Aggregated destination ports per source IP in window |
| `failed_auth_count`| Proxy | Authentication failure count (strictly `0` in generic L4 flow logs) |
| `bytes_per_sec` | Derived | `byte_count / max(duration, 0.001)` |
| `packets_per_sec`| Derived | `packet_count / max(duration, 0.001)` |
| `avg_packet_size`| Derived | `byte_count / max(packet_count, 1)` |

---

## How to Run Evaluations

### 1. Evaluate Production Model on External Benchmark (Generalization Test - Path A)
```powershell
.\ml\.venv\Scripts\python.exe -m ml.evaluation.evaluate_external
```

### 2. Train and Evaluate Experimental External Model (Path B)
```powershell
.\ml\.venv\Scripts\python.exe -m ml.evaluation.train_external_model
```

### 3. Re-train Production Model on Calibrated Synthetic Data
```powershell
.\ml\.venv\Scripts\python.exe -m ml.models.train
```

### 4. Run Complete ML & Backend Pytest Suite
```powershell
.\ml\.venv\Scripts\pytest.exe -q
```
