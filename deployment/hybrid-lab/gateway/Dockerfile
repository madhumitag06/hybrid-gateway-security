FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY backend/requirements.txt /tmp/backend-requirements.txt
COPY ml/requirements.txt /tmp/ml-requirements.txt

RUN grep -iv "pyinstaller" /tmp/backend-requirements.txt > /tmp/backend-req-clean.txt && \
    pip install --no-cache-dir "psycopg2-binary==2.9.10" -r /tmp/backend-req-clean.txt -r /tmp/ml-requirements.txt && \
    python -c "import psycopg2, psycopg, sqlalchemy, alembic, fastapi, uvicorn, pydantic, scapy, numpy, scipy, pandas, sklearn, joblib, shap; print('Verified Python packages; psycopg2=' + psycopg2.__version__ + ', numpy=' + numpy.__version__ + ', sklearn=' + sklearn.__version__)" && \
    rm -f /tmp/backend-requirements.txt /tmp/backend-req-clean.txt /tmp/ml-requirements.txt

# Copy only explicit project source and model artifact paths (never copy host .venv or Windows executables)
COPY backend/alembic.ini /app/backend/alembic.ini
COPY backend/alembic /app/backend/alembic
COPY backend/app /app/backend/app
COPY ml/MODEL_CARD.md /app/ml/MODEL_CARD.md
COPY ml/data /app/ml/data
COPY ml/evaluation /app/ml/evaluation
COPY ml/features /app/ml/features
COPY ml/models/__init__.py \
     ml/models/predict.py \
     ml/models/train.py \
     ml/models/model.joblib \
     ml/models/scaler.joblib \
     ml/models/label_encoder.joblib \
     ml/models/metadata.json \
     /app/ml/models/
COPY deployment/hybrid-lab/gateway/entrypoint.sh /app/entrypoint.sh

RUN test ! -d /app/ml/.venv && \
    test ! -d /app/backend/ml && \
    test ! -d /app/backend/executable && \
    find /app -type d -name "__pycache__" -prune -exec rm -rf {} + && \
    find /app -type f -name "*.pyc" -delete && \
    python -m compileall -q -x "(\.venv|venv|site-packages|executable)" \
        /app/backend/app \
        /app/backend/alembic \
        /app/ml/data \
        /app/ml/evaluation \
        /app/ml/features \
        /app/ml/models && \
    python -c "import ml.features.extractor, ml.models.predict, backend.app.main; from backend.app.services.ml_service import MLService; from backend.app.schemas.predict import NetworkFlowRequest; pred = MLService.get_predictor(); benign_out = pred.predict_flow({'packet_count': 25, 'byte_count': 15000, 'duration': 2.5, 'conn_rate': 2.0, 'dst_port': 443, 'unique_dst_ports': 1, 'failed_auth_count': 0}); assert benign_out.attack_type == 'BENIGN' and not benign_out.is_anomaly and 0 <= benign_out.risk_score < 40; scan_req = NetworkFlowRequest(packet_count=2, byte_count=120, duration=0.08, conn_rate=120.0, dst_port=8080, unique_dst_ports=75, failed_auth_count=0, persist=False); scan_resp = MLService.predict(scan_req, enable_shap=True); assert scan_resp.attack_type == 'PORT_SCAN' and scan_resp.is_anomaly and scan_resp.risk_score >= 40 and scan_resp.explanation_status == 'CALCULATED' and len(scan_resp.top_contributing_features) == 3 and any(f.shap_value is not None for f in scan_resp.top_contributing_features); print('Verified ThreatPredictor.predict_flow + MLService.predict + SHAP:', benign_out.attack_type, benign_out.risk_score, '->', scan_resp.attack_type, scan_resp.risk_score, scan_resp.explanation_status)" && \
    sed -i 's/\r$//' /app/entrypoint.sh && \
    chmod 0755 /app/entrypoint.sh && \
    cp /app/entrypoint.sh /entrypoint.sh && \
    chmod 0755 /entrypoint.sh && \
    sh -n /app/entrypoint.sh && \
    mkdir -p /var/lib/hybrid-lab/telemetry/pcaps \
             /var/lib/hybrid-lab/telemetry/flowlogs \
             /var/lib/hybrid-lab/telemetry/metadata \
             /var/lib/hybrid-lab/telemetry/status

EXPOSE 8000

ENTRYPOINT ["/app/entrypoint.sh"]
