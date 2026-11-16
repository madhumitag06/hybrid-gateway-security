# ==============================================================================
# Adaptive AI Security Gateway — Hardened Multi-Stage Container Definition
# Resolves SEC-10: Multi-stage build discarding compilers + Non-root execution
# ==============================================================================

# Stage 1: Build Dependencies
FROM python:3.12-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp

COPY backend/requirements.txt /tmp/backend-requirements.txt
COPY ml/requirements.txt /tmp/ml-requirements.txt

RUN grep -iv "pyinstaller" /tmp/backend-requirements.txt > /tmp/backend-req-clean.txt && \
    pip install --no-cache-dir --prefix=/install "psycopg2-binary==2.9.10" xgboost -r /tmp/backend-req-clean.txt -r /tmp/ml-requirements.txt

# Stage 2: Hardened Unprivileged Runtime
FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

# Runtime libraries only: build compilers and development headers are discarded from builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    libpq5 \
    && rm -rf /var/lib/apt/lists/*

# Dedicated unprivileged system user and group (SEC-10)
RUN groupadd -r -g 10001 gateway && \
    useradd -r -u 10001 -g gateway -m -d /home/gateway -s /sbin/nologin gateway

WORKDIR /app

# Copy compiled Python packages from builder stage
COPY --from=builder /install /usr/local

# Copy application source, configuration, and ML artifacts
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
COPY ml/models/candidates/bigdata_v2 /app/ml/models/candidates/bigdata_v2
COPY deployment/hybrid-lab/gateway/entrypoint.sh /app/entrypoint.sh

# Verify bytecode compilation and set up writable directories with unprivileged ownership
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
    sed -i 's/\r$//' /app/entrypoint.sh && \
    chmod 0755 /app/entrypoint.sh && \
    mkdir -p /var/lib/hybrid-lab/telemetry/pcaps \
             /var/lib/hybrid-lab/telemetry/flowlogs \
             /var/lib/hybrid-lab/telemetry/metadata \
             /var/lib/hybrid-lab/telemetry/triggers \
             /var/lib/hybrid-lab/telemetry/status && \
    chmod 0777 /var/lib/hybrid-lab/telemetry/triggers && \
    chown -R gateway:gateway /app /var/lib/hybrid-lab/telemetry /home/gateway

USER gateway:gateway

EXPOSE 8000

ENTRYPOINT ["/app/entrypoint.sh"]
