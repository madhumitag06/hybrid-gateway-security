FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    iptables \
    iputils-ping \
    tcpdump \
    procps \
    curl \
    netcat-openbsd \
    && pip install --no-cache-dir "scapy>=2.6.0" \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY routing/configure-routes.sh /app/routing/configure-routes.sh
COPY firewall/iptables-init.sh /app/firewall/iptables-init.sh
COPY entrypoint.sh /app/entrypoint.sh
COPY router_agent.py /app/router_agent.py

RUN sed -i 's/\r$//' /app/routing/configure-routes.sh \
    /app/firewall/iptables-init.sh \
    /app/entrypoint.sh \
    && chmod +x /app/routing/configure-routes.sh \
    /app/firewall/iptables-init.sh \
    /app/entrypoint.sh

ENTRYPOINT ["/app/entrypoint.sh"]

