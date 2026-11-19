FROM python:3.12-slim-bookworm

ARG HEADSCALE_VERSION=0.25.1
ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
    wireguard-tools \
    iproute2 \
    iptables \
    nftables \
    openvpn \
    easy-rsa \
    openssl \
    curl \
    ca-certificates \
    iputils-ping \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Headscale CLI for unix-socket bootstrap / admin against the control server
RUN set -eux; \
    arch="$TARGETARCH"; \
    if [ -z "$arch" ]; then arch="$(dpkg --print-architecture)"; fi; \
    case "$arch" in \
      amd64) hs_arch=amd64 ;; \
      arm64) hs_arch=arm64 ;; \
      *) hs_arch=arm64 ;; \
    esac; \
    curl -fsSL -o /tmp/headscale \
      "https://github.com/juanfont/headscale/releases/download/v${HEADSCALE_VERSION}/headscale_${HEADSCALE_VERSION}_linux_${hs_arch}"; \
    install -m 755 /tmp/headscale /usr/local/bin/headscale; \
    rm -f /tmp/headscale

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
