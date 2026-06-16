# Hardened Dockerfile for IoT Sentinel
# Uses pinned digest, non-root user, minimal attack surface

# Pin base image to digest for reproducibility and supply chain protection
FROM python:3.14-slim@sha256:44dd04494ee8f3b538294360e7c4b3acb87c8268e4d0a4828a6500b1eff50061 AS base

# Prevent Python from writing .pyc files and enable unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Install system dependencies and clean up in one layer
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        tini=0.19.0-3+b7 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN groupadd -r sentinel && useradd -r -g sentinel -d /app -s /sbin/nologin sentinel

WORKDIR /app

# Install Python dependencies first (better layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    # Remove pip cache and unnecessary files
    rm -rf /root/.cache

# Copy application code
COPY iot_fingerprint.py .

# Drop to non-root user
USER sentinel

# Use tini as init to handle signals properly
ENTRYPOINT ["tini", "--", "python", "iot_fingerprint.py"]

# Default: show help
CMD ["--help"]

# Health metadata
LABEL org.opencontainers.image.title="IoT Sentinel" \
      org.opencontainers.image.description="Automated Device-Type Identification for Security Enforcement in IoT" \
      org.opencontainers.image.source="https://github.com/andypitcher/IoT_Sentinel" \
      org.opencontainers.image.licenses="MIT"
