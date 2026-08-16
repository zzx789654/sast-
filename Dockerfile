# SAST Studio — bundles the web app together with all five scanners.
#
# Docker Engine + Compose on Linux are free (Apache-2.0); only the Docker
# Desktop GUI carries a fee for large orgs, and a server image does not need it.
FROM python:3.11-slim

ARG OSV_SCANNER_VERSION=1.9.2
ARG GITLEAKS_VERSION=8.21.2

ENV PYTHONUNBUFFERED=1 \
    PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 \
    SAST_WORKSPACE=/data/workspaces

# --- OS packages: git (clone) + node/npm (npm audit) + curl (fetch tools) ---
RUN apt-get update && apt-get install -y --no-install-recommends \
        git curl ca-certificates nodejs npm \
    && rm -rf /var/lib/apt/lists/*

# --- Semgrep (pip, pulls the Python engine) ---
RUN pip install --no-cache-dir semgrep

# --- OSV-Scanner (static Go binary) ---
RUN arch="$(dpkg --print-architecture)"; \
    case "$arch" in amd64) A=amd64;; arm64) A=arm64;; *) A=amd64;; esac; \
    curl -fsSL -o /usr/local/bin/osv-scanner \
      "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_${OSV_SCANNER_VERSION}_linux_${A}" \
    && chmod +x /usr/local/bin/osv-scanner

# --- Gitleaks (static Go binary) ---
RUN arch="$(dpkg --print-architecture)"; \
    case "$arch" in amd64) A=x64;; arm64) A=arm64;; *) A=x64;; esac; \
    curl -fsSL -o /tmp/gitleaks.tgz \
      "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${A}.tar.gz" \
    && tar -xzf /tmp/gitleaks.tgz -C /usr/local/bin gitleaks \
    && chmod +x /usr/local/bin/gitleaks && rm /tmp/gitleaks.tgz

# NOTE: CodeQL is NOT bundled here — its CLI bundle is hundreds of MB and its
# license restricts automated scanning of proprietary code. Mount it in or set
# CODEQL on PATH to enable; the app degrades gracefully when it is absent.

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app

RUN useradd -m appuser && mkdir -p /data/workspaces && chown -R appuser /data
USER appuser

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
