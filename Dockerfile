# SAST Studio — bundles the web app together with all six scanners.
#
# Docker Engine + Compose on Linux are free (Apache-2.0); only the Docker
# Desktop GUI carries a fee for large orgs, and a server image does not need it.
FROM python:3.11-slim

ARG OSV_SCANNER_VERSION=1.9.2
ARG GITLEAKS_VERSION=8.30.1
ARG TRIVY_VERSION=0.74.0
ARG PIP_TIMEOUT=600
ARG PIP_RETRIES=10

ENV PYTHONUNBUFFERED=1 \
    PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1 \
    SAST_WORKSPACE=/data/workspaces \
    PIP_DEFAULT_TIMEOUT=${PIP_TIMEOUT} \
    PIP_RETRIES=${PIP_RETRIES}

# --- OS packages: git (clone) + node/npm (npm audit) + curl (fetch tools) ---
RUN apt-get -o Acquire::Retries=5 update && apt-get -o Acquire::Retries=5 install -y --no-install-recommends \
        git curl ca-certificates nodejs npm \
    && apt-get -o Acquire::Retries=5 upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/*

# Keep the packaging toolchain current so the runtime does not carry known
# vulnerabilities from the base image's bundled pip/setuptools/wheel.
RUN python -m pip install --no-cache-dir --upgrade \
      --timeout "${PIP_TIMEOUT}" --retries "${PIP_RETRIES}" \
      pip setuptools wheel

# --- Semgrep (pip, pulls the Python engine) ---
RUN python -m pip install --no-cache-dir --prefer-binary \
      --timeout "${PIP_TIMEOUT}" --retries "${PIP_RETRIES}" semgrep

# --- OSV-Scanner (static Go binary) ---
RUN arch="$(dpkg --print-architecture)"; \
    case "$arch" in amd64) A=amd64;; arm64) A=arm64;; *) A=amd64;; esac; \
    curl -fsSL --retry 5 --retry-delay 5 --connect-timeout 30 --max-time 600 \
      -o /usr/local/bin/osv-scanner \
      "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_${A}" \
    && chmod +x /usr/local/bin/osv-scanner

# --- Gitleaks (static Go binary) ---
RUN arch="$(dpkg --print-architecture)"; \
    case "$arch" in amd64) A=x64;; arm64) A=arm64;; *) A=x64;; esac; \
    curl -fsSL --retry 5 --retry-delay 5 --connect-timeout 30 --max-time 600 \
      -o /tmp/gitleaks.tgz \
      "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${A}.tar.gz" \
    && tar -xzf /tmp/gitleaks.tgz -C /usr/local/bin gitleaks \
    && chmod +x /usr/local/bin/gitleaks && rm /tmp/gitleaks.tgz

# --- Trivy (free, Apache-2.0; vuln + secret + IaC misconfig) ---
RUN curl -sfL --retry 5 --retry-delay 5 --connect-timeout 30 --max-time 600 \
      https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
      | sh -s -- -b /usr/local/bin "v${TRIVY_VERSION}"

# --- Bearer (free, Elastic License; semantic SAST — CodeQL alternative) ---
RUN curl -sSfL --retry 5 --retry-delay 5 --connect-timeout 30 --max-time 600 \
      https://raw.githubusercontent.com/Bearer/bearer/main/contrib/install.sh \
      | sh -s -- -b /usr/local/bin

WORKDIR /app
COPY requirements.txt .
RUN python -m pip install --no-cache-dir --prefer-binary \
      --timeout "${PIP_TIMEOUT}" --retries "${PIP_RETRIES}" -r requirements.txt
COPY app ./app

RUN useradd -m appuser && mkdir -p /data/workspaces && chown -R appuser /data
USER appuser

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3)"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
