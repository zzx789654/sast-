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
# Semgrep pins older transitive packaging deps, so re-upgrade setuptools and
# msgpack afterwards; upgrading before this step alone leaves the old versions
# in the image. Semgrep does not constrain either at runtime.
RUN python -m pip install --no-cache-dir --prefer-binary \
      --timeout "${PIP_TIMEOUT}" --retries "${PIP_RETRIES}" semgrep \
    && python -m pip install --no-cache-dir --upgrade \
      --timeout "${PIP_TIMEOUT}" --retries "${PIP_RETRIES}" \
      "setuptools>=78.1.1" "msgpack>=1.2.1"

# Scanner binaries: use the host cache when present, download when not.
# scripts/fetch-vendor.sh fills ./vendor before the build. That matters on a
# slow link -- these downloads are ~100 MB and dominate the build time.
# A download here uses a stall detector (abort below 1 KB/s for 120s) rather
# than a fixed --max-time: a wall-clock cap kills a transfer that is still
# making progress, and the retry then restarts from zero. -C - resumes instead.
COPY vendor/ /vendor/

# --- OSV-Scanner (static Go binary) ---
RUN arch="$(dpkg --print-architecture)"; \
    case "$arch" in amd64) A=amd64;; arm64) A=arm64;; *) A=amd64;; esac; \
    if [ -s "/vendor/osv-scanner_linux_${A}" ]; then \
      echo "osv-scanner: using host cache"; \
      cp "/vendor/osv-scanner_linux_${A}" /usr/local/bin/osv-scanner; \
    else \
      echo "osv-scanner: downloading"; \
      curl -fsSL --retry 5 --retry-delay 5 --connect-timeout 30 --speed-limit 1024 --speed-time 120 -C - \
        -o /usr/local/bin/osv-scanner \
        "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_${A}"; \
    fi; \
    chmod +x /usr/local/bin/osv-scanner; \
    /usr/local/bin/osv-scanner --version

# --- Gitleaks (static Go binary) ---
RUN arch="$(dpkg --print-architecture)"; \
    case "$arch" in amd64) A=x64;; arm64) A=arm64;; *) A=x64;; esac; \
    F="gitleaks_${GITLEAKS_VERSION}_linux_${A}.tar.gz"; \
    if [ -s "/vendor/${F}" ]; then \
      echo "gitleaks: using host cache"; \
      cp "/vendor/${F}" /tmp/gitleaks.tgz; \
    else \
      echo "gitleaks: downloading"; \
      curl -fsSL --retry 5 --retry-delay 5 --connect-timeout 30 --speed-limit 1024 --speed-time 120 -C - \
        -o /tmp/gitleaks.tgz \
        "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${F}"; \
    fi; \
    tar -xzf /tmp/gitleaks.tgz -C /usr/local/bin gitleaks; \
    chmod +x /usr/local/bin/gitleaks; rm /tmp/gitleaks.tgz; \
    /usr/local/bin/gitleaks version

# --- Trivy (free, Apache-2.0; vuln + secret + IaC misconfig) ---
RUN arch="$(dpkg --print-architecture)"; \
    case "$arch" in amd64) A=64bit;; arm64) A=ARM64;; *) A=64bit;; esac; \
    F="trivy_${TRIVY_VERSION}_Linux-${A}.tar.gz"; \
    if [ -s "/vendor/${F}" ]; then \
      echo "trivy: using host cache"; \
      tar -xzf "/vendor/${F}" -C /usr/local/bin trivy; \
      chmod +x /usr/local/bin/trivy; \
    else \
      echo "trivy: downloading"; \
      curl -sfL --retry 5 --retry-delay 5 --connect-timeout 30 --speed-limit 1024 --speed-time 120 \
        https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
        | sh -s -- -b /usr/local/bin "v${TRIVY_VERSION}"; \
    fi; \
    /usr/local/bin/trivy --version

# --- Bearer (free, Elastic License; semantic SAST — CodeQL alternative) ---
# Bearer is not version-pinned, so it always goes through its own installer.
RUN curl -sSfL --retry 5 --retry-delay 5 --connect-timeout 30 --speed-limit 1024 --speed-time 120 \
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
