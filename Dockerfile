# SAST Studio — bundles the web app together with all six scanners.
#
# Docker Engine + Compose on Linux are free (Apache-2.0); only the Docker
# Desktop GUI carries a fee for large orgs, and a server image does not need it.
FROM python:3.11-slim

ARG SEMGREP_VERSION=1.179.0
ARG OSV_SCANNER_VERSION=2.6.0
ARG GITLEAKS_VERSION=8.30.1
ARG TRIVY_VERSION=0.74.0
ARG BEARER_VERSION=2.1.1
# From https://github.com/Bearer/bearer/releases/download/v2.1.1/checksums.txt
ARG BEARER_SHA256_AMD64=6b79d315577fea8305dfe08577bea6ad53852a929cd24de9211d39750a194bbb
ARG BEARER_SHA256_ARM64=ef05756d374aeb179534e1bb441cd2c3bd56b8fcf21c693d71078859c6721916
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

# --- Semgrep (pip, in its own virtualenv) ---
# Semgrep pins opentelemetry-api~=1.37 and FastAPI 0.142 needs >=1.44. In one
# environment whichever installs last wins: the app's install upgraded it and
# semgrep died on import while the service stayed healthy. Its own venv lets
# each side resolve on its own. The symlink is enough: semgrep adds its venv's
# bin to PATH itself to find pysemgrep and semgrep-core. Pinned like the
# other five and root-owned: a new version means a rebuild CI has tested.
# Semgrep pins older transitive packaging deps, so re-upgrade setuptools and
# msgpack afterwards; upgrading before this step alone leaves the old versions
# in the image. Semgrep does not constrain either at runtime.
RUN python -m venv /opt/semgrep \
    && /opt/semgrep/bin/pip install --no-cache-dir --upgrade \
      --timeout "${PIP_TIMEOUT}" --retries "${PIP_RETRIES}" pip setuptools wheel \
    && /opt/semgrep/bin/pip install --no-cache-dir --prefer-binary \
      --timeout "${PIP_TIMEOUT}" --retries "${PIP_RETRIES}" "semgrep==${SEMGREP_VERSION}" \
    && /opt/semgrep/bin/pip install --no-cache-dir --upgrade \
      --timeout "${PIP_TIMEOUT}" --retries "${PIP_RETRIES}" \
      "setuptools>=78.1.1" "msgpack>=1.2.1" \
    && ln -s /opt/semgrep/bin/semgrep /usr/local/bin/semgrep

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
      echo "osv-scanner: verifying against the published checksums"; \
      curl -fsSL --retry 3 --connect-timeout 30 -o /tmp/osv-sums \
        "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_SHA256SUMS"; \
      want="$(grep " osv-scanner_linux_${A}$" /tmp/osv-sums | cut -d" " -f1)"; \
      got="$(sha256sum /usr/local/bin/osv-scanner | cut -d" " -f1)"; \
      if [ -z "$want" ] || [ "$want" != "$got" ]; then \
        echo "osv-scanner checksum mismatch: want ${want:-<none>}, got $got" >&2; \
        exit 1; \
      fi; \
      rm -f /tmp/osv-sums; \
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
# Pinned, and checked against the checksum Bearer publishes, like
# scripts/install-tools.sh and CI. It used to be "curl main/install.sh | sh":
# whatever that branch served at build time, so the image could ship a
# Bearer CI had never run.
RUN arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) A=amd64; SUM="${BEARER_SHA256_AMD64}";; \
      arm64) A=arm64; SUM="${BEARER_SHA256_ARM64}";; \
      *)     echo "bearer: no checksum recorded for $arch" >&2; exit 1;; \
    esac; \
    F="bearer_${BEARER_VERSION}_linux_${A}.tar.gz"; \
    curl -fsSL --retry 5 --retry-delay 5 --connect-timeout 30 --speed-limit 1024 --speed-time 120 -C - \
      -o /tmp/bearer.tgz \
      "https://github.com/Bearer/bearer/releases/download/v${BEARER_VERSION}/${F}"; \
    got="$(sha256sum /tmp/bearer.tgz | cut -d" " -f1)"; \
    if [ "$got" != "$SUM" ]; then \
      echo "bearer checksum mismatch: want $SUM, got $got" >&2; \
      exit 1; \
    fi; \
    tar -xzf /tmp/bearer.tgz -C /usr/local/bin bearer; \
    chmod +x /usr/local/bin/bearer; rm /tmp/bearer.tgz; \
    /usr/local/bin/bearer version

WORKDIR /app
COPY requirements.txt .
RUN python -m pip install --no-cache-dir --prefer-binary \
      --timeout "${PIP_TIMEOUT}" --retries "${PIP_RETRIES}" -r requirements.txt
# Every scanner must still start after the app's packages are in. A health
# check cannot see a broken scanner, so the build is where it has to fail.
# (semgrep --version is the check that caught the broken opentelemetry: it
# goes through the Python side. "import semgrep.main" succeeded on that image.)
RUN SEMGREP_ENABLE_VERSION_CHECK=0 semgrep --version \
    && bearer version && trivy --version && osv-scanner --version \
    && gitleaks version && npm --version
COPY app ./app

# The cache directory exists in the image, owned by appuser, so a volume
# mounted there (the upgrade self-check keeps Trivy's database in one) starts
# out writable instead of root-owned.
RUN useradd -m appuser \
    && mkdir -p /data/workspaces /data/rules /data/accounts /home/appuser/.cache \
    && chown -R appuser /data /home/appuser/.cache
USER appuser
# The same check the deploy and the upgrade run, as the account that scans.
RUN python -m app.selfcheck probe

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3)"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
