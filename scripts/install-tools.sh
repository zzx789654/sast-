#!/usr/bin/env bash
# Best-effort local install of the six free scanners. Intended for a
# Debian/Ubuntu dev box. Prefer the Docker image for a reproducible environment.
#
# Set FORCE=1 to (re)install even when a tool is already present — used by
# `setup.sh --update` to pull the pinned/latest versions.
set -euo pipefail

OSV_SCANNER_VERSION="${OSV_SCANNER_VERSION:-1.9.2}"
GITLEAKS_VERSION="${GITLEAKS_VERSION:-8.21.2}"
TRIVY_VERSION="${TRIVY_VERSION:-0.58.1}"
BIN_DIR="${BIN_DIR:-/usr/local/bin}"

have() { command -v "$1" >/dev/null 2>&1; }
# want X == install X? true when forced, or when it isn't already present.
want() { [ "${FORCE:-0}" = 1 ] || ! have "$1"; }

echo "==> Semgrep (pip)"
if want semgrep; then pip install --user -U semgrep || pip install -U semgrep; fi

echo "==> npm audit (needs Node.js/npm)"
have npm || echo "   npm not found — install Node.js from https://nodejs.org"

arch="$(uname -m)"
case "$arch" in x86_64) OSV_A=amd64; GL_A=x64;; aarch64|arm64) OSV_A=arm64; GL_A=arm64;; *) OSV_A=amd64; GL_A=x64;; esac

echo "==> OSV-Scanner ${OSV_SCANNER_VERSION}"
if want osv-scanner; then
  curl -fsSL -o "${BIN_DIR}/osv-scanner" \
    "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_${OSV_SCANNER_VERSION}_linux_${OSV_A}"
  chmod +x "${BIN_DIR}/osv-scanner"
fi

echo "==> Gitleaks ${GITLEAKS_VERSION}"
if want gitleaks; then
  tmp="$(mktemp -d)"
  curl -fsSL -o "${tmp}/gitleaks.tgz" \
    "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GL_A}.tar.gz"
  tar -xzf "${tmp}/gitleaks.tgz" -C "${BIN_DIR}" gitleaks
  chmod +x "${BIN_DIR}/gitleaks"
  rm -rf "${tmp}"
fi

echo "==> Trivy ${TRIVY_VERSION} (free, Apache-2.0)"
if want trivy; then
  curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b "${BIN_DIR}" "v${TRIVY_VERSION}"
fi

echo "==> Bearer (free, Elastic License — semantic SAST)"
if want bearer; then
  curl -sSfL https://raw.githubusercontent.com/Bearer/bearer/main/contrib/install.sh \
    | sh -s -- -b "${BIN_DIR}"
fi

echo "Done. Installed tools:"
for t in semgrep bearer trivy npm osv-scanner gitleaks; do
  printf "  %-14s %s\n" "$t" "$(command -v "$t" 2>/dev/null || echo 'not found')"
done
