#!/usr/bin/env bash
# Best-effort local install of the four bundle-free scanners (CodeQL excluded —
# install its CLI bundle separately). Intended for a Debian/Ubuntu dev box.
# Prefer the Docker image for a reproducible environment.
set -euo pipefail

OSV_SCANNER_VERSION="${OSV_SCANNER_VERSION:-1.9.2}"
GITLEAKS_VERSION="${GITLEAKS_VERSION:-8.21.2}"
BIN_DIR="${BIN_DIR:-/usr/local/bin}"

have() { command -v "$1" >/dev/null 2>&1; }

echo "==> Semgrep (pip)"
if ! have semgrep; then pip install --user semgrep || pip install semgrep; fi

echo "==> npm audit (needs Node.js/npm)"
have npm || echo "   npm not found — install Node.js from https://nodejs.org"

arch="$(uname -m)"
case "$arch" in x86_64) OSV_A=amd64; GL_A=x64;; aarch64|arm64) OSV_A=arm64; GL_A=arm64;; *) OSV_A=amd64; GL_A=x64;; esac

echo "==> OSV-Scanner ${OSV_SCANNER_VERSION}"
if ! have osv-scanner; then
  curl -fsSL -o "${BIN_DIR}/osv-scanner" \
    "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_${OSV_SCANNER_VERSION}_linux_${OSV_A}"
  chmod +x "${BIN_DIR}/osv-scanner"
fi

echo "==> Gitleaks ${GITLEAKS_VERSION}"
if ! have gitleaks; then
  tmp="$(mktemp -d)"
  curl -fsSL -o "${tmp}/gitleaks.tgz" \
    "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GL_A}.tar.gz"
  tar -xzf "${tmp}/gitleaks.tgz" -C "${BIN_DIR}" gitleaks
  chmod +x "${BIN_DIR}/gitleaks"
  rm -rf "${tmp}"
fi

echo "==> CodeQL"
have codeql || echo "   CodeQL not installed — download the CLI bundle from"
have codeql || echo "   https://github.com/github/codeql-action/releases and add it to PATH"

echo "Done. Installed tools:"
for t in semgrep npm osv-scanner gitleaks codeql; do
  printf "  %-14s %s\n" "$t" "$(command -v "$t" 2>/dev/null || echo 'not found')"
done
