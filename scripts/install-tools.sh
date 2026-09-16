#!/usr/bin/env bash
# Install the native scanner CLIs used by SAST Studio.
#
# This script intentionally remains best-effort: one unavailable upstream
# release must not prevent the other scanners from being installed. It exits
# non-zero when one or more tools failed, so callers can report an honest
# result without losing the successful installations.
set -uo pipefail

OSV_SCANNER_VERSION="${OSV_SCANNER_VERSION:-1.9.2}"
GITLEAKS_VERSION="${GITLEAKS_VERSION:-8.30.1}"
TRIVY_VERSION="${TRIVY_VERSION:-0.74.0}"
BIN_DIR="${BIN_DIR:-/usr/local/bin}"
PIP_CMD="${PIP_CMD:-pip3}"
FORCE="${FORCE:-0}"

have() { command -v "$1" >/dev/null 2>&1; }
installed() { have "$1" || [ -x "${BIN_DIR}/$1" ]; }
want() { [ "$FORCE" = 1 ] || ! installed "$1"; }

failures=()

record_failure() {
  failures+=("$1")
  printf '   [warn] %s failed; continuing with the remaining tools\n' "$1" >&2
}

run_install() {
  local name="$1"
  shift
  printf '==> %s\n' "$name"
  if ! "$@"; then
    record_failure "$name"
  fi
}

download() {
  local url="$1"
  local dest="$2"
  curl -fL --retry 3 --retry-delay 2 --connect-timeout 20 --max-time 600 \
    -o "$dest.tmp" "$url" && mv -f "$dest.tmp" "$dest"
}

if ! have curl; then
  echo "curl is required to install native scanner binaries." >&2
  exit 1
fi
if ! have tar; then
  echo "tar is required to install Gitleaks." >&2
  exit 1
fi
if [ ! -d "$BIN_DIR" ] && ! mkdir -p "$BIN_DIR"; then
  echo "Cannot create scanner directory: $BIN_DIR" >&2
  exit 1
fi
if [ ! -w "$BIN_DIR" ]; then
  echo "Scanner directory is not writable: $BIN_DIR (set BIN_DIR to a writable path)" >&2
  exit 1
fi

if [ "$(uname -s)" != "Linux" ]; then
  echo "scripts/install-tools.sh supports Ubuntu/Linux only. Use Docker on other hosts." >&2
  exit 1
fi

arch="$(uname -m)"
case "$arch" in
  x86_64) OSV_A=amd64; GL_A=x64; TRIVY_A=64bit ;;
  aarch64|arm64) OSV_A=arm64; GL_A=arm64; TRIVY_A=ARM64 ;;
  *) echo "Unsupported Linux architecture: $arch" >&2; exit 1 ;;
esac

install_semgrep() {
  want semgrep || { echo "   already installed: $(command -v semgrep || echo "${BIN_DIR}/semgrep")"; return 0; }
  "$PIP_CMD" install -U semgrep
}

install_osv() (
  want osv-scanner || { echo "   already installed: ${BIN_DIR}/osv-scanner"; return 0; }
  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  download \
    "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_${OSV_A}" \
    "${tmp}/osv-scanner"
  install -m 0755 "${tmp}/osv-scanner" "${BIN_DIR}/osv-scanner"
)

install_gitleaks() (
  want gitleaks || { echo "   already installed: ${BIN_DIR}/gitleaks"; return 0; }
  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  download \
    "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${GL_A}.tar.gz" \
    "${tmp}/gitleaks.tgz"
  tar -xzf "${tmp}/gitleaks.tgz" -C "$tmp" gitleaks
  install -m 0755 "${tmp}/gitleaks" "${BIN_DIR}/gitleaks"
)

install_trivy() (
  want trivy || { echo "   already installed: ${BIN_DIR}/trivy"; return 0; }
  local tmp archive
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  archive="trivy_${TRIVY_VERSION}_Linux-${TRIVY_A}.tar.gz"
  download "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${archive}" "${tmp}/${archive}"
  tar -xzf "${tmp}/${archive}" -C "$tmp" trivy
  install -m 0755 "${tmp}/trivy" "${BIN_DIR}/trivy"
)

install_bearer() {
  want bearer || { echo "   already installed: ${BIN_DIR}/bearer"; return 0; }
  # Bearer's official installer selects the matching Linux release and keeps
  # the version decision in the upstream project.
  curl -sSfL https://raw.githubusercontent.com/Bearer/bearer/main/contrib/install.sh \
    | sh -s -- -b "$BIN_DIR"
}

run_install "Semgrep" install_semgrep
if installed npm; then
  echo "==> npm audit (provided by npm)"
else
  echo "==> npm audit"
  echo "   [warn] npm not found — install Node.js/npm to enable npm audit" >&2
fi
run_install "OSV-Scanner ${OSV_SCANNER_VERSION}" install_osv
run_install "Gitleaks ${GITLEAKS_VERSION}" install_gitleaks
run_install "Trivy ${TRIVY_VERSION}" install_trivy
run_install "Bearer" install_bearer

echo "==> Installed tools"
for tool in semgrep bearer trivy npm osv-scanner gitleaks; do
  if installed "$tool"; then
    printf '  %-14s %s\n' "$tool" "$(command -v "$tool" 2>/dev/null || echo "${BIN_DIR}/${tool}")"
  else
    printf '  %-14s not found\n' "$tool"
  fi
done

if [ "${#failures[@]}" -gt 0 ]; then
  printf '\nFailed tools: %s\n' "${failures[*]}" >&2
  exit 1
fi
