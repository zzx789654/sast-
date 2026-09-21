#!/usr/bin/env bash
# Install the native scanner CLIs used by SAST Studio.
#
# This script intentionally remains best-effort: one unavailable upstream
# release must not prevent the other scanners from being installed. It exits
# non-zero when one or more tools failed, so callers can report an honest
# result without losing the successful installations.
set -uo pipefail

OSV_SCANNER_VERSION="${OSV_SCANNER_VERSION:-2.6.0}"
GITLEAKS_VERSION="${GITLEAKS_VERSION:-8.30.1}"
TRIVY_VERSION="${TRIVY_VERSION:-0.74.0}"
BIN_DIR="${BIN_DIR:-/usr/local/bin}"
PIP_CMD="${PIP_CMD:-pip3}"
PIP_TIMEOUT="${PIP_TIMEOUT:-600}"
PIP_RETRIES="${PIP_RETRIES:-10}"
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

# Where fetch-vendor.sh keeps the binaries it has already downloaded and
# checksum-verified. Re-downloading them on every --update was the slow part:
# on a link of a few hundred KB/s, trivy alone is 50 MB.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENDOR="${VENDOR:-${ROOT}/vendor}"

# The name fetch-vendor.sh stores each download under. Keeping the two in
# step matters: a mismatch here means the cache is silently never hit.
cached_name_for() {
  case "$1" in
    */osv-scanner_linux_*)  printf 'osv-scanner_linux_%s' "${OSV_A}" ;;
    */gitleaks_*)           printf 'gitleaks_%s_linux_%s.tar.gz' "${GITLEAKS_VERSION}" "${GL_A}" ;;
    */trivy_*)              printf 'trivy_%s_Linux-%s.tar.gz' "${TRIVY_VERSION}" "${TRIVY_A}" ;;
    */bearer_*)             printf 'bearer_%s_linux_%s.tar.gz' "${BEARER_VERSION}" "${BEARER_A}" ;;
    *)                      printf '' ;;
  esac
}

# True when this file matches the checksum fetch-vendor.sh records for it.
# Unknown file or no sha256sum -> not trustworthy, so it is not cached; the
# download still installs, it just does not get promoted to the cache.
cache_is_trustworthy() {
  local name="$1" file="$2" want got
  have sha256sum || return 1
  [ -f "${ROOT}/scripts/fetch-vendor.sh" ] || return 1

  want="$(bash "${ROOT}/scripts/fetch-vendor.sh" --expected-for "$name" 2>/dev/null)"
  [ -n "$want" ] || return 1

  got="$(sha256sum "$file" | cut -d" " -f1)"
  [ "$want" = "$got" ]
}

download() {
  local url="$1"
  local dest="$2"
  local name cached

  # Use the local copy when there is one. fetch-vendor.sh verified its
  # checksum before storing it, so this is not a shortcut past that check --
  # it is the reason the check was done up front.
  name="$(cached_name_for "$url")"
  if [ -n "$name" ]; then
    cached="${VENDOR}/${name}"
    if [ -s "$cached" ]; then
      echo "   using local copy: vendor/${name}"
      cp "$cached" "$dest"
      return 0
    fi
  fi

  if ! curl -fL --retry 3 --retry-delay 2 --connect-timeout 20 \
       --speed-limit 1024 --speed-time 120 -C - -o "$dest.tmp" "$url"; then
    rm -f "$dest.tmp"
    return 1
  fi
  mv -f "$dest.tmp" "$dest" || return 1

  # Keep what we just paid for, so the next --update (or a docker build) does
  # not download it again -- but only once it has been checked. Storing an
  # unverified file would make the cache a way to launder a bad download:
  # every later run treats what is in vendor/ as already verified.
  if [ -n "$name" ] && [ -d "$VENDOR" ] && [ -w "$VENDOR" ]; then
    if cache_is_trustworthy "$name" "$dest"; then
      cp "$dest" "${VENDOR}/${name}" 2>/dev/null \
        && echo "   cached to vendor/${name}"
    else
      echo "   not cached: could not verify ${name}" >&2
    fi
  fi

  # Say the download succeeded explicitly. It used to be the exit status of
  # the curl line simply because that line was last; with the caching block
  # after it, the caller would otherwise be told whether *caching* worked.
  return 0
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

# Pinned like every other scanner. Checksums are the values published in
# https://github.com/Bearer/bearer/releases/download/v<ver>/checksums.txt
BEARER_VERSION="${BEARER_VERSION:-2.1.1}"
BEARER_SHA256_AMD64="6b79d315577fea8305dfe08577bea6ad53852a929cd24de9211d39750a194bbb"
BEARER_SHA256_ARM64="ef05756d374aeb179534e1bb441cd2c3bd56b8fcf21c693d71078859c6721916"

arch="$(uname -m)"
case "$arch" in
  x86_64) OSV_A=amd64; GL_A=x64; TRIVY_A=64bit; BEARER_A=amd64 ;;
  aarch64|arm64) OSV_A=arm64; GL_A=arm64; TRIVY_A=ARM64; BEARER_A=arm64 ;;
  *) echo "Unsupported Linux architecture: $arch" >&2; exit 1 ;;
esac

install_semgrep() {
  want semgrep || { echo "   already installed: $(command -v semgrep || echo "${BIN_DIR}/semgrep")"; return 0; }
  "$PIP_CMD" install --prefer-binary --timeout "$PIP_TIMEOUT" \
    --retries "$PIP_RETRIES" -U semgrep
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

install_bearer() (
  want bearer || { echo "   already installed: ${BIN_DIR}/bearer"; return 0; }
  # Was: curl the installer from the main branch straight into sh. That runs
  # whatever that URL returns at the moment it is fetched -- an unreviewed
  # branch, with no version and nothing to check the bytes against. The
  # release archive is pinned and its checksum is the one Bearer publishes,
  # so a tampered or truncated download fails instead of executing.
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' EXIT
  archive="bearer_${BEARER_VERSION}_linux_${BEARER_A}.tar.gz"
  download "https://github.com/Bearer/bearer/releases/download/v${BEARER_VERSION}/${archive}" "${tmp}/${archive}" || return 1

  case "$BEARER_A" in
    amd64) want_sum="$BEARER_SHA256_AMD64" ;;
    arm64) want_sum="$BEARER_SHA256_ARM64" ;;
    *)     want_sum="" ;;
  esac
  if [ -n "$want_sum" ] && have sha256sum; then
    got="$(sha256sum "${tmp}/${archive}" | cut -d' ' -f1)"
    if [ "$got" != "$want_sum" ]; then
      echo "   [error] bearer checksum mismatch: expected $want_sum, got $got" >&2
      return 1
    fi
  fi

  tar -xzf "${tmp}/${archive}" -C "$tmp" bearer
  install -m 0755 "${tmp}/bearer" "${BIN_DIR}/bearer"
)

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
run_install "Bearer ${BEARER_VERSION}" install_bearer

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
