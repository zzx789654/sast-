#!/usr/bin/env bash
# Pre-download the scanner binaries into ./vendor so "docker compose build"
# does not have to fetch them.
#
# Why this exists: on a slow link the build spends nearly all of its time on
# these downloads (~100 MB), and a failure part-way through throws the progress
# away and starts again. Downloading here is resumable (-C -) and survives
# between builds, so a rebuild costs seconds instead of many minutes.
#
# Safe to re-run: a file that is already present and verified is left alone.
set -euo pipefail

# Keep these in step with the ARG defaults in the Dockerfile.
OSV_SCANNER_VERSION="${OSV_SCANNER_VERSION:-1.9.2}"
GITLEAKS_VERSION="${GITLEAKS_VERSION:-8.30.1}"
TRIVY_VERSION="${TRIVY_VERSION:-0.74.0}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENDOR="${ROOT}/vendor"
mkdir -p "${VENDOR}"

case "$(uname -m)" in
  x86_64|amd64)  ARCH_GO=amd64; ARCH_GL=x64;   ARCH_TV=64bit ;;
  aarch64|arm64) ARCH_GO=arm64; ARCH_GL=arm64; ARCH_TV=ARM64 ;;
  *)             ARCH_GO=amd64; ARCH_GL=x64;   ARCH_TV=64bit ;;
esac

info() { printf '  %s\n' "$*"; }
warn() { printf '  ! %s\n' "$*" >&2; }

# Expected SHA-256 for each pinned artifact. These files are copied into the
# image and run as root during the build, so a cached file that nobody checks
# is a supply-chain hole: anything that can write to vendor/ would be executed.
# A recorded hash is enforced; an empty one still uses the file but says
# clearly that it could not be verified.
#
# These are the values published by each project, taken from the checksums
# file attached to its GitHub release (a few KB, so no need to download the
# artifact to refresh them):
#   .../releases/download/v<ver>/trivy_<ver>_checksums.txt
#   .../releases/download/v<ver>/gitleaks_<ver>_checksums.txt
#   .../releases/download/v<ver>/osv-scanner_<ver>_checksums.txt
# To see what you actually have on disk: ./scripts/fetch-vendor.sh --print-hashes
# osv-scanner v1.9.2 publishes no checksums file, so this value is not an
# upstream one: it is what two independent downloads both produced, and the
# resulting binary reports "osv-scanner version: 1.9.2". Weaker provenance
# than the other two -- it detects corruption and later tampering of the
# cache, but cannot prove the original download was authentic.
SHA_OSV="d6af4b67fa5de658598bd2d445efb99e90d1734b3146962418719c4350ecb74b"
SHA_GITLEAKS="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"
SHA_TRIVY="2ae6fe3ee734b7fdf11335663e18c75ea12dccc76062f09f164a3b0f8be4371a"

PRINT_HASHES=0
[ "${1:-}" = "--print-hashes" ] && PRINT_HASHES=1

expected_for() {
  case "$1" in
    osv-scanner_*)  printf '%s' "${SHA_OSV}" ;;
    gitleaks_*)     printf '%s' "${SHA_GITLEAKS}" ;;
    trivy_*)        printf '%s' "${SHA_TRIVY}" ;;
    *)              printf '' ;;
  esac
}

# Verify a file when a hash is recorded for it.
# 0 = matches or unrecorded, 1 = mismatch.
verify() {
  local name="$1" file="$2" want got
  want="$(expected_for "${name}")"
  if [ -z "${want}" ]; then
    info "${name}: no recorded checksum (not verified)"
    return 0
  fi
  got="$(sha256sum "${file}" | cut -d' ' -f1)"
  if [ "${got}" = "${want}" ]; then
    info "${name}: checksum ok"
    return 0
  fi
  warn "${name}: CHECKSUM MISMATCH"
  warn "  expected ${want}"
  warn "  actual   ${got}"
  return 1
}

# Download to <name>.part and only move it into place once curl reports success
# and the checksum passes, so an interrupted or tampered download can never
# leave a file that the build would treat as a valid cache hit.
fetch() {
  local name="$1" url="$2"
  local out="${VENDOR}/${name}"

  if [ -s "${out}" ]; then
    if verify "${name}" "${out}"; then
      info "${name}: already cached ($(du -h "${out}" | cut -f1))"
      return 0
    fi
    warn "${name}: cached copy failed verification - removing and re-fetching"
    rm -f "${out}"
  fi

  info "${name}: downloading"
  if curl -fL --retry 20 --retry-delay 5 --retry-all-errors -C - \
       --connect-timeout 30 --speed-limit 1024 --speed-time 120 \
       -o "${out}.part" "${url}"; then
    if verify "${name}" "${out}.part"; then
      mv "${out}.part" "${out}"
      info "${name}: done ($(du -h "${out}" | cut -f1))"
    else
      rm -f "${out}.part"
      warn "${name}: discarded; the build will fetch it instead"
      return 1
    fi
  else
    warn "${name}: download failed; the build will fall back to fetching it"
    rm -f "${out}.part"
    return 1
  fi
}

OSV_NAME="osv-scanner_linux_${ARCH_GO}"
GL_NAME="gitleaks_${GITLEAKS_VERSION}_linux_${ARCH_GL}.tar.gz"
TV_NAME="trivy_${TRIVY_VERSION}_Linux-${ARCH_TV}.tar.gz"

if [ "${PRINT_HASHES}" -eq 1 ]; then
  echo "Paste these into the SHA_* variables at the top of this script:"
  for f in "${OSV_NAME}" "${GL_NAME}" "${TV_NAME}"; do
    if [ -s "${VENDOR}/${f}" ]; then
      printf '  %s  %s\n' "$(sha256sum "${VENDOR}/${f}" | cut -d' ' -f1)" "${f}"
    else
      printf '  (missing) %s\n' "${f}"
    fi
  done
  exit 0
fi

echo "Caching scanner binaries into ${VENDOR}"

rc=0
fetch "${OSV_NAME}" \
  "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/${OSV_NAME}" || rc=1

fetch "${GL_NAME}" \
  "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${GL_NAME}" || rc=1

fetch "${TV_NAME}" \
  "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${TV_NAME}" || rc=1

# Bearer is not version-pinned in the Dockerfile, so it keeps using its own
# installer and is intentionally not cached here.

echo
if [ "${rc}" -eq 0 ]; then
  echo "All cached. 'docker compose build' will now skip these downloads."
else
  echo "Some downloads failed. The build still works - it falls back to"
  echo "downloading whatever is missing. Re-run to retry; finished files are kept."
fi
exit 0
