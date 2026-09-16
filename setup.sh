#!/usr/bin/env bash
#
# SAST Studio — one-shot installer & builder / 一鍵安裝與建立腳本
#
# Installs everything needed to run SAST Studio and verifies the install:
#   * system prerequisites (git, curl, Node.js/npm)   — via apt-get when available
#   * a Python virtualenv + all Python dependencies
#   * all six scanners (Semgrep, Bearer, Trivy, npm audit, OSV-Scanner, Gitleaks)
#   * runs the test suite to confirm the build
#
# Usage:
#   ./setup.sh                 # full local setup (venv + deps + tools + verify)
#   ./setup.sh --run           # ...then start the server on http://localhost:8000
#   ./setup.sh --docker        # build & start via Docker Compose instead (http://localhost:8080)
#   ./setup.sh --update        # update the scanners to their pinned/latest versions
#   ./setup.sh --no-tools      # skip installing the scanners (Python app only)
#   ./setup.sh --no-venv       # install Python deps into the current environment
#   ./setup.sh --help
#
set -euo pipefail

# ------------------------------------------------------------------ config
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

MODE="local"          # local | docker
DO_TOOLS=1
USE_VENV=1
DO_RUN=0
VENV_DIR="${VENV_DIR:-.venv}"

for arg in "$@"; do
  case "$arg" in
    --docker)   MODE="docker" ;;
    --update)   MODE="update" ;;
    --no-tools) DO_TOOLS=0 ;;
    --no-venv)  USE_VENV=0 ;;
    --run)      DO_RUN=1 ;;
    -h|--help)
      awk 'NR>=3 && /^#/ {sub(/^# ?/,""); print; next} NR>=3 {exit}' "$0"
      exit 0 ;;
    *) echo "unknown option: $arg (see --help)"; exit 2 ;;
  esac
done

say()  { printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

if [ "$MODE" != "docker" ]; then
  if [ "$(uname -s)" != "Linux" ]; then
    echo "Local setup supports Ubuntu Linux only. Use ./setup.sh --docker on other hosts." >&2
    exit 1
  fi
  if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    if [ "${ID:-}" != "ubuntu" ]; then
      echo "Local setup supports Ubuntu only. Use Docker on other distributions." >&2
      exit 1
    fi
  fi
fi

# Run a command with sudo only if we are not already root and sudo exists.
maybe_sudo() {
  if [ "$(id -u)" -eq 0 ]; then "$@"; elif have sudo; then sudo "$@"; else
    warn "need root to run: $*  (skipping)"; return 1; fi
}

# ------------------------------------------------------------------ docker path
if [ "$MODE" = "docker" ]; then
  say "Docker mode / 使用 Docker 建立"
  have docker || { echo "Docker is not installed."; exit 1; }
  if docker compose version >/dev/null 2>&1; then COMPOSE="docker compose";
  elif have docker-compose; then COMPOSE="docker-compose";
  else echo "Docker Compose is not available."; exit 1; fi
  say "Building and starting containers (this pulls the six scanners)…"
  $COMPOSE up --build -d
  say "Done. Open http://localhost:8080"
  echo "  logs:  $COMPOSE logs -f"
  echo "  stop:  $COMPOSE down"
  exit 0
fi

# ------------------------------------------------------------------ update path
if [ "$MODE" = "update" ]; then
  say "Update mode — refreshing scanners to pinned/latest versions / 更新掃描工具"
  if [ -d "$VENV_DIR" ]; then
    # shellcheck disable=SC1091
    source "$VENV_DIR/bin/activate"
  fi
  if have pip; then PIP_CMD=pip;
  elif have pip3; then PIP_CMD=pip3;
  else PIP_CMD=""; fi
  if [ -n "$PIP_CMD" ]; then
    "$PIP_CMD" install -U semgrep || warn "semgrep update failed"
  else
    warn "pip is unavailable; semgrep was not updated"
  fi
  if [ -w /usr/local/bin ]; then BIN_DIR=/usr/local/bin;
  else BIN_DIR="$HOME/.local/bin"; mkdir -p "$BIN_DIR"; fi
  FORCE=1 BIN_DIR="$BIN_DIR" PIP_CMD="${PIP_CMD:-pip3}" bash scripts/install-tools.sh \
    || warn "some tools failed to update"
  say "Update done. Check versions in the Monitor tab or: curl -s localhost:8000/api/tools"
  echo "Tip: bump the pinned versions in scripts/install-tools.sh / Dockerfile to control what --update installs."
  exit 0
fi

# ------------------------------------------------------------------ prerequisites
say "Checking system prerequisites / 檢查系統相依"
NEED_APT=()
have git  || NEED_APT+=("git")
have curl || NEED_APT+=("curl ca-certificates")
have node || NEED_APT+=("nodejs")          # npm audit needs Node.js
have npm  || NEED_APT+=("npm")
if [ "$USE_VENV" -eq 1 ] && ! python3 -c "import venv" >/dev/null 2>&1; then
  NEED_APT+=("python3-venv")
fi
have pip3 || python3 -c "import pip" >/dev/null 2>&1 || NEED_APT+=("python3-pip")

if [ "${#NEED_APT[@]}" -gt 0 ]; then
  if have apt-get; then
    say "Installing system packages: ${NEED_APT[*]}"
    maybe_sudo apt-get update -q || warn "apt-get update failed; continuing"
    # shellcheck disable=SC2086
    maybe_sudo apt-get install -y --no-install-recommends ${NEED_APT[*]} \
      || warn "apt-get install failed; install these manually: ${NEED_APT[*]}"
  else
    warn "Missing (install manually): ${NEED_APT[*]}"
  fi
fi

have python3 || { echo "Python 3 is required."; exit 1; }
PYTHON=python3
say "Python: $($PYTHON --version 2>&1)"

# ------------------------------------------------------------------ python deps
PIP="pip3"
if [ "$USE_VENV" -eq 1 ]; then
  say "Creating virtualenv at ./$VENV_DIR"
  "$PYTHON" -m venv "$VENV_DIR"
  # shellcheck disable=SC1091
  source "$VENV_DIR/bin/activate"
  PIP="pip"
fi
export PIP_CMD="$PIP"

say "Installing Python dependencies / 安裝 Python 相依套件"
"$PIP" install --upgrade pip || warn "could not upgrade pip (continuing)"
"$PIP" install -r requirements.txt
"$PIP" install pytest            # for the verification step

# ------------------------------------------------------------------ scanners
if [ "$DO_TOOLS" -eq 1 ]; then
  say "Installing scanners / 安裝掃描工具"

  # Semgrep is a Python package — install it into this (venv) environment so it
  # is on PATH whenever the app runs.
  "$PIP" install semgrep || warn "semgrep install failed"

  # Native binaries (Trivy, Bearer, OSV-Scanner, Gitleaks) via install-tools.sh.
  if [ -w /usr/local/bin ]; then
    BIN_DIR=/usr/local/bin
  else
    BIN_DIR="$HOME/.local/bin"
    mkdir -p "$BIN_DIR"
  fi
  say "Installing scanner binaries into $BIN_DIR"
  BIN_DIR="$BIN_DIR" PIP_CMD="$PIP" bash scripts/install-tools.sh || warn "some tools failed to install"

  case ":$PATH:" in
    *":$BIN_DIR:"*) : ;;
    *) warn "add $BIN_DIR to your PATH so the app can find the scanners:";
       echo "      export PATH=\"$BIN_DIR:\$PATH\"" ;;
  esac
else
  say "Skipping scanners (--no-tools). The app degrades gracefully; each tool"
  echo "    shows as 'unavailable' until installed."
fi

# ------------------------------------------------------------------ verify
say "Verifying the build (running tests) / 執行測試驗證"
TESTS_OK=1
if "$PYTHON" -m pytest -q; then
  say "Build verified — all tests passed ✅"
else
  warn "tests reported failures — see output above"
  TESTS_OK=0
fi

if [ "$DO_TOOLS" -eq 1 ]; then
  say "Checking scanner availability / 檢查掃描工具"
  MISSING_TOOLS=()
  for tool in semgrep bearer trivy npm osv-scanner gitleaks; do
    if have "$tool" || [ -x "${BIN_DIR:-/usr/local/bin}/$tool" ]; then
      echo "  $tool: available"
    else
      echo "  $tool: unavailable"
      MISSING_TOOLS+=("$tool")
    fi
  done
fi

# ------------------------------------------------------------------ done
ACTIVATE_HINT=""
[ "$USE_VENV" -eq 1 ] && ACTIVATE_HINT="source $VENV_DIR/bin/activate && "

if [ "$TESTS_OK" -eq 1 ]; then
  say "Setup complete / 安裝完成 🎉"
else
  warn "Setup finished with failed verification tests"
fi
echo "Start the server / 啟動服務："
echo "    ${ACTIVATE_HINT}uvicorn app.main:app --host 0.0.0.0 --port 8000"
echo "Then open / 然後開啟：  http://localhost:8000"
echo "Tool status is shown in the UI header and at GET /api/tools"

if [ "$DO_RUN" -eq 1 ]; then
  say "Starting server (Ctrl-C to stop) / 啟動服務中…"
  exec uvicorn app.main:app --host 0.0.0.0 --port 8000
fi

[ "$TESTS_OK" -eq 1 ] || exit 1
