#!/usr/bin/env bash
# One command to update a running deployment: cache, build, switch, verify.
#
#   ./scripts/deploy.sh              # pull, cache, build, restart, verify
#   ./scripts/deploy.sh --no-pull    # deploy the working tree as it is
#   ./scripts/deploy.sh --rollback   # go back to the previous image
#
# The build runs while the old containers keep serving, so the only downtime
# is the container swap at the end. The previous image is tagged first, so a
# bad deploy can be undone without rebuilding anything.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

PULL=1
ROLLBACK=0
PREV=""
for arg in "$@"; do
  case "${arg}" in
    --no-pull)  PULL=0 ;;
    --rollback) ROLLBACK=1 ;;
    --prev=*)   PREV="${arg#--prev=}" ;;   # internal: set by the re-exec below
    -h|--help)  sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown option: ${arg}" >&2; exit 2 ;;
  esac
done

step() { printf '\n== %s\n' "$*"; }
die()  { printf '\nFAILED: %s\n' "$*" >&2; exit 1; }

compose() {
  if docker compose version >/dev/null 2>&1; then docker compose "$@"
  else docker-compose "$@"; fi
}

# The scanner upgrade (scripts/sast_updater.py) switches images too. Two of
# them at once would each tag the other's image as the one to roll back to.
# After the re-exec below, fd 9 is inherited still holding the lock; opening
# it again would drop the lock for a moment, long enough for the updater. So
# open it only when it is not open yet, and always take the lock: locking
# the same open file again succeeds, and no option can skip it.
if ! { true >&9; } 2>/dev/null; then
  exec 9>"${ROOT}/.updater.lock"
fi
flock -n 9 || die "a scanner upgrade is running; try again when it finishes"

# ------------------------------------------------------------------ rollback
if [ "${ROLLBACK}" -eq 1 ]; then
  step "Rolling back to the previous image"
  docker image inspect sast-studio:rollback-previous >/dev/null 2>&1 \
    || die "no rollback image found (nothing to roll back to)"
  docker tag sast-studio:rollback-previous sast-studio:latest
  compose up -d --no-build || die "could not start the previous image"
  echo "Rolled back. Check the service, then redeploy when the fix is ready."
  exit 0
fi

# -------------------------------------------------------------------- deploy
# Pull first, and if that changed this script, run the new one. Bash reads a
# script as it goes, so carrying on would run the old steps -- a deploy once
# skipped the scanner check it was shipping, and printed steps twice.
[ -n "${PREV}" ] || PREV="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
if [ "${PULL}" -eq 1 ] && [ -d .git ]; then
  step "Updating the source"
  before="$(sha256sum "$0" | cut -d' ' -f1)"
  git pull --ff-only || die "git pull failed (local changes? resolve them first)"
  if [ "$(sha256sum "$0" | cut -d' ' -f1)" != "${before}" ]; then
    echo "  deploy.sh itself changed; continuing with the new version"
    exec bash "$0" --no-pull "--prev=${PREV}"
  fi
fi

step "Tagging the current image so this deploy can be undone"
if docker image inspect sast-studio:latest >/dev/null 2>&1; then
  docker tag sast-studio:latest "sast-studio:rollback-${PREV}"
  docker tag sast-studio:latest sast-studio:rollback-previous
  echo "  previous image kept as sast-studio:rollback-${PREV}"
else
  echo "  no existing image (first deploy)"
fi

echo "  deploying $(git rev-parse --short HEAD 2>/dev/null || echo 'working tree')"

# The upgrade exchange directory. It must exist, owned by this user, before
# compose starts: a missing bind-mount source is created by Docker as root,
# and then neither the app nor the host updater could write to it.
mkdir -p "${ROOT}/ops"

# Download the scanner binaries before the build rather than during it. On a
# slow link this is the difference between a build of minutes and one of tens
# of minutes, and a failure here costs nothing: the build falls back to
# downloading whatever is still missing.
# Scanner versions upgraded from the web panel live in .env (written by
# scripts/sast_updater.py), not in the repository. Keep them: a deploy of new
# code must not quietly take a scanner back to the repository's version.
BUILD_ARGS=()
if [ -f .env ]; then
  while IFS='=' read -r key value; do
    export "${key}=${value}"
    BUILD_ARGS+=(--build-arg "${key}=${value}")
    echo "  keeping ${key}=${value} from .env"
  done < <(grep -E '^(SEMGREP|TRIVY|OSV_SCANNER|GITLEAKS)_VERSION=[0-9]+[.][0-9]+[.][0-9]+$' .env || true)
fi

step "Caching scanner binaries (resumable, safe to interrupt)"
bash "${ROOT}/scripts/fetch-vendor.sh" || echo "  continuing; the build will fetch what is missing"

step "Building the new image (the running service is untouched)"
compose build "${BUILD_ARGS[@]}" || die "build failed -- the old version is still serving"

# A healthy service says nothing about its scanners: a deploy once went out
# with semgrep failing on import, and /api/tools cannot be read once accounts
# are on. Ask the scanners themselves, in the new image, before it serves.
step "Checking every scanner starts in the new image"
if ! docker run --rm --entrypoint python sast-studio:latest -m app.selfcheck probe; then
  if docker image inspect sast-studio:rollback-previous >/dev/null 2>&1; then
    docker tag sast-studio:rollback-previous sast-studio:latest
  else
    # First deploy: nothing to go back to, so do not leave the broken image
    # as "latest" for the next compose up to start.
    docker rmi sast-studio:latest >/dev/null 2>&1 || true
  fi
  die "a scanner does not start in the new image -- not switched, the old version is still serving"
fi

step "Switching to the new image"
compose up -d || die "could not start the new image; ./scripts/deploy.sh --rollback"

# nginx.conf is bind-mounted as a single file, which pins the inode it had
# when the container started. git pull replaces the file rather than editing
# it in place, so the container keeps serving the old config and even
# "nginx -s reload" re-reads the stale inode. Compose will not recreate it
# either, because the image has not changed. Recreate it when the file
# differs. (Found when a Host-header fix deployed and silently did nothing.)
if ! compose exec -T nginx cmp -s /etc/nginx/conf.d/default.conf /dev/stdin        < "${ROOT}/nginx/nginx.conf" 2>/dev/null; then
  echo "  nginx config changed on disk; recreating the container"
  compose up -d --force-recreate nginx || die "could not restart nginx"
fi

step "Waiting for the service to report healthy"
ok=0
for _ in $(seq 1 60); do
  state="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' \
           "$(compose ps -q sast-studio 2>/dev/null)" 2>/dev/null || echo unknown)"
  case "${state}" in
    healthy|running) ok=1; break ;;
    unhealthy)       break ;;
  esac
  sleep 5
done
[ "${ok}" -eq 1 ] || die "service did not become healthy -- ./scripts/deploy.sh --rollback"

step "Checking the app answers"
URL="http://localhost:8080"
# Through nginx, which re-resolves the backend every 10 s: a recreated
# container on a new address can take that long to be reachable.
code=000
for _ in $(seq 1 12); do
  code="$(curl -s -o /dev/null -w '%{http_code}' "${URL}/api/health" || echo 000)"
  [ "${code}" = "200" ] && break
  sleep 5
done
[ "${code}" = "200" ] || die "health endpoint returned ${code} -- ./scripts/deploy.sh --rollback"

# /api/tools needs a login once accounts are enabled, so a 401 here is the
# system working, not a failure. Report the scanner count when it is readable
# and say why when it is not, rather than failing a healthy deployment.
tools_code="$(curl -s -o /tmp/sast-tools.$$ -w '%{http_code}' "${URL}/api/tools" || echo 000)"
if [ "${tools_code}" = "200" ]; then
  tools_ok="$(grep -o '"available": *true' /tmp/sast-tools.$$ | wc -l | tr -d ' ')"
  echo "  health 200; ${tools_ok}/6 scanners available"
elif [ "${tools_code}" = "401" ]; then
  echo "  health 200; /api/tools requires a sign-in (accounts are enabled)"
else
  rm -f /tmp/sast-tools.$$
  die "/api/tools returned ${tools_code} -- ./scripts/deploy.sh --rollback"
fi
rm -f /tmp/sast-tools.$$

# On a first run the application generates an administrator password and
# prints it once. Surface it here rather than leaving it buried in the log:
# it is not stored anywhere readable, so a missed line means resetting it.
if compose logs sast-studio 2>/dev/null | grep -q "First run: created administrator"; then
  step "First run: administrator account"
  compose logs sast-studio 2>/dev/null \
    | grep -A 4 "First run: created administrator" \
    | sed 's/^[^|]*| *//'
  echo "  Save these now; the password is not recoverable."
fi

# Every deploy keeps the image it replaced. Without a limit they pile up:
# .145 had 54 of them and 516 MB of disk left.
step "Removing old images (keeping this version and the one before)"
bash "${ROOT}/scripts/prune-rollbacks.sh"

printf '\nDeployed. %s\n' "$(git rev-parse --short HEAD 2>/dev/null || echo 'working tree')"
echo "Open ${URL} -- roll back with ./scripts/deploy.sh --rollback"
