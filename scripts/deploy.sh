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
for arg in "$@"; do
  case "${arg}" in
    --no-pull)  PULL=0 ;;
    --rollback) ROLLBACK=1 ;;
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
step "Tagging the current image so this deploy can be undone"
if docker image inspect sast-studio:latest >/dev/null 2>&1; then
  PREV="$(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
  docker tag sast-studio:latest "sast-studio:rollback-${PREV}"
  docker tag sast-studio:latest sast-studio:rollback-previous
  echo "  previous image kept as sast-studio:rollback-${PREV}"
else
  echo "  no existing image (first deploy)"
fi

if [ "${PULL}" -eq 1 ] && [ -d .git ]; then
  step "Updating the source"
  git pull --ff-only || die "git pull failed (local changes? resolve them first)"
fi
echo "  deploying $(git rev-parse --short HEAD 2>/dev/null || echo 'working tree')"

# The Monitor tab reads the docker socket, which is owned by root:docker with
# no world access. The app runs as a non-root user, so it needs that group --
# and the gid differs between hosts, so read the real one rather than guessing.
# Without this the Monitor tab just says "permission denied".
step "Detecting the docker group id for the Monitor tab"
if [ -S /var/run/docker.sock ]; then
  DOCKER_GID="$(stat -c '%g' /var/run/docker.sock)"
  echo "  docker.sock is group ${DOCKER_GID}"
  if [ -f .env ] && grep -q '^DOCKER_GID=' .env; then
    # Portable in-place edit: BSD and GNU sed disagree about -i.
    tmp="$(mktemp)"
    sed "s/^DOCKER_GID=.*/DOCKER_GID=${DOCKER_GID}/" .env > "${tmp}" && mv "${tmp}" .env
  else
    echo "DOCKER_GID=${DOCKER_GID}" >> .env
  fi
  echo "  wrote DOCKER_GID=${DOCKER_GID} to .env"
else
  echo "  no docker socket on this host; the Monitor tab will show it as off"
fi

# Download the scanner binaries before the build rather than during it. On a
# slow link this is the difference between a build of minutes and one of tens
# of minutes, and a failure here costs nothing: the build falls back to
# downloading whatever is still missing.
step "Caching scanner binaries (resumable, safe to interrupt)"
bash "${ROOT}/scripts/fetch-vendor.sh" || echo "  continuing; the build will fetch what is missing"

step "Building the new image (the running service is untouched)"
compose build || die "build failed -- the old version is still serving"

step "Switching to the new image"
compose up -d || die "could not start the new image; ./scripts/deploy.sh --rollback"

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
code="$(curl -s -o /dev/null -w '%{http_code}' "${URL}/api/health" || echo 000)"
[ "${code}" = "200" ] || die "health endpoint returned ${code} -- ./scripts/deploy.sh --rollback"

tools_ok="$(curl -s "${URL}/api/tools" | grep -o '"available": *true' | wc -l | tr -d ' ')"
echo "  health 200; ${tools_ok}/6 scanners available"

printf '\nDeployed. %s\n' "$(git rev-parse --short HEAD 2>/dev/null || echo 'working tree')"
echo "Open ${URL} -- roll back with ./scripts/deploy.sh --rollback"
